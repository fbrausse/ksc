
#include <errno.h>
#include <pthread.h>

#include "ffi.h"
#include "utils.h"
#include "ksc-ws.h"

#include "SignalService.pb-c.h"

/* .log.context_lvls contains dynamically allocated .desc strings */
struct ksc_ffi_log {
	struct ksc_log log;
};

static void ffi_log_fini(struct object *o)
{
	struct ksc_log *log = OBJ_TO(o, struct ksc_log);
	struct ksc_ffi_log *ffi_log =
		(struct ksc_ffi_log *)((char *)log - offsetof(struct ksc_ffi_log, log));
	assert(ffi_log);
	KSC_DEBUG(DEBUG, "ffi: log_fini with count %zu\n", ffi_log->log.object_base.ref_counted.cnt);
	for (struct ksc_log__context_lvl *c = ffi_log->log.context_lvls; c;
	     c = c->next)
		free((char *)c->desc);
	ksc_log_fini(OBJ_OF(&ffi_log->log));
	ksc_free(log);
}

void ksc_ffi_log_destroy(struct ksc_ffi_log *ffi_log)
{
	KSC_DEBUG(DEBUG, "ffi: log_destroy with count %zu\n", ffi_log->log.object_base.ref_counted.cnt);
	OBJ_UNREF(&ffi_log->log);
}

struct ksc_ffi_log * ksc_ffi_log_create(int fd, const char *level)
{
	struct ksc_ffi_log log = { { {}, .fd = fd } };
	if (!ksc_log_lvl_parse(level, &log.log.max_lvl))
		return NULL;
	OBJ_INIT(&log.log, ffi_log_fini);
	return ksc_memdup(&log, sizeof(log));
}

int ksc_ffi_log_restrict_context(struct ksc_ffi_log *log, const char *desc,
                                 const char *level)
{
	if (!log)
		return -EINVAL;
	if (!desc)
		return -EINVAL;
	enum ksc_log_lvl max_lvl;
	if (!ksc_log_lvl_parse(level, &max_lvl))
		return -EINVAL;
	struct ksc_log__context_lvl cl = {
		.next = log->log.context_lvls,
		.desc = strdup(desc),
		.max_lvl = max_lvl,
	};
	log->log.context_lvls = ksc_memdup(&cl, sizeof(cl));
	return 0;
}

struct ksc_ffi_envelope {
	const Signalservice__Envelope *e;
};

char *   ksc_ffi_envelope_get_source(struct ksc_ffi_envelope *e)
{
	return e->e->source;
}

/* -1 if not present */
int64_t  ksc_ffi_envelope_get_source_device_id(struct ksc_ffi_envelope *e)
{
	if (!e->e->has_sourcedevice)
		return -1;
	return e->e->sourcedevice;
}

/* -1 if not present */
int64_t  ksc_ffi_envelope_get_timestamp(struct ksc_ffi_envelope *e)
{
	if (!e->e->has_timestamp)
		return -1;
	return e->e->timestamp;
}

struct ksc_ffi_data {
	Signalservice__DataMessage *d;
	char *group_id_base64;
};

char * ksc_ffi_data_get_body(struct ksc_ffi_data *d)
{
	return d->d->body;
}

char * ksc_ffi_data_get_group_id_base64(struct ksc_ffi_data *d)
{
	if (!d->d->group || !d->d->group->has_id)
		return NULL;
	if (!d->group_id_base64) {
		size_t len = d->d->group->id.len;
		char *g = malloc(len * 4/3 + 4 + 1);
		size_t n = ksc_base64_encode(g, d->d->group->id.data, len);
		g[n] = '\0';
		d->group_id_base64 = g;
	}
	return d->group_id_base64;
}

/* -1 if not present */
int64_t   ksc_ffi_data_get_timestamp(struct ksc_ffi_data *d)
{
	if (!d->d->has_timestamp)
		return -1;
	return d->d->timestamp;
}

struct ksc_ffi {
	ws_s *ws;
	struct json_store *js;
	struct ksc_ws *kws;
	struct ksc_ffi_log *log;
	pthread_t thread;
	int (*on_receipt)(const struct ksc_ffi *,
	                  struct ksc_ffi_envelope *e);
	int (*on_data)(const struct ksc_ffi *,
	               struct ksc_ffi_envelope *e,
	               struct ksc_ffi_data *c);
	void (*on_open)(const struct ksc_ffi *);
	void (*on_close)(intptr_t uuid, void *udata);
	void *udata;
};

void * ksc_ffi_get_udata(struct ksc_ffi *ffi)
{
	return ffi->udata;
}

static bool ffi_on_receipt(ws_s *ws, struct ksc_ws *kws,
                           const Signalservice__Envelope *e)
{
	struct ksc_ffi *ffi = ksc_ws_get_udata(kws);
	struct ksc_ffi_envelope fe = { e };
	int r = 0;
	if (ffi->on_receipt)
		r = ffi->on_receipt(ffi, &fe);
	return r ? false : true;
	(void)ws;
}

static bool ffi_on_content(ws_s *ws, struct ksc_ws *kws,
                           const Signalservice__Envelope *e,
                           const Signalservice__Content *c)
{
	struct ksc_ffi *ffi = ksc_ws_get_udata(kws);
	if (!c->datamessage)
		return true;
	struct ksc_ffi_envelope fe = { e };
	struct ksc_ffi_data fd = { .d = c->datamessage };
	int r = 0;
	if (ffi->on_data)
		r = ffi->on_data(ffi, &fe, &fd);
	ksc_free(fd.group_id_base64);
	return r ? false : true;
	(void)ws;
}

static void ffi_on_open(ws_s *ws, struct ksc_ws *kws)
{
	struct ksc_ffi *ffi = ksc_ws_get_udata(kws);
	ffi->ws = ws;
	if (ffi->on_open)
		ffi->on_open(ffi);
}

static void ffi_destroy(struct ksc_ffi *ffi)
{
	if (ffi->js)
		json_store_unref(ffi->js);
	ksc_free(ffi);
}

static void ffi_on_close(intptr_t uuid, void *udata)
{
	struct ksc_ffi *ffi = udata;
	if (ffi->on_close)
		ffi->on_close(uuid, ffi->udata);
}

static void * ffi_start(void *p)
{
	fio_start(.threads = 1);
	return NULL;
	(void)p;
}

struct ksc_ffi * ksc_ffi_start(const char *json_store_path,
	int (*on_receipt)(const struct ksc_ffi *,
	                  struct ksc_ffi_envelope *e),
	int (*on_data)(const struct ksc_ffi *,
	               struct ksc_ffi_envelope *e,
	               struct ksc_ffi_data *c),
	void (*on_open)(const struct ksc_ffi *),
	void (*on_close)(intptr_t uuid, void *udata),
	struct ksc_ffi_log *log,
	const char *server_cert_path,
	int on_close_do_reconnect,
	void *udata
)
{
	struct ksc_ffi ffi_ = {
		.on_receipt = on_receipt,
		.on_data = on_data,
		.on_open = on_open,
		.on_close = on_close,
		.udata = udata,
		.log = log,
	};
	struct ksc_ffi *ffi = ksc_memdup(&ffi_, sizeof(ffi_));
	if (!ffi)
		return NULL;
	ffi->js = json_store_create(json_store_path, &log->log);
	if (!ffi->js)
		goto error;
	ffi->log = log; /* we'll use the reference js has on log */
	struct ksc_ws *kws = ksc_ws_connect_service(ffi->js,
		.on_receipt = ffi_on_receipt,
		.on_content = ffi_on_content,
		.on_open = ffi_on_open,
		.on_close = ffi_on_close,
		.udata = ffi,
		.signal_log_ctx = { "signal ctx", "95" /* bright magenta */ },
		.log = &log->log,
		.server_cert_path = server_cert_path,
		.on_close_do_reconnect = on_close_do_reconnect,
	);
	if (!kws)
		goto error;
	ffi->kws = kws;

	int r = pthread_create(&ffi->thread, NULL, ffi_start, ffi);
	if (r) {
		ffi_on_close(ksc_ws_get_uuid(ffi->kws), ffi);
		goto error;
	}

	return ffi;

error:
	ffi_destroy(ffi);
	return NULL;
}

void ksc_ffi_stop(struct ksc_ffi *ffi)
{
	fio_stop();
	pthread_join(ffi->thread, NULL);
	ffi_destroy(ffi);
}

struct ffi_send_message_data {
	struct ksc_ffi *ffi;
	void (*on_response)(int status, char *message, void *udata);
	void *udata;
};

static void ffi_on_result(const struct ksc_service_address *recipient,
                          struct ksc_signal_response *response,
                          unsigned result,
                          void *udata)
{
	struct ffi_send_message_data *d = udata;
	if (d->on_response)
		d->on_response(response->status, response->message, d->udata);
}

int ksc_ffi_send_message(struct ksc_ffi *ffi, const char *recipient,
	const char *body,
	int end_session,
	/*
	const void *const *attachments;
	size_t n_attachments;*/

	/* 0: to unsubscribe, other to stay subscribed */
	void (*on_response)(int status, char *message, void *udata),
	void *udata
)
{
	if (!ffi->ws)
		return -EBADF;
	struct ffi_send_message_data cb_data_ = {
		.ffi = ffi,
		.on_response = on_response,
		.udata = udata,
	}, *cb_data = ksc_memdup(&cb_data_, sizeof(cb_data_));
	int r = ksc_ws_send_message(ffi->ws, ffi->kws, recipient,
	                            .body = body,
	                            .end_session = end_session,
	                            .on_result = ffi_on_result,
	                            .udata = cb_data,
	);
	if (r)
		ksc_free(cb_data);
	return r;
}
