/*
 * test.c
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "json-store.h"
#include "ksc-ws.h"
#include "SignalService.pb-c.h"

#include <inttypes.h>
#include <assert.h>
#include <time.h>	/* ctime_r() */

static const struct ksc_log_context log_ctx = {
	.desc = "main",
	.color = "1;97",
};

/* shortcuts */
#define LOGL_(level,log,...)	KSC_LOG_(level, log, &log_ctx, __VA_ARGS__)
#define LOGL(lvl,log,...)	KSC_LOG(lvl, log, &log_ctx, __VA_ARGS__)
#define LOG_(level,...)		LOGL_(level, &ksc->log, __VA_ARGS__)
#define LOG(lvl,...)		LOGL(lvl, &ksc->log, __VA_ARGS__)

static void print_attachment_pointer(int fd, Signalservice__AttachmentPointer *a, int indent)
{
	if (a->has_id)
		dprintf(fd, "%*sid: %" PRIu64 "\n", indent+2, "", a->id);
	if (a->contenttype)
		dprintf(fd, "%*scontent type: %s\n", indent+2, "", a->contenttype);
	if (a->has_key) {
		dprintf(fd, "%*skey: ", indent+2, "");
		ksc_dprint_hex(fd, a->key.data, a->key.len);
		dprintf(fd, "\n");
	}
	if (a->has_size)
		dprintf(fd, "%*ssize: %" PRIu32 "\n", indent+2, "", a->size);
	if (a->has_thumbnail)
		dprintf(fd, "%*shas thumbnail of size %zu\n", indent+2, "", a->thumbnail.len);
	if (a->has_digest) {
		dprintf(fd, "%*shas digest: ", indent+2, "");
		ksc_dprint_hex(fd, a->digest.data, a->digest.len);
		dprintf(fd, "\n");
	}
	if (a->filename)
		dprintf(fd, "%*sfilename: %s\n", indent+2, "", a->filename);
	if (a->has_flags)
		dprintf(fd, "%*sflags: 0x%" PRIu32 "\n", indent+2, "", a->flags);
	if (a->has_width)
		dprintf(fd, "%*swidth: %" PRIu32 "\n", indent+2, "", a->width);
	if (a->has_height)
		dprintf(fd, "%*sheight: %" PRIu32 "\n", indent+2, "", a->height);
	if (a->caption)
		dprintf(fd, "%*scaption: %s\n", indent+2, "", a->caption);
}

static void print_data_message(int fd, Signalservice__DataMessage *e, int indent)
{
	if (e->base.n_unknown_fields)
		dprintf(fd, "%*s# unknown fields: %u\n", indent, "", e->base.n_unknown_fields);
	if (e->body)
		dprintf(fd, "%*sbody: %s\n", indent, "", e->body);
	if (e->n_attachments) {
		dprintf(fd, "%*s# attachments: %zu\n", indent, "", e->n_attachments);
		for (size_t i=0; i<e->n_attachments; i++)
			print_attachment_pointer(fd, e->attachments[i], indent+2);
	}
	if (e->group) {
		struct _Signalservice__GroupContext *g = e->group;
		dprintf(fd, "%*shas group info:\n", indent, "");
		if (g->has_id) {
			dprintf(fd, "%*sid: ", indent+2, "");
			ksc_dprint_hex(fd, g->id.data, g->id.len);
			dprintf(fd, "\n");
		}
		if (g->has_type) {
			char *type = NULL;
			switch (g->type) {
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__UNKNOWN: type = "unknown"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__UPDATE: type = "update"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__DELIVER: type = "deliver"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__QUIT: type = "quit"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__REQUEST_INFO: type = "request info"; break;
			case _SIGNALSERVICE__GROUP_CONTEXT__TYPE_IS_INT_SIZE: break;
			}
			dprintf(fd, "%*stype: %s (%d)\n", indent+2, "", type, g->type);
		}
		if (g->name)
			dprintf(fd, "%*sname: %s\n", indent+2, "", g->name);
		for (size_t i=0; i<g->n_members; i++)
			dprintf(fd, "%*smember: %s\n", indent+2, "", g->members[i]);
		if (g->avatar)
			dprintf(fd, "%*shas avatar\n", indent+2, "");
	}
	if (e->has_flags)
		dprintf(fd, "%*sflags: 0x%x\n", indent, "", e->flags);
	if (e->has_expiretimer)
		dprintf(fd, "%*sexpire timer: %ud\n", indent, "", e->expiretimer);
	if (e->has_profilekey) {
		dprintf(fd, "%*sprofile key:\n", indent, "");
		ksc_dprint_hex(fd, e->profilekey.data, e->profilekey.len);
		dprintf(fd, "\n");
	}
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		dprintf(fd, "%*stimestamp: %" PRIu64 " %s", indent, "", e->timestamp, buf);
	}
	if (e->quote)
		dprintf(fd, "%*shas quote\n", indent, "");
	if (e->n_contact)
		dprintf(fd, "%*s# contacts: %zu\n", indent, "", e->n_contact);
	if (e->n_preview)
		dprintf(fd, "%*s# previews: %zu\n", indent, "", e->n_preview);
	if (e->sticker)
		dprintf(fd, "%*shas sticker\n", indent, "");
	if (e->has_requiredprotocolversion)
		dprintf(fd, "%*srequired protocol version: %ud\n", indent, "",
		        e->requiredprotocolversion);
	if (e->has_messagetimer)
		dprintf(fd, "%*smessage timer: %ud\n", indent, "", e->messagetimer);
}

static void print_sync_message(int fd, Signalservice__SyncMessage *e, int indent)
{
	if (e->base.n_unknown_fields)
		dprintf(fd, "%*s# unknown fields: %u\n", indent, "", e->base.n_unknown_fields);
	if (e->sent) {
		dprintf(fd, "%*s----- sent -----\n", indent, "");
		dprintf(fd, "%*sdestination: %s\n", indent, "", e->sent->destination);
		if (e->sent->has_timestamp) {
			char buf[32];
			time_t t = e->sent->timestamp / 1000;
			ctime_r(&t, buf);
			dprintf(fd, "%*stimestamp: %" PRIu64 " %s", indent, "",
			        e->sent->timestamp, buf);
		}
		if (e->sent->message) {
			dprintf(fd, "%*smessage:\n", indent, "");
			print_data_message(fd, e->sent->message, indent+2);
		}
		if (e->sent->has_expirationstarttimestamp) {
			char buf[32];
			time_t t = e->sent->expirationstarttimestamp / 1000;
			ctime_r(&t, buf);
			dprintf(fd, "%*sexpiration start timestamp: %" PRIu64 " %s",
			        indent, "", e->sent->expirationstarttimestamp, buf);
		}
		dprintf(fd, "%*s# unidentified status: %zu\n", indent, "", e->sent->n_unidentifiedstatus);
		for (size_t i=0; i<e->sent->n_unidentifiedstatus; i++) {
			struct _Signalservice__SyncMessage__Sent__UnidentifiedDeliveryStatus *u;
			u = e->sent->unidentifiedstatus[i];
			dprintf(fd, "%*sdestination: %s\n", indent+2, "", u->destination);
			if (u->has_unidentified)
				dprintf(fd, "%*sunidentified: %d\n", indent+2, "", u->unidentified);
		}
		if (e->sent->has_isrecipientupdate)
			dprintf(fd, "%*sis recipient update: %d\n", indent, "", e->sent->isrecipientupdate);
	}
	if (e->contacts)
		dprintf(fd, "%*s----- contacts -----\n", indent, "");
	if (e->groups)
		dprintf(fd, "%*s----- groups -----\n", indent, "");
	if (e->request)
		dprintf(fd, "%*s----- request -----\n", indent, "");
	if (e->read) {
		dprintf(fd, "%*s----- # read: %zu -----\n", indent, "", e->n_read);
		for (size_t i=0; i<e->n_read; i++) {
			dprintf(fd, "%*ssender: %s\n", indent+2, "", e->read[i]->sender);
			if (e->read[i]->has_timestamp) {
				char buf[32];
				time_t t = e->read[i]->timestamp / 1000;
				ctime_r(&t, buf);
				dprintf(fd, "%*stimestamp: %" PRIu64 " %s",
				        indent+2, "", e->read[i]->timestamp, buf);
			}
		}
	}
	if (e->blocked)
		dprintf(fd, "%*s----- blocked -----\n", indent, "");
	if (e->verified)
		dprintf(fd, "%*s----- verified -----\n", indent, "");
	if (e->configuration)
		dprintf(fd, "%*s----- configuration -----\n", indent, "");
	if (e->has_padding)
		dprintf(fd, "%*spadding: %zu bytes\n", indent, "", e->padding.len);
	if (e->stickerpackoperation)
		dprintf(fd, "%*s----- sticker pack op -----\n", indent, "");
	if (e->messagetimerread)
		dprintf(fd, "%*s----- message timer read -----\n", indent, "");
}

struct ksc_ctx {
	struct ksc_log log;
	const char *message;
	const char *target;
	Signalservice__SyncMessage__Request__Type sync_request;
	bool end_session;
};

static void on_close_do_stop(intptr_t uuid, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "close, stopping\n");
	fio_stop();
	(void)uuid;
}

static void handle_new_uuid(char *uuid, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "got new uuid: %s\n", uuid);
}

static int recv_get_profile(ws_s *ws, struct ksc_signal_response *r,
                            void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG_(r->status == 200 ? KSC_LOG_INFO : KSC_LOG_ERROR,
	     "recv get profile: %u %s: ", r->status, r->message);

	if (r->status != 200) {
		dprintf(ksc->log.fd, "\n");
		return 0;
	}

	FIOBJ profile;
	size_t parsed = fiobj_json2obj(&profile, r->body.data, r->body.len);
	LOG(INFO, "fio json parsed %zu of %zu", parsed, r->body.len);
	if (parsed) {
		FIOBJ str = fiobj_obj2json(profile, 1);
		fio_str_info_s s = fiobj_obj2cstr(str);
		dprintf(ksc->log.fd, ": %.*s\n", (int)s.len, s.data);
		fiobj_free(str);
		fiobj_free(profile);
	} else
		dprintf(ksc->log.fd, ", failed\n");

	LOG(INFO, "recv get profile: ");
	struct kjson_value p = KJSON_VALUE_INIT;
	if (kjson_parse(&(struct kjson_parser){ r->body.data }, &p)) {
		kjson_value_print(stderr, &p);
		dprintf(ksc->log.fd, "\n");
	} else
		dprintf(ksc->log.fd, "error parsing profile json: '%.*s'\n",
		        (int)r->body.len, r->body.data);
	kjson_value_fini(&p);

	return 0;
	(void)udata;
	(void)ws;
}

static int recv_get_pre_key(ws_s *ws, struct ksc_signal_response *r,
                            void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "recv get pre key: %u %s: %.*s\n",
	          r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)ws;
}

static int recv_get_cert_delivery(ws_s *ws, struct ksc_signal_response *r,
                                  void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "recv get certificate delivery: %u %s: %.*s\n",
	          r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)ws;
}

#if 0
Output is something like this:
recv messages: 200 OK
  body: {
	"messages": [
		{ "guid":"e9842d55-dd8c-4b19-9c2e-88359e49a371"
		, "type":3
		, "relay":""
		, "timestamp":1566388636374
		, "source":"NUMBER"
		, "sourceDevice":DEVICE_ID
		, "message":null
		, "content":"MwgKEiEFAMYX3sB2QebY8yLneK/XF/iv6KXCkk8QJKaXZ/ZFizkaIQUZpRraju9k6p3I1oa5Y9cuFMc6wBvivPQxoGQVzTGhIyLTATMKIQVHly4+yvNDrwcOMqeO/GSrLIhlk6e9bBxXTcDEUYaSXhA/GAAioAHuCFL9nHnwSC7I1fuT1Lz2BDg0AzkGMcxVMXIvqYDaUEIS35aOprUjuTqpzz9fOguz6eDIAqCBnASc0tvlaUZ1xrM1n8KSzVXFDR8z3hlZAiH1qJ6Z4rH/AZx8kq0bw0KLzjBqgn42aMzNsGuahduPTWZjHZDABgupIS9AefDhh/LU19Y/WOQHRJBiT203b79QS2/DhKoQwLJMVsC4VON3BkQO50153Zsotm0wAA=="
		, "serverTimestamp":1566388652354
		}
	],
	"more":false
}
These should be ACK-ed as per fio_defer(delete_request) ...
#endif
static int recv_messages(ws_s *ws, struct ksc_signal_response *r, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "recv messages: %d %s\n", r->status, r->message);
	if (ksc_log_prints(KSC_LOG_INFO, &ksc->log, &log_ctx)) {
		for (size_t i=0; i<r->n_headers; i++)
			dprintf(ksc->log.fd, "  header: %s\n", r->headers[i]);
		dprintf(ksc->log.fd, "  body: %.*s\n",
		        (int)r->body.len, r->body.data);
	}
	return 0;
	(void)ws;
}

static void on_sent(size_t n_failed, uint64_t timestamp,
                    const struct ksc_service_address *addr,
                    const struct ksc_device_array *devs, void *udata)
{
	struct ksc_ctx *ksc = udata;
	if (devs)
		LOG(NOTE, "on_sent to %.*s: failed to build session to %zu of %zu devices\n",
		    (int)addr->name_len, addr->name, n_failed, devs->n);
	else
		LOG(ERROR, "on_sent to %.*s: failed to send messages, timeout?\n",
		    (int)addr->name_len, addr->name);
}

static void send_get_profile(ws_s *s, struct ksc_ws *kws)
{
	struct ksc_ctx *ksc = ksc_ws_get_udata(kws);
	LOG(INFO, "connected\n");
#if 0 && defined(DEFAULT_GET_PROFILE_NUMBER)
	// works
	ksc_ws_send_request(s, "GET",
	                    "/v1/profile/" DEFAULT_GET_PROFILE_NUMBER,
	                    .on_response = recv_get_profile, .udata = ksc);
	// fails
	ksc_ws_send_request(s, "GET",
	                    "/v2/keys/" DEFAULT_GET_PROFILE_NUMBER "/*",
	                    .on_response = recv_get_pre_key, .udata = ksc);
	// fails
	ksc_ws_send_request(s, "GET", "/v1/certificate/delivery",
	                    .on_response = recv_get_cert_delivery,
	                    .udata = ksc);
#elif 0
	ksc_ws_send_request(s, "GET", "/v1/messages/",
	                    .on_response = recv_messages,
	                    .udata = ksc);
#elif 1
	if (ksc->message && ksc->target) {
		int r = ksc_ws_send_message(s, kws, ksc->target,
		                            .end_session = ksc->end_session,
		                            .body = ksc->message,
		                            .on_sent = on_sent,
		                            .udata = ksc);
		LOG(DEBUG, "send -> %d\n", r);
	}
	if (ksc->sync_request != SIGNALSERVICE__SYNC_MESSAGE__REQUEST__TYPE__UNKNOWN) {
		int r = ksc_ws_sync_request(s, kws, ksc->sync_request, NULL, NULL);
		LOG(DEBUG, "sync request -> %d\n", r);
	}
#else
	(void)ksc;
	(void)s;
#endif
}

static bool on_content(ws_s *ws, struct ksc_ws *kws,
                       const Signalservice__Envelope *e,
                       const Signalservice__Content *c)
{
	struct ksc_ctx *ksc = ksc_ws_get_udata(kws);
	if (ksc_log_prints(KSC_LOG_INFO, &ksc->log, &log_ctx)) {
		LOG(INFO, "received content:\n");
		ksc_print_envelope(e, ksc->log.fd,
		                   ksc_log_prints(KSC_LOG_DEBUG, &ksc->log, &log_ctx));
		if (c->base.n_unknown_fields) {
			dprintf(ksc->log.fd, "  ------ base ------\n");
			dprintf(ksc->log.fd, "  # unknown fields: %u\n",
			        c->base.n_unknown_fields);
		}
		if (c->datamessage) {
			dprintf(ksc->log.fd, "  ------ data ------\n");
			print_data_message(ksc->log.fd, c->datamessage, 2);
		}
		if (c->syncmessage) {
			dprintf(ksc->log.fd, "  ------ sync ------\n");
			print_sync_message(ksc->log.fd, c->syncmessage, 4);
		}
		if (c->callmessage)
			dprintf(ksc->log.fd, "  ------ call ------\n");
		if (c->nullmessage)
			dprintf(ksc->log.fd, "  ------ null ------\n");
		if (c->receiptmessage)
			dprintf(ksc->log.fd, "  ------ rcpt ------\n");
		if (c->typingmessage)
			dprintf(ksc->log.fd, "  ------ typn ------\n");
	}
	if (c->base.n_unknown_fields)
		return false;
	if (c->syncmessage) {
		Signalservice__SyncMessage *s = c->syncmessage;
		if (s->base.n_unknown_fields)
			return false;
		if (s->contacts || s->groups || s->request ||
		    s->blocked || s->verified || s->configuration ||
		    s->stickerpackoperation || s->messagetimerread)
			return false;
		if (s->sent || s->read)
			return true;
		return false;
	}
	if (c->callmessage)
		return false;
	if (c->receiptmessage)
		return false;
	if (c->typingmessage)
		return false;
	return true; /* handled */
	(void)ws;
	(void)e;
}


static bool parse_v_lvl(const char *lvl, enum ksc_log_lvl *res)
{
	char *endptr;
	long v = strtol(lvl, &endptr, 0);
	if (endptr == lvl)
		return ksc_log_lvl_parse(lvl, res);
	if (v < KSC_LOG_NONE || v > INT_MAX)
		return false;
	*res = v;
	return true;
}

static bool parse_v(char *arg, struct ksc_log *log)
{
	char *colon = strrchr(arg, ':');
	if (!colon)
		return parse_v_lvl(arg, &log->max_lvl);
	enum ksc_log_lvl lvl;
	if (!parse_v_lvl(colon+1, &lvl))
		return false;
	struct ksc_log__context_lvl *it;
	it = ksc_malloc(sizeof(*it));
	it->max_lvl = lvl;
	*colon = '\0';
	it->desc = arg;
	it->next = log->context_lvls;
	log->context_lvls = it;
	return true;
}

#ifndef DEFAULT_CLI_CONFIG
# define DEFAULT_CLI_CONFIG	NULL
#endif
#ifndef KSIGNAL_SERVER_CERT
# define KSIGNAL_SERVER_CERT	NULL
#endif
#ifndef DEFAULT_GET_PROFILE_NUMBER
# define DEFAULT_GET_PROFILE_NUMBER	NULL
#endif

#define DIE(code,...) do { fprintf(stderr, __VA_ARGS__); exit(code); } while (0)

int main(int argc, char **argv)
{
	struct ksc_log log = KSC_DEFAULT_LOG;
	log.max_lvl = KSC_LOG_INFO;
	const char *cli_path = DEFAULT_CLI_CONFIG;
	const char *cert_path = KSIGNAL_SERVER_CERT;
	bool force = false;
	const char *message = NULL;
	const char *target = DEFAULT_GET_PROFILE_NUMBER;
	bool end_session = false;
	Signalservice__SyncMessage__Request__Type sync_request =
		SIGNALSERVICE__SYNC_MESSAGE__REQUEST__TYPE__UNKNOWN;
	for (int opt; (opt = getopt(argc, argv, ":c:C:efhm:p:s:t:v:")) != -1;)
		switch (opt) {
		case 'c': cert_path = optarg; break;
		case 'C': log.override_color = atoi(optarg); break;
		case 'e': end_session = true; break;
		case 'f': force = true; break;
		case 'h':
			fprintf(stderr, "usage: %s [-c CERT_PATH] [-C OVERRIDE_COLOR] [-f] [-m MESSAGE] [-t MSG_TARGET] [-s SYNC_TYPE] [-p CLI_CONFIG_PATH] [-v ARG]\n", argv[0]);
			exit(0);
		case 'm': message = optarg; break;
		case 'p': cli_path = optarg; break;
		case 's': sync_request = atoi(optarg); break;
		case 't': target = optarg; break;
		case 'v':
			if (!parse_v(optarg, &log))
				DIE(1,"error parsing option '-v %s'\n", optarg);
			break;
		case ':': DIE(1,"error: option '-%c' requires a parameter\n",
		              optopt);
		case '?': DIE(1,"error: unknown option '-%c'\n",optopt);
		}

	if (!cli_path) {
		fprintf(stderr, "require path to JSON config file\n");
		return 1;
	}

	struct stat st;
	if (cert_path && stat(cert_path, &st) == -1) {
		fprintf(stderr, "error accessing certificate path '%s': %s\n",
		        cert_path, strerror(errno));
		return 1;
	}
	if (!cert_path && !force) {
		fprintf(stderr, "no pinned server certificate, refusing to "
		        "connect (use '-f' to circumvent this warning)\n");
		return 1;
	}

	struct ksc_ctx ctx = {
		.log = log,
		.message = message,
		.target = target,
		.end_session = end_session,
		.sync_request = sync_request,
	};
	struct json_store *js = NULL;
	js = json_store_create(cli_path, &ctx.log);
	LOGL_(js ? KSC_LOG_DEBUG : KSC_LOG_ERROR, &ctx.log, "js: %p\n", (void *)js);
	if (!js) {
		fprintf(stderr, "%s: error reading JSON config file\n", cli_path);
		return 1;
	}

	int r = 0;

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	if (!number) {
		fprintf(stderr, "no username, performing a device link\n");
		r = ksc_defer_get_new_uuid("wss://" KSC_SERVICE_HOST,
		                           .new_uuid = handle_new_uuid,
		                           .on_close = on_close_do_stop,
		                           .udata = &ctx) < 0;
	} else if (password) {
		struct ksc_ws *kws = ksc_ws_connect_service(js,
			.on_content = on_content,
			.on_open = send_get_profile,
			.on_close = on_close_do_stop,
			.signal_log_ctx = { "signal ctx", "95" /* bright magenta */ },
			.log = &ctx.log,
			.server_cert_path = cert_path,
			.udata = &ctx
		);
		r = kws ? 0 : 1;
	} else {
		fprintf(stderr, "don't know what to do, username but no password\n");
		r = 1;
	}
	LOGL(DEBUG, &ctx.log, "init: %d\n", r);

	fio_start(.threads=1);

	r = json_store_save(js);
	LOGL_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, &ctx.log,
	      "json_store_save returned %d\n", r);
	if (!r) {
		r = json_store_load(js);
		LOGL_(r ? KSC_LOG_DEBUG : KSC_LOG_ERROR, &ctx.log,
		      "json_store_load returned %d\n", r);
		r = !r;
	}
	if (!r) {
		r = json_store_save(js);
		LOGL_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, &ctx.log,
		      "json_store_save returned %d\n", r);
	}
	json_store_destroy(js);

#ifdef KSC_DEBUG_MEM_USAGE
	for (unsigned i=0; i<KSC_ARRAY_SIZE(ksc_alloc_buckets); i++) {
		size_t n = ksc_alloc_buckets[i];
		if (n)
			LOGL(DEBUG, &ctx.log, "alloc < 2^%2u: %zu\n", i, n);
	}
	LOGL(DEBUG, &ctx.log, "total alloced: %zu\n", ksc_alloc_total);
#endif


	ksc_log_fini(&ctx.log);

	return 0;
}
