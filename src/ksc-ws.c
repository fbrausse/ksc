/*
 * ksc-ws.c
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifdef __STDC_NO_ATOMICS__
# error Need _Atomic support from C11
#endif

#include "ksc-ws.h"
#include "crypto.h"

#include <stdatomic.h>

#include <pthread.h>

#include <signal/protocol.h>
#include <signal/signal_protocol.h>
#include <signal/session_cipher.h>
#include <signal/session_builder.h>

static const struct ksc_log_context log_ctx = {
	.desc = "ksc-ws",
	.color = "34",
};

/* shortcuts */
#define LOGL_(level,log,...)	KSC_LOG_(level, log, &log_ctx, __VA_ARGS__)
#define LOGL(lvl,log,...)	KSC_LOG(lvl, log, &log_ctx, __VA_ARGS__)
#define LOG_(level,...)		LOGL_(level, ksc->args.log, __VA_ARGS__)
#define LOG(lvl,...)		LOGL(lvl, ksc->args.log, __VA_ARGS__)
#define LOGr(r,...)		LOG_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, __VA_ARGS__)

#define UNKNOWN             SIGNALSERVICE__ENVELOPE__TYPE__UNKNOWN
#define CIPHERTEXT          SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT
#define KEY_EXCHANGE        SIGNALSERVICE__ENVELOPE__TYPE__KEY_EXCHANGE
#define PREKEY_BUNDLE       SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE
#define RECEIPT             SIGNALSERVICE__ENVELOPE__TYPE__RECEIPT
#define UNIDENTIFIED_SENDER SIGNALSERVICE__ENVELOPE__TYPE__UNIDENTIFIED_SENDER

void ksc_print_envelope(const Signalservice__Envelope *e, int fd, bool detail)
{
	if (e->has_type) {
		const char *type = NULL;
		switch (e->type) {
		case UNKNOWN            : type = "unknown"; break;
		case CIPHERTEXT         : type = "ciphertext"; break;
		case KEY_EXCHANGE       : type = "key exchange"; break;
		case PREKEY_BUNDLE      : type = "prekey bundle"; break;
		case RECEIPT            : type = "receipt"; break;
		case UNIDENTIFIED_SENDER: type = "unidentified sender"; break;
		case _SIGNALSERVICE__ENVELOPE__TYPE_IS_INT_SIZE: break;
		}
		dprintf(fd, "  type: %s (%d)\n", type, e->type);
	}
	if (e->source)
		dprintf(fd, "  source: %s\n", e->source);
	if (e->has_sourcedevice)
		dprintf(fd, "  source device: %u\n", e->sourcedevice);
	if (e->relay)
		dprintf(fd, "  relay: %s\n", e->relay);
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		dprintf(fd, "  timestamp: %s", buf);
	}
	if (e->has_legacymessage) {
		dprintf(fd, "  has encrypted legacy message of size %zu%s\n",
		        e->legacymessage.len,
		        e->legacymessage.len && detail ? ":" : "");
		if (e->legacymessage.len && detail) {
			ksc_dprint_hex(fd, e->legacymessage.data,
			               e->legacymessage.len);
			dprintf(fd, "\n");
		}
	}
	if (e->has_content) {
		dprintf(fd, "  has encrypted content of size %zu%s\n",
		        e->content.len, e->content.len && detail ? ":" : "");
		if (e->content.len && detail) {
			ksc_dprint_hex(fd, e->content.data, e->content.len);
			dprintf(fd, "\n");
		}
	}
	if (e->serverguid)
		dprintf(fd, "  server guid: %s\n", e->serverguid);
	if (e->has_servertimestamp) {
		char buf[32];
		time_t t = e->servertimestamp / 1000;
		ctime_r(&t, buf);
		dprintf(fd, "  server timestamp: %s", buf);
	}
}

struct ref_counted {
	_Atomic size_t cnt;
};

static inline struct ref_counted * ref(struct ref_counted *ref)
{
	ref->cnt++;
	return ref;
}

static inline size_t unref(struct ref_counted *ref)
{
	assert(ref->cnt);
	return --ref->cnt;
}

#define REF_COUNTED	struct ref_counted ref_counted
#define REF_INIT(ptr,v)	atomic_init(&(ptr)->ref_counted.cnt, (v))
/* only use directly when you know what you're doing: no destructor invoked */
#define REF(ptr)	ref(&(ptr)->ref_counted)
#define UNREF(ptr)	unref(&(ptr)->ref_counted)

struct ksc_ws {
	REF_COUNTED;
	struct json_store *js;
	signal_context *ctx;
	signal_protocol_store_context *psctx;
	char *url;
	intptr_t uuid;
	struct ksc_ws_connect_service_args args;
	bool reconnecting_during_close;
	pthread_mutex_t signal_mtx;
};

static inline void ksignal_ctx_ref(struct ksc_ws *ksc)
{
	REF(ksc);
}

static void ksignal_ctx_unref(struct ksc_ws *ksc)
{
	if (UNREF(ksc))
		return;
	LOG(DEBUG, "destroying ksc_ws\n");
	assert(!ksc->ref_counted.cnt);
	signal_protocol_store_context_destroy(ksc->psctx);
	signal_context_destroy(ksc->ctx);
	ksc_free(ksc->url);
	pthread_mutex_destroy(&ksc->signal_mtx);
	ksc_free(ksc);
}

intptr_t ksc_ws_get_uuid(const struct ksc_ws *kws)
{
	return kws->uuid;
}

void * ksc_ws_get_udata(const struct ksc_ws *kws)
{
	return kws->args.udata;
}

static bool received_message(ws_s *ws, const Signalservice__Envelope *e,
                             uint8_t *text, size_t size,
                             struct ksc_ws *ksc)
{
	/*
	printf("decrypted Content:\n");
	print_hex(stdout, text, size);
	printf("\n");*/
	if (!ksc_one_and_zeroes_unpad(text, &size)) {
		LOG(ERROR, "failed to one-and-zeroes-unpad!\n");
		return false;
	}
	if (ksc_log_prints(KSC_LOG_DEBUG, ksc->args.log, &log_ctx)) {
		int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
		LOG(DEBUG, "decrypted Content (len: %zu): ", size);
		ksc_dprint_hex(fd, text, size);
		dprintf(fd, "\n");
	}
	Signalservice__Content *c;
	c = signalservice__content__unpack(NULL, size, text);
	if (!c) {
		LOG(ERROR, "error decoding decrypted message into Content\n");
		return false;
	}
	bool r = true;
	if (ksc->args.on_content)
		r = ksc->args.on_content(ws, ksc, e, c);
	signalservice__content__free_unpacked(c, NULL);
	return r;
	(void)ws;
}

static int delete_request_on_response(ws_s *ws, struct ksc_signal_response *r,
                                      void *udata)
{
	struct ksc_ws *ksc = udata;
	LOG_(r->status == 204 ? KSC_LOG_DEBUG : KSC_LOG_WARN,
	     "deletion request response line: %d %s\n", r->status, r->message);
	return 0;
	(void)ws;
}

struct delete_request_args {
	ws_s *ws;
	struct ksc_ws *ksc;
};

static void delete_request(void *udata1, void *udata2)
{
	struct delete_request_args *args = udata1;
	char *path = udata2;
	ksc_ws_send_request(args->ws, "DELETE", path,
	                    .on_response = delete_request_on_response,
	                    .udata = args->ksc);
	ksc_free(path);
	ksc_free(args);
}

static char * ack_message_path(const Signalservice__Envelope *e)
{
	return e->serverguid
	       ? ksc_ckprintf("/v1/messages/uuid/%s", e->serverguid)
	       : ksc_ckprintf("/v1/messages/%s/%" PRIu64, e->source, e->timestamp);
}

static int received_ciphertext_or_prekey_bundle(ws_s *ws,
                                                const Signalservice__Envelope *e,
                                                struct ksc_ws *ksc)
{
	signal_protocol_address addr = {
		.name = e->source,
		.name_len = strlen(e->source),
		.device_id = e->sourcedevice,
	};

	signal_buffer *plaintext = NULL;
	session_cipher *cipher;
	int r = session_cipher_create(&cipher, ksc->psctx, &addr, ksc->ctx);
	LOGr(r, "session_cipher_create -> %d\n", r);
	if (r)
		return r;

	if (e->type == CIPHERTEXT) {
		signal_message *msg;
		r = signal_message_deserialize(&msg, e->content.data, e->content.len, ksc->ctx);
		LOGr(r, "signal_message_deserialize -> %d\n", r);
		if (!r) {
			r = session_cipher_decrypt_signal_message(cipher, msg, NULL, &plaintext);
			LOG_(!r ? KSC_LOG_DEBUG :
			     r == SG_ERR_DUPLICATE_MESSAGE ? KSC_LOG_WARN : KSC_LOG_ERROR,
			     "session_cipher_decrypt_signal_message -> %d\n", r);
		}
		SIGNAL_UNREF(msg);
	} else {
		assert(e->type == PREKEY_BUNDLE);
		pre_key_signal_message *msg;
		r = pre_key_signal_message_deserialize(&msg, e->content.data, e->content.len, ksc->ctx);
		LOGr(r, "pre_key_signal_message_deserialize -> %d\n", r);
		if (!r) {
			r = session_cipher_decrypt_pre_key_signal_message(cipher, msg, NULL, &plaintext);
			LOG_(!r ? KSC_LOG_DEBUG :
			     r == SG_ERR_DUPLICATE_MESSAGE ? KSC_LOG_WARN : KSC_LOG_ERROR,
			     "session_cipher_decrypt_pre_key_signal_message -> %d\n", r);
		}
		SIGNAL_UNREF(msg);
	}

	session_cipher_free(cipher);

	if (!r || r == SG_ERR_DUPLICATE_MESSAGE) {
		struct delete_request_args args = { ws, ksc };
		fio_defer(delete_request, ksc_memdup(&args, sizeof(args)),
		          ack_message_path(e));
	}
	if (!r && plaintext)
		r = received_message(ws, e, signal_buffer_data(plaintext),
		                     signal_buffer_len(plaintext), ksc)
		    ? 0 : SG_ERR_UNKNOWN;

	signal_buffer_free(plaintext);

	return r;
}

static int received_receipt(ws_s *ws, const Signalservice__Envelope *e,
                            struct ksc_ws *ksc)
{
	char buf[32];
	time_t t = e->timestamp / 1000;
	ctime_r(&t, buf);
	LOG(NOTE, "got receipt from %s.%u at %s", e->source, e->sourcedevice, buf);
	bool r = true;
	if (ksc->args.on_receipt)
		r = ksc->args.on_receipt(ws, ksc, e);
	return r ? 0 : -1;
}

static bool received_envelope(ws_s *ws, const Signalservice__Envelope *e,
                              struct ksc_ws *ksc)
{
	typedef int received_envelope_handler(ws_s *ws,
	                                      const Signalservice__Envelope *e,
                                              struct ksc_ws *ksc);

	static received_envelope_handler *const handlers[] = {
		[CIPHERTEXT   ] = received_ciphertext_or_prekey_bundle,
		[PREKEY_BUNDLE] = received_ciphertext_or_prekey_bundle,
		[RECEIPT      ] = received_receipt,
	};

	if (!e->has_type) {
		LOG(ERROR, "cannot handle envelope without type\n");
		return false;
	}

	received_envelope_handler *handler;
	if (e->type >= ARRAY_SIZE(handlers) || !(handler = handlers[e->type])) {
		LOG(ERROR, "cannot handle envelope type %d!\n", e->type);
		return false;
	}

	return handler(ws, e, ksc) == 0;
}

static bool is_request_signal_key_encrypted(size_t n_headers,
                                            char *const *headers)
{
	for (size_t i=0; i<n_headers; i++) {
		char *header = headers[i];
		if (strncasecmp(header, "X-Signal-Key", 12))
			continue;
		for (header += 12; *header && isblank(*header); header++);
		if (*header != ':')
			continue;
		for (header += 1; *header && isblank(*header); header++);
		if (!strncasecmp(header, "false", 5))
			return false;
	}
	return true;
}

static int handle_request(ws_s *ws, char *verb, char *path, uint64_t *id,
                          size_t n_headers, char **headers,
                          size_t size, uint8_t *body, void *udata)
{
	struct ksc_ws *ksc = udata;
	bool is_enc = is_request_signal_key_encrypted(n_headers, headers);
	int r = 0;

	if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/message")) {
		/* new message received :) */
		LOG(DEBUG, "message received, encrypted: %d\n", is_enc);/*
		print_hex(stdout, body, size);
		printf("\n");*/
		size_t sg_key_b64_len;
		const char *sg_key_b64 =
			json_store_get_signaling_key_base64(ksc->js,
			                                    &sg_key_b64_len);
		if (!sg_key_b64) {
			LOG(ERROR, "unable retrieve signaling key from JSON store\n");
			return -1;
		}
		if (is_enc && !ksc_decrypt_envelope(&body, &size,
		                                    sg_key_b64,
		                                    sg_key_b64_len)) {
			LOG(ERROR, "error decrypting envelope\n");
			return -1;
		}
		Signalservice__Envelope *e;
		e = signalservice__envelope__unpack(NULL, size, body);
		if (!e) {
			LOG(ERROR, "error decoding envelope protobuf\n");
			return -2;
		}
		LOG(INFO, "received envelope\n");
		if (ksc_log_prints(KSC_LOG_NOTE, ksc->args.log, &log_ctx)) {
			int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
			ksc_print_envelope(e, fd,
				ksc_log_prints(KSC_LOG_DEBUG, ksc->args.log, &log_ctx));
		}
		r = received_envelope(ws, e, ksc) ? 1 : -3;
		LOG(DEBUG, "handle_request for PUT /api/v1/message returning %d\n", r);
		signalservice__envelope__free_unpacked(e, NULL);
	} else if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/queue/empty")) {
		r = 1;
	} else {
		LOG(WARN, "unhandled request: %s %s\n", verb, path);
		r = -1;
	}
	return r;
	(void)id;
}

struct send_message_data {
	struct ksc_ws *ksc;
	/* 0: to unsubscribe, other to stay subscribed */
	int (*on_response)(ws_s *ws, struct ksc_signal_response *response,
	                   void *udata);
	void *udata;
};

/* 0: to unsubscribe, other to stay subscribed */
static int on_send_message_response(ws_s *ws,
                                    struct ksc_signal_response *response,
                                    void *udata)
{
	struct send_message_data *data = udata;
	const struct ksc_ws *ksc = data->ksc;
	LOG(DEBUG, "message send response: %u %s\n",
	    response->status, response->message);
	int r = 0;
	if (data->on_response)
		r = data->on_response(ws, response, data->udata);
	return r;
}

static void on_send_message_unsubscribe(void *udata)
{
	struct send_message_data *data = udata;
	ksignal_ctx_unref(data->ksc);
	ksc_free(data);
}

static FIOBJ get(FIOBJ v, const char *key, size_t len)
{
	FIOBJ k = fiobj_str_new(key, len);
	FIOBJ r = fiobj_hash_get(v, k);
	fiobj_free(k);
	return r;
}

#define GET(v, cstr)	get(v, cstr, sizeof(cstr)-1)

static ec_public_key * str2ec_public_key(FIOBJ s, const struct ksc_ws *ksc)
{
	fio_str_info_s b64 = fiobj_obj2cstr(s);
	ssize_t sz = ksc_base64_decode_size(b64.data, b64.len);
	LOGr(sz != 33, "str2ec_public_key: base64-decoded data size: %zu\n", sz);
	if (sz != 33)
		return NULL;
	uint8_t data[sz];
	ssize_t decoded = ksc_base64_decode(data, b64.data, b64.len);
	assert(decoded == sz);
	ec_public_key *key = NULL;
	int r = curve_decode_point(&key, data, sz, ksc->ctx);
	LOGr(r, "curve_decode_point pub_key -> %d\n", r);
	return key;
}

static int process_hash_pk_bundle_device(FIOBJ device, const char *name,
                                         size_t name_len,
                                         const struct ksc_ws *ksc,
                                         ec_public_key *identity_key)
{
	FIOBJ device_id = GET(device, "deviceId");
	FIOBJ registration_id = GET(device, "registrationId");
	FIOBJ signed_pre_key = GET(device, "signedPreKey");
	FIOBJ pre_key = GET(device, "preKey");
	FIOBJ signed_key_id = GET(signed_pre_key, "keyId");
	FIOBJ signed_sign = GET(signed_pre_key, "signature");
	FIOBJ pre_key_id = GET(pre_key, "keyId");

	LOG(NOTE, "processing pre-key bundle for %.*s.%" PRId32 "\n",
	    (int)name_len, name, (int32_t)fiobj_obj2num(device_id));

	ec_public_key *pre_pub_key = NULL;
	ec_public_key *signed_pub_key = NULL;
	session_pre_key_bundle *bundle = NULL;
	session_builder *builder = NULL;
	int r;

	pre_pub_key = str2ec_public_key(GET(pre_key, "publicKey"), ksc);
	LOGr(!pre_pub_key, "decoding pre-key public key\n");
	if (!pre_pub_key) {
		r = 1 << 1;
		goto skip;
	}

	signed_pub_key = str2ec_public_key(GET(signed_pre_key, "publicKey"), ksc);
	LOGr(!signed_pub_key, "decoding pre-key signed public key\n");
	if (!signed_pub_key) {
		r = 1 << 2;
		goto skip;
	}

	fio_str_info_s sign = fiobj_obj2cstr(signed_sign);
	assert(ksc_base64_decode_size((char *)sign.data, sign.len) == CURVE_SIGNATURE_LEN);
	uint8_t sign_data[CURVE_SIGNATURE_LEN];
	ssize_t decoded = ksc_base64_decode(sign_data, (char *)sign.data, sign.len);
	assert(decoded == CURVE_SIGNATURE_LEN);

	r = session_pre_key_bundle_create(&bundle,
		fiobj_obj2num(registration_id),
		fiobj_obj2num(device_id),
		fiobj_obj2num(pre_key_id),
		pre_pub_key,
		fiobj_obj2num(signed_key_id),
		signed_pub_key,
		sign_data, CURVE_SIGNATURE_LEN,
		identity_key);
	LOGr(r, "session_pre_key_bundle_create -> %d\n", r);
	if (r)
		goto skip;

	signal_protocol_address addr = {
		.name = name,
		.name_len = name_len,
		.device_id = fiobj_obj2num(device_id),
	};
	r = session_builder_create(&builder, ksc->psctx, &addr, ksc->ctx);
	LOGr(r, "session_builder_create -> %d\n", r);
	if (r)
		goto skip;

	r = session_builder_process_pre_key_bundle(builder, bundle);
	LOGr(r, "session_builder_process_pre_key_bundle -> %d\n", r);

skip:
	session_builder_free(builder);
	SIGNAL_UNREF(bundle);
	SIGNAL_UNREF(signed_pub_key);
	SIGNAL_UNREF(pre_pub_key);

	return r;
}

static int process_hash_pk_bundle(FIOBJ response, const char *name,
                                  size_t name_len, const struct ksc_ws *ksc)
{
	ec_public_key *identity_key = NULL;

	identity_key = str2ec_public_key(GET(response, "identityKey"), ksc);
	LOGr(!identity_key, "decoding pre-key identity key\n");
	if (!identity_key)
		return 1;

	int r = 0;
	for (FIOBJ devices = GET(response, "devices"); fiobj_ary_count(devices);) {
		FIOBJ device = fiobj_ary_pop(devices);
		r |= process_hash_pk_bundle_device(device, name, name_len, ksc,
		                                   identity_key) != 0;
		fiobj_free(device);
	}

	SIGNAL_UNREF(identity_key);

	return r;
}

#undef GET

struct send_message_data2 {
	ws_s *ws;
	uint64_t timestamp;
	struct ksc_ws_send_message_args args;
	uint8_t *content_packed;
	size_t content_sz;
};

struct prekey_request_data {
	char *name;
	size_t name_len;
	int32_t *device_ids;
	size_t n_device_ids;
	struct ksc_ws *ksc;
	bool requested;
	bool received;
	FIOBJ auth;

	struct send_message_data2 data;
};

static int send_message_final(const char *recipient, size_t recipient_len,
                              struct ksc_ws *ksc,
                              int32_t *devices, size_t n_devices,
                              struct send_message_data2 data);

#define DEFAULT_DEVICE_ID	1

/* not exported by libsignal-protocol-c :/ */
void signal_lock(signal_context *context);
void signal_unlock(signal_context *context);

/* returns a (negative) signal error or the number of devices placed at
 * *devices. Remember to free *devices. */
static ssize_t known_target_devices(int32_t **devices, const char *recipient,
                                    size_t recipient_len,
                                    const struct ksc_ws *ksc)
{
	int32_t *devs = NULL;
	signal_int_list *sessions = NULL;
	ssize_t r = 0;

	bool myself = !strcmp(json_store_get_username(ksc->js), recipient);
	int32_t my_device_id;
	if (!json_store_get_device_id(ksc->js, &my_device_id))
		my_device_id = DEFAULT_DEVICE_ID;

	signal_lock(ksc->ctx);
	r = signal_protocol_session_get_sub_device_sessions(ksc->psctx,
	                                                    &sessions,
	                                                    recipient,
	                                                    recipient_len);
	LOGr(r < 0, "signal_protocol_session_get_sub_device_sessions -> %zd\n", r);
	if (r < 0)
		goto done;

	size_t n = signal_int_list_size(sessions);
	bool contains_default_device = false;
	for (size_t i=0; !contains_default_device && i<n; i++)
		contains_default_device |=
			signal_int_list_at(sessions, i) == DEFAULT_DEVICE_ID;
	devs = malloc(sizeof(*devs) * (n + !contains_default_device));
	if (!devs) {
		r = SG_ERR_NOMEM;
		goto done;
	}
	int32_t *fill = devs;
	if (!contains_default_device &&
	    (!myself || my_device_id != DEFAULT_DEVICE_ID /* || unidentifiedAccess */))
		*fill++ = DEFAULT_DEVICE_ID;
	for (size_t i=0; i<n; i++) {
		int device_id = signal_int_list_at(sessions, i);
		if (!myself || my_device_id != device_id)
			*fill++ = device_id;
	}
	r = fill - devs;

done:
	signal_int_list_free(sessions);
	signal_unlock(ksc->ctx);
	if (r < 0)
		free(devs);
	else
		*devices = devs;
	return r;
}

static void on_prekey_response(http_s *h)
{
	struct prekey_request_data *pr = h->udata;
	http_settings_s *s = http_settings(h);
	KSC_DEBUG(DEBUG, "on_prekey_response %zu, requested: %d, udata: %p, settings: %p, settings udata: %p\n",
	    h->status, pr->requested, h->udata, (void *)s, s->udata);
	KSC_DEBUG(DEBUG, "  path: %s\n", fiobj_obj2cstr(h->path).data);
	s->udata = pr; /* why is this necessary? bug in facil.io? */
	struct ksc_ws *ksc = pr->ksc;
	if (pr->requested) {
		int r = -1;
		if (200 <= h->status && h->status < 300) {
			FIOBJ response;
			fio_str_info_s s = fiobj_obj2cstr(h->body);
			if (s.len && fiobj_json2obj(&response, s.data, s.len)) {
				r = process_hash_pk_bundle(response, pr->name,
				                           pr->name_len, ksc);
				LOGr(r, "handle_hash_pk_bundle() -> %d\n", r);
				fiobj_free(response);
			} else {
				LOG(ERROR, "error JSON-decoding pre-key response: ");
				if (ksc_log_prints(KSC_LOG_ERROR, ksc->args.log, &log_ctx)) {
					int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
					ksc_dprint_hex(fd, (uint8_t *)s.data, s.len);
					dprintf(fd, "\n");
				}
			}
			int32_t *devices = NULL;
			ssize_t n = r;
			if (!r)
				n = known_target_devices(&devices, pr->name,
				                         pr->name_len, ksc);
			if (n < 0)
				r = n;
			if (!r) {
				r = send_message_final(pr->name, pr->name_len,
				                       ksc, devices, n,
				                       pr->data);
				LOGr(r, "send_message_final() -> %d\n", r);
			}
		}
		if (h->status == 413) {
			LOG(ERROR, "server refuses to send us the pre-key data...\n");
		}
		if (r) {
			/* TODO: retry or delete data2 contents */
		}
	}
	if (!pr->requested) {
		h->method = fiobj_str_new("GET", 3);
		pr->requested = true;
		http_set_header(h, fiobj_str_new("Authorization", 13), pr->auth);
		http_send_body(h, NULL, 0);
	} else {
		LOG(DEBUG, "sending http_finish()\n");
		http_finish(h);
	}
}

static void on_prekey_finish(http_settings_s *s)
{
	struct prekey_request_data *pr = s->udata;
	struct ksc_ws *ksc = pr->ksc;
	LOG(DEBUG, "on_prekey_finish()\n");
	free(pr->name);
	free(pr->device_ids);
	ksignal_ctx_unref(ksc);
	free(pr);
}

#define PREKEY_ALL_DEVICES_PATH		"/v2/keys/%.*s/*"
#define PREKEY_DEVICE_PATH		"/v2/keys/%.*s/%" PRId32

static intptr_t get_pre_keys(const char *recipient, size_t recipient_len,
                             int32_t *device_ids, size_t n_device_ids,
                             struct ksc_ws *ksc,
                             struct send_message_data2 data2)
{
	/* get pre-keys via PushServiceSocket, aka standard HTTPS request */
	const char *user = json_store_get_username(ksc->js);
	const char *pass = json_store_get_password_base64(ksc->js);

	int32_t my_device_id;
	char *auth = json_store_get_device_id(ksc->js, &my_device_id)
	           ? ksc_ckprintf("%s.%" PRId32 ":%s", user, my_device_id, pass)
	           : ksc_ckprintf("%s:%s", user, pass);

	size_t auth_len = strlen(auth);
	char auth_enc[6 + auth_len*4/3+4];
	memcpy(auth_enc, "Basic ", 6);
	size_t auth_enc_len = ksc_base64_encode(auth_enc + 6, (uint8_t *)auth, auth_len);
	FIOBJ auth_header = fiobj_str_new(auth_enc, 6 + auth_enc_len);
	free(auth);

	char *url = n_device_ids != 1 || device_ids[0] == DEFAULT_DEVICE_ID
	          ? ksc_ckprintf("https://" KSC_SERVICE_HOST PREKEY_ALL_DEVICES_PATH,
	                         (int)recipient_len, recipient)
	          : ksc_ckprintf("https://" KSC_SERVICE_HOST PREKEY_DEVICE_PATH,
	                         (int)recipient_len, recipient,
	                         device_ids[0]);
	ksignal_ctx_ref(ksc);
	struct prekey_request_data pr = {
		.name = ksc_memdup(recipient, recipient_len),
		.name_len = recipient_len,
		.ksc = ksc,
		.device_ids = device_ids,
		.n_device_ids = n_device_ids,
		.auth = auth_header,
		.data = data2,
	};
	fio_tls_s *tls = ksc_signal_tls(ksc->args.server_cert_path);
	LOG(NOTE, "getting pre-keys, connecting to %s\n", url);
	intptr_t r = http_connect(url, NULL,
	                          .on_response = on_prekey_response,
	                          .on_finish = on_prekey_finish,
	                          .udata = ksc_memdup(&pr, sizeof(pr)),
	                          .tls = tls);
	fio_tls_destroy(tls);

	free(url);

	return r;
}

struct outgoing_push_message {
	struct outgoing_push_message *next;
	size_t content_sz;
	int type;
	int destination_device_id;
	uint32_t destination_registration_id;
	/* base64-encoded encrypted (un)padded protobuf-encoded Content message */
	char content[];
};

static int encrypt_for(const signal_protocol_address *addr,
                       const struct ksc_ws *ksc,
                       const uint8_t *padded_content, size_t padded_content_sz,
                       struct outgoing_push_message **result)
{
	if (!signal_protocol_session_contains_session(ksc->psctx, addr)) {
		LOG(WARN, "encrypt_for: no session for %.*s.%" PRId32 "\n",
		    (int)addr->name_len, addr->name, addr->device_id);
		return SG_ERR_NO_SESSION;
	}

	session_cipher *cipher = NULL;
	ciphertext_message *message = NULL;
	struct outgoing_push_message *msg = NULL;
	int r;

	r = session_cipher_create(&cipher, ksc->psctx, addr, ksc->ctx);
	LOGr(r, "session_cipher_create -> %d\n", r);
	if (r)
		goto done;
	r = session_cipher_encrypt(cipher, padded_content, padded_content_sz,
	                           &message);
	LOGr(r, "session_cipher_encrypt -> %d\n", r);
	if (r)
		goto done;

	signal_buffer *serialized = ciphertext_message_get_serialized(message);
	LOGr(!serialized, "ciphertext_message_get_serialized -> %p\n",
	     (void *)serialized);

	/* deliver(serialized) */

	size_t serialized_sz = signal_buffer_len(serialized);
	size_t n = serialized_sz * 4 / 3 + 4;
	msg = ksc_malloc(offsetof(struct outgoing_push_message, content) + n);
	if (!msg) {
		r = SG_ERR_NOMEM;
		goto done;
	}
	msg->next = NULL;
	switch (ciphertext_message_get_type(message)) {
	case CIPHERTEXT_SIGNAL_TYPE: msg->type = CIPHERTEXT; break;
	case CIPHERTEXT_PREKEY_TYPE: msg->type = PREKEY_BUNDLE; break;
	default:
		r = SG_ERR_UNKNOWN;
		goto done;
	}
	r = session_cipher_get_remote_registration_id(cipher,
	                                              &msg->destination_registration_id);
	LOGr(r, "session_cipher_get_remote_registration_id -> %d\n", r);
	msg->destination_device_id = addr->device_id;
	msg->content_sz = ksc_base64_encode(msg->content,
	                                    signal_buffer_data(serialized),
	                                    serialized_sz);

done:
	SIGNAL_UNREF(message);
	session_cipher_free(cipher);

	if (!r)
		*result = msg;
	else
		ksc_free(msg);
	return r;
}

#define CSTR2FIOBJ(const_str)	fiobj_str_new(const_str, sizeof(const_str)-1)

static int send_message_final(const char *recipient, size_t recipient_len,
                              struct ksc_ws *ksc,
                              int32_t *devices, size_t n_devices,
                              struct send_message_data2 data)
{
	int r;
	struct outgoing_push_message *message_list = NULL, **message_tail = &message_list;

	struct signal_protocol_address addr = {
		.name = recipient,
		.name_len = recipient_len,
	};

	if (ksc_log_prints(KSC_LOG_INFO, ksc->args.log, &log_ctx)) {
		LOG(INFO, "sending message to %.*s (devices:",
		           (int)recipient_len, recipient);
		int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
		for (size_t i=0; i<n_devices; i++)
			dprintf(fd, " %" PRId32, devices[i]);
		dprintf(fd, ")\n");
	}

	int32_t *a = devices;
	for (int32_t *b = a; b < devices + n_devices; b++) {
		/* encrypt for (target->name, DEFAULT_DEVICE_ID) */
		addr.device_id = *b;
		r = encrypt_for(&addr, ksc, data.content_packed,
		                data.content_sz, message_tail);
		LOGr(r, "encrypt_for device %" PRId32 "-> %d\n", addr.device_id, r);
		if (!r)
			message_tail = &(*message_tail)->next;
		if (r)
			*a++ = *b; /* record failed encryption */
		if (r == SG_ERR_NO_SESSION)
			r = 0;
		if (r)
			goto done;
	}
	size_t n_failed = a - devices;
	LOGr(n_failed, "failed to encrypt to %zu of %zu devices of %.*s\n",
	     n_failed, n_devices, (int)recipient_len, recipient);

	LOGr(!message_list, "message_list: %p\n", message_list);

	ksc_free(data.content_packed);

	char *path = ksc_ckprintf("/v1/messages/%.*s", (int)recipient_len, recipient);

	FIOBJ msg = fiobj_hash_new();
	fiobj_hash_set(msg, CSTR2FIOBJ("destination"),
	                    fiobj_str_new(recipient, recipient_len));
	fiobj_hash_set(msg, CSTR2FIOBJ("timestamp"),
	                    fiobj_num_new(data.timestamp));
	fiobj_hash_set(msg, CSTR2FIOBJ("online"), fiobj_false());
	FIOBJ msgs = fiobj_ary_new();
	for (struct outgoing_push_message *m = message_list; m; m = m->next) {
		FIOBJ f = fiobj_hash_new();
		fiobj_hash_set(f, CSTR2FIOBJ("type"), fiobj_num_new(m->type));
		fiobj_hash_set(f, CSTR2FIOBJ("destinationDeviceId"),
		                  fiobj_num_new(m->destination_device_id));
		fiobj_hash_set(f, CSTR2FIOBJ("destinationRegistrationId"),
		                  fiobj_num_new(m->destination_registration_id));
		fiobj_hash_set(f, CSTR2FIOBJ("content"),
		                  fiobj_str_new(m->content, m->content_sz));
		fiobj_ary_push(msgs, f);
	}
	fiobj_hash_set(msg, CSTR2FIOBJ("messages"), msgs);
	FIOBJ json = fiobj_obj2json(msg, 0);
	fio_str_info_s json_c = fiobj_obj2cstr(json);

	LOG(DEBUG, "sending JSON: %.*s\n", (int)json_c.len, json_c.data);

	struct send_message_data cb_data = {
		.ksc = ksc,
		.on_response = data.args.on_response,
		.udata = data.args.udata,
	};
	ksignal_ctx_ref(ksc);

	static char *headers[] = {
		"Content-Type: application/json",
	};
	r = ksc_ws_send_request(data.ws, "PUT", path,
	                        .size = json_c.len,
	                        .body = json_c.data,
	                        .headers = headers,
	                        .n_headers = ARRAY_SIZE(headers),
	                        .on_response = on_send_message_response,
	                        .on_unsubscribe = on_send_message_unsubscribe,
	                        .udata = ksc_memdup(&cb_data, sizeof(cb_data)));

	fiobj_free(json);
	fiobj_free(msg);
	ksc_free(path);

	LOGr(r, "ksc_ws_send_request -> %d\n", r);

	if (data.args.end_session) {
		r = signal_protocol_session_delete_all_sessions(ksc->psctx,
		                                                recipient,
		                                                recipient_len);
		LOGr(r < 0,
		     "signal_protocol_session_delete_all_sessions -> %d\n", r);
		if (r > 0)
			r = 0;
	}

	/* TODO: directly encode into FIOBJ w/o going via struct outgoing_push_message */

done:
	for (struct outgoing_push_message *m, *mn = message_list; (m = mn);) {
		mn = m->next;
		ksc_free(m);
	}
	message_list = NULL, message_tail = &message_list;
	free(devices);

	return r;
}

#define PADDING			160

int (ksc_ws_send_message)(ws_s *ws, struct ksc_ws *ksc, const char *recipient,
                          struct ksc_ws_send_message_args args)
{
	Signalservice__DataMessage data = SIGNALSERVICE__DATA_MESSAGE__INIT;

	data.body = (char *)args.body;
	if (args.end_session) {
		data.flags |= SIGNALSERVICE__DATA_MESSAGE__FLAGS__END_SESSION;
		data.has_flags = true;
	}
	struct timeval tv;
	gettimeofday(&tv, NULL);
	data.timestamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	data.has_timestamp = true;

	Signalservice__Content content = SIGNALSERVICE__CONTENT__INIT;
	content.datamessage = &data;

	size_t content_sz = signalservice__content__get_packed_size(&content);
	uint8_t *content_packed = ksc_malloc(ksc_one_and_zeroes_padded_size(content_sz, PADDING));
	signalservice__content__pack(&content, content_packed);

	ksc_one_and_zeroes_pad(content_packed, &content_sz, PADDING);

	signal_lock(ksc->ctx);
	int r = 0;
	size_t recipient_len = strlen(recipient);

	int32_t *devs = NULL;
	int32_t *get_prekeys_for = NULL;
	ssize_t n = known_target_devices(&devs, recipient, recipient_len, ksc);
	if (n < 0)
		goto done;

	get_prekeys_for = ksc_memdup(devs, sizeof(*devs) * n);
	int32_t *a = get_prekeys_for;
	struct signal_protocol_address addr = {
		.name = recipient,
		.name_len = recipient_len,
	};
	for (int32_t *b = devs; b < devs + n; b++) {
		addr.device_id = *b;
		r = signal_protocol_session_contains_session(ksc->psctx, &addr);
		if (r < 0)
			break;
		if (r)
			continue;
		*a++ = *b;
	}
	size_t gn = a - get_prekeys_for;
	if (r < 0)
		goto done;

	struct send_message_data2 data2 = {
		ws, data.timestamp, args, content_packed, content_sz,
	};
	content_packed = NULL; /* transferred ownership */
	if (gn) {
		intptr_t sock = get_pre_keys(recipient, recipient_len,
		                             get_prekeys_for, gn, ksc, data2);
		get_prekeys_for = NULL; /* transferred ownership */
		LOGr(sock < 0, "get_pre_keys() -> %zd\n", sock);
		if (sock < 0) {
			r = sock;
			goto done;
		}
	} else {
		r = send_message_final(recipient, recipient_len, ksc, devs, n, data2);
		devs = NULL; /* transferred ownership */
	}

done:
	signal_unlock(ksc->ctx);
	ksc_free(content_packed);
	ksc_free(devs);
	ksc_free(get_prekeys_for);
	return r;
}


static void ctx_log(int level, const char *message, size_t len, void *user_data)
{
	struct ksc_ws *ksc = user_data;
	if (ksc->args.log) {
		enum ksc_log_lvl lvl;
		switch (level) {
		case SG_LOG_ERROR  : lvl = KSC_LOG_ERROR; break;
		case SG_LOG_WARNING: lvl = KSC_LOG_WARN; break;
		/* for libsignal-protocol-c, NOTICE is more severe than INFO;
		 * not for us: INFO is an information to the user, while NOTE
		 * is just a note, not a notification */
		case SG_LOG_NOTICE : lvl = KSC_LOG_INFO; break;
		case SG_LOG_INFO   : lvl = KSC_LOG_NOTE; break;
		case SG_LOG_DEBUG  : lvl = KSC_LOG_DEBUG; break;
		default:
			LOG(DEBUG, "Invalid log level %d from signal-protocol-c "
			    "library for the following signal-ctx message.",
			    level);
			lvl = KSC_LOG_ERROR;
		}
		KSC_LOG_(lvl, ksc->args.log, &ksc->args.signal_log_ctx, "%.*s\n",
		         (int)CLAMP(len,0,INT_MAX), message);
	}
}

static void ctx_lock(void *user_data)
{
	struct ksc_ws *ksc = user_data;
	LOG(DEBUG, "ctx_lock()\n");
	ksignal_ctx_ref(ksc);
	int r = pthread_mutex_lock(&ksc->signal_mtx);
	assert(!r);
	(void)r;
}

static void ctx_unlock(void *user_data)
{
	struct ksc_ws *ksc = user_data;
	LOG(DEBUG, "ctx unlock()\n");
	int r = pthread_mutex_unlock(&ksc->signal_mtx);
	assert(!r);
	ksignal_ctx_unref(ksc);
	(void)r;
}

static struct ksc_ws * ksignal_ctx_create(struct json_store *js,
                                          struct ksc_log *log)
{
	struct ksc_ws *ksc = NULL;

	ksc = ksc_calloc(1, sizeof(*ksc));
	REF_INIT(ksc, 0);
	ksignal_ctx_ref(ksc);

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&ksc->signal_mtx, &attr);
	pthread_mutexattr_destroy(&attr);

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	if (!number || !password)
		goto fail;
	int32_t device_id;
	ksc->url = json_store_get_device_id(js, &device_id)
	         ? ksc_ckprintf("%s/v1/websocket/?login=%s.%" PRId32 "&password=%s",
	                        "wss://" KSC_SERVICE_HOST, number, device_id, password)
	         : ksc_ckprintf("%s/v1/websocket/?login=%s&password=%s",
	                        "wss://" KSC_SERVICE_HOST, number, password);

	int r = signal_context_create(&ksc->ctx, ksc);
	if (r) {
		LOGL(ERROR, log, "signal_context_create failed with code %d\n", r);
		goto fail;
	}

	signal_context_set_crypto_provider(ksc->ctx, &ksc_crypto_provider);
	signal_context_set_log_function(ksc->ctx, ctx_log);
	signal_context_set_locking_functions(ksc->ctx, ctx_lock, ctx_unlock);

	r = signal_protocol_store_context_create(&ksc->psctx, ksc->ctx);
	if (r) {
		LOGL(ERROR, log, "signal_protocol_store_context_create failed with code %d\n", r);
		goto fail;
	}

	json_store_protocol_store_init(ksc->psctx, js);

	ksc->js = js;
	return ksc;

fail:
	ksignal_ctx_unref(ksc);
	return NULL;
}

static void on_open(ws_s *ws, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->reconnecting_during_close = false;
	if (ksc->args.on_open)
		ksc->args.on_open(ws, ksc);
}

static void on_close(intptr_t uuid, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->uuid = -1;
	if (ksc->args.on_close_do_reconnect) {
		if (!ksc->reconnecting_during_close) {
			ksc->reconnecting_during_close = true;
			ksc->uuid = ksc_ws_connect_raw(ksc->url,
				.on_open = on_open,
				.handle_request = handle_request,
				.handle_response = NULL,
				.udata = ksc,
				.on_close = on_close,
				.log = ksc->args.log,
			);
		}
		if (ksc->uuid >= 0)
			return;
	}
	if (ksc->args.on_close)
		ksc->args.on_close(uuid, ksc->args.udata);
	ksignal_ctx_unref(ksc);
}

static void on_shutdown(ws_s *s, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->args.on_close_do_reconnect = false;
	(void)s;
}

struct ksc_ws * (ksc_ws_connect_service)(struct json_store *js,
                                         struct ksc_ws_connect_service_args args)
{
	struct ksc_ws *ksc = ksignal_ctx_create(js, args.log);
	if (!ksc) {
		LOGL(ERROR, args.log, "error init'ing ksignal_ctx\n");
		return NULL;
	}
	ksc->args = args;
	intptr_t uuid = ksc_ws_connect_raw(ksc->url,
		.on_open = on_open,
		.handle_request = handle_request,
		.handle_response = NULL,
		.udata = ksc,
		.on_close = on_close,
		.on_shutdown = on_shutdown,
		.server_cert_path = args.server_cert_path,
		.log = args.log,
	);
	if (uuid == -1)
		return NULL;
	ksc->uuid = uuid;
	return ksc;
}
