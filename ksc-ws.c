/*
 * ksc-ws.c
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#include "ksc-ws.h"
#include "crypto.h"

#include <pthread.h>

#include <signal/protocol.h>
#include <signal/signal_protocol.h>
#include <signal/session_cipher.h>

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

struct ksc_ws {
	struct json_store *js;
	signal_context *ctx;
	signal_protocol_store_context *psctx;
	char *url;
	intptr_t uuid;
	struct ksc_ws_connect_service_args args;
	bool reconnecting_during_close;
	pthread_mutex_t signal_mtx;
};

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
	const struct ksc_ws *ksc;
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
	ksc_free(data);
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
		/* TODO: get pre-keys via PushServiceSocket */
		return -1;
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

#define DEFAULT_DEVICE_ID	1

#define CSTR2FIOBJ(const_str)	fiobj_str_new(const_str, sizeof(const_str)-1)

/* not exported by libsignal-protocol-c :/ */
void signal_lock(signal_context *context);
void signal_unlock(signal_context *context);

#define PADDING			160

int (ksc_ws_send_message)(ws_s *ws, const struct ksc_ws *ksc,
                          const struct ksc_send_message_target *target,
                          struct ksc_ws_send_message_args args)
{
	Signalservice__DataMessage data = SIGNALSERVICE__DATA_MESSAGE__INIT;

	data.body = (char *)args.body;
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

	struct outgoing_push_message *message_list = NULL, **message_tail = &message_list;

	signal_lock(ksc->ctx);
	bool myself = !strcmp(json_store_get_username(ksc->js), target->name);
	int32_t my_device_id;
	if (!json_store_get_device_id(ksc->js, &my_device_id))
		my_device_id = DEFAULT_DEVICE_ID;
	int r = 0;
	size_t target_name_len = strlen(target->name);
	if (!myself || my_device_id != DEFAULT_DEVICE_ID /* || unidentifiedAccess */) {
		/* encrypt for (target->name, DEFAULT_DEVICE_ID) */
		r = encrypt_for(&(struct signal_protocol_address){
			.name = target->name,
			.name_len = target_name_len,
			.device_id = DEFAULT_DEVICE_ID,
		}, ksc, content_packed, content_sz, message_tail);
		LOGr(r, "encrypt_for default device -> %d\n", r);
		message_tail = &(*message_tail)->next;
	}
	signal_int_list *sessions = NULL;
	r = signal_protocol_session_get_sub_device_sessions(ksc->psctx,
	                                                    &sessions,
	                                                    target->name,
	                                                    target_name_len);
	LOGr(r < 0, "signal_protocol_session_get_sub_device_sessions -> %d\n", r);
	for (unsigned i=0; i<signal_int_list_size(sessions); i++) {
		int device_id = signal_int_list_at(sessions, i);
		struct signal_protocol_address addr = {
			.name = target->name,
			.name_len = target_name_len,
			.device_id = device_id,
		};
		if ((!myself || device_id != my_device_id) &&
		    signal_protocol_session_contains_session(ksc->psctx, &addr)) {
			r = encrypt_for(&addr, ksc, content_packed, content_sz,
			                message_tail);
			LOGr(r, "encrypt_for device %d -> %d\n", device_id, r);
			message_tail = &(*message_tail)->next;
		}
	}
	signal_int_list_free(sessions);
	signal_unlock(ksc->ctx);

	LOGr(!message_list, "message_list: %p\n", message_list);

	ksc_free(content_packed);

	char *path = ksc_ckprintf("/v1/messages/%s", target->name);

	FIOBJ msg = fiobj_hash_new();
	fiobj_hash_set(msg, CSTR2FIOBJ("destination"), fiobj_str_new(target->name, target_name_len));
	fiobj_hash_set(msg, CSTR2FIOBJ("timestamp"), fiobj_num_new(data.timestamp));
	fiobj_hash_set(msg, CSTR2FIOBJ("online"), fiobj_false());
	FIOBJ msgs = fiobj_ary_new();
	for (struct outgoing_push_message *m, *mn = message_list; (m = mn);) {
		mn = m->next;
		FIOBJ f = fiobj_hash_new();
		fiobj_hash_set(f, CSTR2FIOBJ("type"), fiobj_num_new(m->type));
		fiobj_hash_set(f, CSTR2FIOBJ("destinationDeviceId"),
		                  fiobj_num_new(m->destination_device_id));
		fiobj_hash_set(f, CSTR2FIOBJ("destinationRegistrationId"),
		                  fiobj_num_new(m->destination_registration_id));
		fiobj_hash_set(f, CSTR2FIOBJ("content"),
		                  fiobj_str_new(m->content, m->content_sz));
		fiobj_ary_push(msgs, f);
		ksc_free(m);
	}
	message_list = NULL, message_tail = &message_list;
	fiobj_hash_set(msg, CSTR2FIOBJ("messages"), msgs);
	FIOBJ json = fiobj_obj2json(msg, 0);
	fio_str_info_s json_c = fiobj_obj2cstr(json);

	LOG(DEBUG, "sending JSON: %.*s\n", (int)json_c.len, json_c.data);

	struct send_message_data cb_data = {
		.ksc = ksc,
		.on_response = args.on_response,
		.udata = args.udata,
	};

	static char *headers[] = {
		"Content-Type: application/json"
	};
	r = ksc_ws_send_request(ws, "PUT", path,
	                        .size = json_c.len,
	                        .body = json_c.data,
	                        .headers = headers,
	                        .n_headers = ARRAY_SIZE(headers),
	                        .on_response = on_send_message_response,
	                        .udata = ksc_memdup(&cb_data, sizeof(cb_data)));

	fiobj_free(json);
	fiobj_free(msg);
	ksc_free(path);

	LOGr(r, "ksc_ws_send_request -> %d\n", r);

	/* TODO: directly encode into FIOBJ w/o going via struct outgoing_push_message */

	return r;
}

static void ksignal_ctx_destroy(struct ksc_ws *ksc)
{
	if (ksc->psctx)
		signal_protocol_store_context_destroy(ksc->psctx);
	if (ksc->ctx)
		signal_context_destroy(ksc->ctx);
	ksc_free(ksc->url);
	pthread_mutex_destroy(&ksc->signal_mtx);
	ksc_free(ksc);
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
	(void)r;
}

static struct ksc_ws * ksignal_ctx_create(struct json_store *js,
                                          struct ksc_log *log)
{
	struct ksc_ws *ksc = NULL;

	ksc = ksc_calloc(1, sizeof(*ksc));

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
	                        KSC_BASE_URL, number, device_id, password)
	         : ksc_ckprintf("%s/v1/websocket/?login=%s&password=%s",
	                        KSC_BASE_URL, number, password);

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
	ksignal_ctx_destroy(ksc);
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
	ksignal_ctx_destroy(ksc);
}

static void on_shutdown(ws_s *s, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->args.on_close_do_reconnect = false;
	(void)s;
}

const struct ksc_ws * (ksc_ws_connect_service)(struct json_store *js,
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
