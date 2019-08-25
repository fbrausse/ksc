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
		        e->legacymessage.len, detail ? ":" : "");
		if (detail) {
			ksc_dprint_hex(fd, e->legacymessage.data,
			               e->legacymessage.len);
			dprintf(fd, "\n");
		}
	}
	if (e->has_content) {
		dprintf(fd, "  has encrypted content of size %zu%s\n",
		        e->content.len, detail ? ":" : "");
		if (detail) {
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
	free(path);
	free(args);
}

static char * ack_message_path(const Signalservice__Envelope *e)
{
	return e->serverguid
	       ? ksc_ckprintf("/v1/messages/uuid/%s", e->serverguid)
	       : ksc_ckprintf("/v1/messages/%s/%" PRIu64, e->source, e->timestamp);
}

static int received_ciphertext(signal_buffer **plaintext, uint8_t *content,
                               size_t size, struct ksc_ws *ksc,
                               session_cipher *cipher)
{
	signal_message *msg;
	int r = signal_message_deserialize(&msg, content, size, ksc->ctx);
	LOGr(r, "signal_message_deserialize -> %d\n", r);
	if (r)
		goto done;

	r = session_cipher_decrypt_signal_message(cipher, msg, NULL, plaintext);
	LOG_(!r ? KSC_LOG_DEBUG :
	     r == SG_ERR_DUPLICATE_MESSAGE ? KSC_LOG_WARN : KSC_LOG_ERROR,
	     "session_cipher_decrypt_signal_message -> %d\n", r);
done:
	SIGNAL_UNREF(msg);
	return r;
}

static int received_pkbundle(signal_buffer **plaintext, uint8_t *content,
                             size_t size, struct ksc_ws *ksc,
                             session_cipher *cipher)
{
	pre_key_signal_message *msg;
	int r;
	r = pre_key_signal_message_deserialize(&msg, content, size, ksc->ctx);
	LOGr(r, "pre_key_signal_message_deserialize -> %d\n", r);
	if (r)
		goto done;

	r = session_cipher_decrypt_pre_key_signal_message(cipher, msg, NULL,
	                                                  plaintext);
	LOG_(!r ? KSC_LOG_DEBUG :
	     r == SG_ERR_DUPLICATE_MESSAGE ? KSC_LOG_WARN : KSC_LOG_ERROR,
	     "session_cipher_decrypt_pre_key_signal_message -> %d\n", r);
done:
	SIGNAL_UNREF(msg);
	return r;
}

static bool received_envelope(ws_s *ws, const Signalservice__Envelope *e,
                              struct ksc_ws *ksc)
{
	typedef int received_envelope_handler(signal_buffer **plaintext,
	                                      uint8_t *content, size_t size,
	                                      struct ksc_ws *ksc,
	                                      session_cipher *cipher);

	static received_envelope_handler *const handlers[] = {
		[CIPHERTEXT   ] = received_ciphertext,
		[PREKEY_BUNDLE] = received_pkbundle,
	};

	received_envelope_handler *handler;
	if (e->type >= ARRAY_SIZE(handlers) || !(handler = handlers[e->type])) {
		LOG(ERROR, "cannot handle envelope type %d!\n", e->type);
		return false;
	}

	signal_protocol_address addr = {
		.name = e->source,
		.name_len = strlen(e->source),
		.device_id = e->sourcedevice,
	};

	session_cipher *cipher;
	int r = session_cipher_create(&cipher, ksc->psctx, &addr, ksc->ctx);
	LOGr(r, "session_cipher_create -> %d\n", r);
	if (r)
		return r;

	signal_buffer *plaintext = NULL;
	r = handler(&plaintext, e->content.data, e->content.len, ksc, cipher);

	session_cipher_free(cipher);

	if (!r || r == SG_ERR_DUPLICATE_MESSAGE) {
		struct delete_request_args args = { ws, ksc };
		fio_defer(delete_request, memdup(&args, sizeof(args)),
		          ack_message_path(e));
	}
	if (!r && plaintext)
		r = received_message(ws, e, signal_buffer_data(plaintext),
		                     signal_buffer_len(plaintext), ksc)
		    ? 0 : SG_ERR_UNKNOWN;

	signal_buffer_free(plaintext);
	return r == 0;
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

static void ksignal_ctx_destroy(struct ksc_ws *ksc)
{
	if (ksc->psctx)
		signal_protocol_store_context_destroy(ksc->psctx);
	if (ksc->ctx)
		signal_context_destroy(ksc->ctx);
	free(ksc->url);
	pthread_mutex_destroy(&ksc->signal_mtx);
	free(ksc);
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
