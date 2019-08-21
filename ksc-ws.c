
#include "ksc-ws.h"
#include "utils.h"
#include "crypto.h"

#include <signal/protocol.h>
#include <signal/signal_protocol.h>
#include <signal/session_cipher.h>

/* shortcuts */
#define UNKNOWN             SIGNALSERVICE__ENVELOPE__TYPE__UNKNOWN
#define CIPHERTEXT          SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT
#define KEY_EXCHANGE        SIGNALSERVICE__ENVELOPE__TYPE__KEY_EXCHANGE
#define PREKEY_BUNDLE       SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE
#define RECEIPT             SIGNALSERVICE__ENVELOPE__TYPE__RECEIPT
#define UNIDENTIFIED_SENDER SIGNALSERVICE__ENVELOPE__TYPE__UNIDENTIFIED_SENDER

struct ksignal_ctx {
	struct json_store *js;
	signal_context *ctx;
	signal_protocol_store_context *psctx;
	char *url;
	intptr_t uuid;
	struct ksc_ws_connect_args args;
	bool reconnecting_during_close;
};

static bool received_message(ws_s *ws, const Signalservice__Envelope *e,
                             uint8_t *text, size_t size,
                             struct ksignal_ctx *ksc)
{
	/*
	printf("decrypted Content:\n");
	print_hex(stdout, text, size);
	printf("\n");*/
	if (!one_and_zeroes_unpad(text, &size)) {
		printf("ERROR: failed to one-and-zeroes-unpad!\n");
		return false;
	}
	printf("decrypted Content (len: %zu): ", size);
	print_hex(stdout, text, size);
	printf("\n");
	Signalservice__Content *c;
	c = signalservice__content__unpack(NULL, size, text);
	if (!c) {
		printf("ERROR: decoding decrypted message into Content\n");
		return false;
	}
	bool r = true;
	if (ksc->args.on_content)
		r = ksc->args.on_content(ws, e, c, ksc->args.udata);
	signalservice__content__free_unpacked(c, NULL);
	return r;
}

static int delete_request_on_response(ws_s *ws, struct signal_response *r,
                                      void *udata)
{
	printf("deletion request response line: %d %s\n", r->status, r->message);
	return 0;
	(void)ws;
	(void)udata;
}

static void delete_request(void *udata1, void *udata2)
{
	ws_s *s = udata1;
	char *path = udata2;
	signal_ws_send_request(s, "DELETE", path,
	                       .on_response = delete_request_on_response);
	free(path);
}

static char * ack_message_path(const Signalservice__Envelope *e)
{
	return e->serverguid
	       ? ckprintf("/v1/messages/uuid/%s", e->serverguid)
	       : ckprintf("/v1/messages/%s/%lu", e->source, e->timestamp);
}

static int received_ciphertext(signal_buffer **plaintext, uint8_t *content,
                               size_t size, struct ksignal_ctx *ksc,
                               session_cipher *cipher)
{
	signal_message *msg;
	int r = signal_message_deserialize(&msg, content, size, ksc->ctx);
	printf("signal_message_deserialize -> %d\n", r);
	if (r)
		goto done;

	r = session_cipher_decrypt_signal_message(cipher, msg, NULL, plaintext);
	printf("session_cipher_decrypt_signal_message -> %d\n", r);
done:
	SIGNAL_UNREF(msg);
	return r;
}

static int received_pkbundle(signal_buffer **plaintext, uint8_t *content,
                             size_t size, struct ksignal_ctx *ksc,
                             session_cipher *cipher)
{
	pre_key_signal_message *msg;
	int r;
	r = pre_key_signal_message_deserialize(&msg, content, size, ksc->ctx);
	printf("pre_key_signal_message_deserialize -> %d\n", r);
	if (r)
		goto done;

	r = session_cipher_decrypt_pre_key_signal_message(cipher, msg, NULL,
	                                                  plaintext);
	printf("session_cipher_decrypt_pre_key_signal_message -> %d\n", r);
done:
	SIGNAL_UNREF(msg);
	return r;
}

static bool received_envelope(ws_s *ws, const Signalservice__Envelope *e,
                              struct ksignal_ctx *ksc)
{
	typedef int received_envelope_handler(signal_buffer **plaintext,
	                                      uint8_t *content, size_t size,
	                                      struct ksignal_ctx *ksc,
	                                      session_cipher *cipher);

	static received_envelope_handler *const handlers[] = {
		[CIPHERTEXT   ] = received_ciphertext,
		[PREKEY_BUNDLE] = received_pkbundle,
	};

	received_envelope_handler *handler;
	if (e->type >= ARRAY_SIZE(handlers) || !(handler = handlers[e->type])) {
		printf("cannot handle envelope type %d!\n", e->type);
		return false;
	}

	signal_protocol_address addr = {
		.name = e->source,
		.name_len = strlen(e->source),
		.device_id = e->sourcedevice,
	};

	session_cipher *cipher;
	int r = session_cipher_create(&cipher, ksc->psctx, &addr, ksc->ctx);
	printf("session_cipher_create -> %d\n", r);
	if (r)
		return r;

	signal_buffer *plaintext = NULL;
	r = handler(&plaintext, e->content.data, e->content.len, ksc, cipher);

	session_cipher_free(cipher);

	if (!r || r == SG_ERR_DUPLICATE_MESSAGE) {
		fio_defer(delete_request, ws, ack_message_path(e));
		r = 0;
	}
	if (!r && plaintext)
		r = received_message(ws, e, signal_buffer_data(plaintext),
		                     signal_buffer_len(plaintext), ksc) ? 0 : SG_ERR_UNKNOWN;

	signal_buffer_free(plaintext);
	return r == 0;
}

static void print_envelope(const Signalservice__Envelope *e)
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
		printf("  type: %s (%d)\n", type, e->type);
	}
	if (e->source)
		printf("  source: %s\n", e->source);
	if (e->has_sourcedevice)
		printf("  source device: %u\n", e->sourcedevice);
	if (e->relay)
		printf("  relay: %s\n", e->relay);
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		printf("  timestamp: %s", buf);
	}
	if (e->has_legacymessage) {
		printf("  has encrypted legacy message of size %zu\n",
		       e->legacymessage.len);
		print_hex(stdout, e->legacymessage.data, e->legacymessage.len);
		printf("\n");
	}
	if (e->has_content) {
		printf("  has encrypted content of size %zu:\n",
		       e->content.len);
		print_hex(stdout, e->content.data, e->content.len);
		printf("\n");
	}
	if (e->serverguid)
		printf("  server guid: %s\n", e->serverguid);
	if (e->has_servertimestamp) {
		char buf[32];
		time_t t = e->servertimestamp / 1000;
		ctime_r(&t, buf);
		printf("  server timestamp: %s", buf);
	}
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
	struct ksignal_ctx *ksc = udata;
	bool is_enc = is_request_signal_key_encrypted(n_headers, headers);
	int r = 0;

	if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/message")) {
		/* new message received :) */
		printf("message received, encrypted: %d\n", is_enc);/*
		print_hex(stdout, body, size);
		printf("\n");*/
		size_t sg_key_b64_len;
		const char *sg_key_b64 =
			json_store_get_signaling_key_base64(ksc->js,
			                                    &sg_key_b64_len);
		if (is_enc && !decrypt_envelope(&body, &size,
		                                sg_key_b64, sg_key_b64_len)) {
			fprintf(stderr, "error decrypting envelope\n");
			return -1;
		}
		Signalservice__Envelope *e;
		e = signalservice__envelope__unpack(NULL, size, body);
		if (!e) {
			fprintf(stderr, "error decoding envelope protobuf\n");
			return -2;
		}
		printf("received envelope:\n");
		print_envelope(e);
		r = received_envelope(ws, e, ksc) ? 0 : -3;
		signalservice__envelope__free_unpacked(e, NULL);
	}
	return r;
	(void)id;
}

static void ksignal_ctx_destroy(struct ksignal_ctx *ksc)
{
	if (ksc->psctx)
		signal_protocol_store_context_destroy(ksc->psctx);
	if (ksc->ctx)
		signal_context_destroy(ksc->ctx);
	free(ksc->url);
	free(ksc);
}

static void ctx_log(int level, const char *message, size_t len, void *user_data)
{
	struct ksignal_ctx *ksc = user_data;
	if (ksc->args.signal_ctx_log) {
		enum ksc_ws_log lvl;
		switch (level) {
		case SG_LOG_ERROR  : lvl = KSC_WS_LOG_ERROR; break;
		case SG_LOG_WARNING: lvl = KSC_WS_LOG_WARNING; break;
		case SG_LOG_NOTICE : lvl = KSC_WS_LOG_NOTICE; break;
		case SG_LOG_INFO   : lvl = KSC_WS_LOG_INFO; break;
		case SG_LOG_DEBUG  : lvl = KSC_WS_LOG_DEBUG; break;
		default:
#define ERR "Invalid log level from signal-protocol-c library for the following message."
			ksc->args.signal_ctx_log(KSC_WS_LOG_ERROR, ERR, sizeof(ERR)-1, ksc->args.udata);
			lvl = KSC_WS_LOG_ERROR;
#undef ERR
		}
		ksc->args.signal_ctx_log(lvl, message, len, ksc->args.udata);
	}
}

static struct ksignal_ctx * ksignal_ctx_create(struct json_store *js)
{
	struct ksignal_ctx *ksc = NULL;

	ksc = calloc(1, sizeof(*ksc));

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	if (!number || !password)
		goto fail;
	int32_t device_id;
	ksc->url = json_store_get_device_id(js, &device_id)
	         ? ckprintf("%s/v1/websocket/?login=%s.%" PRId32 "&password=%s",
	                    BASE_URL, number, device_id, password)
	         : ckprintf("%s/v1/websocket/?login=%s&password=%s",
	                    BASE_URL, number, password);

	int r = signal_context_create(&ksc->ctx, ksc);
	if (r) {
		printf("signal_context_create failed with code %d\n", r);
		goto fail;
	}

	signal_context_set_crypto_provider(ksc->ctx, &crypto_provider);
	signal_context_set_log_function(ksc->ctx, ctx_log);

	r = signal_protocol_store_context_create(&ksc->psctx, ksc->ctx);
	if (r) {
		printf("signal_protocol_store_context_create failed with code %d\n", r);
		goto fail;
	}

	protocol_store_init(ksc->psctx, js);

	ksc->js = js;
	return ksc;

fail:
	ksignal_ctx_destroy(ksc);
	return NULL;
}

static void on_open(ws_s *ws, void *udata)
{
	struct ksignal_ctx *ksc = udata;
	ksc->reconnecting_during_close = false;
	if (ksc->args.on_open)
		ksc->args.on_open(ws, ksc->args.udata);
}

static void on_close(intptr_t uuid, void *udata)
{
	struct ksignal_ctx *ksc = udata;
	if (ksc->args.on_close_do_reconnect) {
		ksc->uuid = 0;
		if (!ksc->reconnecting_during_close) {
			ksc->reconnecting_during_close = true;
			ksc->uuid = signal_ws_connect(ksc->url,
				.on_open = on_open,
				.handle_request = handle_request,
				.handle_response = NULL,
				.udata = ksc,
				.on_close = on_close,
			);
		}
		if (ksc->uuid)
			return;
	}
	if (ksc->args.on_close)
		ksc->args.on_close(uuid, ksc->args.udata);
	ksignal_ctx_destroy(ksc);
}

static void on_shutdown(ws_s *s, void *udata)
{
	struct ksignal_ctx *ksc = udata;
	ksc->args.on_close_do_reconnect = false;
	(void)s;
}

intptr_t * (ksc_ws_connect)(struct json_store *js,
                            struct ksc_ws_connect_args args)
{
	struct ksignal_ctx *ksc = ksignal_ctx_create(js);
	if (!ksc) {
		fprintf(stderr, "error init'ing ksignal_ctx\n");
		return NULL;
	}
	ksc->args = args;
	ksc->uuid = signal_ws_connect(ksc->url,
		.on_open = on_open,
		.handle_request = handle_request,
		.handle_response = NULL,
		.udata = ksc,
		.on_close = on_close,
		.on_shutdown = on_shutdown,
	);
	return &ksc->uuid;
}