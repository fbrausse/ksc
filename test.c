
#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "crypto.h"
#include "json-store.h"
#include "SignalService.pb-c.h"

#include <assert.h>
#include <time.h>	/* ctime_r() */
#include <inttypes.h>	/* PRI* macros */

#include <signal/protocol.h>
#include <signal/signal_protocol.h>
#include <signal/session_cipher.h>

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

/* shortcuts */
#define UNKNOWN             SIGNALSERVICE__ENVELOPE__TYPE__UNKNOWN
#define CIPHERTEXT          SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT
#define KEY_EXCHANGE        SIGNALSERVICE__ENVELOPE__TYPE__KEY_EXCHANGE
#define PREKEY_BUNDLE       SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE
#define RECEIPT             SIGNALSERVICE__ENVELOPE__TYPE__RECEIPT
#define UNIDENTIFIED_SENDER SIGNALSERVICE__ENVELOPE__TYPE__UNIDENTIFIED_SENDER

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

static void print_data_message(Signalservice__DataMessage *e)
{
	if (e->body)
		printf("  body: %s\n", e->body);
	printf("  attachments: %zu\n", e->n_attachments);
	if (e->group)
		printf("  group info for group: %s\n", e->group->name);
	if (e->has_flags)
		printf("  flags: 0x%x\n", e->flags);
	if (e->has_expiretimer)
		printf("  expire timer: %ud\n", e->expiretimer);
	if (e->has_profilekey) {
		printf("  profile key:\n");
		print_hex(stdout, e->profilekey.data, e->profilekey.len);
		printf("\n");
	}
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		printf("  timestamp: %s", buf);
	}
	if (e->quote)
		printf("  has quote\n");
	printf("  # contacts: %zu\n", e->n_contact);
	printf("  # previews: %zu\n", e->n_preview);
	if (e->sticker)
		printf("  has sticker\n");
	if (e->has_requiredprotocolversion)
		printf("  required protocol version: %ud\n",
		       e->requiredprotocolversion);
	if (e->has_messagetimer)
		printf("  message timer: %ud\n", e->messagetimer);
}

struct ksignal_ctx {
	struct json_store *js;
	signal_context *ctx;
	signal_protocol_store_context *psctx;
};

static int decrypt_callback(session_cipher *cipher, signal_buffer *plaintext,
                            void *decrypt_context)
{
	struct ksignal_ctx *ksc = decrypt_context;

	printf("decrypted Content:\n");
	print_hex(stdout, signal_buffer_data(plaintext), signal_buffer_len(plaintext));
	printf("\n");
	/* manually "decode" protobuf in order to determine length of padded
	 * Content message (it just contains one entry, not more) */
	size_t sz = protobuf_entry_size(signal_buffer_data(plaintext));
	printf("decrypted Content (len: %zu):\n", sz);
	print_hex(stdout, signal_buffer_data(plaintext), sz);
	printf("\n");
	Signalservice__Content *c;
	c = signalservice__content__unpack(NULL, sz,
	                                   signal_buffer_data(plaintext));
	assert(c);
	if (c->datamessage)
		print_data_message(c->datamessage);
	signalservice__content__free_unpacked(c, NULL);
	return 0;
	(void)cipher;
	(void)ksc;
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

	r = session_cipher_decrypt_signal_message(cipher, msg, ksc, plaintext);
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

	r = session_cipher_decrypt_pre_key_signal_message(cipher, msg, ksc,
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

	printf("received envelope:\n");
	print_envelope(e);

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

	session_cipher_set_decryption_callback(cipher, decrypt_callback);

	signal_buffer *plaintext = NULL;
	if (e->type < ARRAY_SIZE(handlers) && handlers[e->type]) {
		r = handlers[e->type](&plaintext, e->content.data,
		                      e->content.len, ksc, cipher);
	} else {
		printf("cannot handle envelope type %d!\n", e->type);
		r = SG_ERR_UNKNOWN;
	}

	if (!r || r == SG_ERR_DUPLICATE_MESSAGE) {
		fio_defer(delete_request, ws, ack_message_path(e));
		r = 0;
	}

	signal_buffer_free(plaintext);
	session_cipher_free(cipher);
	return r == 0;
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
		r = received_envelope(ws, e, ksc) ? 0 : -3;
		signalservice__envelope__free_unpacked(e, NULL);
	}
	return r;
	(void)id;
}

static void on_close_do_stop(intptr_t uuid, void *udata)
{
	printf("close, stopping\n");
	fio_stop();
	(void)uuid;
	(void)udata;
}

static void handle_new_uuid(char *uuid, void *udata)
{
	printf("got new uuid: %s\n", uuid);
	(void)uuid;
	(void)udata;
}

#define DIE(code,...) do { fprintf(stderr, __VA_ARGS__); exit(code); } while (0)

static int recv_get_profile(ws_s *ws, struct signal_response *r, void *udata)
{
	fprintf(stderr, "recv get profile: %u %s: ",
	        r->status, r->message);

	if (r->status != 200) {
		fprintf(stderr, "\n");
		return 0;
	}

	FIOBJ profile;
	size_t parsed = fiobj_json2obj(&profile, r->body.data, r->body.len);
	fprintf(stderr, "fio json parsed %zu of %zu",
	        parsed, r->body.len);
	if (parsed) {
		FIOBJ str = fiobj_obj2json(profile, 1);
		fio_str_info_s s = fiobj_obj2cstr(str);
		fprintf(stderr, ": %.*s\n", (int)s.len, s.data);
		fiobj_free(str);
		fiobj_free(profile);
	} else
		fprintf(stderr, ", failed\n");

	fprintf(stderr, "recv get profile: ");
	struct kjson_value p = KJSON_VALUE_INIT;
	if (kjson_parse(&(struct kjson_parser){ r->body.data }, &p)) {
		kjson_value_print(stderr, &p);
		fprintf(stderr, "\n");
	} else
		fprintf(stderr, "error parsing profile json: '%.*s'\n",
		        (int)r->body.len, r->body.data);
	kjson_value_fini(&p);

	return 0;
	(void)udata;
	(void)ws;
}

static int recv_get_pre_key(ws_s *ws, struct signal_response *r, void *udata)
{
	fprintf(stderr, "recv get pre key: %u %s: %.*s\n",
	        r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)udata;
	(void)ws;
}

static int recv_get_cert_delivery(ws_s *ws, struct signal_response *r,
                                  void *udata)
{
	fprintf(stderr, "recv get certificate delivery: %u %s: %.*s\n",
	        r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)udata;
	(void)ws;
}

static void send_get_profile(ws_s *s, void *udata)
{
#if 0 && defined(DEFAULT_GET_PROFILE_NUMBER)
	signal_ws_send_request(s, "GET",
	                       "/v1/profile/" DEFAULT_GET_PROFILE_NUMBER,
	                       .on_response = recv_get_profile, .udata = udata);
	signal_ws_send_request(s, "GET",
	                       "/v2/keys/" DEFAULT_GET_PROFILE_NUMBER "/*",
	                       .on_response = recv_get_pre_key, .udata = udata);
	signal_ws_send_request(s, "GET", "/v1/certificate/delivery",
	                       .on_response = recv_get_cert_delivery,
	                       .udata = udata);
#else
	(void)s;
	(void)udata;
#endif
}

static void ctx_log(int level, const char *message, size_t len, void *user_data)
{
	printf("signal ctx, lvl %d: %.*s\n", level, (int)len, message);
	(void)user_data;
}

static bool ksignal_ctx_init(struct ksignal_ctx *ctx, struct json_store *js)
{
	signal_context *sgctx;
	int r = signal_context_create(&sgctx, NULL);
	printf("signal_context_create -> %d\n", r);
	if (r)
		return false;

	signal_context_set_crypto_provider(sgctx, &crypto_provider);
	signal_context_set_log_function(sgctx, ctx_log);

	signal_protocol_store_context *psctx;
	r = signal_protocol_store_context_create(&psctx, sgctx);
	if (r) {
		printf("signal_protocol_store_context_create -> %d\n", r);
		signal_context_destroy(sgctx);
		return false;
	}

	protocol_store_init(psctx, js);

	ctx->js = js;
	ctx->ctx = sgctx;
	ctx->psctx = psctx;

	return true;
}

static int ksignal_ctx_fini(struct ksignal_ctx *ksc)
{
	signal_protocol_store_context_destroy(ksc->psctx);
	signal_context_destroy(ksc->ctx);

	int r = json_store_save(ksc->js);
	printf("json_store_save returned %d\n", r);
	if (!r) {
		r = json_store_load(ksc->js);
		printf("json_store_load returned %d\n", r);
		r = !r;
	}
	if (!r) {
		r = json_store_save(ksc->js);
		printf("json_store_save returned %d\n", r);
	}
	json_store_destroy(ksc->js);

	return r;
}

#ifndef DEFAULT_CLI_CONFIG
# define DEFAULT_CLI_CONFIG	NULL
#endif

static const char BASE_URL[] = "wss://textsecure-service.whispersystems.org:443";

int main(int argc, char **argv)
{
	const char *cli_path = DEFAULT_CLI_CONFIG;
	for (int opt; (opt = getopt(argc, argv, ":hp:")) != -1;)
		switch (opt) {
		case 'h':
			fprintf(stderr, "usage: %s [-p CLI_CONFIG_PATH]\n", argv[0]);
			exit(0);
		case 'p': cli_path = optarg; break;
		case ':': DIE(1,"error: option '-%c' requires a parameter\n",
		              optopt);
		case '?': DIE(1,"error: unknown option '-%c'\n",optopt);
		}

	if (!cli_path) {
		fprintf(stderr, "require path to JSON config file\n");
		return 1;
	}

	struct json_store *js = NULL;
	js = json_store_create(cli_path);
	printf("js: %p\n", (void *)js);
	if (!js) {
		fprintf(stderr, "%s: error reading JSON config file\n", cli_path);
		return 1;
	}

	int r = 0;
	struct ksignal_ctx ksc;
	if (!ksignal_ctx_init(&ksc, js)) {
		fprintf(stderr, "error init'ing ksignal_ctx\n");
		r = 1;
		goto end;
	}

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	char *url = NULL;
	if (!number) {
		fprintf(stderr, "no username, performing a device link\n");
		r = ksignal_defer_get_new_uuid(BASE_URL,
		                               .new_uuid = handle_new_uuid,
		                               .on_close = on_close_do_stop);
	} else if (password) {
		int32_t device_id;
		url = json_store_get_device_id(js, &device_id)
		    ? ckprintf("%s/v1/websocket/?login=%s.%" PRId32 "&password=%s",
		               BASE_URL, number, device_id, password)
		    : ckprintf("%s/v1/websocket/?login=%s&password=%s",
		               BASE_URL, number, password);
		r = signal_ws_connect(url,
			.on_open = send_get_profile,
			.handle_request = handle_request,
			.handle_response = NULL,
			.udata = &ksc,
			.on_close = on_close_do_stop,
		);
	} else {
		fprintf(stderr, "don't know what to do, username but no password\n");
		r = 1;
	}
	printf("%d\n", r);
	fio_start(.threads=1);
	free(url);

end:
	r = ksignal_ctx_fini(&ksc);
	return 0;
}
