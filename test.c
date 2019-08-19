
#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "json-store.h"
#include "SignalService.pb-c.h"

#include <assert.h>
#include <time.h>	/* ctime_r() */

#include <gcrypt.h>

#include <signal/protocol.h>
#include <signal/signal_protocol.h>
#include <signal/session_builder.h>
#include <signal/session_cipher.h>

#define VERSION_OFFSET		0
#define VERSION_SUPPORTED	1
#define VERSION_LENGTH		1

#define CIPHER_KEY_SIZE		32
#define MAC_KEY_SIZE		20
#define MAC_SIZE		10

#define IV_LENGTH		16
// #define IV_OFFSET		(VERSION_OFFSET + VERSION_LENGTH)
// #define CIPHERTEXT_OFFSET	(IV_OFFSET + IV_LENGTH

_Static_assert(VERSION_OFFSET == 0, "keep in sync with libsignal-service-*");

#define FAIL(lbl,...) do { fprintf(stderr, __VA_ARGS__); goto lbl; } while (0)

static bool verify_envelope(const uint8_t *body, size_t *size_ptr,
                            const uint8_t *mac_key)
{
	size_t size = *size_ptr;

	/* verify HmacSHA256 */
	if (size < MAC_SIZE + 1)
		return false;
	gcry_md_hd_t hd;
	gcry_error_t gr;
	gr = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (gr)
		FAIL(fail, "error on gcry_md_open: %x\n", gr);
	gr = gcry_md_setkey(hd, mac_key, MAC_KEY_SIZE);
	if (gr)
		FAIL(mac_fail, "error on gcry_md_setkey: %x\n", gr);
	gcry_md_write(hd, body, size - MAC_SIZE);
	gcry_md_final(hd);
	const uint8_t *our_mac = gcry_md_read(hd, GCRY_MD_SHA256);
	assert(our_mac);
	const uint8_t *their_mac = body + size - MAC_SIZE;
	if (memcmp(our_mac, their_mac, MAC_SIZE)) {
		fprintf(stderr, "MACs don't match:\n");
		fprintf(stderr, "  ours  : ");
		print_hex(stderr, our_mac, MAC_SIZE);
		fprintf(stderr, "\n  theirs: ");
		print_hex(stderr, their_mac, MAC_SIZE);
		fprintf(stderr, "\n");
		goto mac_fail;
	}
	gcry_md_close(hd);

	// fprintf(stderr, "MACs match! :)\n");

	size -= MAC_SIZE;
	*size_ptr = size;
	return true;

mac_fail:
	gcry_md_close(hd);
fail:
	return false;
}

/* body == VERSION IV CIPHERTEXT MAC
 * where MAC           = HMAC-SHA256(VERSION IV CIPHERTEXT, MAC_KEY)
 *       CIPHERTEXT    = ENC-AES256(PKCS5PAD(PLAINTEXT), IV, CBC, CIPHER_KEY)
 *       SIGNALING_KEY = CIPHER_KEY MAC_KEY
 */
static bool decrypt_envelope(uint8_t **body_ptr, size_t *size_ptr,
                             const struct kjson_value *cfg)
{
	uint8_t *body = *body_ptr;
	size_t size = *size_ptr;

	if (size < VERSION_LENGTH || body[VERSION_OFFSET] != VERSION_SUPPORTED)
		return false;
	const struct kjson_value *key = kjson_get(cfg, "signalingKey");
	assert(key);
	/* properties of base64 */
	assert(key->s.len >= (4*(CIPHER_KEY_SIZE + MAC_KEY_SIZE) + 2) / 3);
	assert(key->s.len <= (4*(CIPHER_KEY_SIZE + MAC_KEY_SIZE + 2)) / 3);
	uint8_t decoded_key[CIPHER_KEY_SIZE + MAC_KEY_SIZE];
	ssize_t r = base64_decode(decoded_key, key->s.begin, key->s.len);
	if (r != CIPHER_KEY_SIZE + MAC_KEY_SIZE) {
		fprintf(stderr,
		        "error decoding signalingKey of length %zu: r: %zd\n",
		        key->s.len, r);
		return false;
	}
	const uint8_t *cipher_key = decoded_key;
	const uint8_t *mac_key = decoded_key + CIPHER_KEY_SIZE;

	if (!verify_envelope(body, &size, mac_key))
		return false;
	size -= VERSION_LENGTH;
	body += VERSION_LENGTH;

	/* decode AES/CBC/PKCS5Padding */
	gcry_cipher_hd_t ci;
	gcry_error_t gr;
	gr = gcry_cipher_open(&ci, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	if (gr)
		FAIL(fail, "error on gcry_cipher_open: %x\n", gr);
	gr = gcry_cipher_setkey(ci, cipher_key, CIPHER_KEY_SIZE);
	if (gr)
		FAIL(cipher_fail, "error on gcry_cipher_setkey: %x\n", gr);
	gr = gcry_cipher_setiv(ci, body, IV_LENGTH);
	if (gr)
		FAIL(cipher_fail, "error on gcry_cipher_setiv: %x\n", gr);
	size -= IV_LENGTH;
	body += IV_LENGTH;
	gr = gcry_cipher_final(ci);
	if (gr)
		FAIL(cipher_fail, "error on gcry_cipher_final: %x\n", gr);
	gr = gcry_cipher_decrypt(ci, body, size, NULL, 0);
	if (gr)
		FAIL(cipher_fail, "error on gcry_cipher_decrypt: %x\n", gr);
	gcry_cipher_close(ci);

	/* remove PKCS5Padding */
	if (!size)
		FAIL(fail, "size of decrypted envelope is zero\n");
	unsigned n = body[size-1];
	if (size < n)
		FAIL(fail, "size of decrypted envelope is smaller than "
		           "PKCS5Padding's value\n");
	for (unsigned i=0; i<n; i++)
		if (body[size-n+i] != n)
			FAIL(fail,
			     "PKCS5Padding of decrypted envelope is broken\n");
	size -= n;

	/*
	fprintf(stderr, "success: ");
	print_hex(stderr, body, size);
	fprintf(stderr, "\n");*/

	*body_ptr = body;
	*size_ptr = size;
	return true;

cipher_fail:
	gcry_cipher_close(ci);
fail:
	return false;
}

static bool is_request_signal_key_encrypted(size_t n_headers, char *const *headers)
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

static void print_envelope(const Signalservice__Envelope *e)
{
	if (e->has_type) {
		const char *type = NULL;
		switch (e->type) {
		case SIGNALSERVICE__ENVELOPE__TYPE__UNKNOWN: type = "unknown"; break;
		case SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT: type = "ciphertext"; break;
		case SIGNALSERVICE__ENVELOPE__TYPE__KEY_EXCHANGE: type = "key exchange"; break;
		case SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE: type = "prekey bundle"; break;
		case SIGNALSERVICE__ENVELOPE__TYPE__RECEIPT: type = "receipt"; break;
		case SIGNALSERVICE__ENVELOPE__TYPE__UNIDENTIFIED_SENDER: type = "unidentified sender"; break;
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

/**
 * Callback for a secure random number generator.
 * This function shall fill the provided buffer with random bytes.
 *
 * @param data pointer to the output buffer
 * @param len size of the output buffer
 * @return 0 on success, negative on failure
 */
static int cry_random_func(uint8_t *data, size_t len, void *user_data)
{
	gcry_randomize(data, len, GCRY_STRONG_RANDOM);
	return 0;
	(void)user_data;
}

/**
 * Callback for an HMAC-SHA256 implementation.
 * This function shall initialize an HMAC context with the provided key.
 *
 * @param hmac_context private HMAC context pointer
 * @param key pointer to the key
 * @param key_len length of the key
 * @return 0 on success, negative on failure
 */
static int cry_hmac_sha256_init_func(void **hmac_context, const uint8_t *key,
                                     size_t key_len, void *user_data)
{
	gcry_md_hd_t hd;
	gcry_error_t gr;
	gr = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (gr)
		FAIL(fail, "error on gcry_md_open: %x\n", gr);
	gr = gcry_md_setkey(hd, key, key_len);
	if (gr)
		FAIL(mac_fail, "error on gcry_md_setkey: %x\n", gr);
	*hmac_context = hd;
	return 0;

mac_fail:
	gcry_md_close(hd);
fail:
	return -1;
	(void)user_data;
}

/**
 * Callback for an HMAC-SHA256 implementation.
 * This function shall update the HMAC context with the provided data
 *
 * @param hmac_context private HMAC context pointer
 * @param data pointer to the data
 * @param data_len length of the data
 * @return 0 on success, negative on failure
 */
static int cry_hmac_sha256_update_func(void *hmac_context, const uint8_t *data,
                                       size_t data_len, void *user_data)
{
	gcry_md_hd_t hd = hmac_context;
	gcry_md_write(hd, data, data_len);
	return 0;
	(void)user_data;
}

/**
 * Callback for an HMAC-SHA256 implementation.
 * This function shall finalize an HMAC calculation and populate the output
 * buffer with the result.
 *
 * @param hmac_context private HMAC context pointer
 * @param output buffer to be allocated and populated with the result
 * @return 0 on success, negative on failure
 */
static int cry_hmac_sha256_final_func(void *hmac_context,
                                      signal_buffer **output, void *user_data)
{
	gcry_md_hd_t hd = hmac_context;
	gcry_md_final(hd);
	*output = signal_buffer_create(gcry_md_read(hd, GCRY_MD_SHA256),
	                               gcry_md_get_algo_dlen(GCRY_MD_SHA256));
	return 0;
	(void)user_data;
}

/**
 * Callback for an HMAC-SHA256 implementation.
 * This function shall free the private context allocated in
 * hmac_sha256_init_func.
 *
 * @param hmac_context private HMAC context pointer
 */
static void cry_hmac_sha256_cleanup_func(void *hmac_context, void *user_data)
{
	gcry_md_hd_t hd = hmac_context;
	gcry_md_close(hd);
	(void)user_data;
}

#if 0
/**
 * Callback for a SHA512 message digest implementation.
 * This function shall initialize a digest context.
 *
 * @param digest_context private digest context pointer
 * @return 0 on success, negative on failure
 */
int (*sha512_digest_init_func)(void **digest_context, void *user_data);

/**
 * Callback for a SHA512 message digest implementation.
 * This function shall update the digest context with the provided data.
 *
 * @param digest_context private digest context pointer
 * @param data pointer to the data
 * @param data_len length of the data
 * @return 0 on success, negative on failure
 */
int (*sha512_digest_update_func)(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);

/**
 * Callback for a SHA512 message digest implementation.
 * This function shall finalize the digest calculation, populate the
 * output buffer with the result, and prepare the context for reuse.
 *
 * @param digest_context private digest context pointer
 * @param output buffer to be allocated and populated with the result
 * @return 0 on success, negative on failure
 */
int (*sha512_digest_final_func)(void *digest_context, signal_buffer **output, void *user_data);

/**
 * Callback for a SHA512 message digest implementation.
 * This function shall free the private context allocated in
 * sha512_digest_init_func.
 *
 * @param digest_context private digest context pointer
 */
void (*sha512_digest_cleanup_func)(void *digest_context, void *user_data);

/**
 * Callback for an AES encryption implementation.
 *
 * @param output buffer to be allocated and populated with the ciphertext
 * @param cipher specific cipher variant to use, either SG_CIPHER_AES_CTR_NOPADDING or SG_CIPHER_AES_CBC_PKCS5
 * @param key the encryption key
 * @param key_len length of the encryption key
 * @param iv the initialization vector
 * @param iv_len length of the initialization vector
 * @param plaintext the plaintext to encrypt
 * @param plaintext_len length of the plaintext
 * @return 0 on success, negative on failure
 */
int (*encrypt_func)(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);
#endif

/**
 * Callback for an AES decryption implementation.
 *
 * @param output buffer to be allocated and populated with the plaintext
 * @param cipher specific cipher variant to use, either SG_CIPHER_AES_CTR_NOPADDING or SG_CIPHER_AES_CBC_PKCS5
 * @param key the encryption key
 * @param key_len length of the encryption key
 * @param iv the initialization vector
 * @param iv_len length of the initialization vector
 * @param ciphertext the ciphertext to decrypt
 * @param ciphertext_len length of the ciphertext
 * @return 0 on success, negative on failure
 */
static int cry_decrypt_func(signal_buffer **output,
                            int cipher,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            void *user_data)
{
	int algo, mode, padding;
	switch (key_len) {
	case 16: algo = GCRY_CIPHER_AES128; break;
	case 24: algo = GCRY_CIPHER_AES192; break;
	case 32: algo = GCRY_CIPHER_AES256; break;
	default: FAIL(fail, "unsupported key_len: %zu\n", key_len);
	}
	switch (cipher) {
	case SG_CIPHER_AES_CTR_NOPADDING:
		mode = GCRY_CIPHER_MODE_CTR;
		padding = 0;
		break;
	case SG_CIPHER_AES_CBC_PKCS5:
		mode = GCRY_CIPHER_MODE_CBC;
		padding = 1;
		break;
	default:
		FAIL(fail, "unknown cipher: %d\n", cipher);
	}

	gcry_cipher_hd_t ci;
	gcry_error_t gr;
	gr = gcry_cipher_open(&ci, algo, mode, 0);
	if (gr)
		FAIL(fail, "error on gcry_cipher_open: %x\n", gr);
	gr = gcry_cipher_setkey(ci, key, key_len);
	if (gr)
		FAIL(cipher_fail, "error on gcry_cipher_setkey: %x\n", gr);
	if (mode == GCRY_CIPHER_MODE_CBC) {
		gr = gcry_cipher_setiv(ci, iv, iv_len);
		if (gr)
			FAIL(cipher_fail, "error on gcry_cipher_setiv: %x\n", gr);
	} else {
		gr = gcry_cipher_setctr(ci, iv, iv_len);
		if (gr)
			FAIL(cipher_fail, "error on gcry_cipher_setctr: %x\n", gr);
	}
	gr = gcry_cipher_final(ci);
	if (gr)
		FAIL(cipher_fail, "error on gcry_cipher_final: %x\n", gr);

	uint8_t *body = malloc(ciphertext_len);
	gr = gcry_cipher_decrypt(ci, body, ciphertext_len, ciphertext, ciphertext_len);
	if (gr)
		FAIL(cipher_fail2, "error on gcry_cipher_decrypt: %x\n", gr);
	gcry_cipher_close(ci);

	/* remove PKCS5Padding */
	size_t size = ciphertext_len;
	if (padding) {
		if (!size)
			FAIL(fail, "size of decrypted envelope is zero\n");
		unsigned n = body[size-1];
		if (size < n)
			FAIL(fail, "size of decrypted envelope is smaller than "
			           "PKCS5Padding's value\n");
		for (unsigned i=0; i<n; i++)
			if (body[size-n+i] != n)
				FAIL(fail,
				     "PKCS5Padding of decrypted envelope is broken\n");
		size -= n;
	}
	*output = signal_buffer_create(body, size);
	free(body);
	return 0;

cipher_fail2:
	free(body);
cipher_fail:
	gcry_cipher_close(ci);
fail:
	return -1;
	(void)user_data;
}

static struct signal_crypto_provider crypto_provider = {
	.random_func              = cry_random_func,
	.hmac_sha256_init_func    = cry_hmac_sha256_init_func,
	.hmac_sha256_update_func  = cry_hmac_sha256_update_func,
	.hmac_sha256_final_func   = cry_hmac_sha256_final_func,
	.hmac_sha256_cleanup_func = cry_hmac_sha256_cleanup_func,
	.decrypt_func             = cry_decrypt_func,
};

static uintmax_t read_varint(uint8_t **data_p)
{
	uint8_t *data = *data_p;
	uintmax_t v = 0;
	for (int b=0;; b += 7) {
		v |= (*data & ~0x80) << b;
		if (!(*data++ & 0x80))
			break;
	}
	*data_p = data;
	return v;
}

static size_t protobuf_entry_size(uint8_t *entry)
{
	uint8_t *data = entry;
	switch (*data++ & 0x07) {
	case 0: /* varint */
		while (*data++ & 0x80);
		break;
	case 1: /* fixed64 */
		data += 8;
		break;
	case 2: { /* length-delimited */
		size_t n = read_varint(&data);
		data += n;
		break;
	}
	case 3:
	case 4:
		/* groups (deprecated) */
		assert(0);
	case 5:
		/* fixed32 */
		data += 4;
		break;
	}
	return data - entry;
}

static int decrypt_callback(session_cipher *cipher, signal_buffer *plaintext,
                            void *decrypt_context)
{
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
	if (c->datamessage) {
		Signalservice__DataMessage *e = c->datamessage;
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
	signalservice__content__free_unpacked(c, NULL);
	return -1; /* fail s.t. the session does not get updated */
	(void)cipher;
	(void)decrypt_context;
}

static void ctx_log(int level, const char *message, size_t len, void *user_data)
{
	printf("signal ctx, lvl %d: %.*s\n", level, (int)len, message);
	(void)user_data;
}

static int handle_request(char *verb, char *path, uint64_t *id,
                          size_t n_headers, char **headers,
                          size_t size, uint8_t *body,
                          void *udata)
{
	struct json_store *js = udata;
	const struct kjson_value *cfg = json_store_get(js);
	bool is_enc = is_request_signal_key_encrypted(n_headers, headers);

	if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/message")) {
		/* new message received :) */
		printf("message received, encrypted: %d\n", is_enc);/*
		print_hex(stdout, body, size);
		printf("\n");*/
		if (is_enc && !decrypt_envelope(&body, &size, cfg)) {
			fprintf(stderr, "error decrypting envelope\n");
			return -1;
		}
		Signalservice__Envelope *e;
		e = signalservice__envelope__unpack(NULL, size, body);
		if (!e) {
			fprintf(stderr, "error decoding envelope protobuf\n");
			return -1;
		}
		printf("received envelope:\n");
		print_envelope(e);
		signal_protocol_address addr = {
			.name = e->source,
			.name_len = strlen(e->source),
			.device_id = e->sourcedevice,
		};

		signal_context *ctx;
		int r = signal_context_create(&ctx, NULL);
		printf("signal_context_create -> %d\n", r);

		signal_context_set_crypto_provider(ctx, &crypto_provider);
		signal_context_set_log_function(ctx, ctx_log);

		signal_protocol_store_context *psctx;
		r = signal_protocol_store_context_create(&psctx, ctx);
		printf("signal_protocol_store_context_create -> %d\n", r);

		protocol_store_init(psctx, js);

		session_builder *sb;
		r = session_builder_create(&sb, psctx, &addr, ctx);
		printf("session_builder_create -> %d\n", r);

		session_cipher *cipher;
		r = session_cipher_create(&cipher, psctx, &addr, ctx);
		printf("session_cipher_create -> %d\n", r);

		session_cipher_set_decryption_callback(cipher, decrypt_callback);

		signal_buffer *plaintext = NULL;
		if (e->type == SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE) {
			pre_key_signal_message *msg;
			pre_key_signal_message_deserialize(&msg, e->content.data, e->content.len, ctx);
			printf("pre_key_signal_message_deserialize -> %d\n", r);

			session_cipher_decrypt_pre_key_signal_message(cipher, msg, NULL, &plaintext);
			printf("session_cipher_decrypt_pre_key_signal_message -> %d\n", r);

			SIGNAL_UNREF(msg);
		} else if (e->type == SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT) {
			signal_message *msg;
			r = signal_message_deserialize(&msg, e->content.data, e->content.len, ctx);
			printf("signal_message_deserialize -> %d\n", r);

			r = session_cipher_decrypt_signal_message(cipher, msg, NULL, &plaintext);
			printf("session_cipher_decrypt_signal_message -> %d\n", r);

			SIGNAL_UNREF(msg);
		}
		signal_buffer_free(plaintext);
		session_cipher_free(cipher);
		session_builder_free(sb);
		signal_protocol_store_context_destroy(psctx);
		signal_context_destroy(ctx);

		signalservice__envelope__free_unpacked(e, NULL);
	}
	return 0;
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
	struct kjson_value *cfg = udata;
	fprintf(stderr, "recv get profile: %u %s: ",
	        r->status, r->message);
	struct kjson_value p = KJSON_VALUE_INIT;
	if (kjson_parse(&(struct kjson_parser){ r->body.data }, &p)) {
		kjson_value_print(stderr, &p);
		fprintf(stderr, "\n");
	} else
		fprintf(stderr, "error parsing profile json: '%.*s'\n",
		        (int)r->body.len, r->body.data);
	kjson_value_fini(&p);
	return 0;
	(void)cfg;
	(void)ws;
}

static int recv_get_pre_key(ws_s *ws, struct signal_response *r, void *udata)
{
	struct kjson_value *cfg = udata;
	fprintf(stderr, "recv get pre key: %u %s: %.*s\n",
	        r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)cfg;
	(void)ws;
}

static int recv_get_cert_delivery(ws_s *ws, struct signal_response *r,
                                  void *udata)
{
	struct kjson_value *cfg = udata;
	fprintf(stderr, "recv get certificate delivery: %u %s: %.*s\n",
	        r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)cfg;
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
#endif
}

#ifndef DEFAULT_NUMBER
# define DEFAULT_NUMBER		NULL
#endif
#ifndef DEFAULT_CLI_PATH
# define DEFAULT_CLI_PATH	NULL
#endif

static const char BASE_URL[] = "wss://textsecure-service.whispersystems.org:443";

int main(int argc, char **argv)
{
	const char *number = DEFAULT_NUMBER;
	const char *cli_path = DEFAULT_CLI_PATH;
	for (int opt; (opt = getopt(argc, argv, ":hp:u:")) != -1;)
		switch (opt) {
		case 'h':
			fprintf(stderr, "usage: %s [-u NUMBER] [-p CLI_PATH]\n", argv[0]);
			exit(0);
		case 'p': cli_path = optarg; break;
		case 'u': number = optarg; break;
		case ':': DIE(1,"error: option '-%c' requires a parameter\n",
		              optopt);
		case '?': DIE(1,"error: unknown option '-%c'\n",optopt);
		}

	struct json_store *js = NULL;
	js = json_store_create(number);
	printf("js: %p\n", (void *)js);
	if (!js)
		return 1;
#if 1
	const struct kjson_value *cfg = json_store_get(js);
	(void)cli_path;
#else
	struct cfg cfg = CFG_INIT;
	if (cli_path) {
		char *cli_cfg_path = ckprintf("%s/%s", cli_path, number);

		FILE *f = fopen(cli_cfg_path, "r");
		if (!f) {
			fprintf(stderr, "%s: %s: performing a link\n",
				cli_cfg_path, strerror(errno));
		} else {
			if (!cfg_init(f, &cfg))
				fprintf(stderr, "%s: error parsing config\n",
					cli_cfg_path);
			fclose(f);
		}
		free(cli_cfg_path);
	}
#endif

	const char *password = NULL;
	if (cfg->type == KJSON_VALUE_OBJECT) {
		const struct kjson_value *pwd = kjson_get(cfg, "password");
		if (pwd)
			password = pwd->s.begin;
	}
	int r = 0;
	char *url = NULL;
	if (cfg->type == KJSON_VALUE_NULL) {
		r = ksignal_defer_get_new_uuid(BASE_URL,
		                               .new_uuid = handle_new_uuid,
		                               .on_close = on_close_do_stop);
	} else if (password) {
		url = ckprintf("%s/v1/websocket/?login=%s&password=%s",
		               BASE_URL, number, password);
		r = signal_ws_connect(url,
			.on_open = send_get_profile,
			.handle_request = handle_request,
			.handle_response = NULL,
			.udata = js,
			.on_close = on_close_do_stop,
		);
	} else {
		fprintf(stderr, "don't know what to do, cfg->type: %d\n",
		        cfg->type);
		r = 1;
	}
	printf("%d\n", r);
	fio_start(.threads=1);
	free(url);
#if 0
	cfg_fini(&cfg);
#endif

	if (js) {
		cfg = NULL;
		r = json_store_save(js);
		printf("json_store_save returned %d\n", r);
		if (!r) {
			r = json_store_load(js);
			printf("json_store_load returned %d\n", r);
			r = !r;
		}
		if (!r) {
			r = json_store_save(js);
			printf("json_store_save returned %d\n", r);
		}
		json_store_destroy(js);
	}
	return 0;
}
