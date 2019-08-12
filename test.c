
#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "SignalService.pb-c.h"

#include <assert.h>
#include <time.h>	/* ctime_r() */

#include <gcrypt.h>

#define VERSION_OFFSET		0
#define VERSION_SUPPORTED	1
#define VERSION_LENGTH		1

#define CIPHER_KEY_SIZE		32
#define MAC_KEY_SIZE		20
#define MAC_SIZE		10

#define IV_LENGTH		16
// #define IV_OFFSET		(VERSION_OFFSET + VERSION_LENGTH)
// #define CIPHERTEXT_OFFSET	(IV_OFFSET + IV_LENGTH

_Static_assert(VERSION_OFFSET == 0);

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

	fprintf(stderr, "MACs match! :)\n");

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
	int n = body[size-1];
	if (size < n)
		FAIL(fail, "size of decrypted envelope is smaller than "
		           "PKCS5Padding's value\n");
	for (int i=0; i<n; i++)
		if (body[size-1-i] != n)
			FAIL(fail,
			     "PKCS5Padding of decrypted envelope is broken\n");
	size -= n;

	fprintf(stderr, "success: ");
	print_hex(stderr, body, size);
	fprintf(stderr, "\n");

	*body_ptr = body;
	*size_ptr = size;
	return true;

cipher_fail:
	gcry_cipher_close(ci);
fail:
	return false;
}

#undef FAIL

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
	if (e->has_legacymessage)
		printf("  has encrypted legacy message of size %zu\n",
		       e->legacymessage.len);
	if (e->has_content)
		printf("  has encrypted content of size %zu\n",
		       e->content.len);
	if (e->serverguid)
		printf("  server guid: %s\n", e->serverguid);
	if (e->has_servertimestamp) {
		char buf[32];
		time_t t = e->servertimestamp / 1000;
		ctime_r(&t, buf);
		printf("  server timestamp: %s", buf);
	}
}

static int handle_request(char *verb, char *path, uint64_t *id,
                          size_t n_headers, char **headers,
                          size_t size, uint8_t *body,
                          void *udata)
{
	bool is_enc = is_request_signal_key_encrypted(n_headers, headers);

	if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/message")) {
		/* new message received :) */
		printf("message received, encrypted: %d\n", is_enc);
		print_hex(stdout, body, size);
		printf("\n");
		if (is_enc && !decrypt_envelope(&body, &size, udata)) {
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
		signalservice__envelope__free_unpacked(e, NULL);
	}
	return 0;
}

static void on_close_do_stop(intptr_t uuid, void *udata)
{
	printf("close, stopping\n");
	fio_stop();
}

static void handle_new_uuid(char *uuid, void *udata)
{
	printf("got new uuid: %s\n", uuid);
}

#define DIE(code,...) do { fprintf(stderr, __VA_ARGS__); exit(code); } while (0)

static int recv_get_profile(fio_str_info_s *msg, void *udata)
{
	// struct kjson_value *cfg = udata;
	fprintf(stderr, "recv get profile: %.*s\n", (int)msg->len, msg->data);
	struct kjson_value p = KJSON_VALUE_INIT;
	if (kjson_parse(&(struct kjson_parser){ msg->data }, &p)) {
		fprintf(stderr, "recv get profile: ");
		kjson_value_print(stderr, &p);
		fprintf(stderr, "\n");
	} else
		fprintf(stderr, "error parsing profile json\n");
	kjson_value_fini(&p);
	return 0;
}

static void send_get_profile(ws_s *s, void *udata)
{
#ifdef DEFAULT_GET_PROFILE_NUMBER
	signal_ws_send_request(s, "GET",
	                       "/v1/profile/" DEFAULT_GET_PROFILE_NUMBER,
	                       .on_response = recv_get_profile, .udata = udata);
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

	struct cfg cfg = CFG_INIT;
	if (cli_path) {
		char *cli_cfg_path = NULL;
		asprintf(&cli_cfg_path, "%s/%s", cli_path, number);
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

	const char *password = NULL;
	if (cfg.v.type == KJSON_VALUE_OBJECT) {
		const struct kjson_value *pwd = kjson_get(&cfg.v, "password");
		if (pwd)
			password = pwd->s.begin;
	}
	int r = 0;
	char *url = NULL;
	if (cfg.v.type == KJSON_VALUE_NULL) {
		r = ksignal_defer_get_new_uuid(BASE_URL,
		                               .new_uuid = handle_new_uuid,
		                               .on_close = on_close_do_stop);
	} else if (password) {
		asprintf(&url, "%s/v1/websocket/?login=%s&password=%s",
		         BASE_URL, number, password);
		r = signal_ws_connect(url,
			.on_open = send_get_profile,
			.handle_request = handle_request,
			.handle_response = NULL,
			.udata = &cfg.v,
			.on_close = on_close_do_stop,
		);
	} else {
		fprintf(stderr, "don't know what to do, cfg.v.type: %d\n",
		        cfg.v.type);
		r = 1;
	}
	printf("%d\n", r);
	fio_start(.threads=1);
	free(url);
	cfg_fini(&cfg);
}
