
#include "crypto.h"
#include "utils.h"

#include <signal/signal_protocol.h>

#include <string.h>		/* memcpy */
#include <assert.h>

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

	void *ctx;
	if (ksc_crypto_provider.hmac_sha256_init_func(&ctx, mac_key, MAC_KEY_SIZE, NULL))
		FAIL(fail, "error on hmac_sha256_init_func\n");

	if (ksc_crypto_provider.hmac_sha256_update_func(ctx, body, size - MAC_SIZE, NULL))
		FAIL(mac_fail, "error on hmac_sha256_update_func\n");

	signal_buffer *our_mac = NULL;
	if (ksc_crypto_provider.hmac_sha256_final_func(ctx, &our_mac, NULL))
		FAIL(mac_fail, "error on hmac_sha256_final_func\n");

	assert(our_mac);
	assert(signal_buffer_len(our_mac) >= MAC_SIZE);
	const uint8_t *their_mac = body + size - MAC_SIZE;
	if (memcmp(signal_buffer_data(our_mac), their_mac, MAC_SIZE)) {
		fprintf(stderr, "MACs don't match:\n");
		fprintf(stderr, "  ours  : ");
		fflush(stderr);
		ksc_dprint_hex(fileno(stderr), signal_buffer_data(our_mac),
		               MAC_SIZE);
		fprintf(stderr, "\n  theirs: ");
		fflush(stderr);
		ksc_dprint_hex(fileno(stderr), their_mac, MAC_SIZE);
		fprintf(stderr, "\n");
		goto mac_fail_2;
	}

	signal_buffer_free(our_mac);
	ksc_crypto_provider.hmac_sha256_cleanup_func(ctx, NULL);

	// fprintf(stderr, "MACs match! :)\n");

	size -= MAC_SIZE;
	*size_ptr = size;
	return true;

mac_fail_2:
	signal_buffer_free(our_mac);
mac_fail:
	ksc_crypto_provider.hmac_sha256_cleanup_func(ctx, NULL);
fail:
	return false;
}

/* body == VERSION IV CIPHERTEXT MAC
 * where MAC           = HMAC-SHA256(VERSION IV CIPHERTEXT, MAC_KEY)
 *       CIPHERTEXT    = ENC-AES256(PKCS5PAD(PLAINTEXT), IV, CBC, CIPHER_KEY)
 *       SIGNALING_KEY = CIPHER_KEY MAC_KEY
 */
bool ksc_decrypt_envelope(uint8_t **body_ptr, size_t *size_ptr,
                          const char *sg_key_b64,
                          size_t sg_key_b64_len)
{
	uint8_t *body = *body_ptr;
	size_t size = *size_ptr;

	if (size < VERSION_LENGTH || body[VERSION_OFFSET] != VERSION_SUPPORTED)
		return false;
	assert(sg_key_b64);
	/* properties of base64 */
	assert(sg_key_b64_len >= (4*(CIPHER_KEY_SIZE + MAC_KEY_SIZE) + 2) / 3);
	assert(sg_key_b64_len <= (4*(CIPHER_KEY_SIZE + MAC_KEY_SIZE + 2)) / 3);
	uint8_t decoded_key[CIPHER_KEY_SIZE + MAC_KEY_SIZE];
	ssize_t r = ksc_base64_decode(decoded_key, sg_key_b64, sg_key_b64_len);
	if (r != CIPHER_KEY_SIZE + MAC_KEY_SIZE) {
		fprintf(stderr,
		        "error decoding signalingKey of length %zu: r: %zd\n",
		        sg_key_b64_len, r);
		return false;
	}
	const uint8_t *cipher_key = decoded_key;
	const uint8_t *mac_key = decoded_key + CIPHER_KEY_SIZE;

	if (!verify_envelope(body, &size, mac_key))
		return false;
	size -= VERSION_LENGTH;
	body += VERSION_LENGTH;

	/* decode AES/CBC/PKCS5Padding */
	signal_buffer *plaintext = NULL;
	uint8_t *iv = body;
	body += IV_LENGTH;
	size -= IV_LENGTH;
	if (ksc_crypto_provider.decrypt_func(&plaintext,SG_CIPHER_AES_CBC_PKCS5,
	                                     cipher_key, CIPHER_KEY_SIZE,
	                                     iv, IV_LENGTH, body, size, NULL))
		goto fail;
	*size_ptr = signal_buffer_len(plaintext);
	memcpy(body, signal_buffer_data(plaintext), *size_ptr);
	*body_ptr = body;
	signal_buffer_free(plaintext);
	return true;
fail:
	return false;
}

void ksc_pkcs5_pad(uint8_t *body, size_t size)
{
	size_t padded = ksc_pkcs5_padded_size(size);
	memset(body + size, padded - size, padded - size);
}

bool ksc_pkcs5_unpad(const uint8_t *restrict body, size_t *restrict size)
{
	if (!*size)
		return false;/*
		FAIL(fail, "size of decrypted envelope is zero\n");*/
	unsigned n = body[*size-1];
	if (*size < n)
		return false;/*
		FAIL(fail, "size of decrypted envelope is smaller than "
		           "PKCS5Padding's value\n");*/
	for (unsigned i=0; i<n; i++)
		if (body[*size-n+i] != n)
			return false;/*
			FAIL(fail,
			     "PKCS5Padding of decrypted envelope is broken\n");*/
	*size -= n;
	return true;
}

bool ksc_one_and_zeroes_unpad(const uint8_t *restrict body,
                              size_t *restrict size)
{
	const uint8_t *restrict begin_pad;
#ifdef _GNU_SOURCE
	begin_pad = memrchr(body, 0x80, *size);
	if (!begin_pad)
		return false;
#else
	if (!*size)
		return false;
	begin_pad = body + *size - 1;
	for (; body < begin_pad && !*begin_pad; begin_pad--);
	if (*begin_pad != 0x80)
		return false;
#endif
	*size = begin_pad - body;
	return true;
}
