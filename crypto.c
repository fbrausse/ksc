
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

#if 1
	void *ctx;
	if (crypto_provider.hmac_sha256_init_func(&ctx, mac_key, MAC_KEY_SIZE, NULL))
		FAIL(fail, "error on hmac_sha256_init_func\n");

	if (crypto_provider.hmac_sha256_update_func(ctx, body, size - MAC_SIZE, NULL))
		FAIL(mac_fail, "error on hmac_sha256_update_func\n");

	signal_buffer *our_mac = NULL;
	if (crypto_provider.hmac_sha256_final_func(ctx, &our_mac, NULL))
		FAIL(mac_fail, "error on hmac_sha256_final_func\n");

	assert(our_mac);
	assert(signal_buffer_len(our_mac) >= MAC_SIZE);
	const uint8_t *their_mac = body + size - MAC_SIZE;
	if (memcmp(signal_buffer_data(our_mac), their_mac, MAC_SIZE)) {
		fprintf(stderr, "MACs don't match:\n");
		fprintf(stderr, "  ours  : ");
		print_hex(stderr, signal_buffer_data(our_mac), MAC_SIZE);
		fprintf(stderr, "\n  theirs: ");
		print_hex(stderr, their_mac, MAC_SIZE);
		fprintf(stderr, "\n");
		goto mac_fail_2;
	}

	signal_buffer_free(our_mac);
	crypto_provider.hmac_sha256_cleanup_func(ctx, NULL);

	// fprintf(stderr, "MACs match! :)\n");

	size -= MAC_SIZE;
	*size_ptr = size;
	return true;

mac_fail_2:
	signal_buffer_free(our_mac);
mac_fail:
	crypto_provider.hmac_sha256_cleanup_func(ctx, NULL);
#else
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
#endif
fail:
	return false;
}

/* body == VERSION IV CIPHERTEXT MAC
 * where MAC           = HMAC-SHA256(VERSION IV CIPHERTEXT, MAC_KEY)
 *       CIPHERTEXT    = ENC-AES256(PKCS5PAD(PLAINTEXT), IV, CBC, CIPHER_KEY)
 *       SIGNALING_KEY = CIPHER_KEY MAC_KEY
 */
bool decrypt_envelope(uint8_t **body_ptr, size_t *size_ptr,
                      const char *signaling_key_base64,
                      size_t signaling_key_base64_len)
{
	uint8_t *body = *body_ptr;
	size_t size = *size_ptr;

	if (size < VERSION_LENGTH || body[VERSION_OFFSET] != VERSION_SUPPORTED)
		return false;
	assert(signaling_key_base64);
	/* properties of base64 */
	assert(signaling_key_base64_len >= (4*(CIPHER_KEY_SIZE + MAC_KEY_SIZE) + 2) / 3);
	assert(signaling_key_base64_len <= (4*(CIPHER_KEY_SIZE + MAC_KEY_SIZE + 2)) / 3);
	uint8_t decoded_key[CIPHER_KEY_SIZE + MAC_KEY_SIZE];
	ssize_t r = base64_decode(decoded_key, signaling_key_base64, signaling_key_base64_len);
	if (r != CIPHER_KEY_SIZE + MAC_KEY_SIZE) {
		fprintf(stderr,
		        "error decoding signalingKey of length %zu: r: %zd\n",
		        signaling_key_base64_len, r);
		return false;
	}
	const uint8_t *cipher_key = decoded_key;
	const uint8_t *mac_key = decoded_key + CIPHER_KEY_SIZE;

	if (!verify_envelope(body, &size, mac_key))
		return false;
	size -= VERSION_LENGTH;
	body += VERSION_LENGTH;

	/* decode AES/CBC/PKCS5Padding */
#if 1
	signal_buffer *plaintext = NULL;
	uint8_t *iv = body;
	body += IV_LENGTH;
	size -= IV_LENGTH;
	if (crypto_provider.decrypt_func(&plaintext, SG_CIPHER_AES_CBC_PKCS5,
	                                 cipher_key, CIPHER_KEY_SIZE,
	                                 iv, IV_LENGTH, body, size, NULL))
		goto fail;
	*size_ptr = signal_buffer_len(plaintext);
	memcpy(body, signal_buffer_data(plaintext), *size_ptr);
	*body_ptr = body;
	signal_buffer_free(plaintext);
	return true;
#else
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
#endif
fail:
	return false;
}

size_t pkcs5_padded_size(size_t size)
{
	return (size+8) & ~(size_t)7;
}

void pkcs5_pad(uint8_t *body, size_t size)
{
	size_t padded = pkcs5_padded_size(size);
	memset(body + size, padded - size, padded - size);
}

bool pkcs5_unpad(const uint8_t *restrict body, size_t *restrict size)
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

bool one_and_zeroes_unpad(const uint8_t *restrict body, size_t *restrict size)
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
