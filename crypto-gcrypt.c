
#include "crypto.h"

#include <gcrypt.h>

#include <signal/signal_protocol.h>

#define FAIL(lbl,...) do { fprintf(stderr, __VA_ARGS__); goto lbl; } while (0)

/**
 * Callback for a secure random number generator.
 * This function shall fill the provided buffer with random bytes.
 *
 * @param data pointer to the output buffer
 * @param len size of the output buffer
 * @return 0 on success, negative on failure
 */
static int random_func(uint8_t *data, size_t len, void *user_data)
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
static int hmac_sha256_init_func(void **hmac_context, const uint8_t *key,
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
static int hmac_sha256_update_func(void *hmac_context, const uint8_t *data,
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
static int hmac_sha256_final_func(void *hmac_context, signal_buffer **output,
                                  void *user_data)
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
static void hmac_sha256_cleanup_func(void *hmac_context, void *user_data)
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
static int decrypt_func(signal_buffer **output, int cipher,
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

	uint8_t *body = ksc_malloc(ciphertext_len);
	gr = gcry_cipher_decrypt(ci, body, ciphertext_len, ciphertext, ciphertext_len);
	if (gr)
		FAIL(cipher_fail2, "error on gcry_cipher_decrypt: %x\n", gr);
	gcry_cipher_close(ci);

	/* remove PKCS5Padding */
	size_t size = ciphertext_len;
	if (padding && !pkcs5_unpad(body, &size))
		goto fail;

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

signal_crypto_provider __attribute__((weak)) ksc_crypto_provider = {
	.random_func              = random_func,
	.hmac_sha256_init_func    = hmac_sha256_init_func,
	.hmac_sha256_update_func  = hmac_sha256_update_func,
	.hmac_sha256_final_func   = hmac_sha256_final_func,
	.hmac_sha256_cleanup_func = hmac_sha256_cleanup_func,
	.decrypt_func             = decrypt_func,
};
