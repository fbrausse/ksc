
#include <openssl/evp.h>	/* EVP_* */
#include <openssl/hmac.h>	/* HMAC_* */
#include <openssl/rand.h>	/* RAND_bytes() */

#include <signal/signal_protocol.h>

static int random_func(uint8_t *data, size_t len, void *user_data)
{
	return RAND_bytes(data, len) ? 0 : SG_ERR_UNKNOWN;
	(void)user_data;
}

static int hmac_sha256_init_func(void **hmac_context, const uint8_t *key,
                                 size_t key_len, void *user_data)
{
	HMAC_CTX *hmac_ctx = HMAC_CTX_new();
	if (!hmac_ctx)
		return SG_ERR_NOMEM;

	// set key
	if (!HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha256(), NULL)) {
		HMAC_CTX_free(hmac_ctx);
		return SG_ERR_UNKNOWN;
	}

	*hmac_context = hmac_ctx;

	return 0;
	(void)user_data;
}

static int hmac_sha256_update_func(void *hmac_context, const uint8_t *data,
                                   size_t data_len, void *user_data)
{
	return HMAC_Update(hmac_context, data, data_len) ? 0 : SG_ERR_UNKNOWN;
	(void)user_data;
}

static int hmac_sha256_final_func(void *hmac_context,
                                  signal_buffer **output, void *user_data)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len = 0;

	if (!HMAC_Final(hmac_context, md, &len))
		return SG_ERR_UNKNOWN;

	*output = signal_buffer_create(md, len);
	if (!*output)
		return SG_ERR_NOMEM;

	return 0;
	(void)user_data;
}

static void hmac_sha256_cleanup_func(void *hmac_context, void *user_data)
{
	HMAC_CTX_free(hmac_context);
	(void)user_data;
}

/* as per the axolotl testcases */
const EVP_CIPHER * choose_aes_cipher(int cipher, size_t key_len)
{
	switch (cipher) {
	case SG_CIPHER_AES_CBC_PKCS5:
		switch (key_len) {
		case 16: return EVP_aes_128_cbc();
		case 24: return EVP_aes_192_cbc();
		case 32: return EVP_aes_256_cbc();
		}
		break;
	case SG_CIPHER_AES_CTR_NOPADDING:
		switch (key_len) {
		case 16: return EVP_aes_128_ctr();
		case 24: return EVP_aes_192_ctr();
		case 32: return EVP_aes_256_ctr();
		}
		break;
	}
	return NULL;
}

static int decrypt_func(signal_buffer **output, int cipher,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        void *user_data)
{
	int ret_val = SG_SUCCESS;
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	uint8_t *out_buf = NULL;
	int out_len = 0;
	int final_len = 0;
	const EVP_CIPHER *evp_cipher = choose_aes_cipher(cipher, key_len);

	if (iv_len != 16)
		return SG_ERR_UNKNOWN;

	// pick correct cipher function according to mode and key length
	if (!evp_cipher)
		return SG_ERR_UNKNOWN;

	// init context
	cipher_ctx = EVP_CIPHER_CTX_new();

	// init cipher
	if (!EVP_DecryptInit_ex(cipher_ctx, evp_cipher, NULL, key, iv)) {
		ret_val = SG_ERR_UNKNOWN;
		goto cleanup;
	}

	if (cipher == SG_CIPHER_AES_CTR_NOPADDING)
		EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);

	// allocate result buffer
	out_buf = malloc(sizeof(uint8_t) *
	                 (ciphertext_len + EVP_MAX_BLOCK_LENGTH));
	if (!out_buf) {
		ret_val = SG_ERR_NOMEM;
		goto cleanup;
	}

	// update cipher with plaintext etc
	if (!EVP_DecryptUpdate(cipher_ctx, out_buf, &out_len, ciphertext,
	                       ciphertext_len)) {
		ret_val = SG_ERR_UNKNOWN;
		goto cleanup;
	}

	// finalise
	if (!EVP_DecryptFinal_ex(cipher_ctx, out_buf + out_len, &final_len)) {
		ret_val = SG_ERR_UNKNOWN;
		goto cleanup;
	}

	*output = signal_buffer_create(out_buf, out_len + final_len);
	if (!*output) {
		ret_val = SG_ERR_NOMEM;
		goto cleanup;
	}

cleanup:
	EVP_CIPHER_CTX_free(cipher_ctx);
	free(out_buf);

	return ret_val;
	(void)user_data;
}

signal_crypto_provider __attribute__((weak)) crypto_provider = {
	.random_func              = random_func,
	.hmac_sha256_init_func    = hmac_sha256_init_func,
	.hmac_sha256_update_func  = hmac_sha256_update_func,
	.hmac_sha256_final_func   = hmac_sha256_final_func,
	.hmac_sha256_cleanup_func = hmac_sha256_cleanup_func,
	.decrypt_func             = decrypt_func,
};
