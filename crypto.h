
#ifndef CRYPTO_H
#define CRYPTO_H

#include <signal/signal_protocol.h>

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

extern signal_crypto_provider crypto_provider;

bool decrypt_envelope(uint8_t **body_ptr, size_t *size_ptr,
                      const char *signaling_key_base64,
                      size_t signaling_key_base64_len);

size_t pkcs5_padded_size(size_t size);
void   pkcs5_pad(uint8_t *body, size_t size);
bool   pkcs5_unpad(const uint8_t *restrict body, size_t *restrict size);

#endif
