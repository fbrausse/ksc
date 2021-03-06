/*
 * crypto.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <signal/signal_protocol.h>

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

extern signal_crypto_provider ksc_crypto_provider;

bool ksc_decrypt_envelope(uint8_t **body_ptr, size_t *size_ptr,
                          const char *signaling_key_base64,
                          size_t signaling_key_base64_len);

static inline size_t ksc_pkcs5_padded_size(size_t size)
{
	return (size+8) & ~(size_t)7;
}

void   ksc_pkcs5_pad(uint8_t *body, size_t size);
bool   ksc_pkcs5_unpad(const uint8_t *restrict body, size_t *restrict size);

static inline size_t ksc_one_and_zeroes_padded_size(size_t size,
                                                    size_t multiple)
{
	size++;
	if (size % multiple)
		size += multiple - (size % multiple);
	return size;
}

void ksc_one_and_zeroes_pad(uint8_t *restrict body, size_t *restrict size,
                            size_t multiple);
bool ksc_one_and_zeroes_unpad(const uint8_t *restrict body,
                              size_t *restrict size);

#endif
