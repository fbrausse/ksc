/*
 * json-store.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef JSON_STORE_H
#define JSON_STORE_H

#include <stdbool.h>
#include <stddef.h>	/* size_t */
#include <stdint.h>	/* int32_t */

struct json_store;
struct ksc_log;

struct json_store * json_store_create(const char *path, struct ksc_log *log);
// void                json_store_destroy(struct json_store *);
int                 json_store_save(struct json_store *);
bool                json_store_load(struct json_store *);
void                json_store_ref(struct json_store *);
void                json_store_unref(struct json_store *);

const char * json_store_get_username(const struct json_store *);
bool         json_store_get_device_id(const struct json_store *, int32_t *ret);
const char * json_store_get_password_base64(const struct json_store *);
const char * json_store_get_signaling_key_base64(const struct json_store *,
                                                 size_t *len);
/* -1: error, 0: false, 1: true */
int          json_store_is_multi_device(const struct json_store *);

struct signal_protocol_store_context;

void json_store_protocol_store_init(struct signal_protocol_store_context *ctx,
                                    struct json_store *st);

#endif
