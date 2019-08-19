
#ifndef JSON_STORE_H
#define JSON_STORE_H

#include <kjson.h>

struct json_store;

struct json_store *        json_store_create(const char *path);
void                       json_store_destroy(struct json_store *);
int                        json_store_save(struct json_store *);
bool                       json_store_load(struct json_store *);
const struct kjson_value * json_store_get(const struct json_store *);

struct signal_protocol_store_context;
struct signal_protocol_session_store;

void session_store_set(struct signal_protocol_session_store *r,
                       struct json_store *st);

void protocol_store_init(struct signal_protocol_store_context *ctx,
                         struct json_store *st);

#endif
