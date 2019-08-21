
#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <kjson.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(...)	(sizeof(__VA_ARGS__)/sizeof(*(__VA_ARGS__)))

#define MAX(a,b)	((a) > (b) ? (a) : (b))

static inline void * memdup(void *p, size_t sz) { return memcpy(malloc(sz), p, sz); }

#define KJSON_VALUE_INIT { .type = KJSON_VALUE_NULL, }

struct kjson_value * kjson_get(const struct kjson_value *v, const char *key);

struct kjson_value *        kjson_array_push_back (struct kjson_array *arr,
                                                   struct kjson_value v);
#define kjson_array_push_back(arr,...) \
	kjson_array_push_back((arr),(struct kjson_value){ __VA_ARGS__ })

struct kjson_object_entry * kjson_object_push_back(struct kjson_object *obj,
                                                   struct kjson_object_entry v);
#define kjson_object_push_back(obj,...) \
	kjson_object_push_back((obj),(struct kjson_object_entry){ __VA_ARGS__ })

void kjson_array_remove (struct kjson_array *arr, struct kjson_value *v);
void kjson_object_remove(struct kjson_object *arr,
                         struct kjson_object_entry *v);

/* requires space (len*4/3 + 4) at target */
size_t base64_encode(char *target, const uint8_t *src, size_t len);
ssize_t base64_decode(uint8_t *target, const char *src, size_t len);
size_t base64_decode_size(const char *src, size_t len);

char * ckprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));
void print_hex(FILE *f, const uint8_t *buf, size_t size);

#endif
