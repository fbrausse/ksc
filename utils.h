
#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <kjson.h>

#define KJSON_VALUE_INIT { .type = KJSON_VALUE_NULL, }

struct cfg {
	char *data;
	struct kjson_value v;
};

#define CFG_INIT { NULL, KJSON_VALUE_INIT }

bool cfg_init(FILE *f, struct cfg *cfg);
void cfg_fini(struct cfg *cfg);

struct kjson_value * kjson_get(const struct kjson_value *v,
                               const char *key);

ssize_t base64_decode(uint8_t *target, const char *src, size_t len);

void print_hex(FILE *f, const uint8_t *buf, size_t size);

#endif
