
#include "fio.h"	/* fio_base64_encode() */
#include "utils.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>

bool cfg_init(FILE *f, struct cfg *cfg)
{
	size_t data_cap = 0;
	size_t data_sz = 0;
	static char buf[4096];
	for (size_t rd; (rd = fread(buf, 1, sizeof(buf), f)) > 0;) {
		size_t n = data_sz + rd;
		if (n > data_cap) {
			data_cap = MAX(n, 2 * data_cap);
			cfg->data = realloc(cfg->data, data_cap);
			assert(cfg->data);
		}
		memcpy(cfg->data + data_sz, buf, rd);
		data_sz = n;
		if (rd < sizeof(buf))
			break;
	}
	assert(feof(f));
	bool r = kjson_parse(&(struct kjson_parser){ cfg->data }, &cfg->v);
	if (!r) {
		free(cfg->data);
		cfg->data = NULL;
		assert(cfg->v.type == KJSON_VALUE_NULL);
	}
	return r;
}

void cfg_fini(struct cfg *cfg)
{
	kjson_value_fini(&cfg->v);
	free(cfg->data);
}

struct kjson_value * kjson_get(const struct kjson_value *v, const char *key)
{
	assert(v->type == KJSON_VALUE_OBJECT);
	for (size_t i=0; i<v->o.n; i++)
		if (!strcmp(v->o.data[i].key.begin, key))
			return &v->o.data[i].value;
	return NULL;
}

struct kjson_value * kjson_array_push_back(struct kjson_array *arr, struct kjson_value v)
{
	/* XXX: inefficient */
	arr->data = realloc(arr->data, sizeof(*arr->data) * (arr->n+1));
	struct kjson_value *r = &arr->data[arr->n++];
	*r = v;
	return r;
}

struct kjson_object_entry * kjson_object_push_back(struct kjson_object *obj, struct kjson_object_entry v)
{
	/* XXX: inefficient */
	obj->data = realloc(obj->data, sizeof(*obj->data) * (obj->n+1));
	struct kjson_object_entry *e = &obj->data[obj->n++];
	*e = v;
	return e;
}

void kjson_array_remove(struct kjson_array *arr, struct kjson_value *v)
{
	memmove(v, v+1, sizeof(*arr->data) * (--arr->n - (v - arr->data)));
}

void kjson_object_remove(struct kjson_object *obj, struct kjson_object_entry *e)
{
	memmove(e, e+1, sizeof(*obj->data) * (--obj->n - (e - obj->data)));
}

static const char BASE64_ENC[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode(char *target, const uint8_t *src, size_t len)
{
	int r = fio_base64_encode(target, (const char *)src, len);
	assert(r >= 0);
	return r;
}

static bool base64_decode_char(char c, uint32_t *block)
{
	char *s = strchr(BASE64_ENC, c);
	if (!s)
		return false;
	*block = *block << 6 | (s - BASE64_ENC);
	return true;
}

size_t base64_decode_size(const char *src, size_t len)
{
	int padding = (4 - (len % 4)) % 4;
	if (!padding)
		padding = len >= 2 && src[len-2] == '=' ? 2
		        : len >= 1 && src[len-1] == '=' ? 1 : 0;
	len -= padding;
	assert((len + padding) % 4 == 0);
	return 3 * (len + padding) / 4 - padding;
}

ssize_t base64_decode(uint8_t *target, const char *src, size_t len)
{
	/* can't use fio_base64_decode() as it seems to be buggy... */
	uint8_t *tgt = target;
	int padding = (4 - (len % 4)) % 4;
	if (!padding)
		padding = len >= 2 && src[len-2] == '=' ? 2
		        : len >= 1 && src[len-1] == '=' ? 1 : 0;
	len -= padding;
	assert((len + padding) % 4 == 0);
	for (; len >= 4; len -= 4) {
		uint32_t block = 0;
		for (int i=0; i<4; i++)
			if (!base64_decode_char(*src++, &block))
				return -1;
		*tgt++ = block >> 16;
		*tgt++ = block >> 8;
		*tgt++ = block;
	}
	if (padding) {
		uint32_t block = 0;
		for (int i=0; i<(int)len; i++)
			if (!base64_decode_char(*src++, &block))
				return -1;
		if (padding == 2) {
			*tgt++ = block >> 4;
		} else {
			*tgt++ = block >> 10;
			*tgt++ = block >> 2;
		}
	}
	return tgt - target;
}

__attribute__((format(printf,1,2)))
char * ckprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n == -1)
		return NULL;
	char *buf = malloc(n+1);
	va_start(ap, fmt);
	n = vsnprintf(buf, n+1, fmt, ap);
	va_end(ap);
	return n == -1 ? free(buf), NULL : buf;
}

void print_hex(FILE *f, const uint8_t *buf, size_t size)
{
	static const char HEX[] = "0123456789abcdef";
	for (size_t i=0; i<size; i++)
		fprintf(f, "%c%c ", HEX[buf[i] >> 4], HEX[buf[i] & 0xf]);
}
