
#include "utils.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define MAX(a,b)	((a) > (b) ? (a) : (b))

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

static const char BASE64_ENC[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static bool base64_decode_char(char c, uint32_t *block)
{
	char *s = strchr(BASE64_ENC, c);
	if (!s)
		return false;
	*block = *block << 6 | (s - BASE64_ENC);
	return true;
}

ssize_t base64_decode(uint8_t *target, const char *src, size_t len)
{
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
		for (int i=0; i<len; i++)
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

void print_hex(FILE *f, const uint8_t *buf, size_t size)
{
	static const char HEX[] = "0123456789abcdef";
	for (size_t i=0; i<size; i++)
		fprintf(f, "%c%c ", HEX[buf[i] >> 4], HEX[buf[i] & 0xf]);
}
