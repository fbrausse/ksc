
#include "utils.h"
#include <fio.h>	/* fio_base64_encode() */

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>

#ifdef KSC_DEBUG_MEM_USAGE
size_t ksc_alloc_buckets[64];
size_t ksc_alloc_total;
#endif

static const char BASE64_ENC[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t ksc_base64_encode(char *target, const uint8_t *src, size_t len)
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

size_t ksc_base64_decode_size(const char *src, size_t len)
{
	int padding = (4 - (len % 4)) % 4;
	if (!padding)
		padding = len >= 2 && src[len-2] == '=' ? 2
		        : len >= 1 && src[len-1] == '=' ? 1 : 0;
	len -= padding;
	assert((len + padding) % 4 == 0);
	return 3 * (len + padding) / 4 - padding;
}

ssize_t ksc_base64_decode(uint8_t *target, const char *src, size_t len)
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
char * ksc_ckprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n == -1)
		return NULL;
	char *buf = ksc_malloc(n+1);
	va_start(ap, fmt);
	n = vsnprintf(buf, n+1, fmt, ap);
	va_end(ap);
	return n == -1 ? free(buf), NULL : buf;
}

void ksc_dprint_hex(int fd, const uint8_t *buf, size_t size)
{
	static const char HEX[] = "0123456789abcdef";
	for (size_t i=0; i<size; i++)
		dprintf(fd, "%c%c%s", HEX[buf[i] >> 4], HEX[buf[i] & 0xf],
		        i+1 < size ? " " : "");
}

static const char *const lvls[] = {
	[KSC_LOG_ERROR] = "error",
	[KSC_LOG_WARN ] = "warn",
	[KSC_LOG_INFO ] = "info",
	[KSC_LOG_NOTE ] = "note",
	[KSC_LOG_DEBUG] = "debug",
};

bool ksc_log_lvl_parse(const char *lvl, enum ksc_log_lvl *res)
{
	if (!strcmp(lvl, "none")) {
		*res = KSC_LOG_NONE;
		return true;
	}
	for (size_t i=0; i<ARRAY_SIZE(lvls); i++)
		if (lvls[i] && !strcmp(lvl, lvls[i])) {
			*res = i;
			return true;
		}
	return false;
}

static void ksc_log_desc_msg(int fd, enum ksc_log_lvl level,
                             const struct ksc_log_context *context)
{
#define BOLD	"1;"
	static const char *const colors[] = {
		[KSC_LOG_ERROR] = BOLD "91", /* bold bright red */
		[KSC_LOG_WARN ] = BOLD "93", /* bold bright yellow */
		[KSC_LOG_INFO ] = BOLD "96", /* bold bright cyan */
		[KSC_LOG_NOTE ] =      "96", /* bright cyan */
		[KSC_LOG_DEBUG] =      "92", /* bright green */
	};
#undef BOLD
	level = MIN(level,ARRAY_SIZE(lvls)-1);
	const char *desc = context && context->desc ? context->desc : "";
	if (isatty(fd)) {
		const char *color;
		color = context && context->color ? context->color : "0";
/* VT100 color escape sequence */
#define COLOR "\x1b[%sm"
		dprintf(fd, COLOR "[%-5s]" COLOR " " COLOR "%s" COLOR ": ",
		        colors[level], lvls[level], "0",
		        color, desc, "0");
#undef COLOR
	} else {
		dprintf(fd, "[%-5s] %s: ", lvls[level], desc);
	}
}

bool ksc_log_prints(enum ksc_log_lvl lvl, const struct ksc_log *log,
                    const struct ksc_log_context *context)
{
	if (!log)
		return true;
	enum ksc_log_lvl max_lvl = log->max_lvl;
	if (context && context->desc)
		for (const struct ksc_log__context_lvl *it = log->context_lvls;
		     it; it = it->next)
			if (!strcmp(context->desc, it->desc)) {
				max_lvl = it->max_lvl;
				break;
			}
	return lvl <= max_lvl;
}

void ksc_vlog(enum ksc_log_lvl level, struct ksc_log *log,
              const struct ksc_log_context *context, const char *fmt,
              va_list ap)
{
	static struct ksc_log default_log = KSC_DEFAULT_LOG;

	if (!ksc_log_prints(level, log, context))
		return;

	level = MAX(KSC_LOG_ERROR, level);
	if (!log)
		log = &default_log;

	ksc_log_desc_msg(log->fd, level, context);
	vdprintf(log->fd, fmt, ap);
}

__attribute__((format(printf,4,5)))
void ksc_log(enum ksc_log_lvl level, struct ksc_log *log,
             const struct ksc_log_context *context, const char *fmt, ...)
{
	va_list ap;
	va_start(ap,fmt);
	ksc_vlog(level, log, context, fmt, ap);
	va_end(ap);
}
