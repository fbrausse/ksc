/*
 * utils.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kjson.h>

#define ARRAY_SIZE(...)	(sizeof(__VA_ARGS__)/sizeof(*(__VA_ARGS__)))

#define KSC_STR(x)	#x
#define KSC_XSTR(x)	KSC_STR(x)

#ifdef KSC_DEBUG_MEM_USAGE
extern size_t ksc_alloc_buckets[64];
extern size_t ksc_alloc_total;

static inline void ksc_count_alloc(size_t n)
{
	for (size_t i=0; i<ARRAY_SIZE(ksc_alloc_buckets); i++)
		if (n < (size_t)1 << i) {
			ksc_alloc_buckets[i]++;
			break;
		}
	ksc_alloc_total += n;
}
#else
static inline void ksc_count_alloc(size_t n) { (void)n; }
#endif

static inline void * ksc_malloc(size_t n)
{
	ksc_count_alloc(n);
	return malloc(n);
}

static inline void * ksc_calloc(size_t n, size_t sz)
{
	ksc_count_alloc(n * sz);
	return calloc(n, sz);
}

static inline void * ksc_realloc(void *ptr, size_t n)
{
	ksc_count_alloc(n);
	return realloc(ptr, n);
}

static inline void * ksc_memdup(void *p, size_t sz) { return memcpy(ksc_malloc(sz), p, sz); }

#define KJSON_VALUE_INIT { .type = KJSON_VALUE_NULL, }

/* requires space (len*4/3 + 4) at target */
size_t  ksc_base64_encode(char *target, const uint8_t *src, size_t len);
ssize_t ksc_base64_decode(uint8_t *target, const char *src, size_t len);
size_t  ksc_base64_decode_size(const char *src, size_t len);

char * ksc_ckprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));
void ksc_dprint_hex(int fd, const uint8_t *buf, size_t size);


#define MMC_DEF(s,type)                                         \
static inline type ksc_min_ ## s(type a, type b)                \
{                                                               \
	return a < b ? a : b;                                   \
}                                                               \
static inline type ksc_max_ ## s(type a, type b)                \
{                                                               \
	return a < b ? b : a;                                   \
}                                                               \
static inline type ksc_clamp_ ## s(type x, type low, type high) \
{                                                               \
	return x < low ? low : x > high ? high : x;             \
}

MMC_DEF(i,intmax_t)
MMC_DEF(u,uintmax_t)
MMC_DEF(f,float)
MMC_DEF(d,double)
MMC_DEF(ld,long double)

#undef MMC_DEF

#define KSC__MMC_GENERIC_BODY(prefix)        \
	         intmax_t   : prefix ## _i,  \
	         uintmax_t  : prefix ## _u,  \
	         float      : prefix ## _f,  \
	         double     : prefix ## _d,  \
	         long double: prefix ## _ld  \

#define MIN(a,b) \
	_Generic((a)+(intmax_t)(b), KSC__MMC_GENERIC_BODY(ksc_min))(a, b)
#define MAX(a,b) \
	_Generic((a)+(intmax_t)(b), KSC__MMC_GENERIC_BODY(ksc_max))(a, b)
#define CLAMP(x,low,high) \
	_Generic((x)+(intmax_t)0, KSC__MMC_GENERIC_BODY(ksc_clamp))(x,low,high)

/* logging */

enum ksc_log_lvl {
	KSC_LOG_NONE = -1,
	KSC_LOG_ERROR,
	KSC_LOG_WARN,
	KSC_LOG_INFO,
	KSC_LOG_NOTE,
	KSC_LOG_DEBUG,
};

bool ksc_log_lvl_parse(const char *lvl, enum ksc_log_lvl *res);

struct ksc_log {
	enum ksc_log_lvl max_lvl;
	int fd;
	struct ksc_log__context_lvl {
		struct ksc_log__context_lvl *next;
		const char *desc;
		enum ksc_log_lvl max_lvl;
	} *context_lvls;
};

#define KSC_DEFAULT_LOG	(struct ksc_log){ INT_MAX, STDERR_FILENO, NULL }

struct ksc_log_context {
	const char *desc;
	const char *color;
};

bool ksc_log_prints(enum ksc_log_lvl lvl, const struct ksc_log *log,
                    const struct ksc_log_context *context);

void ksc_vlog(enum ksc_log_lvl level, struct ksc_log *log,
              const struct ksc_log_context *context, const char *fmt,
              va_list ap);

__attribute__((format(printf,4,5)))
void ksc_log(enum ksc_log_lvl level, struct ksc_log *log,
             const struct ksc_log_context *context, const char *fmt, ...);

/* log and context may be empty */
#define KSC_LOG_(level, log, msg_context, ...) \
	ksc_log(level, \
	        ((struct { struct ksc_log *ptr; }){log}.ptr), \
	        ((struct { const struct ksc_log_context *ptr; }){msg_context}.ptr),\
	        __VA_ARGS__)
/* lvl is the * abbreviation of KSC_LOG_*, log and context may be empty */
#define KSC_LOG(lvl, log_ctx, msg_context, ...) \
	KSC_LOG_(KSC_LOG_ ## lvl, log_ctx, msg_context, __VA_ARGS__)

#define KSC_DEBUGL(lvl, log, ...) \
	KSC_LOG(lvl, log, \
	        (&(struct ksc_log_context){ __FILE__ ":" KSC_XSTR(__LINE__), "92" }), \
	        __VA_ARGS__)

#define KSC_DEBUG(lvl, ...) KSC_DEBUGL(lvl,, __VA_ARGS__)

#endif
