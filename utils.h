
#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <kjson.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(...)	(sizeof(__VA_ARGS__)/sizeof(*(__VA_ARGS__)))

#define KSC_STR(x)	#x
#define KSC_XSTR(x)	KSC_STR(x)

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
void ksc_dprint_hex(int fd, const uint8_t *buf, size_t size);
#define print_hex(f, buf, size)	ksc_dprint_hex(fileno(f), buf, size)


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

static inline bool ksc_log_prints(enum ksc_log_lvl lvl,
                                  const struct ksc_log *log,
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

#define KSC_DEBUG(lvl, ...) \
	KSC_LOG(lvl, \
	        (&KSC_DEFAULT_LOG), \
	        (&(struct ksc_log_context){ __FILE__ ":" KSC_XSTR(__LINE__), "92" }), \
	        __VA_ARGS__)

#endif
