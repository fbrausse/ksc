/*
 * ksc-ws-private.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

/* #include after LOG* definitions */

#ifndef KSC_WS_PRIVATE_H
#define KSC_WS_PRIVATE_H

#include <assert.h>
#include <stdatomic.h>	/* atomic_init() */
#include <inttypes.h>	/* PRI* macros */

#include <pthread.h>	/* pthread_mutex */

#include <signal/signal_protocol.h>

#define UNKNOWN             SIGNALSERVICE__ENVELOPE__TYPE__UNKNOWN
#define CIPHERTEXT          SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT
#define KEY_EXCHANGE        SIGNALSERVICE__ENVELOPE__TYPE__KEY_EXCHANGE
#define PREKEY_BUNDLE       SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE
#define RECEIPT             SIGNALSERVICE__ENVELOPE__TYPE__RECEIPT
#define UNIDENTIFIED_SENDER SIGNALSERVICE__ENVELOPE__TYPE__UNIDENTIFIED_SENDER

/* ref-counted structs */

#ifndef KSC_WARN_UNUSED
# ifdef __GNUC__
#  define KSC_WARN_UNUSED	__attribute__((warn_unused_result))
# else
#  define KSC_WARN_UNUSED
# endif
#endif

struct ref_counted {
	_Atomic size_t cnt;
};

static inline struct ref_counted * ref(struct ref_counted *ref)
{
	ref->cnt++;
	return ref;
}

KSC_WARN_UNUSED
static inline size_t unref(struct ref_counted *ref)
{
	assert(ref->cnt);
	return --ref->cnt;
}

#define REF_COUNTED	struct ref_counted ref_counted
#define REF_INIT(ptr,v)	atomic_init(&(ptr)->ref_counted.cnt, (v))
/* only use directly when you know what you're doing: no destructor invoked */
#define REF(ptr)	ref(&(ptr)->ref_counted)
#define UNREF(ptr)	unref(&(ptr)->ref_counted)

struct ksc_ws {
	REF_COUNTED;
	struct json_store *js;
	signal_context *ctx;
	signal_protocol_store_context *psctx;
	char *url;
	intptr_t uuid;
	struct ksc_ws_connect_service_args args;
	bool reconnecting_during_close;
	pthread_mutex_t signal_mtx;
};

void ksignal_ctx_destroy(struct ksc_ws *ksc);

static inline void ksignal_ctx_ref(struct ksc_ws *ksc)
{
	REF(ksc);
}

static inline void ksignal_ctx_unref(struct ksc_ws *ksc)
{
	if (UNREF(ksc))
		return;
	ksignal_ctx_destroy(ksc);
}

#endif
