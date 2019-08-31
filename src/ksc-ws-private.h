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

#include <inttypes.h>	/* PRI* macros */

#include <pthread.h>	/* pthread_mutex */

#include <signal/signal_protocol.h>

#define UNKNOWN             SIGNALSERVICE__ENVELOPE__TYPE__UNKNOWN
#define CIPHERTEXT          SIGNALSERVICE__ENVELOPE__TYPE__CIPHERTEXT
#define KEY_EXCHANGE        SIGNALSERVICE__ENVELOPE__TYPE__KEY_EXCHANGE
#define PREKEY_BUNDLE       SIGNALSERVICE__ENVELOPE__TYPE__PREKEY_BUNDLE
#define RECEIPT             SIGNALSERVICE__ENVELOPE__TYPE__RECEIPT
#define UNIDENTIFIED_SENDER SIGNALSERVICE__ENVELOPE__TYPE__UNIDENTIFIED_SENDER

struct object {
	REF_COUNTED;
	void (*fini)(struct object *);
};

static inline void obj_init(struct object *v, void (*fini)(struct object *))
{
	REF_INIT(v);
	v->fini = fini;
}

static inline void obj_ref(struct object *v)
{
	KSC_DEBUG(INFO, "obj_ref(%p)\n", v);
	REF(v);
}

static inline void obj_unref(struct object *v)
{
	KSC_DEBUG(INFO, "obj_unref(%p)\n", v);
	if (!UNREF(v))
		v->fini(v);
}

#define OBJECT			struct object object_base
#define OBJ_OF(ptr)		&(ptr)->object_base
#define OBJ_INIT(ptr,fini)	obj_init(OBJ_OF(ptr), fini)
#define OBJ_REF(ptr)		obj_ref(OBJ_OF(ptr))
#define OBJ_UNREF(ptr)		obj_unref(OBJ_OF(ptr))
#define OBJ_TO(obj,type) \
	(type *)((char *)(obj) - offsetof(type, object_base))

/* helper to automate .on_finish by calling OBJ_UNREF */
static inline int obj_run_every(int timeout_ms, int repetitions,
                                void (*on_timeout)(struct object *udata),
                                struct object *udata)
{
	obj_ref(udata);
	return fio_run_every(timeout_ms, repetitions,
	                     (void (*)(void *))on_timeout, udata,
	                     (void (*)(void *))obj_unref);
}

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
