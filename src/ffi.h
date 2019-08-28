/*
 * ffi.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef KSC_FFI_H
#define KSC_FFI_H

#include <stdint.h>

/* public API */

/* logging */

struct ksc_log;

struct ksc_log * ksc_ffi_log_create(int fd, const char *level);
void             ksc_ffi_log_destroy(struct ksc_log *log);
int              ksc_ffi_log_restrict_context(struct ksc_log *log,
                                              const char *desc,
                                              const char *level);

/* service connection */

struct ksc_ffi_envelope;

char *   ksc_ffi_envelope_get_source(struct ksc_ffi_envelope *);
/* -1 if not present */
int64_t  ksc_ffi_envelope_get_source_device_id(struct ksc_ffi_envelope *);
/* -1 if not present */
int64_t  ksc_ffi_envelope_get_timestamp(struct ksc_ffi_envelope *);

struct ksc_ffi_data;

char *    ksc_ffi_data_get_body(struct ksc_ffi_data *);
char *    ksc_ffi_data_get_group_id_base64(struct ksc_ffi_data *);
/* -1 if not present */
int64_t   ksc_ffi_data_get_timestamp(struct ksc_ffi_data *);

struct ksc_ffi;

void * ksc_ffi_get_udata(struct ksc_ffi *);

struct ksc_ffi * ksc_ffi_start(const char *json_store_path,
	int (*on_receipt)(const struct ksc_ffi *,
	                  struct ksc_ffi_envelope *e),
	int (*on_data)(const struct ksc_ffi *,
	               struct ksc_ffi_envelope *e,
	               struct ksc_ffi_data *c),
	void (*on_open)(const struct ksc_ffi *),
	void (*on_close)(intptr_t uuid, void *udata),
	struct ksc_log *log,
	const char *server_cert_path,
	int on_close_do_reconnect,
	void *udata
);

void ksc_ffi_stop(struct ksc_ffi *);

int ksc_ffi_send_message(struct ksc_ffi *ffi,
                         const char *recipient,
	const char *body,
	int end_session,
	/*
	const void *const *attachments;
	size_t n_attachments;*/

	/* 0: to unsubscribe, other to stay subscribed */
	int (*on_response)(int status, char *message, void *udata),
	void *udata
);

#endif
