/*
 * provisioning.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef PROVISIONING_H
#define PROVISIONING_H

#include <stdint.h>

struct ksc_defer_get_new_uuid_args {
	void (*new_uuid)(char *uuid, void *udata);
	void (*on_close)(intptr_t uuid, void *udata);
	void *udata;
};

intptr_t ksc_defer_get_new_uuid(const char *base_url,
                                struct ksc_defer_get_new_uuid_args ps);
#define ksc_defer_get_new_uuid(base_url, ...) \
	ksc_defer_get_new_uuid((base_url), \
	                       (struct ksc_defer_get_new_uuid_args){ __VA_ARGS__ })

#endif
