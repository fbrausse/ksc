
#ifndef PROVISIONING_H
#define PROVISIONING_H

#include <stdint.h>

struct provisioning_sock {
	void (*new_uuid)(char *uuid, void *udata);
	void (*on_close)(intptr_t uuid, void *udata);
	void *udata;
};

intptr_t ksignal_defer_get_new_uuid(const char *base_url,
                                    struct provisioning_sock ps);
#define ksignal_defer_get_new_uuid(base_url, ...) \
	ksignal_defer_get_new_uuid((base_url), \
	                           (struct provisioning_sock){ __VA_ARGS__ })

#endif
