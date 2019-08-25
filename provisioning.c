/*
 * provisioning.c
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "Provisioning.pb-c.h"

static int handle_request(ws_s *ws, char *verb, char *path, uint64_t *id,
                          size_t n_headers, char **headers,
                          size_t size, uint8_t *body,
                          void *udata)
{
	struct ksc_defer_get_new_uuid_args *ps = udata;
	if (!strcmp(path, "/v1/address")) {
		Signalservice__ProvisioningUuid *uuid_msg =
			signalservice__provisioning_uuid__unpack(NULL, size, body);
		assert(uuid_msg);
		if (ps && ps->new_uuid)
			ps->new_uuid(uuid_msg->uuid, ps->udata);
		signalservice__provisioning_uuid__free_unpacked(uuid_msg, NULL);
		return 0;
	} else {
		printf("handle_provisioning_request: cannot handle %s %s\n",
		       verb, path);
		return -1;
	}
	(void)ws;
	(void)id;
	(void)n_headers;
	(void)headers;
}

static void on_close(intptr_t uuid, void *udata)
{
	printf("provisioning ws close\n");
	struct ksc_defer_get_new_uuid_args *h = udata;
	if (h && h->on_close)
		h->on_close(uuid, h->udata);
	free(h);
}

intptr_t (ksc_defer_get_new_uuid)(const char *base_url,
                                  struct ksc_defer_get_new_uuid_args ps)
{
	char *url = ksc_ckprintf("%s/v1/websocket/provisioning/", base_url);
	intptr_t r = ksc_ws_connect_raw(url,
		.on_open = NULL, /* nothing to do, server will send first request */
		.handle_request = handle_request,
		.on_ready = NULL, /* TODO: reply to request */
		.on_shutdown = NULL, /* nothing to do */
		.on_close = on_close, /* TODO: signal this method to return? */
		.udata = memdup(&ps, sizeof(ps)),
	);
	free(url);
	return r;
}
