
#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "Provisioning.pb-c.h"

static int _provisioning_handle_request(char *verb, char *path, uint64_t *id,
                                        size_t n_headers, char **headers,
                                        size_t size, uint8_t *body,
                                        void *udata)
{
	struct provisioning_sock *ps = udata;
	if (!strcmp(path, "/v1/address")) {
		Signalservice__ProvisioningUuid *uuid_msg =
			signalservice__provisioning_uuid__unpack(NULL, size, body);
		assert(uuid_msg);
		if (ps && ps->new_uuid)
			ps->new_uuid(uuid_msg->uuid, ps->udata);
		signalservice__provisioning_uuid__free_unpacked(uuid_msg, NULL);
		return 0;
		(void)id, (void)n_headers, (void)headers;
	} else {
		printf("handle_provisioning_request: cannot handle %s %s\n",
		       verb, path);
		return -1;
	}
}

static void _provisioning_on_close(intptr_t uuid, void *udata)
{
	printf("provisioning ws close\n");
	struct provisioning_sock *h = udata;
	if (h && h->on_close)
		h->on_close(uuid, h->udata);
	free(h);
}

int (ksignal_defer_get_new_uuid)(const char *base_url,
                                 struct provisioning_sock ps)
{
	char *url = ckprintf("%s/v1/websocket/provisioning/", base_url);
	int r = signal_ws_connect(url,
		.on_open = NULL, /* nothing to do, server will send first request */
		.handle_request = _provisioning_handle_request,
		.on_ready = NULL, /* TODO: reply to request */
		.on_shutdown = NULL, /* nothing to do */
		.on_close = _provisioning_on_close, /* TODO: signal this method to return? */
		.udata = memdup(&ps, sizeof(ps)),
	);
	free(url);
	return r;
}
