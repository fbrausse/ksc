
#ifndef KSC_WS_H
#define KSC_WS_H

#include "json-store.h"
#include "SignalService.pb-c.h"
#include "ksignal-ws.h"

struct ksc_ws_connect_args {
	bool (*on_content)(ws_s *, const Signalservice__Envelope *e,
	                   const Signalservice__Content *c, void *udata);
	void (*on_open)(ws_s *s, void *udata);
	void (*on_close)(intptr_t uuid, void *udata);
	void *udata;
};

intptr_t ksc_ws_connect(struct json_store *js, struct ksc_ws_connect_args args);
#define ksc_ws_connect(js, ...) \
	ksc_ws_connect((js), (struct ksc_ws_connect_args){ __VA_ARGS__ })

#endif
