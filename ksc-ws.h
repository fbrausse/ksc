
#ifndef KSC_WS_H
#define KSC_WS_H

#include "json-store.h"
#include "SignalService.pb-c.h"
#include "ksignal-ws.h"

enum ksc_ws_log {
	KSC_WS_LOG_ERROR,
	KSC_WS_LOG_WARNING,
	KSC_WS_LOG_NOTICE,
	KSC_WS_LOG_INFO,
	KSC_WS_LOG_DEBUG,
};

struct ksc_ws_connect_args {
	bool (*on_content)(ws_s *, const Signalservice__Envelope *e,
	                   const Signalservice__Content *c, void *udata);
	void (*on_open)(ws_s *s, void *udata);
	void (*on_close)(intptr_t uuid, void *udata);
	void (*signal_ctx_log)(enum ksc_ws_log level, const char *message,
	                       size_t len, void *udata);
	bool on_close_do_reconnect;
	void *udata;
};

/* returns NULL on error or a pointer to the uuid on success (the uuid may
 * change when args.on_close_do_reconnect is true, however, the pointer remains
 * valid until this socket is closed). It points into an internal structure
 * which is free'd on close of this socket. Success does not mean the connection
 * has been established yet, use the .on_open callback to determine that. */
intptr_t * ksc_ws_connect(struct json_store *js, struct ksc_ws_connect_args args);
#define ksc_ws_connect(js, ...) \
	ksc_ws_connect((js), (struct ksc_ws_connect_args){ __VA_ARGS__ })

#endif
