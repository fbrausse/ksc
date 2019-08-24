
#ifndef KSC_WS_H
#define KSC_WS_H

#include "json-store.h"
#include "SignalService.pb-c.h"
#include "ksignal-ws.h"
#include "utils.h"

struct ksc_ws_connect_service_args {
	bool (*on_content)(ws_s *, const Signalservice__Envelope *e,
	                   const Signalservice__Content *c, void *udata);
	void (*on_open)(ws_s *s, void *udata);
	void (*on_close)(intptr_t uuid, void *udata);
	struct ksc_log_context signal_log_ctx;
	struct ksc_log *log;
	const char *server_cert_path;
	bool on_close_do_reconnect;
	void *udata;
};

void ksc_print_envelope(const Signalservice__Envelope *e, int fd, bool detail);

/* returns NULL on error or a pointer to the uuid on success (the uuid may
 * change when args.on_close_do_reconnect is true, however, the pointer remains
 * valid until this socket is closed). It points into an internal structure
 * which is free'd on close of this socket. Success does not mean the connection
 * has been established yet, use the .on_open callback to determine that. */
intptr_t * ksc_ws_connect_service(struct json_store *js,
                                  struct ksc_ws_connect_service_args args);
#define ksc_ws_connect_service(js, ...) \
	ksc_ws_connect_service((js), \
	                       (struct ksc_ws_connect_service_args){ __VA_ARGS__ })

#endif
