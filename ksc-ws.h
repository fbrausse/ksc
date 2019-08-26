/*
 * ksc-ws.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef KSC_WS_H
#define KSC_WS_H

#include "json-store.h"
#include "SignalService.pb-c.h"
#include "ksignal-ws.h"
#include "utils.h"

struct ksc_ws;

/* returns the UUID of the connection's socket */
intptr_t ksc_ws_get_uuid(const struct ksc_ws *kws);
void * ksc_ws_get_udata(const struct ksc_ws *kws);

struct ksc_ws_send_message_args {
	const char *body;
	/*
	bool end_session;*/
	/*
	const void *const *attachments;
	size_t n_attachments;*/

	/* 0: to unsubscribe, other to stay subscribed */
	int (*on_response)(ws_s *ws, struct ksc_signal_response *response,
	                   void *udata);
	void *udata;
};

struct ksc_send_message_target {
	// bool is_group;
	union {
		const char *name;/*
		struct {
			const void *group_id;
			size_t group_id_size;
		};*/
	};
};

int ksc_ws_send_message(ws_s *ws, const struct ksc_ws *kws,
                        const struct ksc_send_message_target *target,
                        struct ksc_ws_send_message_args args);
#define ksc_ws_send_message(ws, kws, target, ...) \
	ksc_ws_send_message(ws, kws, target, \
	                    (struct ksc_ws_send_message_args){ __VA_ARGS__ });

struct ksc_ws_connect_service_args {
	bool (*on_receipt)(ws_s *, const struct ksc_ws *,
	                   const Signalservice__Envelope *e);
	bool (*on_content)(ws_s *, const struct ksc_ws *,
	                   const Signalservice__Envelope *e,
	                   const Signalservice__Content *c);
	void (*on_open)(ws_s *, const struct ksc_ws *);
	void (*on_close)(intptr_t uuid, void *udata);
	struct ksc_log_context signal_log_ctx;
	struct ksc_log *log;
	const char *server_cert_path;
	bool on_close_do_reconnect;
	void *udata;
};

void ksc_print_envelope(const Signalservice__Envelope *e, int fd, bool detail);

/* returns NULL on error or a pointer to the ksc websocket on success. ksc_ws
 * provides access to the underlying socket's uuid, which may change when
 * args.on_close_do_reconnect is true, however, the pointer to the ksc webscoket
 * remains valid until this socket is closed. It is free'd on close of this
 * socket. Success does not mean the connection has been established yet, use
 * the .on_open callback to determine that. */
const struct ksc_ws * ksc_ws_connect_service(struct json_store *js,
                                             struct ksc_ws_connect_service_args args);
#define ksc_ws_connect_service(js, ...) \
	ksc_ws_connect_service((js), \
	                       (struct ksc_ws_connect_service_args){ __VA_ARGS__ })

#endif
