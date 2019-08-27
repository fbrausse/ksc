/*
 * ksignal-ws.h
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifndef KSIGNAL_WS_H
#define KSIGNAL_WS_H

#include <fio.h>	/* _GNU_SOURCE */
#include <http.h>	/* ws_s */
#include <fio_tls.h>	/* fio_tls_s */

#include <stdbool.h>

#define KSIGNAL_UNKNOWN_WS_PROTOBUF_ERR	(-0x73001)

#ifndef KSC_SERVICE_HOST
# define KSC_SERVICE_HOST	"textsecure-service.whispersystems.org"
#endif

struct ksc_signal_response {
	uint32_t status;
	char *message;
	size_t n_headers;
	char **headers;
	fio_str_info_s body;
};

struct ksc_ws_send_request_args {
	uint64_t *id;
	size_t n_headers;
	char **headers;
	size_t size;
	char *body;
	/* 0: to unsubscribe, other to stay subscribed */
	int (*on_response)(ws_s *ws, struct ksc_signal_response *response,
	                   void *udata);
	void (*on_unsubscribe)(void *udata);
	void *udata;
};

int ksc_ws_send_request(ws_s *s, char *verb, char *path,
                           struct ksc_ws_send_request_args args);
#define ksc_ws_send_request(s, verb, path, ...) \
	ksc_ws_send_request((s), (verb), (path), \
	                    (struct ksc_ws_send_request_args){ __VA_ARGS__ })
int ksc_ws_send_response(ws_s *s, int status, char *message, uint64_t *id);


struct ksc_ws_connect_raw_args {
	void (*on_open)(ws_s *s, void *udata);
	void (*on_ready)(ws_s *s, void *udata);
	/* return < 0 on error, status code > 0 for sending a reply and 0 for not replying */
	int (*handle_request)(ws_s *s, char *verb, char *path, uint64_t *id,
	                      size_t n_headers, char **headers,
	                      size_t size, uint8_t *body,
	                      void *udata);
	void (*handle_response)(ws_s *s, char *message, uint32_t *status, uint64_t *id,
	                        size_t n_headers, char **headers,
	                        size_t size, uint8_t *body,
	                        void *udata);
	void (*on_shutdown)(ws_s *s, void *udata);
	void (*on_close)(intptr_t uuid, void *udata);
	struct ksc_log *log;
	const char *server_cert_path;
	void *udata;
};

fio_tls_s * ksc_signal_tls(const char *cert_path);

intptr_t ksc_ws_connect_raw(const char *url, struct ksc_ws_connect_raw_args h);
#define ksc_ws_connect_raw(url,...) \
	ksc_ws_connect_raw((url), \
	                   (struct ksc_ws_connect_raw_args){ __VA_ARGS__ })

#endif
