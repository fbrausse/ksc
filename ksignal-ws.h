
#ifndef KSIGNAL_WS_H
#define KSIGNAL_WS_H

#include <fio.h>	/* _GNU_SOURCE */
#include <http.h>	/* ws_s */
#include <fio_tls.h>	/* fio_tls_s */

#include <stdbool.h>

#define KSIGNAL_UNKNOWN_WS_PROTOBUF_ERR	(-0x73001)

extern const char BASE_URL[];

struct signal_ws_handler {
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
	void *udata;
};

struct signal_response {
	uint32_t status;
	char *message;
	size_t n_headers;
	char **headers;
	fio_str_info_s body;
};

struct _signal_ws_send_request {
	uint64_t *id;
	size_t n_headers;
	char **headers;
	size_t size;
	char *body;
	/* 0: to unsubscribe, other to stay subscribed */
	int (*on_response)(ws_s *ws, struct signal_response *response, void *udata);
	void (*on_unsubscribe)(void *udata);
	void *udata;
};

int signal_ws_send_request(ws_s *s, char *verb, char *path,
                           struct _signal_ws_send_request args);
#define signal_ws_send_request(s, verb, path, ...) \
	signal_ws_send_request((s), (verb), (path), \
	                       (struct _signal_ws_send_request){ __VA_ARGS__ })
int signal_ws_send_response(ws_s *s, int status, char *message, uint64_t *id);

intptr_t signal_ws_connect(const char *url, struct signal_ws_handler h);
#define signal_ws_connect(url,...) \
	signal_ws_connect((url), (struct signal_ws_handler){ __VA_ARGS__ })

fio_tls_s * signal_tls(const char *cert_path);

#endif
