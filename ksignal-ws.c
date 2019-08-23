
#include "http.h"
#include "fio_tls.h"

#include "ksignal-ws.h"
#include "utils.h"
#include "WebSocketResources.pb-c.h"

#include <protobuf-c/protobuf-c.h>	/* ProtobufCMessage */

static const struct ksc_log_context log_ctx = {
	.desc = "ksignal-ws",
	.color = "33",
};

/* shortcuts */
#define LOGL_(level,log,...)	KSC_LOG_(level, log, &log_ctx, __VA_ARGS__)
#define LOGL(lvl,log,...)	KSC_LOG(lvl, log, &log_ctx, __VA_ARGS__)
#define LOG_(level,...)		LOGL_(level, h->log, __VA_ARGS__)
#define LOG(lvl,...)		LOGL(lvl, h->log, __VA_ARGS__)

const char *const KSC_BASE_URL = "wss://textsecure-service.whispersystems.org:443";

static int signal_ws_send(ws_s *s, ProtobufCMessage *request_or_response)
{
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(s);
	Signalservice__WebSocketMessage ws_msg =
		SIGNALSERVICE__WEB_SOCKET_MESSAGE__INIT;
	if (request_or_response->descriptor ==
	    &signalservice__web_socket_request_message__descriptor) {
		ws_msg.has_type = true;
		ws_msg.type = SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__REQUEST;
		ws_msg.request = (Signalservice__WebSocketRequestMessage *)request_or_response;
		if (ksc_log_prints(KSC_LOG_NOTE, h->log, &log_ctx)) {
			LOG(NOTE, "sending request ws message: %s %s",
			    ws_msg.request->verb, ws_msg.request->path);
			int fd = (h->log ? h->log : &KSC_DEFAULT_LOG)->fd;
			if (ws_msg.request->has_id)
				dprintf(fd, " (id: %lu)", ws_msg.request->id);
			dprintf(fd, "\n");
		}
	} else if (request_or_response->descriptor ==
	           &signalservice__web_socket_response_message__descriptor) {
		ws_msg.has_type = true;
		ws_msg.type = SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__RESPONSE;
		ws_msg.response = (Signalservice__WebSocketResponseMessage *)request_or_response;
		if (ksc_log_prints(KSC_LOG_NOTE, h->log, &log_ctx)) {
			LOG(NOTE, "sending response ws message: %d %s",
			    ws_msg.response->has_status ? ws_msg.response->status : -1U,
			    ws_msg.response->message);
			int fd = (h->log ? h->log : &KSC_DEFAULT_LOG)->fd;
			if (ws_msg.response->has_id)
				dprintf(fd, " (id: %lu)", ws_msg.response->id);
			dprintf(fd, "\n");
		}
	} else {
		printf("sending unknown ws message (not actually)\n");
		assert(0);
		return KSIGNAL_UNKNOWN_WS_PROTOBUF_ERR;
	}
	size_t n = signalservice__web_socket_message__get_packed_size(&ws_msg);
	fio_str_info_s si = {
		.capa = 0,
		.data = malloc(n),
	};
	si.len = signalservice__web_socket_message__pack(&ws_msg,
	                                                 (uint8_t *)si.data);
	int r = websocket_write(s, si, false);
	free(si.data);
	return r;
}

struct requested_subscription {
	int (*on_response)(ws_s *ws, struct ksc_signal_response *r,
	                   void *udata);
	void (*on_unsubscribe)(void *udata);
	subscription_s *subs;
	uint64_t id;
	ws_s *ws;
};

static void _cancel_subscription1(void *udata)
{
	struct requested_subscription *s = udata;
	fio_uuid_unlink(websocket_uuid(s->ws), s);
	fio_unsubscribe(s->subs);
}

static void _cancel_subscription2(void *udata1, void *udata2)
{
	_cancel_subscription1(udata1);
	(void)udata2;
}

static int32_t _id2filter(uint64_t id) { return id ^ (id >> 32); }

static void _on_requested_message(fio_msg_s *msg)
{
	struct requested_subscription *s = msg->udata2;
	if (msg->filter != _id2filter(s->id)) {
		KSC_DEBUG(WARN, "_on_requested_message: ids don't match "
		        "(coincidence?): _id2filter(s->id): %u, msg->filter: %u\n",
		        _id2filter(s->id), msg->filter);
		return;
	}
	struct fio_str_info_s *m = &msg->msg;
	Signalservice__WebSocketResponseMessage *resp;
	resp = signalservice__web_socket_response_message__unpack(NULL, m->len,
	                                                          (uint8_t *)m->data);
	assert(resp);
	struct ksc_signal_response r = {
		.status = resp->has_status ? resp->status : ~0U,
		.message = resp->message,
		.body = {
			.len = resp->has_body ? resp->body.len : 0,
			.data = resp->has_body ? (char *)resp->body.data : NULL
		},
		.n_headers = resp->n_headers,
		.headers = resp->headers,
	};
	if (!s->on_response(s->ws, &r, msg->udata1))
		fio_defer(_cancel_subscription2, s, NULL);
	signalservice__web_socket_response_message__free_unpacked(resp, NULL);
}

static void _on_requested_unsubscribe(void *udata1, void *udata2)
{
	struct requested_subscription *s = udata2;
	if (s->on_unsubscribe)
		s->on_unsubscribe(udata1);
	free(s);
}

int (ksc_ws_send_request)(ws_s *s, char *verb, char *path,
                          struct ksc_ws_send_request_args args)
{
	struct requested_subscription *p = NULL;
	uint64_t ptr;
	if (args.on_response) {
		p = malloc(sizeof(struct requested_subscription));
		if (!args.id) {
			struct timeval tv;
			gettimeofday(&tv, NULL);
			ptr = (uintptr_t)p ^ ((uintptr_t)tv.tv_sec << 20 | tv.tv_usec);
			args.id = &ptr;
		}
	}
	Signalservice__WebSocketRequestMessage req =
		SIGNALSERVICE__WEB_SOCKET_REQUEST_MESSAGE__INIT;
	req.verb = verb;
	req.path = path;
	req.has_id = args.id ? true : false;
	if (req.has_id)
		req.id = *args.id;
	req.has_body = args.size && args.body;
	if (req.has_body) {
		req.body.len = args.size;
		req.body.data = (uint8_t *)args.body;
	}
	if (p) {
		p->on_response = args.on_response;
		p->on_unsubscribe = args.on_unsubscribe;
		p->id = req.id;
		p->ws = s;
		p->subs = fio_subscribe(.filter = _id2filter(req.id),
		                        .udata1 = args.udata, .udata2 = p,
		                        .on_message = _on_requested_message,
		                        .on_unsubscribe = _on_requested_unsubscribe);
		fio_uuid_link(websocket_uuid(s), p, _cancel_subscription1);
	}
	req.n_headers = args.n_headers;
	req.headers = args.headers;
	return signal_ws_send(s, &req.base);
}

int ksc_ws_send_response(ws_s *s, int status, char *message, uint64_t *id)
{
	Signalservice__WebSocketResponseMessage res =
		SIGNALSERVICE__WEB_SOCKET_RESPONSE_MESSAGE__INIT;
	if (id) {
		res.has_id = true;
		res.id = *id;
	}
	res.has_status = true;
	res.status = status;
	res.message = message;
	return signal_ws_send(s, &res.base);
}

static void _on_ws_request(ws_s *s,
                           Signalservice__WebSocketRequestMessage *request,
                           struct ksc_ws_connect_raw_args *h)
{
	if (ksc_log_prints(KSC_LOG_NOTE, h->log, &log_ctx)) {
		LOG(NOTE, "ws request: %s %s\n", request->verb, request->path);
		int fd = (h->log ? h->log : &KSC_DEFAULT_LOG)->fd;
		for (size_t i=0; i<request->n_headers; i++)
			dprintf(fd, "  header: %s\n", request->headers[i]);
		if (request->has_id)
			dprintf(fd, "  id: %lu\n", request->id);
		if (request->has_body)
			dprintf(fd, "  body size: %lu\n", request->body.len);
	}
	int r = 0;
	if (h && h->handle_request)
		r = h->handle_request(s, request->verb, request->path,
		                      request->has_id ? &request->id : NULL,
		                      request->n_headers, request->headers,
		                      request->has_body ? request->body.len : 0,
		                      request->has_body ? request->body.data : NULL,
		                      h->udata);
	if (r > 0)
		ksc_ws_send_response(s, 200, "OK",
		                     request->has_id ? &request->id : NULL);
	else if (r < 0)
		ksc_ws_send_response(s, 400, "Unknown",
		                     request->has_id ? &request->id : NULL);
}

static void _on_ws_response(ws_s *s,
                            Signalservice__WebSocketResponseMessage *response,
                            struct ksc_ws_connect_raw_args *h, char *scratch)
{
	if (ksc_log_prints(KSC_LOG_NOTE, h->log, &log_ctx)) {
		LOG(NOTE, "ws response, status: ");
		int fd = (h->log ? h->log : &KSC_DEFAULT_LOG)->fd;
		if (response->has_status)
			dprintf(fd, "%u ", response->status);
		dprintf(fd, "%s\n", response->message);
		for (size_t i=0; i<response->n_headers; i++)
			dprintf(fd, "%s\n", response->headers[i]);
		if (response->has_id)
			dprintf(fd, "  id: %lu\n", response->id);
		if (response->has_body)
			dprintf(fd, "  body size: %lu\n", response->body.len);
	}
	if (response->has_id) {
		/* TODO: inefficient repacking of unpacked protobuf */
		size_t sz = signalservice__web_socket_response_message__pack(response, (uint8_t *)scratch);
		fio_publish(
			.message = { .data = scratch, .len = sz },
			.filter = _id2filter(response->id)
		);
	}
	if (h && h->handle_response)
		h->handle_response(s, response->message,
		                   response->has_status ? &response->status : NULL,
		                   response->has_id     ? &response->id : NULL,
		                   response->n_headers, response->headers,
		                   response->has_body   ?  response->body.len : 0,
		                   response->has_body   ?  response->body.data : NULL,
		                   h->udata);
}

static void _signal_ws_on_message(ws_s *ws, fio_str_info_s msg, uint8_t is_text)
{
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(ws);
	LOG(DEBUG, "ws received %s message of length %zu\n",
	    is_text ? "text" : "binary", msg.len);
	Signalservice__WebSocketMessage *ws_msg =
		signalservice__web_socket_message__unpack(NULL, msg.len,
		                                          (uint8_t *)msg.data);
	LOG(DEBUG, "%p\n", (void *)ws_msg);
	assert(ws_msg->has_type);
	switch (ws_msg->type) {
	case SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__REQUEST:
		assert(ws_msg->request);
		_on_ws_request(ws, ws_msg->request, h);
		break;
	case SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__RESPONSE:
		assert(ws_msg->response);
		_on_ws_response(ws, ws_msg->response, h, msg.data);
		break;
	default:
		printf("unknown ws_msg->type: %d\n", ws_msg->type);
		abort();
	}
	signalservice__web_socket_message__free_unpacked(ws_msg, NULL);
}

#define KEEPALIVE_TIMEOUT	55	/* seconds */

static void _signal_ws_keepalive(void *udata);

static void _signal_ws_run_timed_keepalive(ws_s *s)
{
	int r = fio_run_every(KEEPALIVE_TIMEOUT * 1000, 1,
	                      _signal_ws_keepalive, s, NULL);
	assert(r != -1);
}

static int _signal_ws_keepalive_on_response(ws_s *s,
                                            struct ksc_signal_response *r,
                                            void *udata)
{
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(s);
	if (200 <= r->status && r->status < 300)
		_signal_ws_run_timed_keepalive(s);
	else
		LOG(ERROR, "keep-alive request failed with status %u %s\n",
		    r->status, r->message);
	return 0;
	(void)udata;
}

static void _signal_ws_keepalive(void *udata)
{
	ws_s *s = udata;
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(s);
	if (!h)
		return;
	LOG(DEBUG, "sending keep-alive\n");
	int r = ksc_ws_send_request(s, "GET", "/v1/keepalive",
	                            .on_response = _signal_ws_keepalive_on_response);
	if (r == -1)
		LOG(ERROR, "sending keep-alive failed\n");
}

static void _signal_ws_on_open(ws_s *s)
{
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(s);
	LOG(DEBUG, "signal_ws_open\n");
	_signal_ws_run_timed_keepalive(s);
	if (h && h->on_open)
		h->on_open(s, h->udata);
}

static void _signal_ws_on_shutdown(ws_s *s)
{
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(s);
	LOG(DEBUG, "signal_ws_shutdown\n");
	if (h && h->on_shutdown)
		h->on_shutdown(s, h->udata);
}

static void _signal_ws_on_ready(ws_s *s)
{
	struct ksc_ws_connect_raw_args *h = websocket_udata_get(s);
	LOG(DEBUG, "signal_ws_ready\n");
	if (h && h->on_ready)
		h->on_ready(s, h->udata);
}

static void _signal_ws_on_close(intptr_t uuid, void *udata)
{
	struct ksc_ws_connect_raw_args *h = udata;
	LOG(NOTE, "signal ws socket closed\n");
	if (h && h->on_close)
		h->on_close(uuid, h->udata);
	free(h);
}

static void _on_websocket_http_connected(http_s *h) {
  websocket_settings_s *s = h->udata;
  struct ksc_ws_connect_raw_args *hh = s->udata;
  LOGL(DEBUG, hh->log, "on_websocket_http_connected\n");
  h->udata = http_settings(h)->udata = NULL;
  if (!h->path) {
    LOGL(DEBUG, hh->log, "(websocket client) path not specified in "
                         "address, assuming root!");
    h->path = fiobj_str_new("/", 1);
  }
#ifdef SIGNAL_USER_AGENT
  fio_hash_set(h->headers, fiobj_str_new("X-Signal-Agent: " SIGNAL_USER_AGENT,
                                         sizeof("X-Signal-Agent: " SIGNAL_USER_AGENT)-1));
#endif
  int r = (http_upgrade2ws)(h, *s);
  LOGL(DEBUG, hh->log, "http_upgrade2ws: %d\n", r);
  free(s);
}

static void _on_websocket_http_connection_finished(http_settings_s *settings) {
  websocket_settings_s *s = settings->udata;
  if (s) {
    struct ksc_ws_connect_raw_args *hh = s->udata;
    LOGL(DEBUG, hh->log, "on_websocket_http_connection_finished\n");
    if (s->on_close)
      s->on_close(0, s->udata);
    free(s);
  } else {
    /*KSC_DEBUG(DEBUG, "on_websocket_http_connection_finished\n")*/;
  }
}

static fio_tls_s * signal_tls(const char *cert_path)
{
	// fio_tls_s *tls = fio_tls_new("textsecure-service.whispersystems.org", NULL, NULL, NULL);
	fio_tls_s *tls = fio_tls_new(NULL, NULL, NULL, NULL);
	assert(tls);
	assert((intptr_t)tls != -1);
	fio_tls_trust(tls, cert_path);
	return tls;
}

#ifdef KSIGNAL_SERVER_CERT
intptr_t (ksc_ws_connect_raw)(const char *url, struct ksc_ws_connect_raw_args h)
{
	LOGL(NOTE, h.log, "signal ws connect to %s\n", url);
	websocket_settings_s *ws_settings = malloc(sizeof(websocket_settings_s));
	*ws_settings = (websocket_settings_s){
		.on_open     = _signal_ws_on_open,
		.on_message  = _signal_ws_on_message,
		.on_ready    = _signal_ws_on_ready,
		.on_shutdown = _signal_ws_on_shutdown,
		.on_close    = _signal_ws_on_close,
		.udata       = memdup(&h, sizeof(h)),
	};
	fio_tls_s *tls = signal_tls((KSIGNAL_SERVER_CERT));
	intptr_t r = http_connect(url, NULL,
	                     .on_request = _on_websocket_http_connected,
	                     .on_response = _on_websocket_http_connected,
	                     .on_finish = _on_websocket_http_connection_finished,
	                     .udata = ws_settings, .tls = tls);
	fio_tls_destroy(tls);
	return r;
}
#else
# error KSIGNAL_SERVER_CERT not defined (path of pinned server certificate)
#endif
