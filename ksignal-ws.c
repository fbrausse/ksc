
#include "http.h"
#include "fio_tls.h"

#include "ksignal-ws.h"
#include "WebSocketResources.pb-c.h"

#include <protobuf-c/protobuf-c.h>	/* ProtobufCMessage */

static int signal_ws_send(ws_s *s, ProtobufCMessage *request_or_response)
{
	Signalservice__WebSocketMessage ws_msg =
		SIGNALSERVICE__WEB_SOCKET_MESSAGE__INIT;
	if (request_or_response->descriptor ==
	    &signalservice__web_socket_request_message__descriptor) {
		ws_msg.has_type = true;
		ws_msg.type = SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__REQUEST;
		ws_msg.request = (Signalservice__WebSocketRequestMessage *)request_or_response;
		printf("sending request ws message: %s %s\n",
		       ws_msg.request->verb, ws_msg.request->path);
	} else if (request_or_response->descriptor ==
	           &signalservice__web_socket_response_message__descriptor) {
		ws_msg.has_type = true;
		ws_msg.type = SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__REQUEST;
		ws_msg.response = (Signalservice__WebSocketResponseMessage *)request_or_response;
		printf("sending response ws message: %d %s\n",
		       ws_msg.response->has_status ? ws_msg.response->status : -1,
		       ws_msg.response->message);
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
	int (*on_response)(fio_str_info_s *msg, void *udata);
	void (*on_unsubscribe)(void *udata);
	subscription_s *subs;
	uint64_t id;
	intptr_t uuid;
};

static void _cancel_subscription1(void *udata)
{
	struct requested_subscription *s = udata;
	fio_uuid_unlink(s->uuid, s);
	fio_unsubscribe(s->subs);
}

static void _cancel_subscription2(void *udata1, void *udata2)
{
	_cancel_subscription1(udata1);
}

static int32_t _id2filter(uint64_t id) { return id ^ (id >> 32); }

static void _on_requested_message(fio_msg_s *msg)
{
	struct requested_subscription *s = msg->udata2;
	if (msg->filter != _id2filter(s->id))
		fprintf(stderr, "_on_requested_message: ids don't match "
		        "(coincidence?): _id2filter(s->id): %u, msg->filter: %u\n",
		        _id2filter(s->id), msg->filter);
	else if (!s->on_response(&msg->msg, msg->udata1))
		fio_defer(_cancel_subscription2, s, NULL);
}

static void _on_requested_unsubscribe(void *udata1, void *udata2)
{
	struct requested_subscription *s = udata2;
	if (s->on_unsubscribe)
		s->on_unsubscribe(udata1);
	free(s);
}

int (signal_ws_send_request)(ws_s *s, char *verb, char *path,
                             struct _signal_ws_send_request args)
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
		p->uuid = websocket_uuid(s);
		p->subs = fio_subscribe(.filter = (int32_t)(req.id ^ (req.id >> 32)),
		                        .udata1 = args.udata, .udata2 = p,
		                        .on_message = _on_requested_message,
		                        .on_unsubscribe = _on_requested_unsubscribe);
		fio_uuid_link(p->uuid, p, _cancel_subscription1);
	}
	req.n_headers = args.n_headers;
	req.headers = args.headers;
	return signal_ws_send(s, &req.base);
}

int signal_ws_send_response(ws_s *s, int status, char *message, uint64_t *id)
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
                           struct signal_ws_handler *h)
{
	printf("ws request: %s %s\n", request->verb, request->path);
	for (size_t i=0; i<request->n_headers; i++)
		printf("%s\n", request->headers[i]);
	if (request->has_id)
		printf("  id: %lu\n", request->id);
	if (request->has_body)
		printf("  body size: %lu\n", request->body.len);
	int r = 0;
	if (h && h->handle_request)
		r = h->handle_request(request->verb, request->path,
		                      request->has_id ? &request->id : NULL,
		                      request->n_headers, request->headers,
		                      request->has_body ? request->body.len : 0,
		                      request->has_body ? request->body.data : NULL,
		                      h->udata);
	assert(r >= 0);
	if (r > 0)
		signal_ws_send_response(s, 200, "OK",
		                        request->has_id ? &request->id : NULL);
}

static void _on_ws_response(Signalservice__WebSocketResponseMessage *response,
                            struct signal_ws_handler *h)
{
	printf("ws response, status: ");
	if (response->has_status)
		printf("%u ", response->status);
	printf("%s\n", response->message);
	for (size_t i=0; i<response->n_headers; i++)
		printf("%s\n", response->headers[i]);
	if (response->has_id)
		printf("  id: %lu\n", response->id);
	if (response->has_body)
		printf("  body size: %lu\n", response->body.len);
	if (response->has_id && response->has_body) {
		fio_publish(
			.message = { .data = (char *)response->body.data,
			             .len = response->body.len },
			.is_json = true,
			.filter = _id2filter(response->id)
		);
	}
	if (h && h->handle_response)
		h->handle_response(response->message,
		                   response->has_status ? &response->status : NULL,
		                   response->has_id     ? &response->id : NULL,
		                   response->n_headers, response->headers,
		                   response->has_body   ?  response->body.len : 0,
		                   response->has_body   ?  response->body.data : NULL,
		                   h->udata);
}

static void _signal_ws_on_message(ws_s *ws, fio_str_info_s msg, uint8_t is_text)
{
	printf("ws received %s message of length %zu\n",
	       is_text ? "text" : "binary", msg.len);
	Signalservice__WebSocketMessage *ws_msg =
		signalservice__web_socket_message__unpack(NULL, msg.len,
		                                          (uint8_t *)msg.data);
	printf("%p\n", (void *)ws_msg);
	assert(ws_msg->has_type);
	switch (ws_msg->type) {
	case SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__REQUEST:
		assert(ws_msg->request);
		_on_ws_request(ws, ws_msg->request, websocket_udata_get(ws));
		break;
	case SIGNALSERVICE__WEB_SOCKET_MESSAGE__TYPE__RESPONSE:
		assert(ws_msg->response);
		_on_ws_response(ws_msg->response, websocket_udata_get(ws));
		break;
	default:
		printf("unknown ws_msg->type: %d\n", ws_msg->type);
		abort();
	}
	signalservice__web_socket_message__free_unpacked(ws_msg, NULL);
}

#define KEEPALIVE_TIMEOUT	55	/* seconds */

static void _signal_ws_keepalive(void *udata)
{
	ws_s *s = udata;
	printf("sending keep-alive\n");
	int r = signal_ws_send_request(s, "PUT", "/v1/keepalive");
	if (r != -1) {
		r = fio_run_every(KEEPALIVE_TIMEOUT * 1000, 1,
		                  _signal_ws_keepalive, s, NULL);
		assert(r != -1);
	} else
		printf("sending keep-alive failed\n");
}

static void _signal_ws_on_open(ws_s *s)
{
	printf("signal_ws_open\n");
	int r = fio_run_every(KEEPALIVE_TIMEOUT * 1000, 1, _signal_ws_keepalive,
	                      s, NULL);
	assert(r != -1);
	struct signal_ws_handler *h = websocket_udata_get(s);
	if (h && h->on_open)
		h->on_open(s, h->udata);
}

static void _signal_ws_on_shutdown(ws_s *s)
{
	printf("signal_ws_shutdown\n");
	struct signal_ws_handler *h = websocket_udata_get(s);
	if (h && h->on_shutdown)
		h->on_shutdown(s, h->udata);
}

static void _signal_ws_on_ready(ws_s *s)
{
	printf("signal_ws_ready\n");
	struct signal_ws_handler *h = websocket_udata_get(s);
	if (h && h->on_ready)
		h->on_ready(s, h->udata);
}

static void _signal_ws_on_close(intptr_t uuid, void *udata)
{
	printf("signal_ws_close\n");
	struct signal_ws_handler *h = udata;
	if (h && h->on_close)
		h->on_close(uuid, h->udata);
	free(h);
}

static void _on_websocket_http_connected(http_s *h) {
  websocket_settings_s *s = h->udata;
  fprintf(stderr, "on_websocket_http_connected\n");
  h->udata = http_settings(h)->udata = NULL;
  if (!h->path) {
    fprintf(stderr, "(websocket client) path not specified in "
                    "address, assuming root!");
    h->path = fiobj_str_new("/", 1);
  }
  int r = (http_upgrade2ws)(h, *s);
  fprintf(stderr, "http_upgrade2ws: %d\n", r);
  free(s);
}

static void _on_websocket_http_connection_finished(http_settings_s *settings) {
  websocket_settings_s *s = settings->udata;
  fprintf(stderr, "on_websocket_http_connection_finished\n");
  if (s) {
    if (s->on_close)
      s->on_close(0, s->udata);
    free(s);
  }
}

fio_tls_s * signal_tls(const char *cert_path)
{
	// fio_tls_s *tls = fio_tls_new("textsecure-service.whispersystems.org", NULL, NULL, NULL);
	fio_tls_s *tls = fio_tls_new(NULL, NULL, NULL, NULL);
	assert(tls);
	assert((intptr_t)tls != -1);
	fio_tls_trust(tls, cert_path);
	return tls;
}

int (signal_ws_connect)(const char *url, struct signal_ws_handler h)
{
	printf("signal ws connect to %s\n", url);
	websocket_settings_s *ws_settings = malloc(sizeof(websocket_settings_s));
	*ws_settings = (websocket_settings_s){
		.on_open     = _signal_ws_on_open,
		.on_message  = _signal_ws_on_message,
		.on_ready    = _signal_ws_on_ready,
		.on_shutdown = _signal_ws_on_shutdown,
		.on_close    = _signal_ws_on_close,
		.udata       = memdup(&h, sizeof(h)),
	};
	fio_tls_s *tls = signal_tls("../whisper.store.asn1");
	int r = http_connect(url, NULL,
	                     .on_request = _on_websocket_http_connected,
	                     .on_response = _on_websocket_http_connected,
	                     .on_finish = _on_websocket_http_connection_finished,
	                     .udata = ws_settings, .tls = tls);
	fio_tls_destroy(tls);
	return r;
}
