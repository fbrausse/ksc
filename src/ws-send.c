/*
 * ws-send.c
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#include "utils.h"
#include "ksignal-ws.h"
#include "ksc-ws.h"
#include "crypto.h"

#include <signal/protocol.h>
#include <signal/session_cipher.h>
#include <signal/session_builder.h>

static const struct ksc_log_context log_ctx = {
	.desc = "ws-send",
	.color = "35",
};

/* shortcuts */
#define LOGL_(level,log,...)	KSC_LOG_(level, log, &log_ctx, __VA_ARGS__)
#define LOGL(lvl,log,...)	KSC_LOG(lvl, log, &log_ctx, __VA_ARGS__)
#define LOG_(level,...)		LOGL_(level, ksc->args.log, __VA_ARGS__)
#define LOG(lvl,...)		LOGL(lvl, ksc->args.log, __VA_ARGS__)
#define LOGr(r,...)		LOG_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, __VA_ARGS__)

#include "ksc-ws-private.h"

/* Sends a Content message via PUT /v1/messages/NUMBER */
static int send_message(ws_s *ws, struct ksc_ws *ksc, const char *recipient,
                        const Signalservice__Content *content_message,
                        uint64_t timestamp,
                        struct ksc_ws_send_message_args args);

/* Sends a Sync message to the local address (ksc->js's username) via
 * send_message() */
static int send_sync_message(ws_s *ws, struct ksc_ws *ksc,
                             Signalservice__SyncMessage *sync,
                             struct ksc_ws_send_message_args args)
{
	Signalservice__Content content = SIGNALSERVICE__CONTENT__INIT;
	content.syncmessage = sync;

	const char *local_name = json_store_get_username(ksc->js);
	assert(local_name);

	uint64_t timestamp;
	if (sync->sent && sync->sent->has_timestamp)
		timestamp = sync->sent->timestamp;
	else {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		timestamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	}

	return send_message(ws, ksc, local_name, &content, timestamp, args);
}

/* --------------------------------------------------------------------------
 * Send a sync-request message. Purpose not clear, yet.
 * -------------------------------------------------------------------------- */

struct sync_request_data {
	struct ksc_ws *ksc;
	Signalservice__SyncMessage__Request__Type type;
	void (*handler)(struct ksc_signal_response *response,
	                Signalservice__SyncMessage__Request__Type type,
	                unsigned result, void *udata);
	void *udata;
};

static void on_sync_request_response(const struct ksc_service_address *myself,
                                     struct ksc_signal_response *response,
                                     unsigned result, void *udata)
{
	struct sync_request_data *data = udata;
	struct ksc_ws *ksc = data->ksc;
	LOG(DEBUG, "on_sync_request_response %p, result: 0x%02x\n", data, result);
	if (response) {
		int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
		dprintf(fd, "  response: %d %s\n", response->status,
		        response->message);
		for (size_t i=0; i<response->n_headers; i++)
			dprintf(fd, "  header: %s\n", response->headers[i]);
		dprintf(fd, "  body: %.*s\n", (int)response->body.len,
		        response->body.data);
	}
	if (data->handler)
		data->handler(response, data->type, result, data->udata);
	free(data);
	(void)myself;
}

int ksc_ws_sync_request(ws_s *ws, struct ksc_ws *ksc,
                        Signalservice__SyncMessage__Request__Type type,
                        void (*handler)(struct ksc_signal_response *response,
                                        Signalservice__SyncMessage__Request__Type type,
                                        unsigned result, void *udata),
                        void *udata)
{
	Signalservice__SyncMessage__Request request =
		SIGNALSERVICE__SYNC_MESSAGE__REQUEST__INIT;
	request.type = type;

	Signalservice__SyncMessage sync =
		SIGNALSERVICE__SYNC_MESSAGE__INIT;
	sync.request = &request;

	struct sync_request_data *data;
	data = ksc_malloc(sizeof(*data)); /* TODO: data gets free'd by send_message()? */
	data->ksc = ksc; /* ksc gets REF'ed by send_message() */
	data->type = type;
	data->handler = handler;
	data->udata = udata;

	struct ksc_ws_send_message_args args = {
		NULL, false, on_sync_request_response, data,
	};
	return send_sync_message(ws, ksc, &sync, args);
}

/* --------------------------------------------------------------------------
 * FIOBJ hash helper.
 * -------------------------------------------------------------------------- */

static FIOBJ get(FIOBJ v, const char *key, size_t len)
{
	FIOBJ k = fiobj_str_new(key, len);
	FIOBJ r = fiobj_hash_get(v, k);
	fiobj_free(k);
	return r;
}

#define GET(v, cstr)	get(v, cstr, sizeof(cstr)-1)

/* --------------------------------------------------------------------------
 * Handle a message-send response message
 * (the server reply to PUT /v1/messages/NUMBER).
 *
 * The server replies with a `needs_sync` information, there also is
 * `needs_sync` info from the setup stage of sending the PUT /v1/messages/NUMBER
 * message. If any `needs_sync` holds, proceed by sending a sync-transcript
 * (to ourself, in order to notify our other devices of the message we just
 * sent). This should only apply to data-messages. No other behaviour from the
 * server has been observed. A sync-transcript is a sync-sent message containing
 * a content-data-message, thus the original protobuf-encoded Content is kept
 * around until either of the following events occur:
 * - on_response
 * - unsubscribe
 * - timeout
 *
 * Finally, call the user's callback with the response and status obtained.
 * -------------------------------------------------------------------------- */

struct send_message_data2 {
	ws_s *ws;
	uint64_t timestamp;
	struct ksc_ws_send_message_args args;
	uint8_t *content;
	size_t content_padded_sz;
	size_t content_sz;
	bool may_need_sync;
};

struct send_message_data {
	REF_COUNTED;
	struct ksc_ws *ksc;
	struct ksc_service_address recipient;

	union {
		struct {
			uint8_t ok : 1;
			uint8_t needs_sync : 1;
			uint8_t sync_sent : 1;
			uint8_t timeout : 1;
			uint8_t cb_called : 1;
			uint8_t unhandled : 1;
		} result;
		uint8_t result_u8;
	};

	struct send_message_data2 data2;
	bool is_recipient_udpate;
};

static void send_message_data_unref(struct send_message_data *data)
{
	if (UNREF(data))
		return;
	ksc_free(data->data2.content);
	ksc_free(data->recipient.relay);
	ksc_free(data->recipient.name);
	ksignal_ctx_unref(data->ksc);
	ksc_free(data);
}

static void
on_sent_sync_transcript_result(const struct ksc_service_address *recipient,
                               struct ksc_signal_response *response,
                               unsigned result, void *udata)
{
	KSC_DEBUG(INFO, "on_sent_sync_transcript_result: 0x%02x\n", result);
	(void)recipient;
	(void)response;
	(void)udata;
}

static int send_sync_transcript(struct send_message_data *d)
{
	struct ksc_ws *ksc = d->ksc;

	Signalservice__Content *content;
	content = signalservice__content__unpack(NULL, d->data2.content_sz,
	                                         d->data2.content);
	assert(content);

	if (!content->datamessage) {
		LOG(ERROR, "refusing to send sync transcript for content "
		           "without a data message sent to %.*s\n",
		           (int)d->recipient.name_len, d->recipient.name);
		return -1;
	}

	assert(content->datamessage);

	Signalservice__DataMessage data = *content->datamessage;

	Signalservice__SyncMessage__Sent sent = SIGNALSERVICE__SYNC_MESSAGE__SENT__INIT;
	sent.destination = d->recipient.name;
	sent.has_timestamp = true;
	sent.timestamp = d->data2.timestamp;
	sent.message = &data;
	if (data.has_expiretimer && data.expiretimer > 0) {
		sent.has_expirationstarttimestamp = true;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		sent.expirationstarttimestamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	}
	if (data.has_messagetimer && data.messagetimer > 0)
		data.attachments = NULL;
	sent.isrecipientupdate = d->is_recipient_udpate;

	Signalservice__SyncMessage sync = SIGNALSERVICE__SYNC_MESSAGE__INIT;
	sync.sent = &sent;

	struct ksc_ws_send_message_args args = {
		NULL, false, on_sent_sync_transcript_result, NULL,
	};
	int r = send_sync_message(d->data2.ws, ksc, &sync, args);

	signalservice__content__free_unpacked(content, NULL);

	return r;
}

static void handle_send_message_result(struct ksc_signal_response *response,
                                       struct send_message_data *data)
{
	if (data->result.needs_sync && !data->result.sync_sent) {
		int r = send_sync_transcript(data);
		if (!r)
			data->result.sync_sent = true;
	}

	if (!data->result.cb_called && data->data2.args.on_result) {
		unsigned res = 0;
		if (data->result.ok) res |= KSC_SEND_MESSAGE_RESULT_OK;
		if (data->result.needs_sync) res |= KSC_SEND_MESSAGE_RESULT_NEEDS_SYNC;
		if (data->result.sync_sent) res |= KSC_SEND_MESSAGE_RESULT_SYNC_SENT;
		if (data->result.timeout) res |= KSC_SEND_MESSAGE_RESULT_TIMEOUT;
		if (data->result.unhandled) res |= KSC_SEND_MESSAGE_RESULT_UNHANDLED;
		data->data2.args.on_result(&data->recipient, response, res,
		                           data->data2.args.udata);
	}
	data->result.cb_called = true;
}

static void on_send_message_response_timeout(void *udata)
{
	struct send_message_data *data = udata;
	struct ksc_ws *ksc = data->ksc;
	LOG(NOTE, "send message response timeout for recipient %.*s, result: %02x\n",
	    (int)data->recipient.name_len, data->recipient.name, data->result_u8);
	data->result.timeout = true;
	handle_send_message_result(NULL, data);
	send_message_data_unref(data);
}

#if 0 /* TODO: handle */
[note ] ksignal-ws: ws response, status: 409 Conflict (id: 1548988872866205)
  body size: 40
[note ] ksc-ws: message send response: 409 Conflict: {"missingDevices":[],"extraDevices":[2]}
#endif

/* 0: to unsubscribe, other to stay subscribed */
static int on_send_message_response(ws_s *ws,
                                    struct ksc_signal_response *response,
                                    void *udata)
{
	struct send_message_data *data = udata;
	struct ksc_ws *ksc = data->ksc;
	FIOBJ body = fiobj_null();
	LOG(NOTE, "message send response: %u %s: %.*s\n",
	    response->status, response->message,
	    (int)response->body.len, response->body.data);
	if (ksc_log_prints(KSC_LOG_DEBUG, ksc->args.log, &log_ctx)) {
		int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
		for (size_t i=0; i<response->n_headers; i++)
			dprintf(fd, "  header: %s\n", response->headers[i]);
	}
	ssize_t r = 0;
	if (response->status < 200 || 300 <= response->status) {
		LOG(ERROR, "send-message failed with status %u %s\n",
		    response->status, response->message);
		goto done;
	}
	if (!response->body.len) {
		LOG(WARN, "send-message-response does not contain a body\n");
		goto done;
	}
	r = fiobj_json2obj(&body, response->body.data, response->body.len);
	if (!r || (size_t)r < response->body.len) {
		LOG_(r ? KSC_LOG_WARN : KSC_LOG_ERROR,
		     "send-message-response: didn't parse entire body, just "
		     "%zd of %zu bytes\n", r, response->body.len);
	}
	if (!r) {
		r = -1;
		goto done;
	}
	FIOBJ needs_sync = GET(body, "needsSync");
	r = fiobj_type_is(needs_sync, FIOBJ_T_TRUE) ? 1
	  : fiobj_type_is(needs_sync, FIOBJ_T_FALSE) ? 0
	  : -1;
	if (r < 0) {
		LOG(ERROR, "send-message-response: 'needsSync' JSON entry is "
		    "not of boolean type; value: %s\n",
		    fiobj_obj2cstr(needs_sync).data);
		goto done;
	}
	LOG(DEBUG, "send-message-response needs sync: %d\n", !!r);
	data->result.ok = true;
	if (r)
		data->result.needs_sync = true;
	r = 0;
done:
	if (r < 0)
		data->result.unhandled = true;
	handle_send_message_result(response, data);
	fiobj_free(body);
	return 0;
	(void)ws;
}

static void on_send_message_unsubscribe(void *udata)
{
	struct send_message_data *data = udata;
	handle_send_message_result(NULL, data);
	send_message_data_unref(data);
}

/* --------------------------------------------------------------------------
 * Decode and process received pre-key bundles into sessions for devices of a
 * single recipient.
 * -------------------------------------------------------------------------- */

static ec_public_key * str2ec_public_key(FIOBJ s, const struct ksc_ws *ksc)
{
	fio_str_info_s b64 = fiobj_obj2cstr(s);
	ssize_t sz = ksc_base64_decode_size(b64.data, b64.len);
	LOGr(sz != 33, "str2ec_public_key: base64-decoded data size: %zu\n", sz);
	if (sz != 33)
		return NULL;
	uint8_t data[sz];
	ssize_t decoded = ksc_base64_decode(data, b64.data, b64.len);
	assert(decoded == sz);
	ec_public_key *key = NULL;
	int r = curve_decode_point(&key, data, sz, ksc->ctx);
	LOGr(r, "curve_decode_point pub_key -> %d\n", r);
	return key;
}

static int process_hash_pk_bundle_device(FIOBJ device, const char *name,
                                         size_t name_len,
                                         const struct ksc_ws *ksc,
                                         ec_public_key *identity_key)
{
	FIOBJ device_id = GET(device, "deviceId");
	FIOBJ registration_id = GET(device, "registrationId");
	FIOBJ signed_pre_key = GET(device, "signedPreKey");
	FIOBJ pre_key = GET(device, "preKey");
	FIOBJ signed_key_id = GET(signed_pre_key, "keyId");
	FIOBJ signed_sign = GET(signed_pre_key, "signature");
	FIOBJ pre_key_id = GET(pre_key, "keyId");

	LOG(NOTE, "processing pre-key bundle for %.*s.%" PRId32 "\n",
	    (int)name_len, name, (int32_t)fiobj_obj2num(device_id));

	ec_public_key *pre_pub_key = NULL;
	ec_public_key *signed_pub_key = NULL;
	session_pre_key_bundle *bundle = NULL;
	session_builder *builder = NULL;
	int r;

	pre_pub_key = str2ec_public_key(GET(pre_key, "publicKey"), ksc);
	LOGr(!pre_pub_key, "decoding pre-key public key\n");
	if (!pre_pub_key) {
		r = 1 << 1;
		goto skip;
	}

	signed_pub_key = str2ec_public_key(GET(signed_pre_key, "publicKey"), ksc);
	LOGr(!signed_pub_key, "decoding pre-key signed public key\n");
	if (!signed_pub_key) {
		r = 1 << 2;
		goto skip;
	}

	fio_str_info_s sign = fiobj_obj2cstr(signed_sign);
	assert(ksc_base64_decode_size((char *)sign.data, sign.len) == CURVE_SIGNATURE_LEN);
	uint8_t sign_data[CURVE_SIGNATURE_LEN];
	ssize_t decoded = ksc_base64_decode(sign_data, (char *)sign.data, sign.len);
	assert(decoded == CURVE_SIGNATURE_LEN);

	r = session_pre_key_bundle_create(&bundle,
		fiobj_obj2num(registration_id),
		fiobj_obj2num(device_id),
		fiobj_obj2num(pre_key_id),
		pre_pub_key,
		fiobj_obj2num(signed_key_id),
		signed_pub_key,
		sign_data, CURVE_SIGNATURE_LEN,
		identity_key);
	LOGr(r, "session_pre_key_bundle_create -> %d\n", r);
	if (r)
		goto skip;

	signal_protocol_address addr = {
		.name = name,
		.name_len = name_len,
		.device_id = fiobj_obj2num(device_id),
	};
	r = session_builder_create(&builder, ksc->psctx, &addr, ksc->ctx);
	LOGr(r, "session_builder_create -> %d\n", r);
	if (r)
		goto skip;

	r = session_builder_process_pre_key_bundle(builder, bundle);
	LOGr(r, "session_builder_process_pre_key_bundle -> %d\n", r);

skip:
	session_builder_free(builder);
	SIGNAL_UNREF(bundle);
	SIGNAL_UNREF(signed_pub_key);
	SIGNAL_UNREF(pre_pub_key);

	return r;
}

static int process_hash_pk_bundle(FIOBJ response, const char *name,
                                  size_t name_len, const struct ksc_ws *ksc)
{
	ec_public_key *identity_key = NULL;

	identity_key = str2ec_public_key(GET(response, "identityKey"), ksc);
	LOGr(!identity_key, "decoding pre-key identity key\n");
	if (!identity_key)
		return 1;

	int r = 0;
	for (FIOBJ devices = GET(response, "devices"); fiobj_ary_count(devices);) {
		FIOBJ device = fiobj_ary_pop(devices);
		r |= process_hash_pk_bundle_device(device, name, name_len, ksc,
		                                   identity_key) != 0;
		fiobj_free(device);
	}

	SIGNAL_UNREF(identity_key);

	return r;
}

/* --------------------------------------------------------------------------
 * Get the known sessions for all devices of a recipient from the protocol
 * store.
 * -------------------------------------------------------------------------- */

struct device_array {
	int32_t *ids;
	size_t n;
};

#define DEVICE_ARRAY_INIT	{ NULL, 0 }

#define DEFAULT_DEVICE_ID	1

/* not exported by libsignal-protocol-c :/ */
void signal_lock(signal_context *context);
void signal_unlock(signal_context *context);

/* returns a (negative) signal error or the number of devices placed at
 * *devices. Remember to free *devices. */
static int known_target_devices(struct device_array *res,
                                const char *recipient,
                                size_t recipient_len,
                                const struct ksc_ws *ksc)
{
	int32_t *devs = NULL;
	signal_int_list *sessions = NULL;
	int r = 0;

	bool myself = !strcmp(json_store_get_username(ksc->js), recipient);
	int32_t my_device_id;
	if (!json_store_get_device_id(ksc->js, &my_device_id))
		my_device_id = DEFAULT_DEVICE_ID;

	signal_lock(ksc->ctx);
	r = signal_protocol_session_get_sub_device_sessions(ksc->psctx,
	                                                    &sessions,
	                                                    recipient,
	                                                    recipient_len);
	LOGr(r < 0, "signal_protocol_session_get_sub_device_sessions -> %d\n", r);
	if (r < 0)
		goto done;

	size_t n = signal_int_list_size(sessions);
	bool contains_default_device = false;
	for (size_t i=0; !contains_default_device && i<n; i++)
		contains_default_device |=
			signal_int_list_at(sessions, i) == DEFAULT_DEVICE_ID;
	devs = malloc(sizeof(*devs) * (n + !contains_default_device));
	if (!devs) {
		r = SG_ERR_NOMEM;
		goto done;
	}
	int32_t *fill = devs;
	if (!contains_default_device &&
	    (!myself || my_device_id != DEFAULT_DEVICE_ID /* || unidentifiedAccess */))
		*fill++ = DEFAULT_DEVICE_ID;
	for (size_t i=0; i<n; i++) {
		int device_id = signal_int_list_at(sessions, i);
		if (!myself || my_device_id != device_id)
			*fill++ = device_id;
	}
	res->n = fill - devs;
	res->ids = devs;

done:
	signal_int_list_free(sessions);
	signal_unlock(ksc->ctx);
	if (r < 0)
		free(devs);
	return r;
}

/* --------------------------------------------------------------------------
 * Get pre-key bundles for devices from the server.
 * -------------------------------------------------------------------------- */

#define PREKEY_ALL_DEVICES_PATH		"/v2/keys/%.*s/*"
#define PREKEY_DEVICE_PATH		"/v2/keys/%.*s/%" PRId32

struct prekey_request_data {
	char *name;
	size_t name_len;
	struct device_array no_session;
	struct ksc_ws *ksc;
	bool requested;
	bool received;
	FIOBJ auth;

	struct send_message_data2 data;
};

static int send_message_final(const char *recipient, size_t recipient_len,
                              struct ksc_ws *ksc, struct device_array *devices,
                              struct send_message_data2 data);

static void on_prekey_response(http_s *h)
{
	struct prekey_request_data *pr = h->udata;
	http_settings_s *s = http_settings(h);
	KSC_DEBUG(DEBUG, "on_prekey_response %zu, requested: %d, udata: %p, settings: %p, settings udata: %p\n",
	    h->status, pr->requested, h->udata, (void *)s, s->udata);
	KSC_DEBUG(DEBUG, "  path: %s\n", fiobj_obj2cstr(h->path).data);
	s->udata = pr; /* why is this necessary? bug in facil.io? */
	struct ksc_ws *ksc = pr->ksc;
	if (pr->requested) {
		int r = -1;
		if (200 <= h->status && h->status < 300) {
			FIOBJ response;
			fio_str_info_s s = fiobj_obj2cstr(h->body);
			if (s.len && fiobj_json2obj(&response, s.data, s.len)) {
				r = process_hash_pk_bundle(response, pr->name,
				                           pr->name_len, ksc);
				LOGr(r, "handle_hash_pk_bundle() -> %d\n", r);
				fiobj_free(response);
			} else {
				LOG(ERROR, "error JSON-decoding pre-key response: ");
				if (ksc_log_prints(KSC_LOG_ERROR, ksc->args.log, &log_ctx)) {
					int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
					ksc_dprint_hex(fd, (uint8_t *)s.data, s.len);
					dprintf(fd, "\n");
				}
			}
			struct device_array devices;
			if (!r)
				r = known_target_devices(&devices, pr->name,
				                         pr->name_len, ksc);
			if (!r) {
				r = send_message_final(pr->name, pr->name_len,
				                       ksc, &devices, pr->data);
				LOGr(r, "send_message_final() -> %d\n", r);
			}
		}
		if (h->status == 413) {
			LOG(ERROR, "server refuses to send us the pre-key data...\n");
		}
		if (r) {
			/* TODO: retry or delete data2 contents */
		}
	}
	if (!pr->requested) {
		h->method = fiobj_str_new("GET", 3);
		pr->requested = true;
		http_set_header(h, fiobj_str_new("Authorization", 13), pr->auth);
		http_send_body(h, NULL, 0);
	} else {
		LOG(DEBUG, "sending http_finish()\n");
		http_finish(h);
	}
}

static void on_prekey_finish(http_settings_s *s)
{
	struct prekey_request_data *pr = s->udata;
	struct ksc_ws *ksc = pr->ksc;
	LOG(DEBUG, "on_prekey_finish()\n");
	free(pr->name);
	free(pr->no_session.ids);
	ksignal_ctx_unref(ksc);
	free(pr);
}

static intptr_t get_pre_keys(const char *recipient, size_t recipient_len,
                             struct device_array *devices,
                             struct ksc_ws *ksc,
                             struct send_message_data2 data2)
{
	/* get pre-keys via PushServiceSocket, aka standard HTTPS request */
	const char *user = json_store_get_username(ksc->js);
	const char *pass = json_store_get_password_base64(ksc->js);

	int32_t my_device_id;
	char *auth = json_store_get_device_id(ksc->js, &my_device_id)
	           ? ksc_ckprintf("%s.%" PRId32 ":%s", user, my_device_id, pass)
	           : ksc_ckprintf("%s:%s", user, pass);

	size_t auth_len = strlen(auth);
	char auth_enc[6 + auth_len*4/3+4];
	memcpy(auth_enc, "Basic ", 6);
	size_t auth_enc_len = ksc_base64_encode(auth_enc + 6, (uint8_t *)auth, auth_len);
	FIOBJ auth_header = fiobj_str_new(auth_enc, 6 + auth_enc_len);
	free(auth);

	char *url = devices->n != 1 || devices->ids[0] == DEFAULT_DEVICE_ID
	          ? ksc_ckprintf("https://" KSC_SERVICE_HOST PREKEY_ALL_DEVICES_PATH,
	                         (int)recipient_len, recipient)
	          : ksc_ckprintf("https://" KSC_SERVICE_HOST PREKEY_DEVICE_PATH,
	                         (int)recipient_len, recipient,
	                         devices->ids[0]);
	ksignal_ctx_ref(ksc);
	struct prekey_request_data pr = {
		.name = ksc_memdup(recipient, recipient_len),
		.name_len = recipient_len,
		.ksc = ksc,
		.no_session = *devices,
		.auth = auth_header,
		.data = data2,
	};
	fio_tls_s *tls = ksc_signal_tls(ksc->args.server_cert_path);
	LOG(NOTE, "getting pre-keys, connecting to %s\n", url);
	intptr_t r = http_connect(url, NULL,
	                          .on_response = on_prekey_response,
	                          .on_finish = on_prekey_finish,
	                          .udata = ksc_memdup(&pr, sizeof(pr)),
	                          .tls = tls);
	fio_tls_destroy(tls);

	free(url);

	return r;
}

/* --------------------------------------------------------------------------
 * Encrypt a message for a NUMBER + device.
 * -------------------------------------------------------------------------- */

struct outgoing_push_message {
	struct outgoing_push_message *next;
	size_t content_sz;
	int type;
	int destination_device_id;
	uint32_t destination_registration_id;
	/* base64-encoded encrypted (un)padded protobuf-encoded Content message */
	char content[];
};

static int encrypt_for(const signal_protocol_address *addr,
                       const struct ksc_ws *ksc,
                       const uint8_t *padded_content, size_t padded_content_sz,
                       struct outgoing_push_message **result)
{
	if (!signal_protocol_session_contains_session(ksc->psctx, addr)) {
		LOG(WARN, "encrypt_for: no session for %.*s.%" PRId32 "\n",
		    (int)addr->name_len, addr->name, addr->device_id);
		return SG_ERR_NO_SESSION;
	}

	session_cipher *cipher = NULL;
	ciphertext_message *message = NULL;
	struct outgoing_push_message *msg = NULL;
	int r;

	r = session_cipher_create(&cipher, ksc->psctx, addr, ksc->ctx);
	LOGr(r, "session_cipher_create -> %d\n", r);
	if (r)
		goto done;
	r = session_cipher_encrypt(cipher, padded_content, padded_content_sz,
	                           &message);
	LOGr(r, "session_cipher_encrypt -> %d\n", r);
	if (r)
		goto done;

	signal_buffer *serialized = ciphertext_message_get_serialized(message);
	LOGr(!serialized, "ciphertext_message_get_serialized -> %p\n",
	     (void *)serialized);

	/* deliver(serialized) */

	size_t serialized_sz = signal_buffer_len(serialized);
	size_t n = serialized_sz * 4 / 3 + 4;
	msg = ksc_malloc(offsetof(struct outgoing_push_message, content) + n);
	if (!msg) {
		r = SG_ERR_NOMEM;
		goto done;
	}
	msg->next = NULL;
	switch (ciphertext_message_get_type(message)) {
	case CIPHERTEXT_SIGNAL_TYPE: msg->type = CIPHERTEXT; break;
	case CIPHERTEXT_PREKEY_TYPE: msg->type = PREKEY_BUNDLE; break;
	default:
		r = SG_ERR_UNKNOWN;
		goto done;
	}
	r = session_cipher_get_remote_registration_id(cipher,
	                                              &msg->destination_registration_id);
	LOGr(r, "session_cipher_get_remote_registration_id -> %d\n", r);
	msg->destination_device_id = addr->device_id;
	msg->content_sz = ksc_base64_encode(msg->content,
	                                    signal_buffer_data(serialized),
	                                    serialized_sz);

done:
	SIGNAL_UNREF(message);
	session_cipher_free(cipher);

	if (!r)
		*result = msg;
	else
		ksc_free(msg);
	return r;
}

/* --------------------------------------------------------------------------
 * Final stage of sending a message via PUT /v1/messages/NUMBER.
 * Encrypt the message for all target devices and set the request. For this,
 * set up ref-counted send_message_data for these events:
 * - on_response: the server sends the information `needs_sync` JSON-encoded,
 *                process that and handle the result.
 * - on_unsubscribe: clean up the callback data and handle the result.
 * - on_send_message_timeout: if the server failed to reply, record that event
 *                            and handle the result.
 * -------------------------------------------------------------------------- */

#define SEND_MESSAGE_PATH	"/v1/messages/%.*s"

#define CSTR2FIOBJ(const_str)	fiobj_str_new(const_str, sizeof(const_str)-1)

#define SEND_MESSAGE_RESPONSE_TIMEOUT	10 /* seconds */

static int send_message_final(const char *recipient, size_t recipient_len,
                              struct ksc_ws *ksc, struct device_array *devices,
                              struct send_message_data2 data)
{
	int r;
	struct outgoing_push_message *message_list = NULL, **message_tail = &message_list;

	struct signal_protocol_address addr = {
		.name = recipient,
		.name_len = recipient_len,
	};

	if (ksc_log_prints(KSC_LOG_INFO, ksc->args.log, &log_ctx)) {
		LOG(INFO, "sending message to %.*s (devices:",
		           (int)recipient_len, recipient);
		int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
		for (size_t i=0; i<devices->n; i++)
			dprintf(fd, " %" PRId32, devices->ids[i]);
		dprintf(fd, ")\n");
	}

	int32_t *a = devices->ids;
	for (int32_t *b = a; b < devices->ids + devices->n; b++) {
		/* encrypt for (target->name, DEFAULT_DEVICE_ID) */
		addr.device_id = *b;
		r = encrypt_for(&addr, ksc, data.content,
		                data.content_padded_sz, message_tail);
		LOGr(r, "encrypt_for device %" PRId32 " -> %d\n", addr.device_id, r);
		if (!r)
			message_tail = &(*message_tail)->next;
		if (r)
			*a++ = *b; /* record failed encryption */
		if (r == SG_ERR_NO_SESSION)
			r = 0;
		if (r)
			goto done;
	}
	size_t n_failed = a - devices->ids;
	LOGr(n_failed, "failed to encrypt to %zu of %zu devices of %.*s\n",
	     n_failed, devices->n, (int)recipient_len, recipient);

	LOGr(!message_list, "message_list: %p\n", message_list);

	char *path = ksc_ckprintf(SEND_MESSAGE_PATH,
	                          (int)recipient_len, recipient);

	FIOBJ msg = fiobj_hash_new();
	fiobj_hash_set(msg, CSTR2FIOBJ("destination"),
	                    fiobj_str_new(recipient, recipient_len));
	fiobj_hash_set(msg, CSTR2FIOBJ("timestamp"),
	                    fiobj_num_new(data.timestamp));
	fiobj_hash_set(msg, CSTR2FIOBJ("online"), fiobj_false());
	FIOBJ msgs = fiobj_ary_new();
	for (struct outgoing_push_message *m = message_list; m; m = m->next) {
		FIOBJ f = fiobj_hash_new();
		fiobj_hash_set(f, CSTR2FIOBJ("type"), fiobj_num_new(m->type));
		fiobj_hash_set(f, CSTR2FIOBJ("destinationDeviceId"),
		                  fiobj_num_new(m->destination_device_id));
		fiobj_hash_set(f, CSTR2FIOBJ("destinationRegistrationId"),
		                  fiobj_num_new(m->destination_registration_id));
		fiobj_hash_set(f, CSTR2FIOBJ("content"),
		                  fiobj_str_new(m->content, m->content_sz));
		fiobj_ary_push(msgs, f);
	}
	fiobj_hash_set(msg, CSTR2FIOBJ("messages"), msgs);
	FIOBJ json = fiobj_obj2json(msg, 0);
	fio_str_info_s json_c = fiobj_obj2cstr(json);

	LOG(DEBUG, "sending JSON: %.*s\n", (int)json_c.len, json_c.data);

	struct send_message_data *cb_data = ksc_calloc(1, sizeof(*cb_data));
	ksignal_ctx_ref(ksc);
	cb_data->ksc = ksc;
	cb_data->recipient.name = strndup(recipient, recipient_len);
	cb_data->recipient.name_len = recipient_len;
	cb_data->data2 = data;
	cb_data->is_recipient_udpate = false; /* TODO */
	cb_data->result.needs_sync = data.may_need_sync &&
	                             json_store_is_multi_device(ksc->js);

	static char *headers[] = {
		"Content-Type: application/json",
	};
	REF(cb_data);
	r = ksc_ws_send_request(data.ws, "PUT", path,
	                        .size = json_c.len,
	                        .body = json_c.data,
	                        .headers = headers,
	                        .n_headers = KSC_ARRAY_SIZE(headers),
	                        .on_response = on_send_message_response,
	                        .on_unsubscribe = on_send_message_unsubscribe,
	                        .udata = cb_data);
	if (r)
		cb_data = NULL;

	if (!r) {
		REF(cb_data);
		fio_run_every(SEND_MESSAGE_RESPONSE_TIMEOUT * 1000, 1,
		              on_send_message_response_timeout, cb_data, NULL);
	}

	fiobj_free(json);
	fiobj_free(msg);
	ksc_free(path);

	LOGr(r, "ksc_ws_send_request -> %d\n", r);

	if (!r && data.args.end_session) {
		r = signal_protocol_session_delete_all_sessions(ksc->psctx,
		                                                recipient,
		                                                recipient_len);
		LOGr(r < 0,
		     "signal_protocol_session_delete_all_sessions -> %d\n", r);
		if (r > 0)
			r = 0;
	}

	/* XXX: directly encode into FIOBJ w/o going via struct outgoing_push_message */

done:
	for (struct outgoing_push_message *m, *mn = message_list; (m = mn);) {
		mn = m->next;
		ksc_free(m);
	}
	message_list = NULL, message_tail = &message_list;
	free(devices->ids);

	return r;
}

#define PADDING			160

static void prepare_data_message(Signalservice__DataMessage *data,
                                 struct ksc_ws_send_message_args *args)
{
	data->body = (char *)args->body;
	if (args->end_session) {
		data->flags |= SIGNALSERVICE__DATA_MESSAGE__FLAGS__END_SESSION;
		data->has_flags = true;
	}
	struct timeval tv;
	gettimeofday(&tv, NULL);
	data->timestamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	data->has_timestamp = true;
}

static int known_target_devices_(struct device_array *all,
                                 struct device_array *no_session,
                                 const char *recipient, size_t recipient_len,
                                 struct ksc_ws *ksc)
{
	int r;
	r = known_target_devices(all, recipient, recipient_len, ksc);
	if (r < 0)
		return r;

	no_session->n = all->n;
	no_session->ids = ksc_memdup(all->ids, sizeof(*all->ids) * all->n);

	int32_t *a = no_session->ids;
	struct signal_protocol_address addr = {
		.name = recipient,
		.name_len = recipient_len,
	};
	for (int32_t *b = a; b < no_session->ids + no_session->n; b++) {
		addr.device_id = *b;
		int r = signal_protocol_session_contains_session(ksc->psctx, &addr);
		if (r < 0)
			goto error;
		if (r)
			continue;
		*a++ = *b;
	}
	no_session->n = a - no_session->ids;

	return 0;

error:
	free(all->ids);
	free(no_session->ids);
	return r;
}

/* --------------------------------------------------------------------------
 * Initiate sending a message via PUT /v1/messages/NUMBER.
 * If for all known devices of `recipient` there is an established session,
 * proceed with the final stage of sending the PUT request to the websocket.
 * Otherwise, before the final stage, send a get-pre-keys request and only on
 * successful reply and processing of the retrieved pre-key bundles proceed
 * with the final stage of sending the message.
 *--------------------------------------------------------------------------- */

static int send_message(ws_s *ws, struct ksc_ws *ksc, const char *recipient,
                        const Signalservice__Content *content,
                        uint64_t timestamp,
                        struct ksc_ws_send_message_args args)
{
	size_t content_sz = signalservice__content__get_packed_size(content);
	uint8_t *content_packed = ksc_malloc(ksc_one_and_zeroes_padded_size(content_sz, PADDING));
	signalservice__content__pack(content, content_packed);

	size_t content_padded_sz = content_sz;
	ksc_one_and_zeroes_pad(content_packed, &content_padded_sz, PADDING);

	signal_lock(ksc->ctx);
	int r = 0;
	size_t recipient_len = strlen(recipient);

	struct device_array all = DEVICE_ARRAY_INIT;
	struct device_array no_session = DEVICE_ARRAY_INIT;
	r = known_target_devices_(&all, &no_session, recipient, recipient_len, ksc);
	if (r < 0)
		goto done;

	struct send_message_data2 data2 = {
		ws, timestamp, args, content_packed, content_padded_sz,
		content_sz, content->datamessage ? true : false,
	};
	content_packed = NULL; /* transferred ownership */
	if (no_session.n) {
		intptr_t sock = get_pre_keys(recipient, recipient_len,
		                             &no_session, ksc, data2);
		no_session.ids = NULL; /* transferred ownership */
		LOGr(sock < 0, "get_pre_keys() -> %zd\n", sock);
		if (sock < 0) {
			r = sock;
			goto done;
		}
	} else {
		r = send_message_final(recipient, recipient_len, ksc, &all, data2);
		all.ids = NULL; /* transferred ownership */
	}

done:
	signal_unlock(ksc->ctx);
	ksc_free(content_packed);
	ksc_free(all.ids);
	ksc_free(no_session.ids);
	return r;
}

int (ksc_ws_send_message)(ws_s *ws, struct ksc_ws *ksc, const char *recipient,
                          struct ksc_ws_send_message_args args)
{
	Signalservice__DataMessage data = SIGNALSERVICE__DATA_MESSAGE__INIT;
	prepare_data_message(&data, &args);

	Signalservice__Content content = SIGNALSERVICE__CONTENT__INIT;
	content.datamessage = &data;

	return send_message(ws, ksc, recipient, &content, data.timestamp, args);
}
