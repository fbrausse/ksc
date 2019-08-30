/*
 * ksc-ws.c
 *
 * Copyright 2019 Franz Brauße <brausse@informatik.uni-trier.de>
 *
 * This file is part of ksc.
 * See the LICENSE file for terms of distribution.
 */

#ifdef __STDC_NO_ATOMICS__
# error Need _Atomic support from C11
#endif

#include "ksc-ws.h"
#include "crypto.h"

#include <signal/protocol.h>
#include <signal/session_cipher.h>

#include <signal/hkdf.h>

#include "UnidentifiedDelivery.pb-c.h"

static const struct ksc_log_context log_ctx = {
	.desc = "ksc-ws",
	.color = "34",
};

/* shortcuts */
#define LOGL_(level,log,...)	KSC_LOG_(level, log, &log_ctx, __VA_ARGS__)
#define LOGL(lvl,log,...)	KSC_LOG(lvl, log, &log_ctx, __VA_ARGS__)
#define LOG_(level,...)		LOGL_(level, ksc->args.log, __VA_ARGS__)
#define LOG(lvl,...)		LOGL(lvl, ksc->args.log, __VA_ARGS__)
#define LOGr(r,...)		LOG_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, __VA_ARGS__)

#include "ksc-ws-private.h"

void ksc_print_envelope(const Signalservice__Envelope *e, int fd, bool detail)
{
	if (e->has_type) {
		const char *type = NULL;
		switch (e->type) {
		case UNKNOWN            : type = "unknown"; break;
		case CIPHERTEXT         : type = "ciphertext"; break;
		case KEY_EXCHANGE       : type = "key exchange"; break;
		case PREKEY_BUNDLE      : type = "prekey bundle"; break;
		case RECEIPT            : type = "receipt"; break;
		case UNIDENTIFIED_SENDER: type = "unidentified sender"; break;
		case _SIGNALSERVICE__ENVELOPE__TYPE_IS_INT_SIZE: break;
		}
		dprintf(fd, "  type: %s (%d)\n", type, e->type);
	}
	if (e->source)
		dprintf(fd, "  source: %s\n", e->source);
	if (e->has_sourcedevice)
		dprintf(fd, "  source device: %u\n", e->sourcedevice);
	if (e->relay)
		dprintf(fd, "  relay: %s\n", e->relay);
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		dprintf(fd, "  timestamp: %s", buf);
	}
	if (e->has_legacymessage) {
		dprintf(fd, "  has encrypted legacy message of size %zu%s\n",
		        e->legacymessage.len,
		        e->legacymessage.len && detail ? ":" : "");
		if (e->legacymessage.len && detail) {
			ksc_dprint_hex(fd, e->legacymessage.data,
			               e->legacymessage.len);
			dprintf(fd, "\n");
		}
	}
	if (e->has_content) {
		dprintf(fd, "  has encrypted content of size %zu%s\n",
		        e->content.len, e->content.len && detail ? ":" : "");
		if (e->content.len && detail) {
			ksc_dprint_hex(fd, e->content.data, e->content.len);
			dprintf(fd, "\n");
		}
	}
	if (e->serverguid)
		dprintf(fd, "  server guid: %s\n", e->serverguid);
	if (e->has_servertimestamp) {
		char buf[32];
		time_t t = e->servertimestamp / 1000;
		ctime_r(&t, buf);
		dprintf(fd, "  server timestamp: %s", buf);
	}
}

intptr_t ksc_ws_get_uuid(const struct ksc_ws *kws)
{
	return kws->uuid;
}

void * ksc_ws_get_udata(const struct ksc_ws *kws)
{
	return kws->args.udata;
}

static bool received_message(ws_s *ws, const Signalservice__Envelope *e,
                             uint8_t *text, size_t size,
                             struct ksc_ws *ksc)
{
	/*
	printf("decrypted Content:\n");
	print_hex(stdout, text, size);
	printf("\n");*/
	if (!ksc_one_and_zeroes_unpad(text, &size)) {
		LOG(ERROR, "failed to one-and-zeroes-unpad!\n");
		return false;
	}
	if (ksc_log_prints(KSC_LOG_DEBUG, ksc->args.log, &log_ctx)) {
		int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
		LOG(DEBUG, "decrypted Content (len: %zu): ", size);
		ksc_dprint_hex(fd, text, size);
		dprintf(fd, "\n");
	}
	Signalservice__Content *c;
	c = signalservice__content__unpack(NULL, size, text);
	if (!c) {
		LOG(ERROR, "error decoding decrypted message into Content\n");
		return false;
	}
	bool r = true;
	if (ksc->args.on_content)
		r = ksc->args.on_content(ws, ksc, e, c);
	signalservice__content__free_unpacked(c, NULL);
	return r;
	(void)ws;
}

static int delete_request_on_response(ws_s *ws, struct ksc_signal_response *r,
                                      void *udata)
{
	struct ksc_ws *ksc = udata;
	LOG_(r->status == 204 ? KSC_LOG_DEBUG : KSC_LOG_WARN,
	     "deletion request response line: %d %s\n", r->status, r->message);
	return 0;
	(void)ws;
}

struct delete_request_args {
	ws_s *ws;
	struct ksc_ws *ksc;
};

static void delete_request(void *udata1, void *udata2)
{
	struct delete_request_args *args = udata1;
	char *path = udata2;
	ksc_ws_send_request(args->ws, "DELETE", path,
	                    .on_response = delete_request_on_response,
	                    .udata = args->ksc);
	ksc_free(path);
	ksc_free(args);
}

static char * ack_message_path(const Signalservice__Envelope *e,
                               const signal_protocol_address *addr)
{
	return e->serverguid
	       ? ksc_ckprintf("/v1/messages/uuid/%s", e->serverguid)
	       : ksc_ckprintf("/v1/messages/%.*s/%" PRIu64,
	                      (int)addr->name_len, addr->name, e->timestamp);
}

static int received_ciphertext_or_prekey_bundle2(ws_s *ws,
                                                 const Signalservice__Envelope *e,
                                                 signal_protocol_address *addr,
                                                 Signalservice__Envelope__Type type,
                                                 const struct ProtobufCBinaryData *content,
                                                 struct ksc_ws *ksc)
{
	signal_buffer *plaintext = NULL;
	session_cipher *cipher;
	int r = session_cipher_create(&cipher, ksc->psctx, addr, ksc->ctx);
	LOGr(r, "session_cipher_create -> %d\n", r);
	if (r)
		return r;

	if (type == CIPHERTEXT) {
		signal_message *msg;
		r = signal_message_deserialize(&msg, content->data, content->len, ksc->ctx);
		LOGr(r, "signal_message_deserialize -> %d\n", r);
		if (!r) {
			r = session_cipher_decrypt_signal_message(cipher, msg, NULL, &plaintext);
			LOG_(!r ? KSC_LOG_DEBUG :
			     r == SG_ERR_DUPLICATE_MESSAGE ? KSC_LOG_WARN : KSC_LOG_ERROR,
			     "session_cipher_decrypt_signal_message -> %d\n", r);
		}
		SIGNAL_UNREF(msg);
	} else {
		assert(type == PREKEY_BUNDLE);
		pre_key_signal_message *msg = NULL;
		r = pre_key_signal_message_deserialize(&msg, content->data, content->len, ksc->ctx);
		LOGr(r, "pre_key_signal_message_deserialize -> %d\n", r);
		if (!r) {
			r = session_cipher_decrypt_pre_key_signal_message(cipher, msg, NULL, &plaintext);
			LOG_(!r ? KSC_LOG_DEBUG :
			     r == SG_ERR_DUPLICATE_MESSAGE ? KSC_LOG_WARN : KSC_LOG_ERROR,
			     "session_cipher_decrypt_pre_key_signal_message -> %d\n", r);
		}
		SIGNAL_UNREF(msg);
	}

	session_cipher_free(cipher);

	if (!r && plaintext)
		r = received_message(ws, e, signal_buffer_data(plaintext),
		                     signal_buffer_len(plaintext), ksc)
		    ? 0 : SG_ERR_UNKNOWN;

	if (!r || r == SG_ERR_DUPLICATE_MESSAGE) {
		struct delete_request_args args = { ws, ksc };
		fio_defer(delete_request, ksc_memdup(&args, sizeof(args)),
		          ack_message_path(e, addr));
		r = 0;
	}

	signal_buffer_free(plaintext);

	return r;
}

static int received_ciphertext_or_prekey_bundle(ws_s *ws,
                                                const Signalservice__Envelope *e,
                                                struct ksc_ws *ksc)
{
	signal_protocol_address addr = {
		.name = e->source,
		.name_len = strlen(e->source),
		.device_id = e->sourcedevice,
	};

	return received_ciphertext_or_prekey_bundle2(ws, e, &addr, e->type,
	                                             &e->content, ksc);
}

static int received_receipt(ws_s *ws, const Signalservice__Envelope *e,
                            struct ksc_ws *ksc)
{
	char buf[32];
	time_t t = e->timestamp / 1000;
	ctime_r(&t, buf);
	LOG(NOTE, "got receipt from %s.%u at %s", e->source, e->sourcedevice, buf);
	bool r = true;
	if (ksc->args.on_receipt)
		r = ksc->args.on_receipt(ws, ksc, e);
	return r ? 0 : -1;
}

#define UNIDENTIFIED_CIPHERTEXT_VERSION		1
#define UNIDENTIFIED_HKDF_MESSAGE_VERSION	3
#define UNIDENTIFIED_SALT_PREFIX		"UnidentifiedDelivery"

#define UNIDENTIFIED_CHAIN_KEY_SZ		32
#define UNIDENTIFIED_CHAIN_KEY_OFF		0
#define UNIDENTIFIED_CIPHER_KEY_SZ		32
#define UNIDENTIFIED_CIPHER_KEY_OFF \
	(UNIDENTIFIED_CHAIN_KEY_OFF + UNIDENTIFIED_CHAIN_KEY_SZ)
#define UNIDENTIFIED_MAC_KEY_SZ			32
#define UNIDENTIFIED_MAC_KEY_OFF \
	(UNIDENTIFIED_CIPHER_KEY_OFF + UNIDENTIFIED_CIPHER_KEY_SZ)
#define UNIDENTIFIED_HKDF_DERIVED_SZ \
	(UNIDENTIFIED_MAC_KEY_OFF + UNIDENTIFIED_MAC_KEY_SZ)

#define UNIDENTIFIED_MSG_MAC_SZ			10

static inline void * ksc_mempcpy(void *restrict tgt, const void *restrict src,
                                 size_t n)
{
	return (char *)memcpy(tgt, src, n) + n;
}

static inline void * ksc_mempcpy_buf(void *restrict tgt, signal_buffer *buf)
{
	return ksc_mempcpy(tgt, signal_buffer_data(buf), signal_buffer_len(buf));
}

static int calculate_keys(ec_public_key *ephemeral,
                          ec_private_key *identity,
                          const struct ksc_ws *ksc,
                          const uint8_t *salt, size_t salt_sz,
                          uint8_t **chain_cipher_mac_key)
{
	uint8_t *agreement = NULL, *derived = NULL;
	hkdf_context *ctx = NULL;

	int r = curve_calculate_agreement(&agreement, ephemeral, identity);
	LOGr(r < 0, "curve_calculate_agreement() -> %d\n", r);
	if (r < 0)
		return r;
	size_t agreement_sz = r;
	r = 0;

	r = hkdf_create(&ctx, UNIDENTIFIED_HKDF_MESSAGE_VERSION, ksc->ctx);
	LOGr(r, "hkdf_create() -> %d\n", r);

	ssize_t sz = hkdf_derive_secrets(ctx, &derived, agreement, agreement_sz,
	                                 salt, salt_sz, NULL, 0,
	                                 UNIDENTIFIED_HKDF_DERIVED_SZ);
	LOGr(sz != UNIDENTIFIED_HKDF_DERIVED_SZ, "hkdf_derive_secrets() -> %zd\n", sz);
	if (sz != UNIDENTIFIED_HKDF_DERIVED_SZ) {
		r = -1;
		goto done;
	}

	*chain_cipher_mac_key = derived;
done:
	SIGNAL_UNREF(ctx);
	free(agreement);
	return r;
}

int signal_hmac_sha256_init(signal_context *context, void **hmac_context, const uint8_t *key, size_t key_len);
int signal_hmac_sha256_update(signal_context *context, void *hmac_context, const uint8_t *data, size_t data_len);
int signal_hmac_sha256_final(signal_context *context, void *hmac_context, signal_buffer **output);
void signal_hmac_sha256_cleanup(signal_context *context, void *hmac_context);

int signal_decrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len);

static signal_buffer * decrypt(const uint8_t cipher_key[static UNIDENTIFIED_CIPHER_KEY_SZ],
                               const uint8_t mac_key[static UNIDENTIFIED_MAC_KEY_SZ],
                               uint8_t *ciphertext, size_t ciphertext_sz,
                               struct ksc_ws *ksc)
{
	if (ciphertext_sz < UNIDENTIFIED_MSG_MAC_SZ) {
		LOG(ERROR, "unidentified-sender message static ciphertext too short for MAC\n");
		return NULL;
	}

	signal_buffer *decrypted = NULL;
	signal_buffer *our_mac = NULL;
	void *hmac = NULL;
	int r;
	signal_hmac_sha256_init(ksc->ctx, &hmac, mac_key, UNIDENTIFIED_MAC_KEY_SZ);
	signal_hmac_sha256_update(ksc->ctx, hmac, ciphertext,
	                          ciphertext_sz - UNIDENTIFIED_MSG_MAC_SZ);
	signal_hmac_sha256_final(ksc->ctx, hmac, &our_mac);
	signal_hmac_sha256_cleanup(ksc->ctx, hmac);

	if (signal_buffer_len(our_mac) < UNIDENTIFIED_MSG_MAC_SZ) {
		LOG(ERROR, "unidentified-sender message static our-MAC too short\n");
		r = -2;
		goto done;
	}
	if (memcmp(signal_buffer_data(our_mac),
	           ciphertext + (ciphertext_sz - UNIDENTIFIED_MSG_MAC_SZ),
	           UNIDENTIFIED_MSG_MAC_SZ)) {
		LOG(ERROR, "unidentified-sender message static MACs don't match\n");
		r = -3;
		goto done;
	}

	static const uint8_t iv[16];

	r = signal_decrypt(ksc->ctx, &decrypted, SG_CIPHER_AES_CTR_NOPADDING,
	                   cipher_key, UNIDENTIFIED_CIPHER_KEY_SZ,
	                   iv, KSC_ARRAY_SIZE(iv),
	                   ciphertext, ciphertext_sz - UNIDENTIFIED_MSG_MAC_SZ);
	LOGr(r, "signal_decrypt() -> %d\n", r);
	if (r) {
		signal_buffer_free(decrypted);
		decrypted = NULL;
	}

done:
	signal_buffer_free(our_mac);
	return decrypted;
}

static signal_buffer *
sealed_session_decrypt(const Signal__UnidentifiedSenderMessage *msg,
                       uint64_t timestamp, struct ksc_ws *ksc)
{
	ratchet_identity_key_pair *our_identity = NULL;
	ec_public_key *ephemeral = NULL;
	ec_public_key *static_key = NULL;
	signal_buffer *ephemeral_buf = NULL;
	signal_buffer *ident_pubkey_buf = NULL;
	signal_buffer *static_key_buf = NULL;
	signal_buffer *dec_msg = NULL;
	uint8_t *keys = NULL;
	uint8_t *salt = NULL;
	uint8_t *static_salt = NULL;
	uint8_t *static_keys = NULL;
	int r;

	if (!msg->has_ephemeralpublic || !msg->has_encryptedstatic ||
	    !msg->has_encryptedmessage) {
		LOG(ERROR, "unidentified-sender message is missing fields\n");
		goto done;
	}

	/* XXX: this is an extremely inefficient copy orgy, but "super safe C"
	 * ... omg */

	r = curve_decode_point(&ephemeral, msg->ephemeralpublic.data,
	                       msg->ephemeralpublic.len, ksc->ctx);
	LOGr(r, "curve_decode_point() -> %d\n", r);

	r = signal_protocol_identity_get_key_pair(ksc->psctx, &our_identity);
	LOGr(r, "signal_protocol_identity_get_key_pair() -> %d\n", r);

	r = ec_public_key_serialize(&ephemeral_buf, ephemeral);
	LOGr(r, "ec_public_key_serialize(identity-public-key) -> %d\n", r);

	r = ec_public_key_serialize(&ident_pubkey_buf,
	                            ratchet_identity_key_pair_get_public(our_identity));
	LOGr(r, "ec_public_key_serialize(identity-public-key) -> %d\n", r);

	size_t salt_sz = sizeof(UNIDENTIFIED_SALT_PREFIX)-1 +
	                 signal_buffer_len(ident_pubkey_buf) +
	                 signal_buffer_len(ephemeral_buf);
	salt = malloc(salt_sz);
	if (!salt)
		goto done;

	uint8_t *tgt = salt;
	tgt = ksc_mempcpy(tgt, UNIDENTIFIED_SALT_PREFIX, sizeof(UNIDENTIFIED_SALT_PREFIX)-1);
	tgt = ksc_mempcpy_buf(tgt, ident_pubkey_buf);
	tgt = ksc_mempcpy_buf(tgt, ephemeral_buf);

	r = calculate_keys(ephemeral,
	                   ratchet_identity_key_pair_get_private(our_identity),
	                   ksc, salt, salt_sz, &keys);
	LOGr(r, "calculate_keys() -> %d\n", r);

	static_key_buf = decrypt(keys + UNIDENTIFIED_CIPHER_KEY_OFF,
	                         keys + UNIDENTIFIED_MAC_KEY_OFF,
	                         msg->encryptedstatic.data, msg->encryptedstatic.len, ksc);
	LOGr(!static_key_buf, "decrypt(static) -> %p\n", static_key_buf);

	r = curve_decode_point(&static_key, signal_buffer_data(static_key_buf),
	                       signal_buffer_len(static_key_buf), ksc->ctx);
	LOGr(r, "curve_decode_point(static-key) -> %d\n", r);

	size_t static_salt_sz = UNIDENTIFIED_CHAIN_KEY_SZ + msg->encryptedstatic.len;
	static_salt = ksc_malloc(static_salt_sz);
	tgt = static_salt;
	tgt = ksc_mempcpy(tgt, keys + UNIDENTIFIED_CHAIN_KEY_OFF, UNIDENTIFIED_CHAIN_KEY_SZ);
	tgt = ksc_mempcpy(tgt, msg->encryptedstatic.data, msg->encryptedstatic.len);

	r = calculate_keys(static_key,
	                   ratchet_identity_key_pair_get_private(our_identity),
	                   ksc, static_salt, static_salt_sz, &static_keys);
	LOGr(r, "calculate_keys(static-keys) -> %d\n", r);

	dec_msg = decrypt(static_keys + UNIDENTIFIED_CIPHER_KEY_OFF,
	                  static_keys + UNIDENTIFIED_MAC_KEY_OFF,
	                  msg->encryptedmessage.data, msg->encryptedmessage.len,
	                  ksc);
	LOGr(!dec_msg, "decrypt(msg) -> %p\n", dec_msg);

done:
	free(static_keys);
	free(static_salt);
	free(keys);
	free(salt);
	signal_buffer_free(static_key_buf);
	signal_buffer_free(ident_pubkey_buf);
	signal_buffer_free(ephemeral_buf);
	SIGNAL_UNREF(our_identity);
	SIGNAL_UNREF(static_key);
	SIGNAL_UNREF(ephemeral);
	return dec_msg;
}

static int received_unidentified_sender(ws_s *ws,
                                        const Signalservice__Envelope *e,
                                        struct ksc_ws *ksc)
{
	uint8_t *data = e->content.data;
	signal_buffer *dec_msg_buf = NULL;
	Signal__UnidentifiedSenderMessage__Message *dec_msg = NULL;
	Signal__SenderCertificate__Certificate *sender_cert = NULL;
	Signal__ServerCertificate__Certificate *server_cert = NULL;
	int r;

	if (e->content.len < 1)
		return SG_ERR_INVALID_VERSION;

	int version = data[0] >> 4;
	if (version != UNIDENTIFIED_CIPHERTEXT_VERSION)
		return SG_ERR_INVALID_VERSION;

	Signal__UnidentifiedSenderMessage *msg = NULL;

	msg = signal__unidentified_sender_message__unpack(NULL, e->content.len-1,
	                                                  data+1);
	LOGr(!msg, "protobuf-unpacking unidentified-sender message -> %p\n", msg);
	if (!msg) {
		r = SG_ERR_INVALID_PROTO_BUF;
		goto done;
	}

	dec_msg_buf = sealed_session_decrypt(msg, e->servertimestamp, ksc);
	LOGr(!dec_msg_buf, "sealed_session_decrypt() -> %p\n", dec_msg_buf);

	dec_msg = (Signal__UnidentifiedSenderMessage__Message *)
	          protobuf_c_message_unpack(
		&signal__unidentified_sender_message__message__descriptor,
		NULL, signal_buffer_len(dec_msg_buf),
		signal_buffer_data(dec_msg_buf));
	LOGr(!dec_msg, "protobuf-unpacking decrypted unidentified-sender message -> %p\n", dec_msg);
	if (!dec_msg) {
		r = SG_ERR_INVALID_PROTO_BUF;
		goto done;
	}

	KSC_DEBUG(NOTE, "decoded unid message:\n");
	if (dec_msg->has_type)
		dprintf(STDERR_FILENO, "  type: %d\n", dec_msg->type);
	if (dec_msg->sendercertificate) {
		dprintf(STDERR_FILENO, "  has sender certificate\n");
		if (dec_msg->sendercertificate->has_certificate)
			dprintf(STDERR_FILENO, "    has certificate\n");
		if (dec_msg->sendercertificate->has_signature)
			dprintf(STDERR_FILENO, "    has signature\n");
	}
	if (dec_msg->has_content)
		dprintf(STDERR_FILENO, "  has content: %zu bytes\n",
		        dec_msg->content.len);

	if (!dec_msg->has_type || !dec_msg->sendercertificate ||
	    !dec_msg->has_content) {
		LOG(ERROR, "decrypted unid message is missing fields\n");
		r = SG_ERR_INVALID_MESSAGE;
		goto done;
	}
	if (!dec_msg->sendercertificate->has_signature ||
	    !dec_msg->sendercertificate->has_certificate) {
		LOG(ERROR, "unid's sender certificate is missing fields\n");
		r = SG_ERR_INVALID_MESSAGE;
		goto done;
	}

	sender_cert = (Signal__SenderCertificate__Certificate *)
	              protobuf_c_message_unpack(
		&signal__sender_certificate__certificate__descriptor,
		NULL, dec_msg->sendercertificate->certificate.len,
		dec_msg->sendercertificate->certificate.data);
	LOGr(!sender_cert, "unid: protobuf-unpacking sender certificate -> %p\n", sender_cert);

	if (!sender_cert->signer || !sender_cert->has_identitykey ||
	    !sender_cert->has_senderdevice || !sender_cert->sender) {
		LOG(ERROR, "unid's unpacked sender certificate is missing fields\n");
		r = SG_ERR_INVALID_MESSAGE;
		goto done;
	}

	if (!sender_cert->signer->has_certificate ||
	    !sender_cert->signer->has_signature) {
		LOG(ERROR, "unid's signer's certificate is missing fields\n");
		r = SG_ERR_INVALID_MESSAGE;
		goto done;
	}

	server_cert = (Signal__ServerCertificate__Certificate *)
	              protobuf_c_message_unpack(
		&signal__server_certificate__certificate__descriptor,
		NULL, sender_cert->signer->certificate.len,
		sender_cert->signer->certificate.data);
	LOGr(!server_cert, "unid: protobuf-unpacking server certificate -> %p\n", server_cert);

	if (!server_cert->has_id || !server_cert->has_key) {
		LOG(ERROR, "unid's unpacked server certificate is missing fields\n");
		r = SG_ERR_INVALID_MESSAGE;
		goto done;
	}

/* TODO:
      validator.validate(content.getSenderCertificate(), timestamp);

      if (!MessageDigest.isEqual(content.getSenderCertificate().getKey().serialize(), staticKeyBytes)) {
        throw new InvalidKeyException("Sender's certificate key does not match key used in message");
      }

      if (content.getSenderCertificate().getSender().equals(localAddress.getName()) &&
          content.getSenderCertificate().getSenderDeviceId() == localAddress.getDeviceId())
      {
        throw new SelfSendException();
      }
*/

	struct signal_protocol_address addr = {
		sender_cert->sender,
		strlen(sender_cert->sender),
		sender_cert->senderdevice,
	};

	Signalservice__Envelope__Type type;
	switch (dec_msg->type) {
	case SIGNAL__UNIDENTIFIED_SENDER_MESSAGE__MESSAGE__TYPE__MESSAGE:
		type = CIPHERTEXT;
		break;
	case SIGNAL__UNIDENTIFIED_SENDER_MESSAGE__MESSAGE__TYPE__PREKEY_MESSAGE:
		type = PREKEY_BUNDLE;
		break;
	default:
		LOG(ERROR, "unid's decrypted message type %d not understood\n",
		    dec_msg->type);
		r = SG_ERR_INVALID_MESSAGE;
		goto done;
	}

	r = received_ciphertext_or_prekey_bundle2(ws, e, &addr, type,
	                                          &dec_msg->content, ksc);
	LOGr(r, "received_ciphertext_or_prekey_bundle2() -> %d\n", r);

done:
	if (server_cert)
		protobuf_c_message_free_unpacked(&server_cert->base, NULL);
	if (sender_cert)
		protobuf_c_message_free_unpacked(&sender_cert->base, NULL);
	if (dec_msg)
		protobuf_c_message_free_unpacked(&dec_msg->base, NULL);
	signal_buffer_free(dec_msg_buf);
	if (msg)
		signal__unidentified_sender_message__free_unpacked(msg, NULL);
	return r;
}

static bool received_envelope(ws_s *ws, const Signalservice__Envelope *e,
                              struct ksc_ws *ksc)
{
	typedef int received_envelope_handler(ws_s *ws,
	                                      const Signalservice__Envelope *e,
                                              struct ksc_ws *ksc);

	static received_envelope_handler *const handlers[] = {
		[CIPHERTEXT         ] = received_ciphertext_or_prekey_bundle,
		[PREKEY_BUNDLE      ] = received_ciphertext_or_prekey_bundle,
		[RECEIPT            ] = received_receipt,
		[UNIDENTIFIED_SENDER] = received_unidentified_sender,
	};

	if (!e->has_type) {
		LOG(ERROR, "cannot handle envelope without type\n");
		return false;
	}

	received_envelope_handler *handler;
	if (e->type >= KSC_ARRAY_SIZE(handlers) || !(handler = handlers[e->type])) {
		LOG(ERROR, "cannot handle envelope type %d!\n", e->type);
		return false;
	}

	return handler(ws, e, ksc) == 0;
}

static bool is_request_signal_key_encrypted(size_t n_headers,
                                            char *const *headers)
{
	for (size_t i=0; i<n_headers; i++) {
		char *header = headers[i];
		if (strncasecmp(header, "X-Signal-Key", 12))
			continue;
		for (header += 12; *header && isblank(*header); header++);
		if (*header != ':')
			continue;
		for (header += 1; *header && isblank(*header); header++);
		if (!strncasecmp(header, "false", 5))
			return false;
	}
	return true;
}

static int handle_request(ws_s *ws, char *verb, char *path, uint64_t *id,
                          size_t n_headers, char **headers,
                          size_t size, uint8_t *body, void *udata)
{
	struct ksc_ws *ksc = udata;
	bool is_enc = is_request_signal_key_encrypted(n_headers, headers);
	int r = 0;

	if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/message")) {
		/* new message received :) */
		LOG(DEBUG, "message received, encrypted: %d\n", is_enc);/*
		print_hex(stdout, body, size);
		printf("\n");*/
		size_t sg_key_b64_len;
		const char *sg_key_b64 =
			json_store_get_signaling_key_base64(ksc->js,
			                                    &sg_key_b64_len);
		if (!sg_key_b64) {
			LOG(ERROR, "unable retrieve signaling key from JSON store\n");
			return -1;
		}
		if (is_enc && !ksc_decrypt_envelope(&body, &size,
		                                    sg_key_b64,
		                                    sg_key_b64_len)) {
			LOG(ERROR, "error decrypting envelope\n");
			return -1;
		}
		Signalservice__Envelope *e;
		e = signalservice__envelope__unpack(NULL, size, body);
		if (!e) {
			LOG(ERROR, "error decoding envelope protobuf\n");
			return -2;
		}
		LOG(INFO, "received envelope\n");
		if (ksc_log_prints(KSC_LOG_NOTE, ksc->args.log, &log_ctx)) {
			int fd = (ksc->args.log ? ksc->args.log : &KSC_DEFAULT_LOG)->fd;
			ksc_print_envelope(e, fd,
				ksc_log_prints(KSC_LOG_DEBUG, ksc->args.log, &log_ctx));
		}
		r = received_envelope(ws, e, ksc) ? 1 : -3;
		LOG(DEBUG, "handle_request for PUT /api/v1/message returning %d\n", r);
		signalservice__envelope__free_unpacked(e, NULL);
	} else if (!strcmp(verb, "PUT") && !strcmp(path, "/api/v1/queue/empty")) {
		r = 1;
	} else {
		LOG(WARN, "unhandled request: %s %s\n", verb, path);
		r = -1;
	}
	return r;
	(void)id;
}


static void ctx_log(int level, const char *message, size_t len, void *user_data)
{
	struct ksc_ws *ksc = user_data;
	if (ksc->args.log) {
		enum ksc_log_lvl lvl;
		switch (level) {
		case SG_LOG_ERROR  : lvl = KSC_LOG_ERROR; break;
		case SG_LOG_WARNING: lvl = KSC_LOG_WARN; break;
		/* for libsignal-protocol-c, NOTICE is more severe than INFO;
		 * not for us: INFO is an information to the user, while NOTE
		 * is just a note, not a notification */
		case SG_LOG_NOTICE : lvl = KSC_LOG_INFO; break;
		case SG_LOG_INFO   : lvl = KSC_LOG_NOTE; break;
		case SG_LOG_DEBUG  : lvl = KSC_LOG_DEBUG; break;
		default:
			LOG(DEBUG, "Invalid log level %d from signal-protocol-c "
			    "library for the following signal-ctx message.",
			    level);
			lvl = KSC_LOG_ERROR;
		}
		KSC_LOG_(lvl, ksc->args.log, &ksc->args.signal_log_ctx, "%.*s\n",
		         (int)CLAMP(len,0,INT_MAX), message);
	}
}

static void ctx_lock(void *user_data)
{
	struct ksc_ws *ksc = user_data;
	LOG(DEBUG, "ctx_lock()\n");
	ksignal_ctx_ref(ksc);
	int r = pthread_mutex_lock(&ksc->signal_mtx);
	assert(!r);
	(void)r;
}

static void ctx_unlock(void *user_data)
{
	struct ksc_ws *ksc = user_data;
	LOG(DEBUG, "ctx unlock()\n");
	int r = pthread_mutex_unlock(&ksc->signal_mtx);
	assert(!r);
	ksignal_ctx_unref(ksc);
	(void)r;
}

static struct ksc_ws * ksignal_ctx_create(struct json_store *js,
                                          struct ksc_log *log)
{
	struct ksc_ws *ksc = NULL;

	ksc = ksc_calloc(1, sizeof(*ksc));
	REF_INIT(ksc, 0);
	ksignal_ctx_ref(ksc);

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&ksc->signal_mtx, &attr);
	pthread_mutexattr_destroy(&attr);

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	if (!number || !password)
		goto fail;
	int32_t device_id;
	ksc->url = json_store_get_device_id(js, &device_id)
	         ? ksc_ckprintf("%s/v1/websocket/?login=%s.%" PRId32 "&password=%s",
	                        "wss://" KSC_SERVICE_HOST, number, device_id, password)
	         : ksc_ckprintf("%s/v1/websocket/?login=%s&password=%s",
	                        "wss://" KSC_SERVICE_HOST, number, password);

	int r = signal_context_create(&ksc->ctx, ksc);
	if (r) {
		LOGL(ERROR, log, "signal_context_create failed with code %d\n", r);
		goto fail;
	}

	signal_context_set_crypto_provider(ksc->ctx, &ksc_crypto_provider);
	signal_context_set_log_function(ksc->ctx, ctx_log);
	signal_context_set_locking_functions(ksc->ctx, ctx_lock, ctx_unlock);

	r = signal_protocol_store_context_create(&ksc->psctx, ksc->ctx);
	if (r) {
		LOGL(ERROR, log, "signal_protocol_store_context_create failed with code %d\n", r);
		goto fail;
	}

	json_store_protocol_store_init(ksc->psctx, js);

	ksc->js = js;
	return ksc;

fail:
	ksignal_ctx_unref(ksc);
	return NULL;
}

static void on_open(ws_s *ws, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->reconnecting_during_close = false;
	if (ksc->args.on_open)
		ksc->args.on_open(ws, ksc);
}

static void on_close(intptr_t uuid, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->uuid = -1;
	if (ksc->args.on_close_do_reconnect) {
		if (!ksc->reconnecting_during_close) {
			ksc->reconnecting_during_close = true;
			ksc->uuid = ksc_ws_connect_raw(ksc->url,
				.on_open = on_open,
				.handle_request = handle_request,
				.handle_response = NULL,
				.udata = ksc,
				.on_close = on_close,
				.log = ksc->args.log,
			);
		}
		if (ksc->uuid >= 0)
			return;
	}
	if (ksc->args.on_close)
		ksc->args.on_close(uuid, ksc->args.udata);
	ksignal_ctx_unref(ksc);
}

static void on_shutdown(ws_s *s, void *udata)
{
	struct ksc_ws *ksc = udata;
	ksc->args.on_close_do_reconnect = false;
	(void)s;
}

struct ksc_ws * (ksc_ws_connect_service)(struct json_store *js,
                                         struct ksc_ws_connect_service_args args)
{
	struct ksc_ws *ksc = ksignal_ctx_create(js, args.log);
	if (!ksc) {
		LOGL(ERROR, args.log, "error init'ing ksignal_ctx\n");
		return NULL;
	}
	ksc->args = args;
	intptr_t uuid = ksc_ws_connect_raw(ksc->url,
		.on_open = on_open,
		.handle_request = handle_request,
		.handle_response = NULL,
		.udata = ksc,
		.on_close = on_close,
		.on_shutdown = on_shutdown,
		.server_cert_path = args.server_cert_path,
		.log = args.log,
	);
	if (uuid == -1)
		return NULL;
	ksc->uuid = uuid;
	return ksc;
}
