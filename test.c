
#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "json-store.h"
#include "ksc-ws.h"
#include "SignalService.pb-c.h"

#include <assert.h>
#include <time.h>	/* ctime_r() */

static const struct ksc_log_context log_ctx = {
	.desc = "main",
	.color = "1;97",
};

/* shortcuts */
#define LOGL_(level,log,...)	KSC_LOG_(level, log, &log_ctx, __VA_ARGS__)
#define LOGL(lvl,log,...)	KSC_LOG(lvl, log, &log_ctx, __VA_ARGS__)
#define LOG_(level,...)		LOGL_(level, &ksc->log, __VA_ARGS__)
#define LOG(lvl,...)		LOGL(lvl, &ksc->log, __VA_ARGS__)

static void print_data_message(int fd, Signalservice__DataMessage *e)
{
	if (e->body)
		dprintf(fd, "  body: %s\n", e->body);
	if (e->n_attachments)
		dprintf(fd, "  attachments: %zu\n", e->n_attachments);
	if (e->group) {
		struct _Signalservice__GroupContext *g = e->group;
		dprintf(fd, "  has group info:\n");
		if (g->has_id) {
			dprintf(fd, "    id: ");
			ksc_dprint_hex(fd, g->id.data, g->id.len);
			dprintf(fd, "\n");
		}
		if (g->has_type) {
			char *type = NULL;
			switch (g->type) {
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__UNKNOWN: type = "unknown"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__UPDATE: type = "update"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__DELIVER: type = "deliver"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__QUIT: type = "quit"; break;
			case SIGNALSERVICE__GROUP_CONTEXT__TYPE__REQUEST_INFO: type = "request info"; break;
			case _SIGNALSERVICE__GROUP_CONTEXT__TYPE_IS_INT_SIZE: break;
			}
			dprintf(fd, "    type: %s (%d)\n", type, g->type);
		}
		if (g->name)
			dprintf(fd, "    name: %s\n", g->name);
		for (size_t i=0; i<g->n_members; i++)
			dprintf(fd, "    member: %s\n", g->members[i]);
		if (g->avatar)
			dprintf(fd, "    has avatar\n");
	}
	if (e->has_flags)
		dprintf(fd, "  flags: 0x%x\n", e->flags);
	if (e->has_expiretimer)
		dprintf(fd, "  expire timer: %ud\n", e->expiretimer);
	if (e->has_profilekey) {
		dprintf(fd, "  profile key:\n");
		ksc_dprint_hex(fd, e->profilekey.data, e->profilekey.len);
		dprintf(fd, "\n");
	}
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		dprintf(fd, "  timestamp: %s", buf);
	}
	if (e->quote)
		dprintf(fd, "  has quote\n");
	if (e->n_contact)
		dprintf(fd, "  # contacts: %zu\n", e->n_contact);
	if (e->n_preview)
		dprintf(fd, "  # previews: %zu\n", e->n_preview);
	if (e->sticker)
		dprintf(fd, "  has sticker\n");
	if (e->has_requiredprotocolversion)
		dprintf(fd, "  required protocol version: %ud\n",
		        e->requiredprotocolversion);
	if (e->has_messagetimer)
		dprintf(fd, "  message timer: %ud\n", e->messagetimer);
}

struct ksc_ctx {
	struct ksc_log log;
};

static void on_close_do_stop(intptr_t uuid, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "close, stopping\n");
	fio_stop();
	(void)uuid;
}

static void handle_new_uuid(char *uuid, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "got new uuid: %s\n", uuid);
}

static int recv_get_profile(ws_s *ws, struct ksc_signal_response *r,
                            void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG_(r->status == 200 ? KSC_LOG_INFO : KSC_LOG_ERROR,
	     "recv get profile: %u %s: ", r->status, r->message);

	if (r->status != 200) {
		dprintf(ksc->log.fd, "\n");
		return 0;
	}

	FIOBJ profile;
	size_t parsed = fiobj_json2obj(&profile, r->body.data, r->body.len);
	LOG(INFO, "fio json parsed %zu of %zu", parsed, r->body.len);
	if (parsed) {
		FIOBJ str = fiobj_obj2json(profile, 1);
		fio_str_info_s s = fiobj_obj2cstr(str);
		dprintf(ksc->log.fd, ": %.*s\n", (int)s.len, s.data);
		fiobj_free(str);
		fiobj_free(profile);
	} else
		dprintf(ksc->log.fd, ", failed\n");

	LOG(INFO, "recv get profile: ");
	struct kjson_value p = KJSON_VALUE_INIT;
	if (kjson_parse(&(struct kjson_parser){ r->body.data }, &p)) {
		kjson_value_print(stderr, &p);
		dprintf(ksc->log.fd, "\n");
	} else
		dprintf(ksc->log.fd, "error parsing profile json: '%.*s'\n",
		        (int)r->body.len, r->body.data);
	kjson_value_fini(&p);

	return 0;
	(void)udata;
	(void)ws;
}

static int recv_get_pre_key(ws_s *ws, struct ksc_signal_response *r,
                            void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "recv get pre key: %u %s: %.*s\n",
	          r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)ws;
}

static int recv_get_cert_delivery(ws_s *ws, struct ksc_signal_response *r,
                                  void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "recv get certificate delivery: %u %s: %.*s\n",
	          r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)ws;
}

#if 0
Output is something like this:
recv messages: 200 OK
  body: {
	"messages": [
		{ "guid":"e9842d55-dd8c-4b19-9c2e-88359e49a371"
		, "type":3
		, "relay":""
		, "timestamp":1566388636374
		, "source":"NUMBER"
		, "sourceDevice":DEVICE_ID
		, "message":null
		, "content":"MwgKEiEFAMYX3sB2QebY8yLneK/XF/iv6KXCkk8QJKaXZ/ZFizkaIQUZpRraju9k6p3I1oa5Y9cuFMc6wBvivPQxoGQVzTGhIyLTATMKIQVHly4+yvNDrwcOMqeO/GSrLIhlk6e9bBxXTcDEUYaSXhA/GAAioAHuCFL9nHnwSC7I1fuT1Lz2BDg0AzkGMcxVMXIvqYDaUEIS35aOprUjuTqpzz9fOguz6eDIAqCBnASc0tvlaUZ1xrM1n8KSzVXFDR8z3hlZAiH1qJ6Z4rH/AZx8kq0bw0KLzjBqgn42aMzNsGuahduPTWZjHZDABgupIS9AefDhh/LU19Y/WOQHRJBiT203b79QS2/DhKoQwLJMVsC4VON3BkQO50153Zsotm0wAA=="
		, "serverTimestamp":1566388652354
		}
	],
	"more":false
}
These should be ACK-ed as per fio_defer(delete_request) ...
#endif
static int recv_messages(ws_s *ws, struct ksc_signal_response *r, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "recv messages: %d %s\n", r->status, r->message);
	if (ksc_log_prints(KSC_LOG_INFO, &ksc->log, &log_ctx)) {
		for (size_t i=0; i<r->n_headers; i++)
			dprintf(ksc->log.fd, "  header: %s\n", r->headers[i]);
		dprintf(ksc->log.fd, "  body: %.*s\n",
		        (int)r->body.len, r->body.data);
	}
	return 0;
	(void)ws;
}

static void send_get_profile(ws_s *s, void *udata)
{
	struct ksc_ctx *ksc = udata;
#if 0 && defined(DEFAULT_GET_PROFILE_NUMBER)
	// works
	ksc_ws_send_request(s, "GET",
	                    "/v1/profile/" DEFAULT_GET_PROFILE_NUMBER,
	                    .on_response = recv_get_profile, .udata = ksc);
	// fails
	ksc_ws_send_request(s, "GET",
	                    "/v2/keys/" DEFAULT_GET_PROFILE_NUMBER "/*",
	                    .on_response = recv_get_pre_key, .udata = ksc);
	// fails
	ksc_ws_send_request(s, "GET", "/v1/certificate/delivery",
	                    .on_response = recv_get_cert_delivery,
	                    .udata = ksc);
#elif 0
	ksc_ws_send_request(s, "GET", "/v1/messages/",
	                    .on_response = recv_messages,
	                    .udata = ksc);
#else
	(void)ksc;
	(void)s;
#endif
}

static bool on_content(ws_s *ws, const Signalservice__Envelope *e,
                       const Signalservice__Content *c, void *udata)
{
	struct ksc_ctx *ksc = udata;
	LOG(INFO, "received content:\n");
	if (ksc_log_prints(KSC_LOG_INFO, &ksc->log, &log_ctx)) {
		ksc_print_envelope(e, ksc->log.fd,
		                   ksc_log_prints(KSC_LOG_DEBUG, &ksc->log, &log_ctx));
	}
	if (c->datamessage && ksc_log_prints(KSC_LOG_INFO, &ksc->log, &log_ctx)) {
		dprintf(ksc->log.fd, "  ------ data ------\n");
		print_data_message(ksc->log.fd, c->datamessage);
	}
	return true;
	(void)ws;
	(void)e;
}


static bool parse_v_lvl(const char *lvl, enum ksc_log_lvl *res)
{
	char *endptr;
	long v = strtol(lvl, &endptr, 0);
	if (endptr == lvl)
		return ksc_log_lvl_parse(lvl, res);
	if (v < KSC_LOG_NONE || v > INT_MAX)
		return false;
	*res = v;
	return true;
}

static bool parse_v(char *arg, struct ksc_log *log)
{
	char *colon = strrchr(arg, ':');
	if (!colon)
		return parse_v_lvl(arg, &log->max_lvl);
	enum ksc_log_lvl lvl;
	if (!parse_v_lvl(colon+1, &lvl))
		return false;
	struct ksc_log__context_lvl *it;
	it = malloc(sizeof(*it));
	it->max_lvl = lvl;
	*colon = '\0';
	it->desc = arg;
	it->next = log->context_lvls;
	log->context_lvls = it;
	return true;
}

#ifndef DEFAULT_CLI_CONFIG
# define DEFAULT_CLI_CONFIG	NULL
#endif

#define DIE(code,...) do { fprintf(stderr, __VA_ARGS__); exit(code); } while (0)

int main(int argc, char **argv)
{
	struct ksc_log log = KSC_DEFAULT_LOG;
	const char *cli_path = DEFAULT_CLI_CONFIG;
	for (int opt; (opt = getopt(argc, argv, ":hp:v:")) != -1;)
		switch (opt) {
		case 'h':
			fprintf(stderr, "usage: %s [-p CLI_CONFIG_PATH] [-v ARG]\n", argv[0]);
			exit(0);
		case 'p': cli_path = optarg; break;
		case 'v':
			if (!parse_v(optarg, &log))
				DIE(1,"error parsing option '-v %s'\n", optarg);
			break;
		case ':': DIE(1,"error: option '-%c' requires a parameter\n",
		              optopt);
		case '?': DIE(1,"error: unknown option '-%c'\n",optopt);
		}

	if (!cli_path) {
		fprintf(stderr, "require path to JSON config file\n");
		return 1;
	}

	struct ksc_ctx ctx = {
		.log = log,
	};
	struct json_store *js = NULL;
	js = json_store_create(cli_path, &ctx.log);
	LOGL_(js ? KSC_LOG_DEBUG : KSC_LOG_ERROR, &ctx.log, "js: %p\n", (void *)js);
	if (!js) {
		fprintf(stderr, "%s: error reading JSON config file\n", cli_path);
		return 1;
	}

	int r = 0;

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	if (!number) {
		fprintf(stderr, "no username, performing a device link\n");
		r = ksc_defer_get_new_uuid(KSC_BASE_URL,
		                           .new_uuid = handle_new_uuid,
		                           .on_close = on_close_do_stop,
		                           .udata = &ctx) < 0;
	} else if (password) {
		intptr_t *uuid;
		uuid = ksc_ws_connect_service(js,
			.on_content = on_content,
			.on_open = send_get_profile,
			.on_close = on_close_do_stop,
			.signal_log_ctx = { "signal ctx", "95" /* bright magenta */ },
			.log = &ctx.log,
			.udata = &ctx
		);
		r = uuid && *uuid >= 0 ? 0 : 1;
	} else {
		fprintf(stderr, "don't know what to do, username but no password\n");
		r = 1;
	}
	LOGL(DEBUG, &ctx.log, "init: %d\n", r);

	fio_start(.threads=1);

	r = json_store_save(js);
	LOGL_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, &ctx.log,
	      "json_store_save returned %d\n", r);
	if (!r) {
		r = json_store_load(js);
		LOGL_(r ? KSC_LOG_DEBUG : KSC_LOG_ERROR, &ctx.log,
		      "json_store_load returned %d\n", r);
		r = !r;
	}
	if (!r) {
		r = json_store_save(js);
		LOGL_(r ? KSC_LOG_ERROR : KSC_LOG_DEBUG, &ctx.log,
		      "json_store_save returned %d\n", r);
	}
	json_store_destroy(js);

	for (struct ksc_log__context_lvl *it, *jt = ctx.log.context_lvls; (it = jt);) {
		jt = it->next;
		free(it);
	}

	return 0;
}
