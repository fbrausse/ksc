
#include "ksignal-ws.h"
#include "provisioning.h"
#include "utils.h"
#include "json-store.h"
#include "ksc-ws.h"
#include "SignalService.pb-c.h"

#include <assert.h>
#include <time.h>	/* ctime_r() */

static void print_data_message(Signalservice__DataMessage *e)
{
	if (e->body)
		printf("  body: %s\n", e->body);
	printf("  attachments: %zu\n", e->n_attachments);
	if (e->group) {
		struct _Signalservice__GroupContext *g = e->group;
		printf("  has group info:\n");
		if (g->has_id) {
			printf("    id: ");
			print_hex(stdout, g->id.data, g->id.len);
			printf("\n");
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
			printf("    type: %s (%d)\n", type, g->type);
		}
		if (g->name)
			printf("    name: %s\n", g->name);
		for (size_t i=0; i<g->n_members; i++)
			printf("    member: %s\n", g->members[i]);
		if (g->avatar)
			printf("    has avatar\n");
	}
	if (e->has_flags)
		printf("  flags: 0x%x\n", e->flags);
	if (e->has_expiretimer)
		printf("  expire timer: %ud\n", e->expiretimer);
	if (e->has_profilekey) {
		printf("  profile key:\n");
		print_hex(stdout, e->profilekey.data, e->profilekey.len);
		printf("\n");
	}
	if (e->has_timestamp) {
		char buf[32];
		time_t t = e->timestamp / 1000;
		ctime_r(&t, buf);
		printf("  timestamp: %s", buf);
	}
	if (e->quote)
		printf("  has quote\n");
	printf("  # contacts: %zu\n", e->n_contact);
	printf("  # previews: %zu\n", e->n_preview);
	if (e->sticker)
		printf("  has sticker\n");
	if (e->has_requiredprotocolversion)
		printf("  required protocol version: %ud\n",
		       e->requiredprotocolversion);
	if (e->has_messagetimer)
		printf("  message timer: %ud\n", e->messagetimer);
}

static void on_close_do_stop(intptr_t uuid, void *udata)
{
	printf("close, stopping\n");
	fio_stop();
	(void)uuid;
	(void)udata;
}

static void handle_new_uuid(char *uuid, void *udata)
{
	printf("got new uuid: %s\n", uuid);
	(void)uuid;
	(void)udata;
}

#define DIE(code,...) do { fprintf(stderr, __VA_ARGS__); exit(code); } while (0)

static int recv_get_profile(ws_s *ws, struct signal_response *r, void *udata)
{
	fprintf(stderr, "recv get profile: %u %s: ",
	        r->status, r->message);

	if (r->status != 200) {
		fprintf(stderr, "\n");
		return 0;
	}

	FIOBJ profile;
	size_t parsed = fiobj_json2obj(&profile, r->body.data, r->body.len);
	fprintf(stderr, "fio json parsed %zu of %zu",
	        parsed, r->body.len);
	if (parsed) {
		FIOBJ str = fiobj_obj2json(profile, 1);
		fio_str_info_s s = fiobj_obj2cstr(str);
		fprintf(stderr, ": %.*s\n", (int)s.len, s.data);
		fiobj_free(str);
		fiobj_free(profile);
	} else
		fprintf(stderr, ", failed\n");

	fprintf(stderr, "recv get profile: ");
	struct kjson_value p = KJSON_VALUE_INIT;
	if (kjson_parse(&(struct kjson_parser){ r->body.data }, &p)) {
		kjson_value_print(stderr, &p);
		fprintf(stderr, "\n");
	} else
		fprintf(stderr, "error parsing profile json: '%.*s'\n",
		        (int)r->body.len, r->body.data);
	kjson_value_fini(&p);

	return 0;
	(void)udata;
	(void)ws;
}

static int recv_get_pre_key(ws_s *ws, struct signal_response *r, void *udata)
{
	fprintf(stderr, "recv get pre key: %u %s: %.*s\n",
	        r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)udata;
	(void)ws;
}

static int recv_get_cert_delivery(ws_s *ws, struct signal_response *r,
                                  void *udata)
{
	fprintf(stderr, "recv get certificate delivery: %u %s: %.*s\n",
	        r->status, r->message, (int)r->body.len, r->body.data);
	return 0;
	(void)udata;
	(void)ws;
}

static int recv_messages(ws_s *ws, struct signal_response *r,
                                  void *udata)
{
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
	printf("recv messages: %d %s\n", r->status, r->message);
	for (size_t i=0; i<r->n_headers; i++)
		printf("  header: %s\n", r->headers[i]);
	printf("  body: %.*s\n", (int)r->body.len, r->body.data);
	return 0;
	(void)ws;
	(void)udata;
}

static void send_get_profile(ws_s *s, void *udata)
{
#if 0 && defined(DEFAULT_GET_PROFILE_NUMBER)
	signal_ws_send_request(s, "GET",
	                       "/v1/profile/" DEFAULT_GET_PROFILE_NUMBER,
	                       .on_response = recv_get_profile, .udata = udata);
	signal_ws_send_request(s, "GET",
	                       "/v2/keys/" DEFAULT_GET_PROFILE_NUMBER "/*",
	                       .on_response = recv_get_pre_key, .udata = udata);
	signal_ws_send_request(s, "GET", "/v1/certificate/delivery",
	                       .on_response = recv_get_cert_delivery,
	                       .udata = udata);
#else
	signal_ws_send_request(s, "GET", "/v1/messages/",
	                       .on_response = recv_messages);
	(void)s;
	(void)udata;
#endif
}

static bool on_content(ws_s *ws, const Signalservice__Envelope *e,
                       const Signalservice__Content *c, void *udata)
{
	printf("received content:\n");
	if (c->datamessage)
		print_data_message(c->datamessage);
	return true;
	(void)ws;
	(void)e;
	(void)udata;
}

static void ctx_log(enum ksc_ws_log level, const char *message, size_t len,
                    void *udata)
{
	static const char *const lvls[] = {
		[KSC_WS_LOG_DEBUG  ] = "debug",
		[KSC_WS_LOG_INFO   ] = "info ",
		[KSC_WS_LOG_NOTICE ] = "note ",
		[KSC_WS_LOG_WARNING] = "warn ",
		[KSC_WS_LOG_ERROR  ] = "error",
	};
	printf("[%s] signal ctx: %.*s\n", lvls[level], (int)len, message);
	(void)udata;
}

#ifndef DEFAULT_CLI_CONFIG
# define DEFAULT_CLI_CONFIG	NULL
#endif

int main(int argc, char **argv)
{
	const char *cli_path = DEFAULT_CLI_CONFIG;
	for (int opt; (opt = getopt(argc, argv, ":hp:")) != -1;)
		switch (opt) {
		case 'h':
			fprintf(stderr, "usage: %s [-p CLI_CONFIG_PATH]\n", argv[0]);
			exit(0);
		case 'p': cli_path = optarg; break;
		case ':': DIE(1,"error: option '-%c' requires a parameter\n",
		              optopt);
		case '?': DIE(1,"error: unknown option '-%c'\n",optopt);
		}

	if (!cli_path) {
		fprintf(stderr, "require path to JSON config file\n");
		return 1;
	}

	struct json_store *js = NULL;
	js = json_store_create(cli_path);
	printf("js: %p\n", (void *)js);
	if (!js) {
		fprintf(stderr, "%s: error reading JSON config file\n", cli_path);
		return 1;
	}

	int r = 0;

	const char *number = json_store_get_username(js);
	const char *password = json_store_get_password_base64(js);
	if (!number) {
		fprintf(stderr, "no username, performing a device link\n");
		r = ksignal_defer_get_new_uuid(BASE_URL,
		                               .new_uuid = handle_new_uuid,
		                               .on_close = on_close_do_stop);
	} else if (password) {
		r = ksc_ws_connect(js, .on_content = on_content,
		                       .on_open = send_get_profile,
		                       .on_close = on_close_do_stop,
		                       .signal_ctx_log = ctx_log) ? 0 : 1;
	} else {
		fprintf(stderr, "don't know what to do, username but no password\n");
		r = 1;
	}
	printf("%d\n", r);

	fio_start(.threads=1);

	r = json_store_save(js);
	printf("json_store_save returned %d\n", r);
	if (!r) {
		r = json_store_load(js);
		printf("json_store_load returned %d\n", r);
		r = !r;
	}
	if (!r) {
		r = json_store_save(js);
		printf("json_store_save returned %d\n", r);
	}
	json_store_destroy(js);
	return 0;
}
