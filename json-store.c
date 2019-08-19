
#include "json-store.h"
#include "utils.h"

#include <signal/signal_protocol.h>

#include <stdio.h>	/* FILE */
#include <assert.h>
#include <limits.h>	/* INT_{MIN,MAX} */
#include <string.h>	/* strncmp() */
#include <errno.h>
#include <sys/stat.h>	/* S_* flags for open(3p) */
#include <fcntl.h>	/* open() */
#include <unistd.h>	/* lockf() */

#define BUFSIZE		4096

struct json_store {
	struct kjson_value cfg;
	char *data;
	size_t data_cap;
	size_t data_sz;
	int fd;
	char *path;
};

static char * json_store_alloc(struct json_store *js, size_t n)
{
	size_t sz = js->data_sz + n;
	if (sz > js->data_cap) {
		size_t new_cap = MAX(sz, 2 * js->data_cap);
		void *p = realloc(js->data, new_cap);
		if (!p)
			return NULL;
		js->data_cap = new_cap;
		js->data = p;
	}
	char *r = js->data + js->data_sz;
	js->data_sz += n;
	return r;
}

bool json_store_load(struct json_store *js)
{
	js->data_sz = 0;
	static char buf[BUFSIZE];
	if (lseek(js->fd, 0, SEEK_SET) == (off_t)-1)
		return false;
	errno = 0;
	for (ssize_t rd; (rd = read(js->fd, buf, sizeof(buf))) > 0;) {
		char *data = json_store_alloc(js, rd);
		if (!data)
			break;
		memcpy(data, buf, rd);
	}
	if (errno)
		return false;
	kjson_value_fini(&js->cfg);
	js->cfg.type = KJSON_VALUE_NULL;
	bool r = kjson_parse(&(struct kjson_parser){ js->data }, &js->cfg);
	if (!r)
		assert(js->cfg.type == KJSON_VALUE_NULL);
	else {
		bool modified = false;
		struct kjson_value *ax;
		if (!(ax = kjson_get(&js->cfg, "axolotlStore"))) {
			modified = true;
			ax = &kjson_object_push_back(&js->cfg.o, (struct kjson_object_entry){
				.key = { .begin = "axolotlStore", .len = 12 },
				.value = {
					.type = KJSON_VALUE_OBJECT,
					.o = { .n = 0, .data = NULL },
				},
			})->value;
		}
		if (!kjson_get(ax, "sessionStore")) {
			modified = true;
			kjson_object_push_back(&ax->o, (struct kjson_object_entry){
				.key = { .begin = "sessionStore", .len = 12 },
				.value = {
					.type = KJSON_VALUE_ARRAY,
					.a = { .n = 0, .data = NULL },
				},
			});
		}
		if (!kjson_get(ax, "preKeys")) {
			modified = true;
			kjson_object_push_back(&ax->o, (struct kjson_object_entry){
				.key = { .begin = "preKeys", .len = 7 },
				.value = {
					.type = KJSON_VALUE_ARRAY,
					.a = { .n = 0, .data = NULL },
				},
			});
		}
		if (!kjson_get(ax, "signedPreKeyStore")) {
			modified = true;
			kjson_object_push_back(&ax->o, (struct kjson_object_entry){
				.key = { .begin = "signedPreKeyStore", .len = 17 },
				.value = {
					.type = KJSON_VALUE_ARRAY,
					.a = { .n = 0, .data = NULL },
				},
			});
		}
		struct kjson_value *idk;
		if (!(idk = kjson_get(ax, "identityKeyStore"))) {
			modified = true;
			idk = &kjson_object_push_back(&ax->o, (struct kjson_object_entry){
				.key = { .begin = "identityKeyStore", .len = 16 },
				.value = {
					.type = KJSON_VALUE_OBJECT,
					.o = { .n = 0, .data = NULL },
				},
			})->value;
		}
		if (!kjson_get(idk, "trustedKeys")) {
			modified = true;
			kjson_object_push_back(&idk->o, (struct kjson_object_entry){
				.key = { "trustedKeys", 11 },
				.value = {
					.type = KJSON_VALUE_ARRAY,
					.a = { .n = 0, .data = NULL },
				},
			});
		}
		if (modified)
			r = json_store_save(js) < 0 ? false : true;
	}
	return r;
}

void json_store_destroy(struct json_store *js)
{
	kjson_value_fini(&js->cfg);
	free(js->data);
	free(js->path);
	close(js->fd); /* also releases lockf(3p) lock */
	free(js);
}

struct json_store * json_store_create(const char *path)
{
	struct json_store *js = NULL;
	int fd = open(path, O_RDWR | O_CLOEXEC | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("open");
		return NULL;
	}
	if (lockf(fd, F_TLOCK, 0) == -1) {
		perror("lockf");
		goto fail;
	}
	js = calloc(1, sizeof(struct json_store));
	if (!js) {
		perror("calloc");
		goto fail;
	}
	js->fd = fd;
	js->path = strdup(path);
	if (!js->path) {
		perror("strdup");
		goto fail_1;
	}
	if (!json_store_load(js)) {
		fprintf(stderr, "json_store_load: failed\n");
		json_store_destroy(js);
		js = NULL;
	}
	return js;

fail_1:
	free(js);
fail:
	close(fd);
	return NULL;
}

int json_store_save(struct json_store *js)
{
	char *tmp = ckprintf("%sXXXXXX", js->path);
	if (!tmp)
		goto fail;
	int tfd = mkstemp(tmp);
	if (tfd == -1)
		goto fail;
	if (fcntl(tfd, F_SETFD, FD_CLOEXEC) == -1)
		goto fail_1;
	if (lockf(tfd, F_TLOCK, 0) == -1)
		goto fail_1;
	int tfd2 = dup(tfd);
	if (tfd2 == -1)
		goto fail_1;
	FILE *f = fdopen(tfd2, "w");
	if (!f)
		goto fail_2;
	kjson_value_print(f, &js->cfg);
	if (fclose(f) == EOF)
		goto fail_1;
	if (fsync(tfd) == -1)
		goto fail_1;

	if (rename(tmp, js->path) == -1)
		goto fail_1;

	free(tmp);
	close(js->fd);
	js->fd = tfd;
#if 1
	return 0;
#else
	bool r = json_store_load(js);
	return r ? 0 : -2;
#endif

fail_2:
	close(tfd2);
fail_1:
	close(tfd);
fail:
	free(tmp);
	return -1;
}

const struct kjson_value * json_store_get(const struct json_store *js)
{
	return &js->cfg;
}

static int kjscmp(const struct kjson_string *a, const char *b, size_t b_len)
{
	ssize_t r = a->len - b_len;
	if (r)
		return r < 0 ? -1 : 1;
	return strncmp(a->begin, b, b_len);
}

static struct kjson_value *
find_by_address(struct kjson_value *st, const signal_protocol_address *address)
{
	assert(st->type == KJSON_VALUE_ARRAY);
	for (size_t i=0; st && i<st->a.n; i++) {
		struct kjson_value *v = &st->a.data[i];
		struct kjson_value *name = kjson_get(v, "name");
		struct kjson_value *devid = kjson_get(v, "deviceId");
		assert(name->type == KJSON_VALUE_STRING);
		assert(devid->type == KJSON_VALUE_NUMBER_INTEGER);
		if (kjscmp(&name->s, address->name, address->name_len) ||
		    devid->i != address->device_id)
			continue;
		return v;
	}
	return NULL;
}

static struct kjson_value * sess_store(struct json_store *js)
{
	struct kjson_value *ax = kjson_get(&js->cfg, "axolotlStore");
	struct kjson_value *st = kjson_get(ax, "sessionStore");
	return st;
}

static void base64_to_signal_buffer(signal_buffer **buf, struct kjson_value *r)
{
	assert(r && r->type == KJSON_VALUE_STRING);
	size_t n = base64_decode_size(r->s.begin, r->s.len);
	signal_buffer *b = signal_buffer_alloc(n);
	ssize_t k = base64_decode(signal_buffer_data(b), r->s.begin, r->s.len);
	assert(k >= 0);
	assert((size_t)k == n);
	*buf = b;
}

static int sess_load_session_func(signal_buffer **record,
                                  signal_buffer **user_record,
                                  const signal_protocol_address *address,
                                  void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sess_store(js);
	struct kjson_value *v = find_by_address(st, address);
	if (!v)
		return 0;
	base64_to_signal_buffer(record, kjson_get(v, "record"));
	if (user_record)
		*user_record = NULL;
	return 1;
}

static int sess_get_sub_device_sessions_func(signal_int_list **sessions,
                                             const char *name, size_t name_len,
                                             void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sess_store(js);
	assert(st->type == KJSON_VALUE_ARRAY);
	signal_int_list *r = signal_int_list_alloc();
	for (size_t i=0; st && i<st->a.n; i++) {
		struct kjson_value *v = &st->a.data[i];
		struct kjson_value *nm = kjson_get(v, "name");
		assert(nm->type == KJSON_VALUE_STRING);
		if (kjscmp(&nm->s, name, name_len))
			continue;
		struct kjson_value *devid = kjson_get(v, "deviceId");
		assert(devid->type == KJSON_VALUE_NUMBER_INTEGER);
		assert(INT_MIN <= devid->i && devid->i <= INT_MAX);
		signal_int_list_push_back(r, devid->i);
	}
	*sessions = r;
	return signal_int_list_size(r);
}

static struct kjson_array array_copy_shallow(struct kjson_array *a)
{
	return (struct kjson_array){
		.data = memdup(&a->data, sizeof(*a->data) * a->n),
		.n = a->n,
	};
}

static int array_handle_store_result(int r, struct kjson_array *tgt,
                                     struct kjson_array shallow_org)
{
	if (r < 0) {
		free(tgt->data);
		*tgt = shallow_org;
	} else
		free(shallow_org.data);
	return r;
}

static struct kjson_value kjson_value_dup(struct kjson_value *v)
{
	struct kjson_value r = *v;
	switch (r.type) {
	case KJSON_VALUE_NULL:
	case KJSON_VALUE_BOOLEAN:
	case KJSON_VALUE_NUMBER_INTEGER:
	case KJSON_VALUE_NUMBER_DOUBLE:
	case KJSON_VALUE_STRING:
		break;
	case KJSON_VALUE_ARRAY:
		r.a.data = malloc(sizeof(*r.a.data) * r.a.n);
		for (size_t i=0; i<r.a.n; i++)
			r.a.data[i] = kjson_value_dup(&v->a.data[i]);
		break;
	case KJSON_VALUE_OBJECT:
		r.o.data = malloc(sizeof(*r.o.data) * r.o.n);
		for (size_t i=0; i<r.o.n; i++)
			r.o.data[i].value = kjson_value_dup(&v->o.data[i].value);
		break;
	}
	return r;
}

static int sess_store_session_func(const signal_protocol_address *address,
                                   uint8_t *record, size_t record_len,
                                   uint8_t *user_record, size_t user_record_len,
                                   void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sess_store(js);
	char *record_enc = json_store_alloc(js, (record_len + 2) / 3 * 4);
	assert(record_enc);
	ssize_t n = base64_encode(record_enc, record, record_len);
	assert(n >= 0);
	assert((size_t)n == (record_len + 2) / 3 * 4);
	struct kjson_string record_str = { record_enc, n };
	struct kjson_value *v = find_by_address(st, address);
	int r;
	if (v) {
		struct kjson_value *s = kjson_get(v, "record");
		assert(s->type == KJSON_VALUE_STRING);
		struct kjson_string org = s->s;
		s->s = record_str;
		r = json_store_save(js);
		if (r < 0)
			s->s = org;
		goto done;
	}
	struct kjson_object_entry entries[] = {
		{ .key = { "name", 4 }, .value = {
			.type = KJSON_VALUE_STRING,
			.s = { (char *)address->name, address->name_len },
		} },
		{ .key = { "deviceId", 8 }, .value = {
			.type = KJSON_VALUE_NUMBER_INTEGER,
			.i = address->device_id,
		} },
		{ .key = { "record", 6 }, .value = {
			.type = KJSON_VALUE_STRING,
			.s = record_str,
		} },
	};
	struct kjson_value entry = {
		.type = KJSON_VALUE_OBJECT,
		.o = { .data = entries, .n = ARRAY_SIZE(entries), },
	};
	struct kjson_value e = kjson_value_dup(&entry);
	kjson_array_push_back(&st->a, e);
	r = json_store_save(js);
	if (r < 0) {
		kjson_value_fini(&e);
		st->a.n--;
	}
done:
	return r;
	(void)user_record, (void)user_record_len;
}

static int sess_contains_session_func(const signal_protocol_address *address,
                                      void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sess_store(js);
	return find_by_address(st, address) ? 1 : 0;
}

static int sess_delete_session_func(const signal_protocol_address *address,
                                    void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sess_store(js);
	struct kjson_value *v = find_by_address(st, address);
	if (!v)
		return 0;
	struct kjson_array org = array_copy_shallow(&st->a);
	kjson_array_remove(&st->a, v);
	return array_handle_store_result(json_store_save(js), &st->a, org);
}

static int sess_delete_all_sessions_func(const char *name, size_t name_len,
                                         void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sess_store(js);
	assert(!st || st->type == KJSON_VALUE_ARRAY);
	int removed = 0;
	if (!st)
		return removed;
	struct kjson_array org = array_copy_shallow(&st->a);
	for (size_t i=0; st && i<st->a.n; i++) {
		struct kjson_value *v = &st->a.data[i];
		struct kjson_value *nm = kjson_get(v, "name");
		assert(nm->type == KJSON_VALUE_STRING);
		if (kjscmp(&nm->s, name, name_len))
			continue;
		kjson_array_remove(&st->a, v);
		i--;
		removed++;
	}
	int r = array_handle_store_result(json_store_save(js), &st->a, org);
	return r < 0 ? r : removed;
}

static void sess_destroy_session_func(void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	(void)js;
}

#define SESSION_STORE_INIT(json_st) {                                      \
	.load_session_func            = sess_load_session_func,            \
	.get_sub_device_sessions_func = sess_get_sub_device_sessions_func, \
	.store_session_func           = sess_store_session_func,           \
	.contains_session_func        = sess_contains_session_func,        \
	.delete_session_func          = sess_delete_session_func,          \
	.delete_all_sessions_func     = sess_delete_all_sessions_func,     \
	.destroy_func                 = sess_destroy_session_func,         \
	.user_data                    = (json_st),                         \
}

#define SESSION_STORE_LV(json_st) \
	(signal_protocol_session_store)SESSION_STORE_INIT(json_st)

void session_store_set(struct signal_protocol_session_store *r,
                       struct json_store *st)
{
	*r = SESSION_STORE_LV(st);
}

static struct kjson_value * prek_store(struct json_store *js)
{
	struct kjson_value *ax = kjson_get(&js->cfg, "axolotlStore");
	struct kjson_value *st = kjson_get(ax, "preKeys");
	return st;
}

static struct kjson_value * prek_lookup(struct kjson_value *st,
                                        uint32_t pre_key_id)
{
	assert(st->type == KJSON_VALUE_ARRAY);
	for (size_t i=0; st && i<st->a.n; i++) {
		struct kjson_value *v = &st->a.data[i];
		struct kjson_value *id = kjson_get(v, "id");
		if (!id || id->type != KJSON_VALUE_NUMBER_INTEGER ||
		    id->i != (intptr_t)pre_key_id)
			continue;
		return v;
	}
	return NULL;
}

/**
 * Load a local serialized PreKey record.
 *
 * @param record pointer to a newly allocated buffer containing the record,
 *     if found. Unset if no record was found.
 *     The Signal Protocol library is responsible for freeing this buffer.
 * @param pre_key_id the ID of the local serialized PreKey record
 * @retval SG_SUCCESS if the key was found
 * @retval SG_ERR_INVALID_KEY_ID if the key could not be found
 */
static int prek_load_pre_key(signal_buffer **record, uint32_t pre_key_id,
                             void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = prek_store(js);
	struct kjson_value *v = prek_lookup(st, pre_key_id);
	if (!v)
		return SG_ERR_INVALID_KEY_ID;
	base64_to_signal_buffer(record, kjson_get(v, "record"));
	return SG_SUCCESS;
}

/**
 * Determine whether there is a committed PreKey record matching the
 * provided ID.
 *
 * @param pre_key_id A PreKey record ID.
 * @return 1 if the store has a record for the PreKey ID, 0 otherwise
 */
static int prek_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = prek_store(js);
	struct kjson_value *v = prek_lookup(st, pre_key_id);
	return v ? 1 : 0;
}

/**
 * Store a local serialized PreKey record.
 *
 * @param pre_key_id the ID of the PreKey record to store.
 * @param record pointer to a buffer containing the serialized record
 * @param record_len length of the serialized record
 * @return 0 on success, negative on failure
 */
static int prek_store_pre_key(uint32_t pre_key_id, uint8_t *record,
                              size_t record_len, void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = prek_store(js);
	if (prek_lookup(st, pre_key_id))
		return SG_ERR_INVALID_KEY_ID; /* already exists */
	char *record_enc = json_store_alloc(js, (record_len + 2) / 3 * 4);
	assert(record_enc);
	ssize_t n = base64_encode(record_enc, record, record_len);
	assert(n >= 0);
	assert((size_t)n == (record_len + 2) / 3 * 4);
	struct kjson_object_entry entries[] = {
		{ .key = { "id", 2 }, .value = {
			.type = KJSON_VALUE_NUMBER_INTEGER,
			.i = pre_key_id,
		} },
		{ .key = { "record", 6 }, .value = {
			.type = KJSON_VALUE_STRING,
			.s = { record_enc, n },
		} },
	};
	kjson_array_push_back(&st->a, kjson_value_dup(&(struct kjson_value){
		.type = KJSON_VALUE_OBJECT,
		.o = { .n = ARRAY_SIZE(entries), .data = entries },
	}));
	int r = json_store_save(js);
	if (r < 0)
		kjson_value_fini(st->a.data + --st->a.n);
	return r;
}

/**
 * Delete a PreKey record from local storage.
 *
 * @param pre_key_id The ID of the PreKey record to remove.
 * @return 0 on success, negative on failure
 */
static int prek_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = prek_store(js);
	struct kjson_value *v = prek_lookup(st, pre_key_id);
	if (!v)
		return SG_ERR_INVALID_KEY_ID; /* key does not exist */
	struct kjson_array org = array_copy_shallow(&st->a);
	kjson_array_remove(&st->a, v);
	return array_handle_store_result(json_store_save(js), &st->a, org);
}

static void prek_destroy_func(void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	(void)js;
}

#define PRE_KEY_STORE_INIT(json_st) {              \
	.load_pre_key     = prek_load_pre_key,     \
	.store_pre_key    = prek_store_pre_key,    \
	.contains_pre_key = prek_contains_pre_key, \
	.remove_pre_key   = prek_remove_pre_key,   \
	.destroy_func     = prek_destroy_func,     \
	.user_data        = (json_st),             \
}

#define PRE_KEY_STORE_LV(json_st) \
	(signal_protocol_pre_key_store)PRE_KEY_STORE_INIT(json_st)


static struct kjson_value * sipk_store(struct json_store *js)
{
	struct kjson_value *ax = kjson_get(&js->cfg, "axolotlStore");
	struct kjson_value *st = kjson_get(ax, "signedPreKeyStore");
	return st;
}

static struct kjson_value * sipk_lookup(struct kjson_value *st,
                                      uint32_t pre_key_id)
{
	assert(st->type == KJSON_VALUE_ARRAY);
	for (size_t i=0; st && i<st->a.n; i++) {
		struct kjson_value *v = &st->a.data[i];
		struct kjson_value *id = kjson_get(v, "id");
		if (!id || id->type != KJSON_VALUE_NUMBER_INTEGER ||
		    id->i != (intptr_t)pre_key_id)
			continue;
		return v;
	}
	return NULL;
}

/**
 * Load a local serialized signed PreKey record.
 *
 * @param record pointer to a newly allocated buffer containing the record,
 *     if found. Unset if no record was found.
 *     The Signal Protocol library is responsible for freeing this buffer.
 * @param signed_pre_key_id the ID of the local signed PreKey record
 * @retval SG_SUCCESS if the key was found
 * @retval SG_ERR_INVALID_KEY_ID if the key could not be found
 */
static int sipk_load_signed_pre_key(signal_buffer **record,
                                    uint32_t signed_pre_key_id,
                                    void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sipk_store(js);
	struct kjson_value *v = sipk_lookup(st, signed_pre_key_id);
	if (!v)
		return SG_ERR_INVALID_KEY_ID;
	base64_to_signal_buffer(record, kjson_get(v, "record"));
	return SG_SUCCESS;
}

/**
 * Store a local serialized signed PreKey record.
 *
 * @param signed_pre_key_id the ID of the signed PreKey record to store
 * @param record pointer to a buffer containing the serialized record
 * @param record_len length of the serialized record
 * @return 0 on success, negative on failure
 */
static int sipk_store_signed_pre_key(uint32_t signed_pre_key_id,
                                     uint8_t *record, size_t record_len,
                                     void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sipk_store(js);
	if (prek_lookup(st, signed_pre_key_id))
		return SG_ERR_INVALID_KEY_ID; /* already exists */
	char *record_enc = json_store_alloc(js, (record_len + 2) / 3 * 4);
	assert(record_enc);
	ssize_t n = base64_encode(record_enc, record, record_len);
	assert(n >= 0);
	assert((size_t)n == (record_len + 2) / 3 * 4);
	struct kjson_object_entry entries[] = {
		{ .key = { "id", 2 }, .value = {
			.type = KJSON_VALUE_NUMBER_INTEGER,
			.i = signed_pre_key_id,
		} },
		{ .key = { "record", 6 }, .value = {
			.type = KJSON_VALUE_STRING,
			.s = { record_enc, n },
		} },
	};
	kjson_array_push_back(&st->a, kjson_value_dup(&(struct kjson_value){
		.type = KJSON_VALUE_OBJECT,
		.o = { .n = ARRAY_SIZE(entries), .data = entries },
	}));
	int r = json_store_save(js);
	if (r < 0)
		kjson_value_fini(st->a.data + --st->a.n);
	return r;
}

/**
 * Determine whether there is a committed signed PreKey record matching
 * the provided ID.
 *
 * @param signed_pre_key_id A signed PreKey record ID.
 * @return 1 if the store has a record for the signed PreKey ID, 0 otherwise
 */
static int sipk_contains_signed_pre_key(uint32_t signed_pre_key_id,
                                        void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sipk_store(js);
	struct kjson_value *v = sipk_lookup(st, signed_pre_key_id);
	return v ? 1 : 0;
}

/**
 * Delete a SignedPreKeyRecord from local storage.
 *
 * @param signed_pre_key_id The ID of the signed PreKey record to remove.
 * @return 0 on success, negative on failure
 */
static int sipk_remove_signed_pre_key(uint32_t signed_pre_key_id,
                                      void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = sipk_store(js);
	struct kjson_value *v = sipk_lookup(st, signed_pre_key_id);
	if (!v)
		return SG_ERR_INVALID_KEY_ID; /* key does not exist */
	struct kjson_array org = array_copy_shallow(&st->a);
	kjson_array_remove(&st->a, v);
	return array_handle_store_result(json_store_save(js), &st->a, org);
}

/**
 * Function called to perform cleanup when the data store context is being
 * destroyed.
 */
static void sipk_destroy_func(void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	(void)js;
}

#define SIPK_STORE_INIT(json_st) {                               \
	.load_signed_pre_key     = sipk_load_signed_pre_key,     \
	.store_signed_pre_key    = sipk_store_signed_pre_key,    \
	.contains_signed_pre_key = sipk_contains_signed_pre_key, \
	.remove_signed_pre_key   = sipk_remove_signed_pre_key,   \
	.destroy_func            = sipk_destroy_func,            \
	.user_data               = (json_st),                    \
}

#define SIPK_STORE_LV(json_st) \
	(signal_protocol_signed_pre_key_store)SIPK_STORE_INIT(json_st)


static struct kjson_value * idk_store(struct json_store *js)
{
	struct kjson_value *ax = kjson_get(&js->cfg, "axolotlStore");
	struct kjson_value *st = kjson_get(ax, "identityKeyStore");
	return st;
}

#include "LocalStorageProtocol.pb-c.h"

/**
 * Get the local client's identity key pair.
 *
 * @param public_data pointer to a newly allocated buffer containing the
 *     public key, if found. Unset if no record was found.
 *     The Signal Protocol library is responsible for freeing this buffer.
 * @param private_data pointer to a newly allocated buffer containing the
 *     private key, if found. Unset if no record was found.
 *     The Signal Protocol library is responsible for freeing this buffer.
 * @return 0 on success, negative on failure
 */
static int idk_get_identity_key_pair(signal_buffer **public_data,
                                     signal_buffer **private_data,
                                     void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = idk_store(js);
	signal_buffer *pb_keys = NULL;
	base64_to_signal_buffer(&pb_keys, kjson_get(st, "identityKey"));
	Ksignal__IdentityKeyPairStructure *ikp;
	ikp = ksignal__identity_key_pair_structure__unpack(NULL,
	                                                   signal_buffer_len(pb_keys),
	                                                   signal_buffer_data(pb_keys));
	assert(ikp);
	assert(ikp->has_publickey);
	assert(ikp->has_privatekey);
	signal_buffer_free(pb_keys);
	*public_data = signal_buffer_create(ikp->publickey.data, ikp->publickey.len);
	*private_data = signal_buffer_create(ikp->privatekey.data, ikp->privatekey.len);
	ksignal__identity_key_pair_structure__free_unpacked(ikp, NULL);
	return 0;
}

/**
 * Return the local client's registration ID.
 *
 * Clients should maintain a registration ID, a random number
 * between 1 and 16380 that's generated once at install time.
 *
 * @param registration_id pointer to be set to the local client's
 *     registration ID, if it was successfully retrieved.
 * @return 0 on success, negative on failure
 */
static int idk_get_local_registration_id(void *user_data,
                                         uint32_t *registration_id)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = idk_store(js);
	struct kjson_value *v = kjson_get(st, "registrationId");
	if (!v || v->type != KJSON_VALUE_NUMBER_INTEGER ||
	    v->i < 0 || v->i > UINT32_MAX)
		return -EINVAL;
	*registration_id = v->i;
	return 0;
}

static
struct kjson_value * idk_lookup_tk(struct kjson_value *st,
                                   const signal_protocol_address *address)
{
	struct kjson_value *tk = kjson_get(st, "trustedKeys");
	for (size_t i=0; i<tk->a.n; i++) {
		struct kjson_value *entry = &tk->a.data[i];
		struct kjson_value *name = kjson_get(entry, "name");
		assert(name->type == KJSON_VALUE_STRING);
		if (kjscmp(&name->s, address->name, address->name_len))
			continue;
		struct kjson_value *devid = kjson_get(entry, "deviceId");
		if (devid) {
			assert(devid->type == KJSON_VALUE_NUMBER_INTEGER);
			if (devid->i != address->device_id)
				continue;
		}
		return entry;
	}
	return NULL;
}

/**
 * Save a remote client's identity key
 * <p>
 * Store a remote client's identity key as trusted.
 * The value of key_data may be null. In this case remove the key data
 * from the identity store, but retain any metadata that may be kept
 * alongside it.
 *
 * @param address the address of the remote client
 * @param key_data Pointer to the remote client's identity key, may be null
 * @param key_len Length of the remote client's identity key
 * @return 0 on success, negative on failure
 */
static int idk_save_identity(const signal_protocol_address *address,
                             uint8_t *key_data, size_t key_len, void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = idk_store(js);
	struct kjson_value *tk = kjson_get(st, "trustedKeys");
	struct kjson_value *e = idk_lookup_tk(st, address);
	struct kjson_array org_tk = tk->a;
	if (!e) {
		size_t len = address->name_len;
		char *name = memcpy(json_store_alloc(js, len), address->name, len);
		struct kjson_object_entry entries[] = {
			{ .key = { "name", 4 }, .value = {
				.type = KJSON_VALUE_STRING,
				.s = { name, len },
			} },
		};
		e = kjson_array_push_back(&tk->a, kjson_value_dup(&(struct kjson_value){
			.type = KJSON_VALUE_OBJECT,
			.o = { .n = ARRAY_SIZE(entries), .data = entries },
		}));
	}
	struct kjson_value *idk = kjson_get(e, "identityKey");
	if (key_data) {
		struct kjson_string record_str = { NULL, 0 };
		char *record_enc = json_store_alloc(js, (key_len + 2) / 3 * 4);
		assert(record_enc);
		ssize_t n = base64_encode(record_enc, key_data, key_len);
		assert(n >= 0);
		assert((size_t)n == (key_len + 2) / 3 * 4);
		record_str.begin = record_enc;
		record_str.len = n;
		if (idk) {
			/* update idk in e */
			idk->s = record_str;
		} else {
			/* insert idk into e */
			kjson_object_push_back(&e->o, (struct kjson_object_entry){
				.key = { "identityKey", 11 },
				.value = {
					.type = KJSON_VALUE_STRING,
					.s = record_str,
				},
			});
		}
	} else if (idk) {
		/* remove idk from e */
		kjson_object_remove(&e->o, (struct kjson_object_entry *)(
			(char *)idk - offsetof(struct kjson_object_entry, value)
		));
	}
	int r = json_store_save(js);
	if (r < 0) { /* TODO */
		fprintf(stderr,
		        "ERROR %d saving identity key, session state garbled!\n",
		        r);
	}
	return r;
	(void)key_len;
}

/**
 * Verify a remote client's identity key.
 *
 * Determine whether a remote client's identity is trusted.  Convention is
 * that the TextSecure protocol is 'trust on first use.'  This means that
 * an identity key is considered 'trusted' if there is no entry for the recipient
 * in the local store, or if it matches the saved key for a recipient in the local
 * store.  Only if it mismatches an entry in the local store is it considered
 * 'untrusted.'
 *
 * @param address the address of the remote client
 * @param identityKey The identity key to verify.
 * @param key_data Pointer to the identity key to verify
 * @param key_len Length of the identity key to verify
 * @return 1 if trusted, 0 if untrusted, negative on failure
 */
static int idk_is_trusted_identity(const signal_protocol_address *address,
                                   uint8_t *key_data, size_t key_len,
                                   void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	struct kjson_value *st = idk_store(js);
	struct kjson_value *e = idk_lookup_tk(st, address);
	if (!e)
		return 1;
	struct kjson_value *idk = kjson_get(e, "identityKey");
	if (!idk || idk->type != KJSON_VALUE_STRING)
		return 0;
	signal_buffer *key = NULL;
	base64_to_signal_buffer(&key, idk);
	int r = signal_buffer_len(key) == key_len &&
	        !memcmp(signal_buffer_data(key), key_data, key_len);
	signal_buffer_free(key);
	return r;
}

/**
 * Function called to perform cleanup when the data store context is being
 * destroyed.
 */
static void idk_destroy_func(void *user_data)
{
	printf("%s:%d in %s\n", __FILE__, __LINE__, __FUNCTION__);
	struct json_store *js = user_data;
	(void)js;
}

#define IDK_STORE_INIT(json_st) { \
	.get_identity_key_pair     = idk_get_identity_key_pair, \
	.get_local_registration_id = idk_get_local_registration_id, \
	.save_identity             = idk_save_identity, \
	.is_trusted_identity       = idk_is_trusted_identity, \
	.destroy_func              = idk_destroy_func, \
	.user_data                 = (json_st), \
}

#define IDK_STORE_LV(json_st) \
	(signal_protocol_identity_key_store)IDK_STORE_INIT(json_st)

void protocol_store_init(signal_protocol_store_context *c,
                         struct json_store *s)
{
	signal_protocol_store_context_set_session_store(c, &SESSION_STORE_LV(s));
	signal_protocol_store_context_set_pre_key_store(c, &PRE_KEY_STORE_LV(s));
	signal_protocol_store_context_set_signed_pre_key_store(c, &SIPK_STORE_LV(s));
	signal_protocol_store_context_set_identity_key_store(c, &IDK_STORE_LV(s));
}

/*
signal_protocol_sender_key_store sender_key_store;
*/
