Building
========
Requires the following prerequisites (all of these refer to the `master`
branch at the linked URL if not specified otherwise):

* GNU make (1)

* The executable `protoc-c` from `protobuf-c`: https://github.com/protobuf-c/protobuf-c

* Installed libraries (found by `pkg-config`(1), see below for customization):
  - libsignal-protocol-c: https://github.com/fbrausse/libsignal-protocol-c
    ```
    mkdir build
    cd build
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=1 -DCMAKE_INSTALL_PREFIX=/some/prefix/path ..
    make install
    ```
    Pass `-DCMAKE_POSITION_INDEPENDENT_CODE=1` if you get linker errors like
    ```
    libsignal-protocol-c.a(gen_veddsa.c.o): relocation R_X86_64_PC32 against symbol `B_bytes' can not be used when making a shared object; recompile with -fPIC
    ```
  - facil.io (branch `0.7.x`): https://github.com/boazsegev/facil.io
    including TLS support (requires `openssl-1.1.x`(1))
    ```
    make lib # should print "Detected the OpenSSL library, setting HAVE_OPENSSL"
    ```
  - kjson: https://github.com/fbrausse/kjson
    ```
    make libkjson.a
    ```

* A copy of (the protocol buffer definitions from):
  - libsignal-service-java: https://github.com/Turasa/libsignal-service-java
    (commit `4f46fa53938a5e61f88967f755c7476ac501a754`).
    The path to the `protobuf` sub-directory is to be set in the `make` variable
    `SERVICE_PROTO_PATH` when building `ksc`.
  - libsignal-metadata-java: https://github.com/signalapp/libsignal-metadata-java
    The path to the `protobuf` sub-directory is to be set in the `make` variable
    `METADATA_PROTO_PATH` when building `ksc`.

Customization
-------------
For custom install paths of the above libraries, define the PKG_CONFIG variable
in a new file `default.mk` which is included in the main `Makefile`, e.g. like
this:
```
PKG_CONFIG := PKG_CONFIG_PATH=/path/to/lib/pkgconfig $(PKG_CONFIG)
```

If you don't plan to install this software, in `default.mk` you should also set
```
my_datadir = share
```

The `make` variable `GCRYPT` can be set to use `libgcrypt` instead of `openssl`
for any signal-related processing.

A sample `default.mk` is included as `default.mk.sample`.


How to run
==========
`make` builds an executable `test` which connects to the Signal server
websocket, listens for incoming requests (such as messages), and decrypts and
prints received messages to standard output.

The persistent state of the protocol / Signal account is stored in a JSON file
the path to which is given `test` via parameter `-p`. See `-h` for a short help
message.

The JSON protocol state file is compatible with that used by
[`signal-cli`](https://github.com/AsamK/signal-cli/),
[`signald`](https://gitlab.com/thefinn93/signald) and
[`scli`](https://github.com/fbrausse/scli).
POSIX locks are employed in a cooperative fashion such that the state file
won't be modified by any two processes `test`, `signal-cli` or `signald`
simultaneously.

The default log level is `info` and can be set to `debug`, `note`, `info`,
`warn`, `error` or `none` using the parameter `-v`. An optional prefix
controls logging for a specific subsystem, e.g., `-v ksignal-ws:note` will
result in outputs of various network-related events.

API
===
General notes
-------------
Many of the functions exported as global in `ksc`'s header files follow a
scheme for passing of optional arguments I copied from `facil.io`:
Suppose a function `f` takes mandatory arguments `int k` and `const char *path`
as well as some optional arguments `struct ksc_log *log`, `bool do_something`,
and a callback `void (*on_event)(struct event_data *data, void *udata)` as well
as a pointer `void *udata` to user-data which is passed on to the event handler.

In C there is no such concept of "optional arguments" to a function. The way
`facil.io` handles these in my opinion is quite elegant: It defines a
`struct` holding all optional arguments:
```
struct f_args {
	struct ksc_log *log;
	bool do_something;
	void (*on_event)(struct event_data *data, void *udata);
	void *udata;
};
```
and then shadows the declaration of the function `f`
```
int f(int k, const char *path, struct f_args args);
```
by a macro with the same name:
 ```
 #define f(k, path, ...) f(k, path, (struct f_args){ __VA_ARGS__ })
 ```
which allows calls to `f` to look like this:
```
int res = f(42, "some/path",
            .log = my_log,
            .on_event = handle_f_event,
            .udata = my_udata_for_handle_f_event);
```
Note that `.do_something` is not explicitely given at the function call,
instead by the `(struct f_args){ __VA_ARGS__ }` initialization it defaults to
`false`, the same would happen if pointer arguments were left out - they would
default to `NULL`.
