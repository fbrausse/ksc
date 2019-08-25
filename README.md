Building
========
Requires the following prerequisites (all of these refer to the `master`
branch at the linked URL if not specified otherwise):

* GNU make (1)

* Installed libraries (found by `pkg-config`(1), see below for customization):
  - libsignal-protocol-c: https://github.com/fbrausse/libsignal-protocol-c
    ```
    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX=/some/prefix/path ..
    make install
    ```
  - facil.io (branch `0.7.x`): https://github.com/fbrausse/facil.io
    including TLS support (requires `openssl-1.1.x`(1))
    ```
    make static-libs # should print "Detected the OpenSSL library, setting HAVE_OPENSSL"
    ```
  - kjson: https://github.com/fbrausse/kjson
    The path to the `kjson` directory is to be set in the `make` variable `KJSON_PATH`
    when building `ksc`.
    ```
    make libkjson.a
    ```

* A copy of (the protocol buffer definitions from)
  libsignal-service-java: https://github.com/Turasa/libsignal-service-java
  (commit `4f46fa53938a5e61f88967f755c7476ac501a754`).
  The path to the `protobuf` sub-directory is to be set in the `make` variable
  `SERVICE_PROTO_PATH` when building `ksc`.

Customization
-------------
For custom install paths of the above libraries (except kjson), define
the PKG_CONFIG variable in a new file `default.mk` which is included in the
main `Makefile`, e.g. like this:
```
PKG_CONFIG := PKG_CONFIG_PATH=/path/to/lib/pkgconfig $(PKG_CONFIG)
```

If you don't plan to install this software, in `default.mk` you should also set
```
my_datadir = share
```

The `make` variable `GCRYPT` can be set to use `libgcrypt` instead of `openssl`
for any signal-related processing.


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
