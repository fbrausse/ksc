Building
========
Requires the following prerequisites:

* Installed libraries (found by `pkg-config`(1), see below for customization):
  - libsignal-protocol-c: https://github.com/fbrausse/libsignal-protocol-c
  - facil.io: https://github.com/fbrausse/facil.io
  - kjson: https://github.com/fbrausse/kjson

* A copy of (the protocol buffer definitions from)
  libsignal-service-java: https://github.com/Turasa/libsignal-service-java
  set in the `make` variable `SERVICE_PROTO_PATH`.

Customization
-------------
For custom install paths of the above libraries (except kjson), define
the PKG_CONFIG variable in a new file `default.mk` which is included in the
main `Makefile`, e.g. like this:
```
PKG_CONFIG = PKG_CONFIG_PATH=/path/to/lib/pkgconfig $(PKG_CONFIG)
```

If you don't plan to install this software, in `default.mk` you should also set
```
my_datadir = share
```
