# default target
all:

CFLAGS  ?= -g
LDFLAGS ?= -Wl,--as-needed
OPTS    ?= #-flto
CLDFLAGS ?= \
	#-fsanitize=address \
	#-fsanitize=undefined \
	#-pthread \

PKG_CONFIG ?= pkg-config

-include default.mk

my_datadir ?= $(datadir)/ksignal

TS_SERVER_CERT = $(my_datadir)/whisper.store.asn1

PKGS = facil libsignal-protocol-c

ifdef GCRYPT
  CRYPT_OBJS = crypto-gcrypt.o
  test: override LDLIBS += -lgcrypt
else
  CRYPT_OBJS = crypto-openssl-11.o
  PKGS += libcrypto
endif

CSTD = -std=c11

override CPPFLAGS += \
	-D_POSIX_C_SOURCE=200809L \
	-D_XOPEN_SOURCE=500 \
	$(CSTD) \

override CLDFLAGS := \
	$(CSTD) \
	-pthread \
	$(OPTS) \
	$(CLDFLAGS)

# don't do the non-standard thing and include the path component "signal" under
# the include/ path (no need to import all their files into global #include
# namespace)
SED_STRIP_SIGNAL = s%(-I[^ ]*)/signal( |$$)%\1\2%g

override CFLAGS := \
	-MD \
	$(shell $(PKG_CONFIG) --cflags $(filter-out libsignal-protocol-c,$(PKGS))) \
	$(shell $(PKG_CONFIG) --cflags libsignal-protocol-c | sed -r '$(SED_STRIP_SIGNAL)') \
	-I../kjson \
	-Wall -Wextra \
	$(CLDFLAGS) \
	$(CFLAGS) \

test: override LDFLAGS := \
	$(shell $(PKG_CONFIG) --libs-only-L --libs-only-other $(PKGS)) \
	$(subst -L,-Xlinker -rpath -Xlinker ,$(shell $(PKG_CONFIG) --libs-only-L $(PKGS))) \
	-L../kjson \
	$(CLDFLAGS) \
	$(LDFLAGS) \

test: override LDLIBS += $(shell $(PKG_CONFIG) --libs-only-l $(PKGS)) -lkjson

OBJS = \
	test.o \
	provisioning.o \
	ksignal-ws.o \
	utils.o \
	ksc-ws.o \
	crypto.o \
	json-store.o \
	$(CRYPT_OBJS) \
	$(PROTO_FILES:.proto=.pb-c.o) \

SERVICE_PROTO_FILES = \
	WebSocketResources.proto \
	Provisioning.proto \
	SignalService.proto \

LOCAL_PROTO_FILES = \
	LocalStorageProtocol.proto \

PROTO_FILES = \
	$(SERVICE_PROTO_FILES) \
	$(LOCAL_PROTO_FILES) \

PROTO_INCLUDE = $(shell echo ~/dev/libsignal-service-java/protobuf)

.PHONY: all clean

all: test

test: $(OBJS)

$(OBJS): %.o: %.c Makefile protos

ksignal-ws.o: override CPPFLAGS += -DKSIGNAL_SERVER_CERT='"$(TS_SERVER_CERT)"'

$(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h): protos

protos: $(addprefix $(PROTO_INCLUDE)/,$(SERVICE_PROTO_FILES)) $(LOCAL_PROTO_FILES)
	protoc-c --c_out=. --proto_path=$(PROTO_INCLUDE) --proto_path=. $(PROTO_FILES) && touch $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) test protos $(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h)

-include $(OBJS:.o=.d)
