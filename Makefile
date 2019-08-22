
CFLAGS  ?= -g
LDFLAGS ?= -Wl,--as-needed
OPTS    ?= #-flto
CLDFLAGS ?= \
	#-fsanitize=address \
	#-fsanitize=undefined \
	#-pthread \

-include default.mk

my_datadir ?= $(datadir)/ksignal

TS_SERVER_CERT = $(my_datadir)/whisper.store.asn1

ifdef GCRYPT
  CRYPT_OBJS = crypto-gcrypt.o
  test: override LDLIBS += -lgcrypt
else
  CRYPT_OBJS = crypto-openssl-11.o
  test: override LDLIBS += -lcrypto
endif

CSTD = -std=c11

override CPPFLAGS += \
	-D_POSIX_C_SOURCE=200809L \
	-D_XOPEN_SOURCE=500 \
	$(CSTD) \

override CLDFLAGS := \
	$(CSTD) \
	$(OPTS) \
	$(CLDFLAGS)

override CFLAGS := \
	-MD \
	-I../facil.io/libdump/include \
	-I../kjson \
	-I../libsignal-protocol-c/installed/include \
	-Wall -Wextra \
	$(CLDFLAGS) \
	$(CFLAGS) \

override LDFLAGS := \
	-L../facil.io/tmp -Wl,-rpath,`realpath ../facil.io/tmp` \
	-L../kjson -Wl,-rpath,`realpath ../kjson` \
	-L../libsignal-protocol-c/build/src -Wl,-rpath,`realpath ../libsignal-protocol-c/build/src` \
	$(CLDFLAGS) \
	$(LDFLAGS) \

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

test: override LDLIBS += -lfacil -lprotobuf-c -lkjson -lsignal-protocol-c -lm
test: $(OBJS)

$(OBJS): %.o: %.c Makefile protos

ksignal-ws.o: override CPPFLAGS += -DKSIGNAL_SERVER_CERT='"$(TS_SERVER_CERT)"'

$(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h): protos

protos: $(addprefix $(PROTO_INCLUDE)/,$(SERVICE_PROTO_FILES)) $(LOCAL_PROTO_FILES)
	protoc-c --c_out=. --proto_path=$(PROTO_INCLUDE) --proto_path=. $(PROTO_FILES) && touch $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) test protos $(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h)

-include $(OBJS:.o=.d)
