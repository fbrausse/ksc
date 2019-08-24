# default target
all:

PROJECT_NAME = ksc
PROJECT_VERSION = 0.1

CFLAGS  ?= -g
OPTS    ?= #-Os -flto
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
  CRYPT_OBJS = crypto-openssl-$(shell $(PKG_CONFIG) --modversion openssl | cut -c1,3).o
  PKGS += libcrypto
endif

CSTD = -std=c11

override CPPFLAGS += \
	-D_POSIX_C_SOURCE=200809L \
	-D_XOPEN_SOURCE=500 \
	-DSIGNAL_USER_AGENT='"$(PROJECT_NAME) $(PROJECT_VERSION)"' \
	$(CSTD) \

override CLDFLAGS := \
	$(CSTD) \
	-pthread \
	$(OPTS) \
	$(CLDFLAGS)

override CFLAGS := \
	-MD \
	$(shell $(PKG_CONFIG) --cflags libsignal-protocol-c,$(PKGS)) \
	-I$(KJSON_PATH) \
	-Wall -Wextra \
	$(CLDFLAGS) \
	$(CFLAGS) \

test: override LDFLAGS := \
	$(shell $(PKG_CONFIG) --libs-only-L --libs-only-other $(PKGS)) \
	$(subst -L,-Xlinker -rpath -Xlinker ,$(shell $(PKG_CONFIG) --libs-only-L $(PKGS))) \
	-L$(KJSON_PATH) \
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

.PHONY: all clean

all: test

test: $(OBJS)

$(OBJS): %.o: %.c Makefile protos

test.o: override CPPFLAGS += -DKSIGNAL_SERVER_CERT='"$(TS_SERVER_CERT)"'

$(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h): protos

protos: $(addprefix $(SERVICE_PROTO_PATH)/,$(SERVICE_PROTO_FILES)) $(LOCAL_PROTO_FILES)
	protoc-c --c_out=. --proto_path=$(SERVICE_PROTO_PATH) --proto_path=. $(PROTO_FILES) && touch $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) test protos $(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h)

-include $(OBJS:.o=.d)
