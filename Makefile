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
PROTOC_C   ?= protoc-c

-include default.mk

prefix ?= /usr/local
libdir ?= $(prefix)/lib
bindir ?= $(prefix)/bin
sharedir ?= $(prefix)/share
datadir ?= $(sharedir)/$(PROJECT_NAME)

TS_SERVER_CERT = $(DESTDIR)$(datadir)/whisper.store.asn1

PKGS = facil libsignal-protocol-c kjson

ifeq ($(OS),Windows_NT)
  OS = Windows
else
  OS = $(shell uname)
endif

ifeq ($(OS),Darwin)
libksc.so: override LDFLAGS += -dynamiclib -install_name $(realpath $(DESTDIR)$(libdir))/libksc.so
endif

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
	$(shell $(PKG_CONFIG) --cflags $(PKGS)) \
	-Wall -Wextra \
	$(CLDFLAGS) \
	$(CFLAGS) \

libksc.so test: override LDFLAGS := \
	$(shell $(PKG_CONFIG) --libs-only-L --libs-only-other $(PKGS)) \
	$(subst -L,-Xlinker -rpath -Xlinker ,$(shell $(PKG_CONFIG) --libs-only-L $(PKGS))) \
	$(CLDFLAGS) \
	$(LDFLAGS) \

libksc.so: override LDFLAGS += -shared

libksc.so test: override LDLIBS += $(shell $(PKG_CONFIG) --libs-only-l $(PKGS))

COMMON_OBJS = \
	provisioning.o \
	ksignal-ws.o \
	utils.o \
	ksc-ws.o \
	crypto.o \
	json-store.o \
	$(CRYPT_OBJS) \
	$(PROTO_FILES:.proto=.pb-c.o) \

LIB_OBJS = $(addprefix pic/,\
	ffi.o \
	$(COMMON_OBJS) \
)

OBJS = \
	test.o \
	$(COMMON_OBJS) \

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

all: test libksc.so

libksc.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: $(OBJS)

$(OBJS): %.o: %.c Makefile protos

test.o: override CPPFLAGS += -DKSIGNAL_SERVER_CERT='"$(TS_SERVER_CERT)"'

$(PROTO_FILES:.proto=.pb-c.c) \
$(PROTO_FILES:.proto=.pb-c.h): protos

protos: $(addprefix $(SERVICE_PROTO_PATH)/,$(SERVICE_PROTO_FILES)) $(LOCAL_PROTO_FILES)
	$(PROTOC_C) --c_out=. --proto_path=$(SERVICE_PROTO_PATH) --proto_path=. $(PROTO_FILES) && touch $@

pic/%.o: override CFLAGS += -fPIC

$(LIB_OBJS): pic/%.o: %.c Makefile protos | pic/
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%/:
	mkdir -p $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) $(LIB_OBJS) $(LIB_OBJS:.o=.d) \
		test libksc.so protos \
		$(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h)

-include $(OBJS:.o=.d)
