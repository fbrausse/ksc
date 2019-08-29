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

PKGS = facil libsignal-protocol-c kjson libprotobuf-c

ifeq ($(OS),Windows_NT)
  OS = Windows
else
  OS = $(shell uname)
endif

ifeq ($(OS),Darwin)
libksc.so: override LDFLAGS += -dynamiclib -install_name $(realpath $(DESTDIR)$(libdir))/libksc.so
else
  override CLDFLAGS += -pthread
endif
ifeq ($(OS),OpenBSD)
  PKGC_LIBCRYPTO = libecrypto11
endif

PKGC_LIBCRYPTO ?= libcrypto

ifdef GCRYPT
  CRYPT_OBJS = crypto-gcrypt.o
  test: override LDLIBS += -lgcrypt
else
  CRYPT_OBJS = crypto-openssl-$(shell $(PKG_CONFIG) --modversion $(PKGC_LIBCRYPTO) | cut -c1,3).o
  PKGS += $(PKGC_LIBCRYPTO)
endif

CSTD = -std=c11

override CPPFLAGS += \
	-D_POSIX_C_SOURCE=200809L \
	-D_XOPEN_SOURCE=700 \
	-DSIGNAL_USER_AGENT='"$(PROJECT_NAME) $(PROJECT_VERSION)"' \
	$(CSTD) \

override CLDFLAGS := \
	$(CSTD) \
	$(OPTS) \
	$(CLDFLAGS)

override CFLAGS := \
	-MD \
	$(shell $(PKG_CONFIG) --cflags $(PKGS)) \
	-Wall -Wextra \
	$(CLDFLAGS) \
	$(CFLAGS) \

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

OBJS = $(addprefix npic/,\
	test.o \
	$(COMMON_OBJS) \
)

SERVICE_PROTO_FILES = \
	WebSocketResources.proto \
	Provisioning.proto \
	SignalService.proto \

LOCAL_PROTO_FILES = \
	LocalStorageProtocol.proto \

PROTO_FILES = \
	$(SERVICE_PROTO_FILES) \
	$(LOCAL_PROTO_FILES) \

PROTO_SRCS = $(addprefix src/,\
	$(PROTO_FILES:.proto=.pb-c.c) \
	$(PROTO_FILES:.proto=.pb-c.h) \
)

BUILD = \
	test \
	libksc.so \

.PHONY: all clean

all: $(BUILD)

$(BUILD): override LDLIBS += $(shell $(PKG_CONFIG) --libs-only-l $(PKGS))
$(BUILD): override LDFLAGS := \
	$(shell $(PKG_CONFIG) --libs-only-L --libs-only-other $(PKGS)) \
	$(subst -L,-Xlinker -rpath -Xlinker ,$(shell $(PKG_CONFIG) --libs-only-L $(PKGS))) \
	$(CLDFLAGS) \
	$(LDFLAGS) \

libksc.so: override LDFLAGS += -shared
libksc.so: $(LIB_OBJS)

test: $(OBJS)

$(LIB_OBJS): pic/%.o: src/%.c Makefile protos | pic/

$(OBJS): npic/%.o: src/%.c Makefile protos | npic/

$(BUILD):
	+$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJS) $(LIB_OBJS):
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

npic/test.o: override CPPFLAGS += -DKSIGNAL_SERVER_CERT='"$(TS_SERVER_CERT)"'

pic/%.o: override CFLAGS += -fPIC

$(PROTO_SRCS): protos

protos: $(addprefix $(SERVICE_PROTO_PATH)/,$(SERVICE_PROTO_FILES)) $(LOCAL_PROTO_FILES)
	$(PROTOC_C) --c_out=src/ --proto_path=$(SERVICE_PROTO_PATH) --proto_path=. $(PROTO_FILES) && touch $@

%/:
	mkdir -p $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) $(LIB_OBJS) $(LIB_OBJS:.o=.d) \
		$(BUILD) protos $(PROTO_SRCS)

-include $(OBJS:.o=.d) $(LIB_OBJS:.o=.d)
