
CFLAGS ?= -g
LDFLAGS ?= -Wl,--as-needed

-include default.mk

my_datadir ?= $(datadir)/ksignal

CSTD = -std=c99

TS_SERVER_CERT = $(my_datadir)/whisper.store.asn1

override CPPFLAGS += \
	-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
	$(CSTD) \

override CFLAGS := \
	-MD \
	-I../facil.io/libdump/include \
	-I../kjson \
	-I../libsignal-protocol-c/installed/include \
	-Wall -Wextra \
	$(CFLAGS) #-fsanitize=address

LDFLAGS += \
	-L../facil.io/tmp -Wl,-rpath,`realpath ../facil.io/tmp` \
	-L../kjson -Wl,-rpath,`realpath ../kjson` \
	-L../libsignal-protocol-c/installed/lib -Wl,-rpath,`realpath ../libsignal-protocol-c/installed/lib` \
	#-fsanitize=address

OBJS = \
	test.o \
	provisioning.o \
	ksignal-ws.o \
	utils.o \
	json-store.o \
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

test: LDLIBS += -lfacil -lprotobuf-c -lkjson -lgcrypt -lsignal-protocol-c -lm
test: $(OBJS)

$(OBJS): %.o: %.c Makefile protos

ksignal-ws.o: override CPPFLAGS += -DKSIGNAL_SERVER_CERT='"$(TS_SERVER_CERT)"'

$(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h): protos

protos: $(addprefix $(PROTO_INCLUDE)/,$(SERVICE_PROTO_FILES)) $(LOCAL_PROTO_FILES)
	protoc-c --c_out=. --proto_path=$(PROTO_INCLUDE) --proto_path=. $(PROTO_FILES) && touch $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) test protos $(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h)

-include $(OBJS:.o=.d)
