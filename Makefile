
CFLAGS ?= -g

-include default.mk

override CFLAGS := \
	-MMD -I../facil.io/libdump/include -I../kjson \
	-Wall -Wno-unused $(CFLAGS) #-fsanitize=address

LDFLAGS = \
	-L../facil.io/tmp -Wl,-rpath,`realpath ../facil.io/tmp` \
	-L../kjson -Wl,-rpath,`realpath ../kjson` \
	#-fsanitize=address

OBJS = \
	test.o \
	provisioning.o \
	ksignal-ws.o \
	utils.o \
	$(PROTO_FILES:.proto=.pb-c.o) \

PROTO_FILES = \
	WebSocketResources.proto \
	Provisioning.proto \
	SignalService.proto \

PROTO_INCLUDE = $(shell echo ~/dev/libsignal-service-java/protobuf)

.PHONY: all clean

all: test

test: LDLIBS += -lfacil -lprotobuf-c -lkjson -lgcrypt
test: $(OBJS)

$(OBJS): %.o: %.c Makefile

$(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h): protos

protos: $(addprefix $(PROTO_INCLUDE)/,$(PROTO_FILES))
	protoc-c --c_out=. --proto_path=$(PROTO_INCLUDE) $(PROTO_FILES) && touch $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) test protos

-include $(OBJS:.o=.d)
