include commands.mk

CFLAGS  := -std=c99 -fPIC -Wall
LDFLAGS :=

SRC  = $(wildcard *.c)
OBJ  = $(foreach obj, $(SRC:.c=.o), $(notdir $(obj)))
DEP  = $(SRC:.c=.d)

TARGETS     = gpushd-server gpushd-client

SERVER_OBJ = gpushd-server.o version.o help.o safe-call.o common.o iobuf.o time-substract.o stack.o buffer.o swap.o statistics.o
CLIENT_OBJ = gpushd-client.o version.o help.o safe-call.o common.o aligned-display.o names.o parser.o buffer.o scale.o command.o

PREFIX  ?= /usr/local
BIN     ?= /bin

ifeq ($(OS),Linux)
	CFLAGS  += -D_BSD_SOURCE=1
endif

commit = $(shell ./hash.sh)
ifneq ($(commit), UNKNOWN)
	CFLAGS += -DCOMMIT="\"$(commit)\""
	CFLAGS += -DPARTIAL_COMMIT="\"$(shell echo $(commit) | cut -c1-8)\""
endif

ifndef DISABLE_DEBUG
CFLAGS += -ggdb -O0
else
CFLAGS += -DNDEBUG=1 -O2
endif

.PHONY: all clean

all: $(TARGETS)

gpushd-server: $(SERVER_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

gpushd-client: $(CLIENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -Wp,-MMD,$*.d -c $(CFLAGS) -o $@ $<

clean:
	$(RM) $(DEP)
	$(RM) $(OBJ)
	$(RM) $(CATALOGS)
	$(RM) $(TARGETS)

install:
	$(MKDIR) -p $(DESTDIR)/$(PREFIX)/$(BIN)
	$(INSTALL_PROGRAM) gpushd-server $(DESTDIR)/$(PREFIX)/$(BIN)
	$(INSTALL_PROGRAM) gpushd-client $(DESTDIR)/$(PREFIX)/$(BIN)

uninstall:
	$(RM) $(DESTDIR)/$(PREFIX)/$(BIN)/gpushd-server
	$(RM) $(DESTDIR)/$(PREFIX)/$(BIN)/gpushd-client

-include $(DEP)

