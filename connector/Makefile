# Connector network Makefile
CC      ?= cc
CFLAGS  := -std=c17 -Wall -Wextra -Werror -O2 -g -I../src -Isrc

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

HAVE_ASAN := $(shell echo 'int main(void){return 0;}' | $(CC) -fsanitize=address,undefined -x c -o /dev/null - 2>/dev/null && echo yes)
ifeq ($(HAVE_ASAN),yes)
  SANFLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
  SANFLAGS ?=
endif

# Main blockchain lib sources needed by connector
SC_LIB_SRC := ../src/config.c ../src/log.c ../src/crypto.c ../src/tx.c

# Connector library sources
CN_LIB_SRC := src/cn_config.c src/cn_store.c src/cn_net.c src/cn_chain.c \
              src/cn_activity.c src/cn_transfer.c src/cn_rate.c src/cn_http.c

CN_HEADERS  := $(wildcard src/*.h)
SC_HEADERS  := $(wildcard ../src/*.h)

UNIT_SRC  := $(wildcard tests/test_*.c)
UNIT_BINS := $(patsubst tests/%.c,build/%,$(UNIT_SRC))

.PHONY: all test clean

all: bin/connector bin/sc_wallet

bin/connector: src/connector_main.c $(CN_LIB_SRC) $(SC_LIB_SRC) $(CN_HEADERS) $(SC_HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(CN_LIB_SRC) $(SC_LIB_SRC) $(OPENSSL_LIBS)

bin/sc_wallet: src/sc_wallet.c $(CN_LIB_SRC) $(SC_LIB_SRC) $(CN_HEADERS) $(SC_HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(CN_LIB_SRC) $(SC_LIB_SRC) $(OPENSSL_LIBS)

build/test_%: tests/test_%.c $(CN_LIB_SRC) $(SC_LIB_SRC) $(CN_HEADERS) $(SC_HEADERS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SANFLAGS) $(OPENSSL_CFLAGS) -Itests -o $@ $< $(CN_LIB_SRC) $(SC_LIB_SRC) $(OPENSSL_LIBS)

test: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; ./$$t; done

clean:
	rm -rf bin build
