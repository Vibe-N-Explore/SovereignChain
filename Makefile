# SovereignChain - Phase 3 Makefile
CC      ?= cc
CFLAGS  := -std=c17 -Wall -Wextra -Werror -O2 -g -Isrc
SANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

# OpenSSL: pkg-config is the right way to find include/lib paths.
# If pkg-config is missing, fall back to bare -lssl -lcrypto.
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo "-lssl -lcrypto")

# Phase 3: add crypto.c and net.c to the shared library sources.
LIB_SRC := src/config.c src/log.c src/crypto.c src/net.c
HEADERS := $(wildcard src/*.h)

UNIT_SRC  := $(wildcard tests/unit/test_*.c)
UNIT_BINS := $(patsubst tests/unit/%.c,build/%,$(UNIT_SRC))

.PHONY: all test test-unit test-integration clean

all: bin/node

bin/node: src/main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ src/main.c $(LIB_SRC) $(OPENSSL_LIBS)

# Unit tests: built with AddressSanitizer + UBSan.
# test_crypto links OpenSSL; other tests don't (the rule is general).
build/test_%: tests/unit/test_%.c tests/unit/testutil.h $(LIB_SRC) $(HEADERS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SANFLAGS) $(OPENSSL_CFLAGS) -Itests/unit \
	    -o $@ $< $(LIB_SRC) $(OPENSSL_LIBS)

test-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; ./$$t; done

test-integration: bin/node
	./tests/integration/phase1.sh
	./tests/integration/phase3.sh

test: test-unit test-integration

clean:
	rm -rf bin build logs
