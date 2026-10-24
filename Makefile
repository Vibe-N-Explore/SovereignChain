# SovereignChain - Phase 1 Makefile
CC      ?= cc
CFLAGS  := -std=c17 -Wall -Wextra -Werror -O2 -g -Isrc
SANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

LIB_SRC := src/config.c src/log.c
HEADERS := $(wildcard src/*.h)

UNIT_SRC  := $(wildcard tests/unit/test_*.c)
UNIT_BINS := $(patsubst tests/unit/%.c,build/%,$(UNIT_SRC))

.PHONY: all test test-unit test-integration clean

all: bin/node

bin/node: src/main.c $(LIB_SRC) $(HEADERS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ src/main.c $(LIB_SRC)

# Unit tests are built with AddressSanitizer + UBSan so memory bugs and
# undefined behaviour fail the test instead of hiding.
build/test_%: tests/unit/test_%.c tests/unit/testutil.h $(LIB_SRC) $(HEADERS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SANFLAGS) -Itests/unit -o $@ $< $(LIB_SRC)

test-unit: $(UNIT_BINS)
	@set -e; for t in $(UNIT_BINS); do echo "== $$t"; ./$$t; done

test-integration: bin/node
	./tests/integration/phase1.sh

test: test-unit test-integration

clean:
	rm -rf bin build logs
