# Build a client and server for the secure directory service.
#
#   make        build bin/client and bin/server
#   make test   build and run the unit tests in tests/
#   make clean  remove build output

CXX      = g++

# OpenSSL isn't always on the default include/library path (e.g. Homebrew on
# macOS installs it outside of /usr/include and /usr/lib). Prefer
# pkg-config; fall back to Homebrew's prefix; otherwise assume the system
# paths already work (typical on Linux).
OPENSSL_PKGCONFIG := $(shell pkg-config --exists openssl 2>/dev/null && echo yes)
ifeq ($(OPENSSL_PKGCONFIG),yes)
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
  OPENSSL_LIBS   := $(shell pkg-config --libs openssl)
else
  OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
  ifneq ($(OPENSSL_PREFIX),)
    OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
    OPENSSL_LIBS   := -L$(OPENSSL_PREFIX)/lib -lcrypto
  else
    OPENSSL_LIBS   := -lcrypto
  endif
endif

CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -MMD $(OPENSSL_CFLAGS)
LDFLAGS  = $(OPENSSL_LIBS) -lpthread

BUILD    = build
BIN      = bin

COMMON_SRC = $(wildcard common/*.cc)
CLIENT_SRC = $(wildcard client/*.cc) $(COMMON_SRC)
SERVER_SRC = $(wildcard server/*.cc) $(COMMON_SRC)

CLIENT_OBJ = $(patsubst %.cc,$(BUILD)/%.o,$(CLIENT_SRC))
SERVER_OBJ = $(patsubst %.cc,$(BUILD)/%.o,$(SERVER_SRC))

# The unit tests exercise the pure logic (crypto, storage, the map) and don't
# need the networking code or either program's main(), so they link against
# just the library pieces they actually use.
TEST_SRC     = $(wildcard tests/*.cc)
TEST_LIB_SRC = common/crypto.cc common/err.cc common/file.cc \
               server/sequentialmap_factories.cc server/my_storage.cc
TEST_OBJ     = $(patsubst %.cc,$(BUILD)/%.o,$(TEST_SRC) $(TEST_LIB_SRC))

.PHONY: all clean test
all: $(BIN)/client $(BIN)/server

$(BIN)/client: $(CLIENT_OBJ) | $(BIN)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(BIN)/server: $(SERVER_OBJ) | $(BIN)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(BIN)/tests: $(TEST_OBJ) | $(BIN)
	$(CXX) $^ -o $@ $(LDFLAGS)

test: $(BIN)/tests
	./$(BIN)/tests

$(BUILD)/%.o: %.cc | $(BUILD)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN) $(BUILD):
	@mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

-include $(wildcard $(BUILD)/*/*.d)
