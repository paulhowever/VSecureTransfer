# Сборка без CMake (при необходимости: make OPENSSL_PREFIX=/path/to/openssl)
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
ifeq ($(wildcard $(OPENSSL_PREFIX)/include/openssl),)
  OPENSSL_PREFIX := /opt/homebrew/opt/openssl
endif
ifeq ($(wildcard $(OPENSSL_PREFIX)/include/openssl),)
  OPENSSL_PREFIX := /usr/local/opt/openssl@3
endif

CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic -Iinclude
LDFLAGS ?= -L$(OPENSSL_PREFIX)/lib
LDLIBS ?= -lssl -lcrypto

SRC_LIB := src/crypto.cpp src/metadata.cpp src/packet.cpp src/tcp.cpp src/replay.cpp
OBJ_LIB := $(SRC_LIB:.cpp=.o)

all: vsecure_sender vsecure_receiver

vsecure_sender: apps/sender_main.o $(OBJ_LIB)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

vsecure_receiver: apps/receiver_main.o $(OBJ_LIB)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(OPENSSL_PREFIX)/include -c -o $@ $<

clean:
	rm -f vsecure_sender vsecure_receiver $(OBJ_LIB) apps/sender_main.o apps/receiver_main.o

.PHONY: all clean
