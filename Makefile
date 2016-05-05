# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

NATIVE := 0

TOPDIR := $(shell pwd)

# Assume there are symlinks to nacl_sdk, webports, and openconnect here
NACL_SDK_ROOT ?= $(TOPDIR)/nacl_sdk/pepper_canary
WEBPORTS ?= $(TOPDIR)/webports/src/bin/webports
GCLIENT ?= $(TOPDIR)/depot_tools/gclient

LIBOPENCONNECT_COMMIT := 489cb6c1023dac9d003f82cd70a7285108e5f110

# Project Build flags
WARNINGS := -Wall -Wextra -Wno-unused-parameter
CXXFLAGS := -O2 -std=gnu++0x -pthread $(WARNINGS)

#
# Compute tool paths
#
OSNAME := linux
NEWLIB_TC_PATH := $(abspath $(NACL_SDK_ROOT)/toolchain/$(OSNAME)_pnacl)

ifeq ($(NATIVE),1)
NACL_CXX := $(NEWLIB_TC_PATH)/bin/x86_64-nacl-clang++
HEADER_DIR := clang-newlib_x86_64
EXE := openconnect.nexe
NACL_ARCH := x86_64
TOOLCHAIN := clang-newlib
else
NACL_CXX := $(NEWLIB_TC_PATH)/bin/pnacl-clang++
NACL_FINALIZE := $(NEWLIB_TC_PATH)/bin/pnacl-finalize
HEADER_DIR := pnacl
EXE := openconnect.pexe
NACL_ARCH := pnacl
TOOLCHAIN := pnacl
endif

export NACL_SDK_ROOT NACL_ARCH TOOLCHAIN

CXXFLAGS += -I$(NACL_SDK_ROOT)/include
LDFLAGS := -L$(NACL_SDK_ROOT)/lib/$(HEADER_DIR)/Release \
	-lopenconnect -lz -llz4 -lstoken -lgnutls -lxml2 -lpthread \
	-lm -lhogweed -lgmp -lnettle \
	-lnacl_io -lglibc-compat -lppapi -lppapi_cpp

KEY := $(TOPDIR)/../openconnect.pem
SHELL := /bin/bash

SRCS := vpn_module.cc vpn_instance.cc crypto.cc
HDRS := vpn_module.h vpn_instance.h crypto.h crypto_callback.h

# Declare the ALL target first, to make the 'all' target the default build
.PHONY: all
all: crx

.PHONY: crx
crx: $(EXE) $(KEY)
	rm -rf crx openconnect.crx crx.crx
	mkdir crx
	cp *.{js,json,nmf,html,png} $(EXE) crx/
	./crxmake.sh crx $(KEY)
	mv crx.crx openconnect.crx

$(KEY):
	openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out $(KEY)

nacl_sdk/.installed:
	rm -rf nacl_sdk
	curl https://storage.googleapis.com/nativeclient-mirror/nacl/nacl_sdk/nacl_sdk.zip > nacl_sdk.zip
	unzip nacl_sdk.zip
	cd nacl_sdk && ./naclsdk install pepper_canary
	rm -f nacl_sdk.zip
	touch $@

depot_tools/.installed:
	rm -rf depot_tools
	git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
	touch $@

webports/.installed: depot_tools/.installed nacl_sdk/.installed
	rm -rf webports
	mkdir webports
	cd webports && \
		$(GCLIENT) config --unmanaged --name=src \
			https://chromium.googlesource.com/webports.git && \
		$(GCLIENT) sync --with_branch_heads
	cd webports/src && ./bin/webports install \
		glibc-compat libxml2 gnutls zlib lz4 stoken
	touch $@

openconnect/.sources:
	rm -rf openconnect
	git clone git://git.infradead.org/users/dwmw2/openconnect.git
	cd openconnect && \
		git checkout $(LIBOPENCONNECT_COMMIT) && \
		git am -3 $(TOPDIR)/patch/*.patch
	touch $@

openconnect/.installed:
	$(MAKE) libopenconnect
	touch $@

.PHONY: libopenconnect
libopenconnect: webports/.installed openconnect/.sources
	$(WEBPORTS) -v -f install openconnect

.PHONY: clean
clean:
	rm -rf openconnect.nexe openconnect.pexe openconnect.bc crx \
		openconnect.crx buildcfg.js

.PHONY: distclean
distclean: clean
	rm -rf depot_tools webports nacl_sdk openconnect

openconnect.bc: $(SRCS) $(HDRS) openconnect/.installed
	$(NACL_CXX) -o $@ $(SRCS) $(CXXFLAGS) $(LDFLAGS)

openconnect.nexe: $(SRCS) $(HDRS)
	$(NACL_CXX) -o $@ $(SRCS) $(CXXFLAGS) $(LDFLAGS)
	echo "var buildcfg = { portable: false };" > buildcfg.js

openconnect.pexe: openconnect.bc
	$(NACL_FINALIZE) -o $@ $<
	echo "var buildcfg = { portable: true };" > buildcfg.js
