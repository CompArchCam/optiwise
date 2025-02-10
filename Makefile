###############################################################################
# Variables (Can be overriden on command line)

# Note: to cross-compile you need to specify the standard tools (CC, CXX, etc)
# on the command line e.g. 'make CXX=aarch64-linux-gnu-g++ ...'

ARCH ?= $(shell $(CXX) -dumpmachine | sed -e 's/^\([^-]*\).*/\1/')
BUILD_DIR ?= build.$(ARCH)
INSTALL_DIR ?= install_dir.$(ARCH)
DYNAMORIO_VERSION ?= 11.3.0-1

ifeq ($(ARCH),aarch64)
  DYNAMORIO_PREFIX ?= AArch64-Linux
else ifeq ($(ARCH),x86_64)
  DYNAMORIO_PREFIX ?= Linux
else ifndef DYNAMORIO_URL
  $(error Machine '$(ARCH)' not recognised. Expected 'aarch64' or 'x86_64')
else ifndef DYNAMORIO_DIRNAME
  $(error Machine '$(ARCH)' not recognised. Expected 'aarch64' or 'x86_64')
endif

# Name for the directory (not a path)
DYNAMORIO_DIRNAME ?= DynamoRIO-$(DYNAMORIO_PREFIX)-$(DYNAMORIO_VERSION)
DYNAMORIO_TARNAME ?= DynamoRIO-$(DYNAMORIO_PREFIX)-$(firstword $(subst -, ,$(DYNAMORIO_VERSION))).tar.gz
DYNAMORIO_URL ?= https://github.com/DynamoRIO/dynamorio/releases/download/release_$(DYNAMORIO_VERSION)/$(DYNAMORIO_TARNAME)

###############################################################################
# Meta rules

SRC_SCRIPTS := scripts/bin/optiwise $(wildcard scripts/share/optiwise/bin/*)
INSTALL_SCRIPTS := $(patsubst scripts%,$(INSTALL_DIR)%,$(SRC_SCRIPTS))
INSTALL_LIBS := $(addprefix $(INSTALL_DIR)/share/optiwise/lib/,liboptiwise.so libexit0.so)
INSTALL_PYTHON := $(patsubst src/gui/%,$(INSTALL_DIR)/share/optiwise/lib/gui/%,$(wildcard src/gui/*.py))

all: $(INSTALL_SCRIPTS) $(INSTALL_LIBS) $(INSTALL_PYTHON) $(INSTALL_DIR)/share/optiwise/dynamorio \
	$(INSTALL_DIR)/share/optiwise/bin/analyzer \
	$(INSTALL_DIR)/share/optiwise/bin/analyzer-serial
.PHONY: all

clean:
	rm -rf $(INSTALL_DIR)/bin/optiwise $(INSTALL_DIR)/share/optiwise $(BUILD_DIR)
.PHONY: clean

install:
	$(MAKE) all INSTALL_DIR=/usr
uninstall:
	$(MAKE) clean INSTALL_DIR=/usr
.PHONY: install uninstall

FORCE: ;
.PHONY: FORCE
###############################################################################
# DynamoRIO download & build & copy

# Rule to download DynamoRIO
$(DYNAMORIO_DIRNAME)/bin64/drrun:
	wget -qO- $(DYNAMORIO_URL) | tar xvz

# Rule to minify DynamoRIO
$(INSTALL_DIR)/share/optiwise/$(DYNAMORIO_DIRNAME): scripts/minify_dynamorio.sh | $(DYNAMORIO_DIRNAME)/bin64/drrun $(INSTALL_DIR)/share/optiwise
	$< $(DYNAMORIO_DIRNAME) $@

# Rule to make DynamoRIO symlink
$(INSTALL_DIR)/share/optiwise/dynamorio: | $(INSTALL_DIR)/share/optiwise/$(DYNAMORIO_DIRNAME) $(INSTALL_DIR)/share/optiwise
	ln -s -f -T $(DYNAMORIO_DIRNAME) $@

###############################################################################
# Scripts build & copy

# Rules to copy scripts directly
$(INSTALL_DIR)/bin/optiwise: FORCE
$(INSTALL_DIR)/bin/%: scripts/bin/% | $(INSTALL_DIR)/bin
	if version=$$(git describe --dirty); then \
		sed -e "s/^version=.*/version=$$version/" $< > $@; \
		chmod --reference=$< $@; \
	else \
		cp $< $@; \
	fi
$(INSTALL_DIR)/share/optiwise/bin/%: scripts/share/optiwise/bin/% | $(INSTALL_DIR)/share/optiwise/bin
	cp $< $@

###############################################################################
# DynamoRIO client build & copy

$(BUILD_DIR)/dyclient/Makefile: src/dyclient/CMakeLists.txt | $(BUILD_DIR)/dyclient $(DYNAMORIO_DIRNAME)/bin64/drrun
	cd $(BUILD_DIR)/dyclient; cmake -DDynamoRIO_DIR=../../$(DYNAMORIO_DIRNAME)/cmake ../../src/dyclient
$(BUILD_DIR)/dyclient/bin/lib%.so: $(BUILD_DIR)/dyclient/Makefile src/dyclient/*.cpp
	$(MAKE) -C $(BUILD_DIR)/dyclient $*
$(INSTALL_DIR)/share/optiwise/lib/%.so: $(BUILD_DIR)/dyclient/bin/%.so | $(INSTALL_DIR)/share/optiwise/lib
	cp $< $@

###############################################################################
# analyzer build & copy
$(BUILD_DIR)/analyzer: src/analyzer/Makefile $(wildcard src/analyzer/*) | $(BUILD_DIR)
	$(MAKE) -C src/analyzer EXE=$$(realpath $@)
$(BUILD_DIR)/analyzer-serial: src/analyzer/Makefile $(wildcard src/analyzer/*) | $(BUILD_DIR)
	$(MAKE) -C src/analyzer EXE=$$(realpath $@) SERIAL=1
$(INSTALL_DIR)/share/optiwise/bin/analyzer: $(BUILD_DIR)/analyzer | $(INSTALL_DIR)/share/optiwise/bin
	cp $< $@
$(INSTALL_DIR)/share/optiwise/bin/analyzer-serial: $(BUILD_DIR)/analyzer-serial | $(INSTALL_DIR)/share/optiwise/bin
	cp $< $@

###############################################################################
# Gui copy
$(INSTALL_DIR)/share/optiwise/lib/gui/%.py: src/gui/%.py | $(INSTALL_DIR)/share/optiwise/lib/gui
	cp $< $@

###############################################################################
# Directory structure rules

# Rules to make target directory structure
$(BUILD_DIR):
	[ -d "$@" ] || mkdir "$@"
$(BUILD_DIR)/dyclient: | $(BUILD_DIR)
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR):
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR)/bin: | $(INSTALL_DIR)
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR)/share: | $(INSTALL_DIR)
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR)/share/optiwise: | $(INSTALL_DIR)/share
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR)/share/optiwise/bin: | $(INSTALL_DIR)/share/optiwise
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR)/share/optiwise/lib: | $(INSTALL_DIR)/share/optiwise
	[ -d "$@" ] || mkdir "$@"
$(INSTALL_DIR)/share/optiwise/lib/gui: | $(INSTALL_DIR)/share/optiwise/lib
	[ -d "$@" ] || mkdir "$@"
