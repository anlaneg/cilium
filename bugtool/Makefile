# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET := cilium-bugtool

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	#生成cilium-bugtool程序
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f .cilium-bugtool.config $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-binary: install

install-bash-completion:
