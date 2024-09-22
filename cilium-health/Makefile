# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET := cilium-health
SUBDIRS := responder

.PHONY: all $(TARGET) $(SUBDIRS) clean install

all: $(TARGET) $(SUBDIRS)

$(TARGET):
	@$(ECHO_GO)
	#生成cilium-health程序
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i install; done
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

install-binary: install

install-bash-completion:


$(SUBDIRS): force
	#针对其子目录进行编译
	@ $(MAKE) $(SUBMAKEOPTS) -C $@ all

.PHONY: force
force :;
