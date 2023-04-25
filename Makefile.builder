ifeq ($(PACKAGE_SET),vm)
  RPM_SPEC_FILES := rpm_spec/core-agent.spec

  ifneq ($(filter $(DISTRIBUTION), debian qubuntu),)
    DEBIAN_BUILD_DIRS := debian
    SOURCE_COPY_IN := source-debian-quilt-copy-in
  endif

  ARCH_BUILD_DIRS := archlinux
endif

source-debian-quilt-copy-in: VERSION = $(file <$(ORIG_SRC)/version)
source-debian-quilt-copy-in: ORIG_FILE = "$(CHROOT_DIR)/$(DIST_SRC)/../qubes-core-agent_$(VERSION).orig.tar.gz"
ifneq ($(filter $(DIST), jessie stretch),)
source-debian-quilt-copy-in: series_ext = -$(DIST)
endif
source-debian-quilt-copy-in:
	if [[ $(DIST) == bionic ||  $(DIST) == focal ]] ; then \
		sed -i /initscripts/d $(CHROOT_DIR)/$(DIST_SRC)/debian/control ;\
	fi
	-$(shell $(ORIG_SRC)/debian-quilt $(ORIG_SRC)/series-debian$(series_ext)-vm.conf $(CHROOT_DIR)/$(DIST_SRC)/debian/patches)

# Support for new packaging
ifneq ($(filter $(DISTRIBUTION), archlinux),)
VERSION := $(file <$(ORIG_SRC)/$(DIST_SRC)/version)
GIT_TARBALL_NAME ?= qubes-vm-core-$(VERSION)-1.tar.gz
SOURCE_COPY_IN := source-archlinux-copy-in

source-archlinux-copy-in: PKGBUILD = $(CHROOT_DIR)/$(DIST_SRC)/$(ARCH_BUILD_DIRS)/PKGBUILD
source-archlinux-copy-in:
	cp $(PKGBUILD).in $(CHROOT_DIR)/$(DIST_SRC)/PKGBUILD
	sed -i "s/@VERSION@/$(VERSION)/g" $(CHROOT_DIR)/$(DIST_SRC)/PKGBUILD
	sed -i "s/@REL@/1/g" $(CHROOT_DIR)/$(DIST_SRC)/PKGBUILD
endif

# vim: filetype=make
