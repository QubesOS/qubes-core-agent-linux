ifeq ($(PACKAGE_SET),vm)
  RPM_SPEC_FILES := rpm_spec/core-agent.spec

  ifneq ($(filter $(DISTRIBUTION), debian qubuntu),)
    DEBIAN_BUILD_DIRS := debian
    SOURCE_COPY_IN := source-debian-quilt-copy-in
  endif

  ARCH_BUILD_DIRS := archlinux
endif

source-debian-quilt-copy-in: VERSION = $(shell cat $(ORIG_SRC)/version)
source-debian-quilt-copy-in: ORIG_FILE = "$(CHROOT_DIR)/$(DIST_SRC)/../qubes-core-agent_$(VERSION).orig.tar.gz"
source-debian-quilt-copy-in:
	if [ $(DIST) == trusty ] ; then \
		sed -i /locales-all/d $(CHROOT_DIR)/$(DIST_SRC)/debian/control ;\
	fi
	if [ $(DIST) == zesty ] ; then \
		sed -i /initscripts/d $(CHROOT_DIR)/$(DIST_SRC)/debian/control ;\
	fi
	-$(shell $(ORIG_SRC)/debian-quilt $(ORIG_SRC)/series-debian-vm.conf $(CHROOT_DIR)/$(DIST_SRC)/debian/patches)
	tar cfz $(ORIG_FILE) --exclude-vcs --exclude=rpm --exclude=pkgs --exclude=deb --exclude=debian -C $(CHROOT_DIR)/$(DIST_SRC) .

# vim: filetype=make
