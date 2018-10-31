ifeq ($(PACKAGE_SET),vm)
  RPM_SPEC_FILES := rpm_spec/core-vm.spec \
  rpm_spec/core-vm-doc.spec

  ifneq ($(filter $(DISTRIBUTION), debian qubuntu),)
    DEBIAN_BUILD_DIRS := debian
    ifeq ($(DISTRIBUTION),qubuntu)
	  SOURCE_COPY_IN := source-debian-quilt-copy-in
    endif
  endif

  ARCH_BUILD_DIRS := archlinux
endif

source-debian-quilt-copy-in: VERSION = $(shell cat $(ORIG_SRC)/version)
source-debian-quilt-copy-in: ORIG_FILE = "$(CHROOT_DIR)/$(DIST_SRC)/../qubes-core-agent_$(VERSION).orig.tar.gz"
source-debian-quilt-copy-in:
	if [ $(DIST) == trusty ] ; then \
		sed -i /locales-all/d $(CHROOT_DIR)/$(DIST_SRC)/debian/control ;\
	fi
	if [ $(DIST) == bionic ] ; then \
		sed -i /initscripts/d $(CHROOT_DIR)/$(DIST_SRC)/debian/control ;\
	fi
	-$(shell $(ORIG_SRC)/debian-quilt $(ORIG_SRC)/series-debian-vm.conf $(CHROOT_DIR)/$(DIST_SRC)/debian/patches)

# vim: filetype=make
