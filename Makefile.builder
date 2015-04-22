ifeq ($(PACKAGE_SET),vm)
ifeq ($(UPGRADE_PKG_ONLY),yes)
RPM_SPEC_FILES := rpm_spec/upgrade-vm.spec
else
RPM_SPEC_FILES := rpm_spec/core-vm.spec \
    rpm_spec/core-vm-doc.spec \
    rpm_spec/core-vm-kernel-placeholder.spec
endif
ARCH_BUILD_DIRS := archlinux
DEBIAN_BUILD_DIRS := debian
endif
