ifeq ($(PACKAGE_SET),vm)
RPM_SPEC_FILES := rpm_spec/core-vm.spec \
    rpm_spec/core-vm-doc.spec \
    rpm_spec/core-vm-kernel-placeholder.spec
ARCH_BUILD_DIRS := archlinux
DEBIAN_BUILD_DIRS := debian
endif
