RPMS_DIR=rpm/

VERSION := $(shell cat version)

DIST_DOM0 ?= fc18

help:
	@echo "make rpms                  -- generate binary rpm packages"
	@echo "make rpms-vm               -- generate binary rpm packages for VM"
	@echo "make update-repo-current   -- copy newly generated rpms to qubes yum repo"
	@echo "make update-repo-current-testing  -- same, but to -current-testing repo"
	@echo "make update-repo-unstable  -- same, but to -testing repo"
	@echo "make update-repo-installer -- copy dom0 rpms to installer repo"
	@echo "make clean                 -- cleanup"

rpms: rpms-vm

rpms-vm:
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm.spec
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm-doc.spec
	rpmbuild --define "_rpmdir $(RPMS_DIR)" -bb rpm_spec/core-vm-kernel-placeholder.spec
	rpm --addsign \
		$(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*.rpm \
		$(RPMS_DIR)/x86_64/qubes-core-vm-doc-*$(VERSION)*.rpm \
		$(RPMS_DIR)/x86_64/qubes-core-vm-kernel-placeholder-*.rpm

rpms-dom0:
	@true

update-repo-current:
	for vmrepo in ../yum/current-release/current/vm/* ; do \
		dist=$$(basename $$vmrepo) ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-kernel-placeholder-*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-libs-$(VERSION_LIBS)*$$dist*.rpm $$vmrepo/rpm/;\
	done

update-repo-current-testing:
	for vmrepo in ../yum/current-release/current-testing/vm/* ; do \
		dist=$$(basename $$vmrepo) ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-kernel-placeholder-*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-libs-$(VERSION_LIBS)*$$dist*.rpm $$vmrepo/rpm/;\
	done

update-repo-unstable:
	for vmrepo in ../yum/current-release/unstable/vm/* ; do \
		dist=$$(basename $$vmrepo) ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-kernel-placeholder-*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-libs-$(VERSION_LIBS)*$$dist*.rpm $$vmrepo/rpm/;\
	done

update-repo-template:
	for vmrepo in ../template-builder/yum_repo_qubes/* ; do \
		dist=$$(basename $$vmrepo) ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-*$(VERSION)*$$dist*.rpm $$vmrepo/rpm/ ;\
		ln -f $(RPMS_DIR)/x86_64/qubes-core-vm-kernel-placeholder-*$$dist*.rpm $$vmrepo/rpm/ ;\
	done

clean:
	make -C dom0/qmemman clean
	make -C dom0/restore clean
	make -C misc clean
	make -C qrexec clean
	make -C u2mfn clean
	make -C vchan -f Makefile.linux clean
