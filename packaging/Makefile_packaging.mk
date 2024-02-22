# Common Makefile for including
# Needs the following variables set at a minimum:
# NAME :=
# SRC_EXT :=

# force bash (looking at you Ubuntu)
SHELL=/bin/bash

# Put site overrides (i.e. DAOS_STACK_*_LOCAL_REPO) in here
-include Makefile.local

# default to Leap 15 distro for chrootbuild
CHROOT_NAME ?= opensuse-leap-15.3-x86_64
include packaging/Makefile_distro_vars.mk

ifeq ($(DEB_NAME),)
DEB_NAME := $(NAME)
endif

CALLING_MAKEFILE := $(word 1, $(MAKEFILE_LIST))

# this Makefile should always be executed from it's own dir
TOPDIR ?= $(abspath $(dir $(firstword $(MAKEFILE_LIST))))

BUILD_PREFIX ?= .

DOT     := .
RPM_BUILD_OPTIONS += $(EXTERNAL_RPM_BUILD_OPTIONS)

# some defaults the caller can override
PACKAGING_CHECK_DIR ?= ../packaging
LOCAL_REPOS ?= true
TEST_PACKAGES ?= ${NAME}

# unfortunately we cannot always name the repo the same as the project
REPO_NAME ?= $(NAME)

PR_REPOS                 ?= $(shell git show -s --format=%B | sed -ne 's/^PR-repos: *\(.*\)/\1/p')
LEAP_15_PR_REPOS         ?= $(shell git show -s --format=%B | sed -ne 's/^PR-repos-leap15: *\(.*\)/\1/p')
EL_7_PR_REPOS            ?= $(shell git show -s --format=%B | sed -ne 's/^PR-repos-el7: *\(.*\)/\1/p')
EL_8_PR_REPOS            ?= $(shell git show -s --format=%B | sed -ne 's/^PR-repos-el8: *\(.*\)/\1/p')
EL_9_PR_REPOS            ?= $(shell git show -s --format=%B | sed -ne 's/^PR-repos-el9: *\(.*\)/\1/p')
UBUNTU_20_04_PR_REPOS    ?= $(shell git show -s --format=%B | sed -ne 's/^PR-repos-ubuntu20: *\(.*\)/\1/p')
REPO_FILES_PR            ?= $(shell git show -s --format=%B | sed -ne 's/^Repo-files-PR: *\(.*\)/\1/p')

ifneq ($(PKG_GIT_COMMIT),)
ifeq ($(GITHUB_PROJECT),)
ifeq ($(GIT_PROJECT),)
$(error You must set either GITHUB_PROJECT or GIT_PROJECT if you set PKG_GIT_COMMIT)
endif
endif
BUILD_DEFINES     := --define "commit $(PKG_GIT_COMMIT)"
RPM_BUILD_OPTIONS := $(BUILD_DEFINES)
GIT_DIFF_EXCLUDES := $(PATCH_EXCLUDE_FILES:%=':!%')
endif

COMMON_RPM_ARGS  := --define "_topdir $$PWD/_topdir" $(BUILD_DEFINES)
SPEC             := $(shell if [ -f $(NAME)-$(DISTRO_BASE).spec ]; then echo $(NAME)-$(DISTRO_BASE).spec; else echo $(NAME).spec; fi)
VERSION           = $(eval VERSION := $(shell rpm $(COMMON_RPM_ARGS) --specfile --qf '%{version}\n' $(SPEC) | sed -n '1p'))$(VERSION)
DEB_RVERS        := $(subst $(DOT),\$(DOT),$(VERSION))
DEB_BVERS        := $(basename $(subst ~rc,$(DOT)rc,$(VERSION)))
RELEASE           = $(eval RELEASE := $(shell rpm $(COMMON_RPM_ARGS) --specfile --qf '%{release}\n' $(SPEC) | sed -n '$(SED_EXPR)'))$(RELEASE)
SRPM              = _topdir/SRPMS/$(NAME)-$(VERSION)-$(RELEASE)$(DIST).src.rpm
RPMS              = $(eval RPMS := $(addsuffix .rpm,$(addprefix _topdir/RPMS/x86_64/,$(shell rpm --specfile $(SPEC)))))$(RPMS)
DEB_TOP          := _topdir/BUILD
DEB_BUILD        := $(DEB_TOP)/$(NAME)-$(VERSION)
DEB_TARBASE      := $(DEB_TOP)/$(DEB_NAME)_$(VERSION)
REAL_SOURCE      ?= $(eval REAL_SOURCE := $(shell CHROOT_NAME=$(CHROOT_NAME) $(SPECTOOL) $(COMMON_RPM_ARGS) -S -l $(SPEC) | sed -e 2,\$$d -e 's/\#/\\\#/g' -e 's/Source.*:  *//'))$(REAL_SOURCE)
ifeq ($(ID_LIKE),debian)
ifneq ($(DEB_SOURCE),)
SOURCE           ?= $(DEB_SOURCE)
endif
endif
SOURCE           ?= $(REAL_SOURCE)
PATCHES          ?= $(eval PATCHES := $(shell CHROOT_NAME=$(CHROOT_NAME) $(SPECTOOL) $(COMMON_RPM_ARGS) -l $(SPEC) | sed -ne 1d -e '/already present/d' -e 's/.*:  *//' -e 's/.*\///' -e '/\.patch/p'))$(PATCHES)
OTHER_SOURCES    := $(eval OTHER_SOURCES := $(shell CHROOT_NAME=$(CHROOT_NAME) $(SPECTOOL) $(COMMON_RPM_ARGS) -l $(SPEC) | sed -ne 1d -e '/already present/d' -e '/^Patch.*:/d' -e 's/Source.*:  *//' -e 's/.*\///' -e p))$(OTHER_SOURCES)
SOURCES          := $(addprefix _topdir/SOURCES/,$(notdir $(SOURCE) $(OTHER_SOURCES)) $(PATCHES))
ifeq ($(ID_LIKE),debian)
DEBS             := $(addsuffix _$(VERSION)-1_amd64.deb,$(shell sed -n '/-udeb/b; s,^Package:[[:blank:]],$(DEB_TOP)/,p' $(TOPDIR)/debian/control))
DEB_PREV_RELEASE := $(shell cd $(TOPDIR) && dpkg-parsechangelog -S version)
ifneq ($(GIT_SHORT),)
GIT_INFO         ?= .$(GIT_NUM_COMMITS).g$(GIT_SHORT)
endif
DEB_DSC          := $(DEB_NAME)_$(DEB_PREV_RELEASE)$(GIT_INFO).dsc
TARGETS := $(DEBS)
else
TARGETS := $(RPMS) $(SRPM)
endif

define distro_map
	case $(DISTRO_ID) in               \
	    el7) distro="centos7"          \
	    ;;                             \
	    el*) distro="$(DISTRO_ID)"     \
	    ;;                             \
	    sle12.3) distro="sles12.3"     \
	    ;;                             \
	    sl42.3) distro="leap42.3"      \
	    ;;                             \
	    sl15.*) distro="leap15"        \
	    ;;                             \
	    ubuntu*) distro="$(DISTRO_ID)" \
	    ;;                             \
	esac;
endef

define install_repos
	if [ "$(ID_LIKE)" = "debian" ]; then                            \
	    IFS='|' read -ra BASES <<< "$($(DISTRO_BASE)_LOCAL_REPOS)"; \
	    for baseurl in "$${BASES[@]}"; do                           \
	        baseurl="$${baseurl# *}";                               \
	        $(call install_repo,$$baseurl)                          \
	    done;                                                       \
	fi
	for repo in $($(DISTRO_BASE)_PR_REPOS)                                                             \
	            $(PR_REPOS) $(1); do                                                                   \
	    branch="master";                                                                               \
	    build_number="lastSuccessfulBuild";                                                            \
	    if [[ $$repo = *@* ]]; then                                                                    \
	        branch="$${repo#*@}";                                                                      \
	        repo="$${repo%@*}";                                                                        \
	        if [[ $$branch = *:* ]]; then                                                              \
	            build_number="$${branch#*:}";                                                          \
	            branch="$${branch%:*}";                                                                \
	        fi;                                                                                        \
	    fi;                                                                                            \
	    $(call distro_map)                                                                             \
	    baseurl=$${JENKINS_URL:-https://build.hpdd.intel.com/}job/daos-stack/job/$$repo/job/$$branch/; \
	    baseurl+=$$build_number/artifact/artifacts/$$distro/;                                          \
	    $(call install_repo,$$baseurl)                                                                 \
        done
endef

all: $(TARGETS)

%/:
	mkdir -p $@

%.gz: %
	rm -f $@
	gzip $<

%.bz2: %
	rm -f $@
	bzip2 $<

%.xz: %
	rm -f $@
	xz -z $<

_topdir/SOURCES/%: % | _topdir/SOURCES/
	rm -f $@
	ln $< $@

# At least one spec file, SLURM (sles), has a different version for the
# download file than the version in the spec file.
ifeq ($(DL_VERSION),)
DL_VERSION = $(subst ~,,$(VERSION))
endif
ifeq ($(DL_NAME),)
DL_NAME = $(NAME)
endif

$(notdir $(SOURCE) $(OTHER_SOURCES) $(REAL_SOURCE)): $(SPEC) $(CALLING_MAKEFILE)
	# TODO: need to clean up old ones
	$(SPECTOOL) -g $(SPEC)

$(DEB_TOP)/%: % | $(DEB_TOP)/

$(DEB_BUILD)/%: % | $(DEB_BUILD)/

$(DEB_BUILD).tar.$(SRC_EXT): $(notdir $(SOURCE)) | $(DEB_TOP)/
	ln -f $< $@

$(DEB_TARBASE).orig.tar.$(SRC_EXT): $(DEB_BUILD).tar.$(SRC_EXT)
	rm -f $(DEB_TOP)/*.orig.tar.*
	ln -f $< $@

deb_detar: $(notdir $(SOURCE)) $(DEB_TARBASE).orig.tar.$(SRC_EXT)
	# Unpack tarball
	rm -rf ./$(DEB_TOP)/.patched ./$(DEB_TOP)/.detar
	rm -rf ./$(DEB_BUILD)/* ./$(DEB_BUILD)/.pc ./$(DEB_BUILD)/.libs
	mkdir -p $(DEB_BUILD)
	tar -C $(DEB_BUILD) --strip-components=1 -xpf $<

# Extract patches for Debian
$(DEB_TOP)/.patched: $(PATCHES) check-env deb_detar | \
	$(DEB_BUILD)/debian/
	mkdir -p ${DEB_BUILD}/debian/patches
	mkdir -p $(DEB_TOP)/patches
	for f in $(PATCHES); do                                              \
          rm -f $(DEB_TOP)/patches/*;                                    \
	  if git mailsplit -o$(DEB_TOP)/patches < "$$f"; then                \
	      fn=$$(basename "$$f");                                         \
	      for f1 in $(DEB_TOP)/patches/*;do                              \
	        [ -e "$$f1" ] || continue;                                   \
	        f1n=$$(basename "$$f1");                                     \
	        echo "$${fn}_$${f1n}" >> $(DEB_BUILD)/debian/patches/series; \
	        mv "$$f1" $(DEB_BUILD)/debian/patches/$${fn}_$${f1n};        \
	      done;                                                          \
	  else                                                               \
	    fb=$$(basename "$$f");                                           \
	    cp "$$f" $(DEB_BUILD)/debian/patches/;                           \
	    echo "$$fb" >> $(DEB_BUILD)/debian/patches/series;               \
	    if ! grep -q "^Description:\|^Subject:" "$$f"; then              \
	      sed -i '1 iSubject: Auto added patch'                          \
	        "$(DEB_BUILD)/debian/patches/$$fb";                          \
		fi;                                                              \
	    if ! grep -q "^Origin:\|^Author:\|^From:" "$$f"; then            \
	      sed -i '1 iOrigin: other'                                      \
	        "$(DEB_BUILD)/debian/patches/$$fb";                          \
		fi;                                                              \
	  fi;                                                                \
	done
	touch $@


# Move the debian files into the Debian directory.
ifeq ($(ID_LIKE),debian)
$(DEB_TOP)/.deb_files: $(shell find $(TOPDIR)/debian -type f) deb_detar | \
	  $(DEB_BUILD)/debian/
	cd $(TOPDIR)/ && \
	    find debian -maxdepth 1 -type f -exec cp '{}' '$(BUILD_PREFIX)/$(DEB_BUILD)/{}' ';'
	if [ -e $(TOPDIR)/debian/source ]; then \
	  cp -r $(TOPDIR)/debian/source $(DEB_BUILD)/debian; fi
	if [ -e $(TOPDIR)/debian/local ]; then \
	  cp -r $(TOPDIR)/debian/local $(DEB_BUILD)/debian; fi
	if [ -e $(TOPDIR)/debian/examples ]; then \
	  cp -r $(TOPDIR)/debian/examples $(DEB_BUILD)/debian; fi
	if [ -e $(TOPDIR)/debian/upstream ]; then \
	  cp -r $(TOPDIR)/debian/upstream $(DEB_BUILD)/debian; fi
	if [ -e $(TOPDIR)/debian/tests ]; then \
	  cp -r $(TOPDIR)/debian/tests $(DEB_BUILD)/debian; fi
	rm -f $(DEB_BUILD)/debian/*.ex $(DEB_BUILD)/debian/*.EX
	rm -f $(DEB_BUILD)/debian/*.orig
ifneq ($(GIT_INFO),)
	cd $(DEB_BUILD); dch --distribution unstable \
	  --newversion $(DEB_PREV_RELEASE)$(GIT_INFO) \
	  "Git commit information"
endif
	touch $@
endif

# see https://stackoverflow.com/questions/2973445/ for why we subst
# the "rpm" for "%" to effectively turn this into a multiple matching
# target pattern rule
$(subst rpm,%,$(RPMS)): $(SPEC) $(SOURCES)
	rpmbuild -bb $(COMMON_RPM_ARGS) $(RPM_BUILD_OPTIONS) $(SPEC)

$(subst deb,%,$(DEBS)): $(DEB_BUILD).tar.$(SRC_EXT) \
	  deb_detar $(DEB_TOP)/.deb_files $(DEB_TOP)/.patched
	rm -f $(DEB_TOP)/*.deb $(DEB_TOP)/*.ddeb $(DEB_TOP)/*.dsc \
	      $(DEB_TOP)/*.dsc $(DEB_TOP)/*.build* $(DEB_TOP)/*.changes \
	      $(DEB_TOP)/*.debian.tar.*
	rm -rf $(DEB_TOP)/*-tmp
	cd $(DEB_BUILD); debuild --no-lintian -b -us -uc
	cd $(DEB_BUILD); debuild -- clean
	git status
	rm -rf $(DEB_TOP)/$(NAME)-tmp
	lfile1=$(shell echo $(DEB_TOP)/$(NAME)[0-9]*_$(VERSION)-1_amd64.deb);\
	  lfile=$$(ls $${lfile1}); \
	  lfile2=$${lfile##*/}; lname=$${lfile2%%_*}; \
	  dpkg-deb -R $${lfile} \
	    $(DEB_TOP)/$(NAME)-tmp; \
	  if [ -e $(DEB_TOP)/$(NAME)-tmp/DEBIAN/symbols ]; then \
	    sed 's/$(DEB_RVERS)-1/$(DEB_BVERS)/' \
	    $(DEB_TOP)/$(NAME)-tmp/DEBIAN/symbols \
	    > $(DEB_BUILD)/debian/$${lname}.symbols; fi
	cd $(DEB_BUILD); debuild -us -uc
	rm $(DEB_BUILD).tar.$(SRC_EXT)
	for f in $(DEB_TOP)/*.deb; do \
	  echo $$f; dpkg -c $$f; done

$(DEB_TOP)/$(DEB_DSC): $(CALLING_MAKEFILE) $(DEB_BUILD).tar.$(SRC_EXT) \
          deb_detar $(DEB_TOP)/.deb_files $(DEB_TOP)/.patched
	rm -f $(DEB_TOP)/*.deb $(DEB_TOP)/*.ddeb $(DEB_TOP)/*.dsc \
	  $(DEB_TOP)/*.dsc $(DEB_TOP)/*.build* $(DEB_TOP)/*.changes \
	  $(DEB_TOP)/*.debian.tar.*
	rm -rf $(DEB_TOP)/*-tmp
	cd $(DEB_BUILD); dpkg-buildpackage -S --no-sign --no-check-builddeps

$(SRPM): $(SPEC) $(SOURCES)
	if [ -f bz-1955184_find-requires ]; then \
	    chmod 755 bz-1955184_find-requires;  \
	fi
	rpmbuild -bs $(COMMON_RPM_ARGS) $(RPM_BUILD_OPTIONS) $(SPEC)

srpm: $(SRPM)

$(RPMS): $(SRPM) $(CALLING_MAKEFILE)

rpms: $(RPMS)

repo: rpms
	rm -rf _topdir/RPMS/repodata/
	createrepo _topdir/RPMS/

$(DEBS): $(CALLING_MAKEFILE)

debs: $(DEBS)

ls: $(TARGETS)
	ls -ld $^

ifneq ($(PKG_GIT_COMMIT),)
# This not really intended to run in CI.  It's meant as a developer
# convenience to generate the needed patch and add it to the repo to
# be committed.
$(VERSION)..$(PKG_GIT_COMMIT).patch:
ifneq ($(GITHUB_PROJECT),)
	# it really sucks that GitHub's "compare" returns such dirty patches
	#curl -O 'https://github.com/$(GITHUB_PROJECT)/compare/$@'
	git clone https://github.com/$(GITHUB_PROJECT).git
else
	git clone $(GIT_PROJECT)
endif
	set -x; pushd $(NAME) &&                              \
	trap 'popd && rm -rf $(NAME)' EXIT;                   \
	echo git diff $(VERSION)..$(PKG_GIT_COMMIT) --stat -- \
	    $(GIT_DIFF_EXCLUDES );                            \
	git diff $(VERSION)..$(PKG_GIT_COMMIT) --             \
	    $(GIT_DIFF_EXCLUDES) > ../$@;                     \
	popd;                                                 \
	trap 'rm -rf $(NAME)' EXIT;                           \
	git add $@
patch: $(VERSION)..$(PKG_GIT_COMMIT).patch
else
patch:
	echo "PKG_GIT_COMMIT is not defined"
endif

ifeq ($(ID_LIKE),debian)
chrootbuild: $(DEB_TOP)/$(DEB_DSC)
	$(call distro_map)                                      \
	DISTRO="$$distro"                                       \
	PR_REPOS="$(PR_REPOS)"                                  \
	REPO_FILES_PR="$(REPO_FILES_PR)"                        \
	DISTRO_BASE_PR_REPOS="$($(DISTRO_BASE)_PR_REPOS)"       \
	JENKINS_URL="$${JENKINS_URL}"                           \
	JOB_REPOS="$(JOB_REPOS)"                                \
	REPO_FILE_URL="$(REPO_FILE_URL)"                        \
	DISTRO_BASE_LOCAL_REPOS="$($(DISTRO_BASE)_LOCAL_REPOS)" \
	VERSION_CODENAME="$(VERSION_CODENAME)"                  \
	DEB_TOP="$(DEB_TOP)"                                    \
	DEB_DSC="$(DEB_DSC)"                                    \
	DISTRO_ID_OPT="$(DISTRO_ID_OPT)"                        \
	LOCAL_REPOS='$(LOCAL_REPOS)'                            \
	ARTIFACTORY_URL="$(ARTIFACTORY_URL)"                    \
	packaging/debian_chrootbuild
else
chrootbuild: $(SRPM) $(CALLING_MAKEFILE)
	$(call distro_map)                                      \
	DISTRO="$$distro"                                       \
	CHROOT_NAME="$(CHROOT_NAME)"                            \
	PR_REPOS="$(PR_REPOS)"                                  \
	REPO_FILES_PR="$(REPO_FILES_PR)"                        \
	DISTRO_BASE_PR_REPOS="$($(DISTRO_BASE)_PR_REPOS)"       \
	JENKINS_URL="$${JENKINS_URL}"                           \
	JOB_REPOS="$(JOB_REPOS)"                                \
	REPO_FILE_URL="$(REPO_FILE_URL)"                        \
	MOCK_OPTIONS="$(MOCK_OPTIONS)"                          \
	RPM_BUILD_OPTIONS='$(RPM_BUILD_OPTIONS)'                \
	LOCAL_REPOS='$(LOCAL_REPOS)'                            \
	ARTIFACTORY_URL="$(ARTIFACTORY_URL)"                    \
	DISTRO_VERSION="$(DISTRO_VERSION)"                      \
	TARGET="$<"                                             \
	packaging/rpm_chrootbuild
endif

podman_chrootbuild:
	if ! podman build --build-arg REPO_FILE_URL=$(REPO_FILE_URL) \
	                  -t $(subst +,-,$(CHROOT_NAME))-chrootbuild \
	                  -f packaging/Dockerfile.mockbuild .; then  \
		echo "Container build failed";                           \
	    exit 1;                                                  \
	fi
	rm -f /var/lib/mock/$(CHROOT_NAME)/result/{root,build}.log
	if ! podman run --rm --privileged -w $(TOPDIR) -v=$(TOPDIR)/..:$(TOPDIR)/..                                                     \
	                -it $(subst +,-,$(CHROOT_NAME))-chrootbuild                                                                     \
	                bash -c 'if ! DISTRO_REPOS=false                                                                                \
	                              REPO_FILE_URL=$(REPO_FILE_URL)                                                                    \
	                              make REPO_FILES_PR=$(REPO_FILES_PR)                                                               \
	                                   MOCK_OPTIONS=$(MOCK_OPTIONS)                                                                 \
	                                   CHROOT_NAME=$(CHROOT_NAME) -C $(CURDIR) chrootbuild; then                                    \
	                                 cat /var/lib/mock/$(CHROOT_NAME)/{result/{root,build},root/builddir/build/BUILD/*/config}.log; \
	                                 exit 1;                                                                                        \
	                             fi;                                                                                                \
	                             rpmlint $$(ls /var/lib/mock/$(CHROOT_NAME)/result/*.rpm |                                          \
	                                 grep -v -e debuginfo -e debugsource -e src.rpm)'

docker_chrootbuild:
	if ! $(DOCKER) build --build-arg UID=$$(id -u) -t chrootbuild   \
	                     --build-arg REPO_FILE_URL=$(REPO_FILE_URL) \
	                     -f packaging/Dockerfile.mockbuild .; then  \
		echo "Container build failed";                         \
	    exit 1;                                                \
	fi
	rm -f /var/lib/mock/$(CHROOT_NAME)/result/{root,build}.log
	if ! $(DOCKER) run --user=$$(id -u) --privileged=true -w $(TOPDIR) \
	              -v=$(TOPDIR):$(TOPDIR)                               \
	              -it chrootbuild bash -c "make -C $(CURDIR)           \
	              CHROOT_NAME=$(CHROOT_NAME) chrootbuild"; then        \
	    cat /var/lib/mock/$(CHROOT_NAME)/result/{root,build}.log;      \
	    exit 1;                                                        \
	fi

rpmlint: $(SPEC)
	rpmlint --ignore-unused-rpmlintrc $<

packaging_check:
	if grep -e --repo $(CALLING_MAKEFILE); then                                    \
	    echo "SUSE repos in $(CALLING_MAKEFILE) don't need a \"--repo\" any more"; \
	    exit 2;                                                                    \
	fi
	if ! diff --exclude \*.sw?                              \
	          --exclude debian                              \
	          --exclude .git                                \
	          --exclude Jenkinsfile                         \
	          --exclude libfabric.spec                      \
	          --exclude Makefile                            \
	          --exclude README.md                           \
	          --exclude _topdir                             \
	          --exclude \*.tar.\*                           \
	          --exclude \*.code-workspace                   \
	          --exclude install                             \
	          --exclude packaging                           \
	          --exclude utils                               \
	          --exclude .vscode                             \
	          -bur $(PACKAGING_CHECK_DIR)/ packaging/; then \
	    exit 1;                                             \
	fi

check-env:
ifndef DEBEMAIL
	$(error DEBEMAIL is undefined)
endif
ifndef DEBFULLNAME
	$(error DEBFULLNAME is undefined)
endif

test:
	# Test the rpmbuild by installing the built RPM
	$(call install_repos,$(REPO_NAME)@$(BRANCH_NAME):$(BUILD_NUMBER))
	dnf -y install $(TEST_PACKAGES)

show_NAME:
	@echo '$(NAME)'

show_DISTRO_ID:
	@echo '$(DISTRO_ID)'

show_distro_map:
	@$(call distro_map) echo "$$distro"

show_spec:
	@echo '$(SPEC)'

show_build_defines:
	@echo '$(BUILD_DEFINES)'

show_common_rpm_args:
	@echo '$(COMMON_RPM_ARGS)'

show_version:
	@echo '$(VERSION)'

show_dl_version:
	@echo '$(DL_VERSION)'

show_release:
	@echo '$(RELEASE)'

show_rpms:
	@echo '$(RPMS)'

show_source:
	@echo '$(SOURCE)'

show_real_source:
	@echo '$(REAL_SOURCE)'

show_patches:
	@echo '$(PATCHES)'

show_sources:
	@echo '$(SOURCES)'

show_other_sources:
	@echo '$(OTHER_SOURCES)'

show_targets:
	@echo '$(TARGETS)'

show_makefiles:
	@echo '$(MAKEFILE_LIST)'

show_calling_makefile:
	@echo '$(CALLING_MAKEFILE)'

show_git_metadata:
	@echo '$(GIT_SHA1):$(GIT_SHORT):$(GIT_NUM_COMMITS)'

.PHONY: srpm rpms debs deb_detar ls chrootbuild rpmlint FORCE        \
        show_version show_release show_rpms show_source show_sources \
        show_targets check-env show_git_metadata
