DOT     := .

DOCKER  := docker

# Find out what we are
ID_LIKE          := $(shell . /etc/os-release; echo $$ID_LIKE)
# Of course that does not work for SLES-12
ID               := $(shell . /etc/os-release; echo $$ID)
VERSION_ID       := $(shell . /etc/os-release; echo $$VERSION_ID)
VERSION_CODENAME := $(shell . /etc/os-release; echo $$VERSION_CODENAME)

ifeq ($(ID_LIKE),debian)
SPECTOOL       := spectool
UBUNTU_VERS    := $(shell . /etc/os-release; echo $$VERSION)
DISTRO_ID_OPT  := --distribution $(VERSION_CODENAME)
DISTRO_ID      := ubuntu$(VERSION_ID)
VERSION_ID_STR := $(subst $(DOT),_,$(VERSION_ID))
DISTRO_BASE    := UBUNTU_$(VERSION_ID_STR)
endif
ifeq ($(ID),fedora)
DOCKER   := podman
SPECTOOL := spectool
# a Fedora-based mock builder
# derive the the values of:
# VERSION_ID (i.e. 7)
# DISTRO_ID (i.e. el7)
# DISTRO_BASE (i.e. EL_7)
# from the CHROOT_NAME
ifeq ($(patsubst %epel-7-x86_64,,$(lastword $(subst +, ,$(CHROOT_NAME)))),)
DIST            := $(shell rpm $(COMMON_RPM_ARGS) --eval %{?dist})
VERSION_ID      := 7
DISTRO_ID       := el7
DISTRO_BASE     := EL_7
DISTRO_VERSION  ?= $(VERSION_ID)
ORIG_TARGET_VER := 7
SED_EXPR        := 1s/$(DIST)//p
endif
ifeq ($(patsubst %epel-8-x86_64,,$(lastword $(subst +, ,$(CHROOT_NAME)))),)
DIST            := $(shell rpm $(COMMON_RPM_ARGS) --eval %{?dist})
VERSION_ID      := 8
DISTRO_ID       := el8
DISTRO_BASE     := EL_8
ifneq ($(DISTRO_VERSION_EL8),)
override DISTRO_VERSION := $(DISTRO_VERSION_EL8)
endif
DISTRO_VERSION  ?= $(VERSION_ID)
ORIG_TARGET_VER := 8
SED_EXPR        := 1s/$(DIST)//p
endif
ifeq ($(patsubst %epel-9-x86_64,,$(lastword $(subst +, ,$(CHROOT_NAME)))),)
DIST            := $(shell rpm $(COMMON_RPM_ARGS) --eval %{?dist})
VERSION_ID      := 9
DISTRO_ID       := el9
DISTRO_BASE     := EL_9
ifneq ($(DISTRO_VERSION_EL9),)
override DISTRO_VERSION := $(DISTRO_VERSION_EL9)
endif
DISTRO_VERSION  ?= $(VERSION_ID)
ORIG_TARGET_VER := 9
SED_EXPR        := 1s/$(DIST)//p
endif
ifeq ($(CHROOT_NAME),opensuse-leap-15.2-x86_64)
VERSION_ID      := 15.2
DISTRO_ID       := sl15.2
DISTRO_BASE     := LEAP_15
DISTRO_VERSION  ?= $(VERSION_ID)
ORIG_TARGET_VER := 15.2
SED_EXPR        := 1p
endif
ifeq ($(CHROOT_NAME),opensuse-leap-15.3-x86_64)
VERSION_ID      := 15.3
DISTRO_ID       := sl15.3
DISTRO_BASE     := LEAP_15
DISTRO_VERSION  ?= $(VERSION_ID)
ORIG_TARGET_VER := 15.3
SED_EXPR        := 1p
endif
ifeq ($(CHROOT_NAME),opensuse-leap-15.4-x86_64)
VERSION_ID      := 15.4
DISTRO_ID       := sl15.4
DISTRO_BASE     := LEAP_15
DISTRO_VERSION  ?= $(VERSION_ID)
ORIG_TARGET_VER := 15.4
SED_EXPR        := 1p
endif
endif
ifeq ($(ID),centos)
ID = el
endif
ifeq ($(ID),rocky)
ID = el
endif
ifeq ($(ID),almalinux)
ID = el
endif
ifeq ($(ID),rhel)
ID = el
endif
ifeq ($(ID),el)
DISTRO_ID := el$(VERSION_ID)
DISTRO_BASE := $(basename EL_$(VERSION_ID))
DIST        := $(shell rpm $(COMMON_RPM_ARGS) --eval %{?dist})
SED_EXPR    := 1s/$(DIST)//p
SPECTOOL    := spectool
define install_repo
	if yum-config-manager --add-repo=$(1); then                  \
	    repo_file=$$(ls -tar /etc/yum.repos.d/*.repo | tail -1); \
	    sed -i -e 1d -e '$$s/^/gpgcheck=False/' $$repo_file;     \
	else                                                         \
	    exit 1;                                                  \
	fi
endef
endif
ifeq ($(findstring opensuse,$(ID)),opensuse)
ID_LIKE := suse
DISTRO_ID := sl$(VERSION_ID)
DISTRO_BASE := $(basename LEAP_$(VERSION_ID))
endif
ifeq ($(ID),sles)
# SLES-12 or 15 detected.
ID_LIKE := suse
DISTRO_ID := sle$(VERSION_ID)
DISTRO_BASE := $(basename SLES_$(VERSION_ID))
endif
ifeq ($(ID_LIKE),suse)
SPECTOOL    := rpmdev-spectool
define install_repo
	zypper --non-interactive ar $(1)
endef
endif
ifeq ($(ID_LIKE),debian)
ifndef LANG
export LANG = C.UTF-8
endif
ifndef LC_ALL
export LC_ALL = C.UTF-8
endif
else
ifndef LANG
export LANG = C.utf8
endif
ifndef LC_ALL
export LC_ALL = C.utf8
endif
endif
