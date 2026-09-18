#!/bin/bash
#
# Run a test/ci-build.sh command line against another kernel, in a virtme-ng
# guest.
#
# The guest boots the chosen kernel on the host's own filesystem, so the
# checkout, the toolchain and the caller's uid are the ones already here and
# only the kernel differs. That is the whole point: a GitHub runner cannot be
# rebooted into the kernel a test needs.

set -e

usage()
{
    cat >&2 <<EOF
usage: $0 --kernel KERNEL [options] -- test/ci-build.sh ARG...

  --kernel KERNEL   what to boot:
                      latest-rc  newest release candidate in the Ubuntu
                                 mainline archive, kernel.ubuntu.com/mainline
                      latest     newest release there
                      v7.3-rc2   that version from the same archive
                      FILE.deb   a kernel deb, unpacked for this run; a
                                 directory of debs works too, and its
                                 linux-headers ones are skipped
                      PATH       a kernel image, or a directory holding a
                                 kernel built from source
                    Archive kernels are downloaded once and cached under
                    ~/.cache/virtme-ng.
  --logs-out DIR    host directory to copy the run logs into
  --cpus N          guest cpus (default: the host's, at most 8)
  --memory SIZE     guest memory (default: 8G)

--work-dir is appended to the command: the guest one has to be guest-local,
see below.
EOF
    exit 1
}

need_arg()
{
    [ $# -ge 2 ] || { echo "$0: $1 needs an argument" >&2; exit 1; }
}

MAINLINE_URL=https://kernel.ubuntu.com/mainline

# newest_mainline latest-rc|latest
# Print the newest release candidate, or the newest release, that the mainline
# archive has packages for on this architecture.
newest_mainline()
{
    local want=$1 arch versions version

    arch="$(dpkg --print-architecture)"
    versions="$(curl -sS --max-time 60 "${MAINLINE_URL}/" |
        grep -oE 'href="v[0-9][^"/]*/"' | sed 's/href="//; s#/"##')"
    if [ "${want}" = latest-rc ]; then
        versions="$(printf '%s\n' "${versions}" | grep -E -- '-rc[0-9]+$')"
    else
        versions="$(printf '%s\n' "${versions}" | grep -Ev -- '-rc[0-9]+$')"
    fi

    # A version is listed as soon as its build starts, and a build that failed
    # leaves the directory there with a log and no packages, so walk down from
    # the newest until one has some.
    for version in $(printf '%s\n' "${versions}" | sort -rV); do
        if curl -sS --max-time 30 "${MAINLINE_URL}/${version}/${arch}/" |
                grep -q '\.deb'; then
            printf '%s\n' "${version}"
            return 0
        fi
    done

    echo "$0: no ${want} kernel with ${arch} packages" >&2
    return 1
}

# `dpkg -x` writes usr/lib/modules and no lib symlink. virtme looks for
# lib/modules beside the kernel image, finds nothing, and builds an initramfs
# without virtiofs -- the guest then panics on the root filesystem it was
# handed.
link_usr_lib()
{
    [ -e "$1/lib" ] || ln -s usr/lib "$1/lib"
}

# kernel_debs PATH
# Print the kernel debs at PATH, and nothing at all when it holds none: an
# image or a build directory goes to vng as it is.
kernel_debs()
{
    local path=$1 deb

    case "${path}" in
    *.deb)
        printf '%s\n' "${path}"
        return 0
        ;;
    esac

    [ -d "${path}" ] || return 0
    for deb in "${path}"/*.deb; do
        [ -e "${deb}" ] || continue
        # A headers package carries no kernel and unpacks a source tree.
        case "${deb}" in
        *headers*) continue ;;
        esac
        printf '%s\n' "${deb}"
    done
}

# unpack_kernel_debs DIR DEB...
# Unpack kernel debs into DIR and print the kernel image they hold. vng --run
# hands a path straight to --kimg, which wants an image and not a package.
unpack_kernel_debs()
{
    local dir=$1 host_arch deb deb_arch images version
    shift

    host_arch="$(dpkg --print-architecture)"
    for deb in "$@"; do
        deb_arch="$(dpkg-deb -f "${deb}" Architecture)"
        if [ "${deb_arch}" != all ] &&
                [ "${deb_arch}" != "${host_arch}" ]; then
            echo "$0: ${deb} is ${deb_arch}, this host runs ${host_arch}" >&2
            return 1
        fi
        dpkg -x "${deb}" "${dir}"
    done
    link_usr_lib "${dir}"

    images=("${dir}"/boot/vmlinuz*)
    if [ ! -e "${images[0]}" ]; then
        echo "$0: no kernel image in $*" >&2
        return 1
    fi
    if [ "${#images[@]}" -gt 1 ]; then
        echo "$0: $* hold ${#images[@]} kernels, pick one" >&2
        return 1
    fi

    version="$(basename "${images[0]}")"
    version="${version#vmlinuz-}"
    if [ ! -d "${dir}/lib/modules/${version}" ]; then
        echo "$0: no modules for ${version} in $*" >&2
        echo "$0: Ubuntu keeps them in a separate linux-modules deb" >&2
        return 1
    fi

    printf '%s\n' "${images[0]}"
}

cleanup()
{
    [ -z "${DEB_DIR}" ] || rm -rf "${DEB_DIR}"
    [ -z "${PROLOGUE}" ] || rm -f "${PROLOGUE}"
}

KERNEL=
LOGS_OUT=
DEB_DIR=
PROLOGUE=
trap cleanup EXIT
# A fuse-over-io-uring daemon takes a queue per core and the suite runs many
# of them at once, so handing a guest every core of a big host runs it out of
# memory rather than making it faster.
CPUS="$(nproc)"
[ "${CPUS}" -le 8 ] || CPUS=8
MEMORY=8G

while [ $# -gt 0 ]; do
    case $1 in
    --kernel)    need_arg "$@"; KERNEL=$2; shift 2 ;;
    --logs-out)  need_arg "$@"; LOGS_OUT=$2; shift 2 ;;
    --cpus)      need_arg "$@"; CPUS=$2; shift 2 ;;
    --memory)    need_arg "$@"; MEMORY=$2; shift 2 ;;
    --)          shift; break ;;
    *)           usage ;;
    esac
done
[ -n "${KERNEL}" ] || usage
[ $# -gt 0 ] || usage

command -v vng > /dev/null ||
    { echo "$0: no vng; install the virtme-ng package" >&2; exit 1; }

# Resolved before anything else uses it, and reported: a run that picked its
# own kernel has to say which one, or a failure cannot be repeated.
case "${KERNEL}" in
latest-rc|latest)
    KERNEL="$(newest_mainline "${KERNEL}")" || exit 1
    echo "$0: kernel ${KERNEL}"
    ;;
esac

case "${KERNEL}" in
v[0-9]*)
    # KernelDownloader unpacks the mainline debs. Fetch first so the cache
    # directory exists, then link it.
    CACHE="${HOME}/.cache/virtme-ng/${KERNEL}/$(dpkg --print-architecture)"
    if [ ! -d "${CACHE}/boot" ]; then
        vng --run "${KERNEL}" --dry-run --exec /bin/true > /dev/null
    fi
    link_usr_lib "${CACHE}"
    ;;
*)
    mapfile -t DEBS < <(kernel_debs "${KERNEL}")
    if [ "${#DEBS[@]}" -gt 0 ]; then
        # Unpacked afresh every run, never cached: `make bindeb-pkg` writes
        # the same file name on every rebuild, so a cache keyed by that name
        # would boot the kernel the caller has just replaced.
        DEB_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/fuse-vm-kernel.XXXXXX")"
        KERNEL="$(unpack_kernel_debs "${DEB_DIR}" "${DEBS[@]}")" || exit 1
    fi
    ;;
esac

# The work directory has to stay on the guest's own tmpfs. Handing it out over
# 9p instead costs a setuid fusermount3 -- files land on the host owned by the
# qemu user, so the bit elevates to that user rather than to root -- and a
# build there did not finish at all.
GUEST_WORK_DIR=/var/tmp/fuse-tests
RUN_USER="$(id -un)"
VNG_OPTS=(--run "${KERNEL}" --cpus "${CPUS}" --memory "${MEMORY}")

if [ -n "${LOGS_OUT}" ]; then
    mkdir -p "${LOGS_OUT}"
    LOGS_OUT="$(readlink -f "${LOGS_OUT}")"
    VNG_OPTS+=(--rwdir "${LOGS_OUT}")
fi

# The guest reads this through the overlay over the host's /tmp. Passing the
# prologue as a --exec string instead would nest three levels of quoting
# around the caller's own command line.
PROLOGUE="$(mktemp /tmp/fuse-vm-run.XXXXXX)"
chmod +x "${PROLOGUE}"

# virtme-ng runs --exec as root, and virtme-init writes its own /etc/sudoers
# holding a single root rule and no @includedir, so a /etc/sudoers.d drop-in
# is read by nobody and ci-build.sh cannot reach `sudo ninja install`.
cat > "${PROLOGUE}" <<EOF
#!/bin/bash

echo '${RUN_USER} ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers

# fusectl holds /sys/fs/fuse/connections/<dev>/abort, which the teardown tests
# write to. systemd mounts it and this guest has no systemd; without it those
# tests sit until their timeout.
mkdir -p /sys/fs/fuse/connections
mount -t fusectl none /sys/fs/fuse/connections 2> /dev/null || true

# Same story for /dev/cuse, which the cuse example needs: nothing in the guest
# autoloads a module.
modprobe cuse 2> /dev/null || true

cd $(printf '%q' "$PWD")

rc=0
runuser -u '${RUN_USER}' -- \
    env HOME=$(printf '%q' "$HOME") USER='${RUN_USER}' PATH=$(printf '%q' "$PATH") \
    $(printf '%q ' "$@") --work-dir '${GUEST_WORK_DIR}' || rc=\$?

[ -z '${LOGS_OUT}' ] ||
    cp -a '${GUEST_WORK_DIR}'/run '${LOGS_OUT}'/ 2> /dev/null || true

exit \$rc
EOF

# Not exec: the EXIT trap has to run, and an unpacked kernel is not small.
vng "${VNG_OPTS[@]}" --exec "${PROLOGUE}"
