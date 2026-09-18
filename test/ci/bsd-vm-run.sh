#!/bin/bash
#
# Build libfuse and run the test suite in a FreeBSD guest under qemu.
#
# The guest boots a stock FreeBSD cloud image, gets the checkout over ssh and
# runs everything as root, so the one run is the same on a GitHub runner and
# on a developer machine.

set -e

usage()
{
    cat >&2 <<EOF
usage: $0 [options]

  --release REL     FreeBSD release to boot: "latest" (default) for the
                    newest one on download.freebsd.org, or a version such
                    as 15.1. Images are downloaded once and cached under
                    ~/.cache/fuse-bsd-vm.
  --print-cache     print the image cache directory and the release that
                    would boot, as NAME=VALUE lines, and boot nothing
  --logs-out DIR    host directory to copy the run logs into
  --cpus N          guest cpus (default: the host's, at most 4)
  --memory SIZE     guest memory (default: 4G)
EOF
    exit 1
}

need_arg()
{
    [ $# -ge 2 ] || { echo "$0: $1 needs an argument" >&2; exit 1; }
}

IMAGES_URL=https://download.freebsd.org/releases/VM-IMAGES
CACHE_DIR="${HOME}/.cache/fuse-bsd-vm"

# newest_release
# Print the newest N.M release the image archive has, betas and release
# candidates skipped.
newest_release()
{
    local release

    release="$(curl -sS --max-time 60 "${IMAGES_URL}/" |
        grep -oE 'href="[0-9]+\.[0-9]+-RELEASE/"' |
        sed 's/href="//; s/-RELEASE\/"//' | sort -V | tail -n 1)"
    if [ -z "${release}" ]; then
        echo "$0: no release listed at ${IMAGES_URL}" >&2
        return 1
    fi
    printf '%s\n' "${release}"
}

# fetch_image RELEASE
# Print the cached qcow2 image for RELEASE, downloading and verifying it
# first when the cache does not hold it yet.
fetch_image()
{
    local release=$1 name url image expected actual

    name="FreeBSD-${release}-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2"
    url="${IMAGES_URL}/${release}-RELEASE/amd64/Latest"
    image="${CACHE_DIR}/${name}"
    if [ -e "${image}" ]; then
        printf '%s\n' "${image}"
        return 0
    fi

    mkdir -p "${CACHE_DIR}"
    echo "$0: fetching ${name}.xz" >&2
    curl -sS --fail --max-time 1800 -o "${image}.xz.part" "${url}/${name}.xz"
    expected="$(curl -sS --fail --max-time 60 "${url}/CHECKSUM.SHA256" |
        sed -n "s/^SHA256 (${name}.xz) = //p")"
    actual="$(sha256sum "${image}.xz.part" | cut -d' ' -f1)"
    if [ -z "${expected}" ] || [ "${expected}" != "${actual}" ]; then
        rm -f "${image}.xz.part"
        echo "$0: checksum mismatch on ${name}.xz" >&2
        return 1
    fi
    xz -d -c "${image}.xz.part" > "${image}.part"
    rm -f "${image}.xz.part"
    mv "${image}.part" "${image}"
    printf '%s\n' "${image}"
}

# free_port
# Print a TCP port nothing on localhost listens on.
free_port()
{
    python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])'
}

cleanup()
{
    [ -z "${QEMU_PID}" ] || kill "${QEMU_PID}" 2> /dev/null || true
    [ -z "${RUN_DIR}" ] || rm -rf "${RUN_DIR}"
}

RELEASE=latest
PRINT_CACHE=0
LOGS_OUT=
QEMU_PID=
RUN_DIR=
trap cleanup EXIT
CPUS="$(nproc)"
[ "${CPUS}" -le 4 ] || CPUS=4
MEMORY=4G

while [ $# -gt 0 ]; do
    case $1 in
    --release)   need_arg "$@"; RELEASE=$2; shift 2 ;;
    --print-cache) PRINT_CACHE=1; shift ;;
    --logs-out)  need_arg "$@"; LOGS_OUT=$2; shift 2 ;;
    --cpus)      need_arg "$@"; CPUS=$2; shift 2 ;;
    --memory)    need_arg "$@"; MEMORY=$2; shift 2 ;;
    *)           usage ;;
    esac
done

# Resolved before anything else uses it, and reported: a run that picked its
# own release has to say which one, or a failure cannot be repeated.
if [ "${RELEASE}" = latest ]; then
    RELEASE="$(newest_release)" || exit 1
fi
if [ "${PRINT_CACHE}" = 1 ]; then
    echo "dir=${CACHE_DIR}"
    echo "release=${RELEASE}"
    exit 0
fi
echo "$0: FreeBSD ${RELEASE}"

for tool in qemu-system-x86_64 qemu-img ssh ssh-keygen xz; do
    command -v "${tool}" > /dev/null ||
        { echo "$0: no ${tool}" >&2; exit 1; }
done
if command -v xorriso > /dev/null; then
    MKISOFS=(xorriso -as mkisofs)
elif command -v genisoimage > /dev/null; then
    MKISOFS=(genisoimage)
else
    echo "$0: no xorriso and no genisoimage" >&2
    exit 1
fi

IMAGE="$(fetch_image "${RELEASE}")" || exit 1
SOURCE_DIR="$(readlink -f "$(dirname "$0")/../..")"
RUN_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/fuse-bsd-vm.XXXXXX")"

# The cached image stays pristine; every run writes into its own overlay.
# growfs on the guest's first boot takes the extra space.
qemu-img create -q -f qcow2 -b "${IMAGE}" -F qcow2 "${RUN_DIR}/disk.qcow2" 20G

ssh-keygen -q -t ed25519 -N '' -f "${RUN_DIR}/id_ed25519"

# NoCloud seed: nuageinit reads it from a cidata-labelled ISO. The rc.conf.d
# file is written before sshd starts, and lets root in with the key only.
mkdir "${RUN_DIR}/seed"
printf 'instance-id: fuse-tests\nlocal-hostname: freebsd\n' \
    > "${RUN_DIR}/seed/meta-data"
cat > "${RUN_DIR}/seed/user-data" <<EOF
#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "${RUN_DIR}/id_ed25519.pub")
write_files:
  - path: /etc/rc.conf.d/sshd
    content: |
      sshd_flags="-o PermitRootLogin=prohibit-password"
EOF
"${MKISOFS[@]}" -quiet -V cidata -J -r -o "${RUN_DIR}/seed.iso" \
    "${RUN_DIR}/seed/meta-data" "${RUN_DIR}/seed/user-data"

if [ -w /dev/kvm ]; then
    ACCEL=kvm
else
    ACCEL=tcg
    echo "$0: /dev/kvm not writable, running without hardware acceleration" >&2
fi

PORT="$(free_port)"
qemu-system-x86_64 -accel "${ACCEL}" -cpu max -smp "${CPUS}" -m "${MEMORY}" \
    -display none -serial "file:${RUN_DIR}/console.log" \
    -drive "file=${RUN_DIR}/disk.qcow2,if=virtio,format=qcow2" \
    -cdrom "${RUN_DIR}/seed.iso" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${PORT}-:22" \
    -device virtio-net-pci,netdev=net0 &
QEMU_PID=$!

SSH=(ssh -p "${PORT}" -i "${RUN_DIR}/id_ed25519" -o StrictHostKeyChecking=no
     -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
     -o ConnectTimeout=5 root@127.0.0.1)

# The first boot grows the filesystem and runs nuageinit before sshd is up.
for _ in $(seq 60); do
    if ! kill -0 "${QEMU_PID}" 2> /dev/null; then
        echo "$0: qemu exited, see ${RUN_DIR}/console.log" >&2
        RUN_DIR=
        exit 1
    fi
    "${SSH[@]}" true 2> /dev/null && break
    sleep 5
done
if ! "${SSH[@]}" true 2> /dev/null; then
    echo "$0: guest never answered on ssh, see ${RUN_DIR}/console.log" >&2
    RUN_DIR=
    exit 1
fi

# The tree as git sees it: tracked and untracked-but-not-ignored files, with
# whatever is modified locally, and none of the build directories.
git -C "${SOURCE_DIR}" ls-files -co --exclude-standard -z |
    tar -C "${SOURCE_DIR}" --null -T - -c |
    "${SSH[@]}" 'mkdir -p libfuse && tar -x -C libfuse'

rc=0
"${SSH[@]}" sh -s <<'EOF' || rc=$?
set -e
# bash because FreeBSD has none in base and common.sh uses arrays, python3
# for checks.py, and gdb because the base debugger is lldb -- one backtrace
# back-end keeps the runner's output identical on both platforms.
pkg install -y meson ninja bash python3 gdb
kldload fusefs || true
sysctl kern.coredump=1
# Mirrors the core.%e.%p Ubuntu is set to, so a core lands in the test's own
# log directory under the same name on both platforms.
sysctl kern.corefile=core.%N.%P
sysctl vfs.usermount=1
cd libfuse
mkdir build
cd build
meson setup ..
ninja -v
../test/run-tests.py --build-dir . --run-dir "$PWD/../fuse-tests/run/freebsd"
EOF

if [ -n "${LOGS_OUT}" ]; then
    mkdir -p "${LOGS_OUT}"
    "${SSH[@]}" 'cd libfuse/fuse-tests 2> /dev/null &&
        tar -c --exclude mnt --exclude "*.sock" run' |
        tar -x -C "${LOGS_OUT}"
fi

exit ${rc}
