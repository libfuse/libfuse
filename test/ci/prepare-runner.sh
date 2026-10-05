#!/bin/bash
#
# CI runner setup. Not for a workstation: it changes kernel settings and
# directory permissions outside the build tree.
#
# Usage: prepare-runner.sh <work-dir>
#        prepare-runner.sh --vm

set -e

if [ "$1" = --vm ]; then
    # Without /dev/kvm qemu emulates and the suite takes hours.
    echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
        sudo tee /etc/udev/rules.d/99-kvm4all.rules
    sudo udevadm control --reload-rules
    sudo udevadm trigger --name-match=kvm
    exit 0
fi

WORK_DIR="$(readlink -f "${1:?usage: prepare-runner.sh <work-dir> | --vm}")"
SOURCE_DIR="$(readlink -f "$(dirname "$0")/../..")"

# Keep cores in the test's log directory instead of handing them to apport.
sudo sysctl -w kernel.core_pattern=core.%e.%p
sudo sysctl -w kernel.core_uses_pid=0

# Root tests without CAP_DAC_OVERRIDE must still reach the built binaries.
dir="$(dirname "${WORK_DIR}")"
while [ "${dir}" != / ]; do
    if [ -z "$(find "${dir}" -maxdepth 0 -perm -001)" ]; then
        chmod o+x "${dir}" 2>/dev/null || sudo chmod o+x "${dir}"
    fi
    dir="$(dirname "${dir}")"
done
python3 "${SOURCE_DIR}/test/cases/lib/checks.py" fuse_test_reachable_without_caps \
    "$(dirname "${WORK_DIR}")" ||
    { echo "use --work-dir to build somewhere reachable"; exit 1; }
