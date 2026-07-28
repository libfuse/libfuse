#!/bin/bash
#
# The build configurations, one case branch each. Usage:
#   configs.sh <name> [args]   run ci-build.sh for that configuration
#
# The set of names is the workflow's build matrix; an unknown one is a typo
# there and fails below rather than silently building nothing.

set -eu

name="$1"; shift
build="$(dirname "$0")/../ci-build.sh"

# A CI job is only useful if it can be repeated by hand, so print the whole
# command. The argv itself is the one spelling that cannot drift from what
# runs.
run()
{
	printf 'running: %s\n' "$*"
	exec "$@"
}

case "${name}" in
gcc)
	run "${build}" --name gcc --cc gcc --valgrind "$@"
	;;
gcc-9)
	run "${build}" --name gcc-9 --cc gcc-9 --valgrind "$@"
	;;
gcc-10)
	run "${build}" --name gcc-10 --cc gcc-10 --valgrind \
		--meson-opt -Dc_args=-flto=auto "$@"
	;;
clang)
	# No valgrind: it and the sanitizers are kept apart, and clang is what
	# the sanitized configurations use.
	run "${build}" --name clang --cc clang --cxx clang++ "$@"
	;;
san)
	# The plain sanitized build. This is also the configuration that
	# exercises fuse-io-uring: the transport is worth testing with the
	# sanitizers on, and once per run rather than once per build and user.
	run "${build}" --name san --cc clang --cxx clang++ --sanitize \
		--root-pass --io-uring "$@"
	;;
san-nosymver)
	# Sanitized build without libc versioned symbols.
	run "${build}" --name san-nosymver --cc clang --cxx clang++ \
		--sanitize --root-pass \
		--meson-opt -Ddisable-libc-symbol-version=true "$@"
	;;
san-noiouring)
	# Sanitized build with fuse-io-uring compiled out. It runs the default
	# suite only; run-tests.py --io-uring would refuse this build anyway,
	# since HAVE_URING is absent from its fuse_config.h.
	run "${build}" --name san-noiouring --cc clang --cxx clang++ \
		--sanitize --root-pass \
		--meson-opt -Denable-io-uring=false "$@"
	;;
san-m32)
	# 32-bit sanitized build. These are compiler flags rather than meson
	# options, so they travel in the environment; env keeps them part of
	# the printed command instead of an export the reader has to guess.
	run env CFLAGS=-m32 CXXFLAGS=-m32 LDFLAGS=-m32 \
		PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig \
		"${build}" --name san-m32 --cc clang --cxx clang++ --sanitize \
		--root-pass "$@"
	;;
*)
	echo "unknown configuration: ${name}" >&2
	exit 1
	;;
esac
