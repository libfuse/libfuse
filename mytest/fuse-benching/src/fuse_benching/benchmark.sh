#!/usr/bin/env bash
#
# benchmark.sh
# /home/kvelusamy/Desktop/fuse-benching/src/fuse_benching/benchmark.sh
#
# Before running, ensure you have a directory “/sizedFiles/” containing:
#	1GiB.bin
#
#	Other-Files in /sizedFiles/(not currently used -- keeping them JIC for testing purposes): 
#	1B.bin, 2B.bin, 256B.bin, 1KiB.bin, 2KiB.bin, 4KiB.bin, 16KiB.bin, 64KiB.bin, 256KiB.bin, 512KiB.bin,
#	1MiB.bin, 2MiB.bin, 4MiB.bin, 16MiB.bin, 64MiB.bin, 256MiB.bin, 512MiB.bin, 	
#
# Usage:
#   ./benchmark.sh
#
# This script should benchmark file transfers with FUSE, altering the byte value of max_read using flags (-o max_read=X) from 1 byte to 1GiB.
# The script should record: bandwidth per transfer, average transfer (bandwidth), standard deviations of transfer (bandwidth).
# The script should just test with the /sizedFiles/1GiB.bin file.
# This script feeds into a python script named plot_bench.py in order to plot with matplotlib.
# /home/kvelusamy/Desktop/fuse-benching/src/fuse_benching/plot_bench.py

set -euo pipefail

####################################################################################
# 1) Configuration
####################################################################################

# Path to passthrough
PASSTHROUGH_BIN="/home/kvelusamy/Desktop/libfuse-master/example/passthrough"

# The backing-store directory
BACKING_STORE="/home/kvelusamy/Desktop/fuse-benching/passthroughData"

# The mountpoint for FUSE
MOUNTPOINT="/home/kvelusamy/Desktop/fuse-benching/mountpoint"

# Directory containing the the pre-made test files
SIZE_DIR="/home/kvelusamy/Desktop/fuse-benching/sizedFiles"

# .bin file to be tested with various max_read values.
TESTED_SIZED_FILE="/home/kvelusamy/Desktop/fuse-benching/sizedFiles/1GiB.bin"

ITERATIONS=10

MAX_READ_SIZES=(
  1	     # 1 B
  256	     # 256 B
  1024       # 1 KiB
  4096       # 4 KiB
  65536      # 64 KiB
  131072     # 128 KiB <-(Default)
  262144     # 256 KiB
  524288     # 512 KiB
  1048576    # 1 MiB
  2097152    # 2 MiB
  1073741824 # 1 GiB
)

####################################################################################
# 2) Preparation
####################################################################################

# Ensure mountpoint exists
mkdir -p "$MOUNTPOINT"

# Initialize results CSV
RESULTS_CSV="results.csv"
echo "max_read,iteration,bandwidth_MBps" > "$RESULTS_CSV"

ls -lah /usr/lib/libfuse3.so.4

####################################################################################
# 3) Benchmark loop
####################################################################################

test_num=0
for maxr in "${MAX_READ_SIZES[@]}"; do
  test_num=$((test_num+1))
  echo
  echo "Starting Test $test_num: max_read=$maxr"
  echo "------------------------------------------------"

  for i in $(seq 1 "$ITERATIONS"); do
    # Start FUSE passthrough in foreground
    "$PASSTHROUGH_BIN" -f -o max_read=$maxr "$MOUNTPOINT" &
    PT_PID=$!
    sleep 0.2  # allow mount

    # Clear OS page cache
    sync
    sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'

    # Time the copy operation (wall-clock seconds)
    ELAPSED=$(
      /usr/bin/time -f "%e" \
        cp "$TESTED_SIZED_FILE" "$MOUNTPOINT/" 2>&1 >/dev/null
    )

    # Compute throughput (MB/s)
    BYTES=$(stat --printf=%s "$TESTED_SIZED_FILE")
    MBPS=$(awk -v b=$BYTES -v s=$ELAPSED 'BEGIN{printf("%.2f", b/1024/1024/s)}')

    # Print iteration result 
    echo "Iteration $i: $MBPS MB/s"

	# add elapsed time

    # Record results
    echo "$maxr,$i,$MBPS" >> "$RESULTS_CSV"

    # Teardown
    kill "$PT_PID" >/dev/null 2>&1 || true
    fusermount3 -u "$MOUNTPOINT" >/dev/null 2>&1 || true
    sleep 0.1
  done

  echo "Completed max_read=$maxr"
done

####################################################################################
# 4) Plotting
####################################################################################

# Call the Python plotting script and open the result
python plot_bench.py "$RESULTS_CSV"
# Optionally open automatically
xdg-open benchmark_plot.png >/dev/null 2>&1 || true

