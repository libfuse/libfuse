#!/bin/bash

# Script to create a 4 GiB file named 4GiB.bin using dd

OUTPUT_FILE="4GiB.bin"
BLOCK_SIZE="1M"  # 1 MiB
COUNT=4096       # 4096 * 1 MiB = 4096 MiB = 4 GiB

# Check if output file already exists
if [[ -e "$OUTPUT_FILE" ]]; then
  echo "Error: '$OUTPUT_FILE' already exists. Aborting to avoid overwriting."
  exit 1
fi

echo "Creating $OUTPUT_FILE of size 4 GiB..."
dd if=/dev/zero of="$OUTPUT_FILE" bs=$BLOCK_SIZE count=$COUNT status=progress

echo "Done. '$OUTPUT_FILE' created."
