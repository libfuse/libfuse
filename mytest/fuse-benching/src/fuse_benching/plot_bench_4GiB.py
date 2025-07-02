#!/home/kvelusamy/anaconda3/bin/python
"""
plot_bench_4GiB.py

Reads a CSV of 4GiB FUSE benchmark results and produces two bar charts:
  - Throughput (MB/s) vs. max_read
  - Elapsed time (s) vs. max_read
Usage:
    ./plot_bench_4GiB.py results4GiB.csv
Produces:
    throughput_4GiB.png
    elapsed_4GiB.png
"""
import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Validate arguments
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <results4GiB.csv>")
    sys.exit(1)

# Load benchmark data
csv_path = sys.argv[1]
df = pd.read_csv(csv_path)

# Aggregate mean and std for both metrics
summary = (
    df.groupby('max_read')
      .agg(
          mean_bw=('bandwidth_MBps', 'mean'),
          std_bw =('bandwidth_MBps', 'std'),
          mean_time=('elapsed_seconds', 'mean'),
          std_time =('elapsed_seconds',  'std')
      )
      .reset_index()
)

# Prepare x-axis labels
labels = summary['max_read'].astype(int).astype(str)
indices = np.arange(len(labels))

# 1) Throughput bar chart
plt.figure()
plt.bar(indices, summary['mean_bw'], yerr=summary['std_bw'], capsize=5)
plt.xticks(indices, labels, rotation=45, ha='right')
plt.xlabel('max_read (bytes)')
plt.ylabel('Throughput (MB/s)')
plt.title('4GiB Copy Benchmark: Throughput vs. max_read')
plt.tight_layout()
plt.savefig('throughput_4GiB.png')
print('Saved plot to throughput_4GiB.png')

# 2) Elapsed time bar chart
plt.figure()
plt.bar(indices, summary['mean_time'], yerr=summary['std_time'], capsize=5)
plt.xticks(indices, labels, rotation=45, ha='right')
plt.xlabel('max_read (bytes)')
plt.ylabel('Elapsed Time (s)')
plt.title('4GiB Copy Benchmark: Elapsed Time vs. max_read')
plt.tight_layout()
plt.savefig('elapsed_4GiB.png')
print('Saved plot to elapsed_4GiB.png')

