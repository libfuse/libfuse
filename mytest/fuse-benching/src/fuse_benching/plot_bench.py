#!/home/kvelusamy/anaconda3/bin/python
"""
plot_bench.py

Reads a CSV of FUSE benchmark results and plots average throughput with error bars
as a bar chart (log-scaled x-axis) to avoid smushing large values.
Usage:
    ./plot_bench.py results.csv
Produces:
    benchmark_plot.png
"""
import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load
df = pd.read_csv(sys.argv[1])
summary = (
    df.groupby('max_read')['bandwidth_MBps']
      .agg(mean='mean', std='std')
      .reset_index()
)

# Treat max_read as categories
labels = summary['max_read'].astype(int).astype(str)
means  = summary['mean']
stds   = summary['std']
xpos   = np.arange(len(labels))

plt.figure()
plt.bar(xpos, means, yerr=stds, capsize=5, width=0.8)
plt.xticks(xpos, labels, rotation=45, ha='right')
plt.xlabel('max_read (bytes)')
plt.ylabel('Bandwidth (MB/s)')
plt.title('FUSE Benchmark: Bandwidth of 1GiB file Transfers Altering max_read.')
plt.tight_layout()

# leave extra space for the caption
plt.subplots_adjust(bottom=0.3)

# caption text
caption = "File copies done via GNU cp (kernel-determined buffer size)"
plt.figtext(0.5, 0.05, caption,
            ha="center", va="bottom",
            fontsize=8, color="gray")

plt.savefig('benchmark_plot.png')
print("Saved plot to benchmark_plot.png")

