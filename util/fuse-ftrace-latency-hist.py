#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Generate latency histograms for FUSE operations from trace events.
Reads from stdin or a trace file and outputs per-operation latency distributions.

Example usage:
    cat /sys/kernel/debug/tracing/trace | ./fuse-ftrace-latency-hist.py
    ./fuse-ftrace-latency-hist.py trace.txt
    ./fuse-ftrace-latency-hist.py --debug trace.txt
"""

import sys
import argparse
from collections import defaultdict
import re
import math

# Histogram configuration
HIST_BUCKETS = 20
MIN_LATENCY_US = 10      # 10 microseconds
MAX_LATENCY_US = 20000   # 20ms

def debug_print(msg, debug_enabled):
    """Print debug message if debug is enabled"""
    if debug_enabled:
        print(f"DEBUG: {msg}", file=sys.stderr)

def calculate_bucket(latency_us):
    """Calculate histogram bucket for given latency"""
    boundaries = [
        10, 20, 50,                     # 10-50µs
        100, 200, 500,                  # 100-500µs
        1000, 2000, 5000,              # 1-5ms
        10000, 20000                    # 10-20ms
    ]
    
    if latency_us < boundaries[0]:
        return 0

    for i, boundary in enumerate(boundaries[:-1]):
        if latency_us >= boundary and latency_us < boundaries[i + 1]:
            return i + 1

    if latency_us >= boundaries[-1]:
        return len(boundaries) + 1

    return i + 1  # Fallback case

def format_histogram(counts, total):
    """Format histogram ASCII art"""
    if not counts:
        return "No measurements available"

    max_count = max(counts.values())
    hist_width = 40
    result = []
    
    # Define bucket labels
    labels = [
        "<10 us",
        "10-20 us", "20-50 us",
        "50-100 us", "100-200 us", "200-500 us",
        "0.5-1 ms", "1-2 ms", "2-5 ms",
        "5-10 ms", "10-20 ms",
        ">20 ms"
    ]

    for bucket in range(len(labels)):
        label = labels[bucket]
        count = counts[bucket]
        if max_count:
            bar = "#" * int(count * hist_width / max_count)
        else:
            bar = ""
        percentage = (count * 100.0) / total if total else 0
        result.append(f"{label:>13} {count:>8} ({percentage:>6.2f}%) |{bar}")
    
    return "\n".join(result)

def parse_trace_line(line, debug):
    """Parse a single trace line"""
    # Basic line parsing
    timestamp_match = re.search(r'(\d+\.\d+):', line)
    if not timestamp_match:
        debug_print("Failed to match timestamp", debug)
        return None

    timestamp = float(timestamp_match.group(1))

    # Extract connection and request IDs
    conn_match = re.search(r'connection (\d+)', line)
    req_match = re.search(r'req (\d+)', line)
    if not conn_match or not req_match:
        debug_print("Failed to match connection/request IDs", debug)
        return None

    conn_id = conn_match.group(1)
    req_id = req_match.group(1)

    # Determine event type and extract relevant info
    event_type = None
    if 'fuse_request_bg_enqueue:' in line:
        op_match = re.search(r'opcode (\d+) \((FUSE_\w+)\)', line)
        if not op_match:
            debug_print("Failed to match opcode/operation", debug)
            return None
        event_type = 'bg_enqueue'
        op_name = op_match.group(2)
    elif 'fuse_request_enqueue:' in line:
        op_match = re.search(r'opcode (\d+) \((FUSE_\w+)\)', line)
        if not op_match:
            debug_print("Failed to match opcode/operation", debug)
            return None
        event_type = 'enqueue'
        op_name = op_match.group(2)
    elif 'fuse_request_send:' in line:
        op_match = re.search(r'opcode (\d+) \((FUSE_\w+)\)', line)
        if not op_match:
            debug_print("Failed to match opcode/operation", debug)
            return None
        event_type = 'send'
        op_name = op_match.group(2)
    elif 'fuse_request_end:' in line:
        error_match = re.search(r'error (-?\d+)', line)
        event_type = 'end'
        error = int(error_match.group(1)) if error_match else 0
        op_name = None  # We'll get this from the stored request info

    result = {
        'type': event_type,
        'timestamp': timestamp,
        'conn_id': conn_id,
        'req_id': req_id,
    }

    if event_type in ('bg_enqueue', 'enqueue', 'send'):
        result['op_name'] = op_name
    elif event_type == 'end':
        result['error'] = error

    debug_print(f"Parsed event: {result}", debug)
    return result

def process_trace(trace_file, debug, op_filter=None):
    """Process trace events and generate histograms"""
    requests = {}  # key: conn_id:req_id
    bg_queue_latency_by_op = defaultdict(lambda: defaultdict(int))
    queue_latency_by_op = defaultdict(lambda: defaultdict(int))
    proc_latency_by_op = defaultdict(lambda: defaultdict(int))
    total_by_op = defaultdict(int)
    errors_by_op = defaultdict(int)
    has_bg_queue = defaultdict(bool)  # Track if op has any bg queue measurements
    
    for line in trace_file:
        event = parse_trace_line(line, debug)
        if not event:
            continue
        
        key = f"{event['conn_id']}:{event['req_id']}"

        if event['type'] == 'bg_enqueue':
            if op_filter and event['op_name'] != op_filter:
                continue
            requests[key] = {
                'bg_enqueue_time': event['timestamp'],
                'op_name': event['op_name']
            }
        elif event['type'] == 'enqueue':
            if op_filter and event['op_name'] != op_filter:
                continue
            if key in requests and 'bg_enqueue_time' in requests[key]:
                # Calculate background queue latency
                bg_latency_us = int((event['timestamp'] - requests[key]['bg_enqueue_time']) * 1_000_000)
                bucket = calculate_bucket(bg_latency_us)
                op_name = requests[key]['op_name']
                bg_queue_latency_by_op[op_name][bucket] += 1
                has_bg_queue[op_name] = True

            if key not in requests:
                requests[key] = {}
            requests[key].update({
                'enqueue_time': event['timestamp'],
                'op_name': event['op_name']
            })
        elif event['type'] == 'send':
            if key not in requests:
                debug_print(f"Send without enqueue for {key}", debug)
                continue
            req_info = requests[key]

            # Calculate queue latency from either bg_enqueue or regular enqueue
            start_time = req_info.get('enqueue_time', req_info.get('bg_enqueue_time'))
            if start_time:
                queue_latency_us = int((event['timestamp'] - start_time) * 1_000_000)
                bucket = calculate_bucket(queue_latency_us)
                queue_latency_by_op[req_info['op_name']][bucket] += 1

            req_info['send_time'] = event['timestamp']

        elif event['type'] == 'end':
            if key not in requests:
                debug_print(f"End without enqueue/send for {key}", debug)
                continue
            req_info = requests[key]
            if 'send_time' in req_info:
                proc_latency_us = int((event['timestamp'] - req_info['send_time']) * 1_000_000)
                bucket = calculate_bucket(proc_latency_us)
                proc_latency_by_op[req_info['op_name']][bucket] += 1

            total_by_op[req_info['op_name']] += 1
            if event['error'] != 0:
                errors_by_op[req_info['op_name']] += 1

    # Print results
    print("\nFUSE Operation Latency Histograms")
    print("=================================\n")

    for op_name in sorted(total_by_op.keys()):
        if op_filter and op_name != op_filter:
            continue

        print(f"Operation: {op_name}")
        print(f"Total requests: {total_by_op[op_name]}")
        if errors_by_op[op_name]:
            print(f"Errors: {errors_by_op[op_name]}")
        print()

        if has_bg_queue[op_name]:
            print("Background queue latency (bg_enqueue to enqueue):")
            print(format_histogram(bg_queue_latency_by_op[op_name], total_by_op[op_name]))
            print()

        print("Queue latency (enqueue/bg_enqueue to send):")
        print(format_histogram(queue_latency_by_op[op_name], total_by_op[op_name]))
        print()

        print("Processing latency (send to end):")
        print(format_histogram(proc_latency_by_op[op_name], total_by_op[op_name]))
        print("\n" + "="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Generate FUSE operation latency histograms from trace events',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('trace_file', nargs='?', type=argparse.FileType('r'), 
                       default=sys.stdin, help='Trace file (default: stdin)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('--op', type=str,
                       help='Filter by operation type (e.g., FUSE_LOOKUP, FUSE_GETATTR)')
    args = parser.parse_args()

    try:
        process_trace(args.trace_file, args.debug, args.op)
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)

if __name__ == '__main__':
    main()
