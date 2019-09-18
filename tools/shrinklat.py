#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
#

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples=""""""

parser = argparse.ArgumentParser(
    description="Summarize shrink zone latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

#define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

const u8 max_latency_slot = 26;

BPF_HISTOGRAM(shrink_node_latency, u64, max_latency_slot + 2);

BPF_HASH(start, u32);

int trace_shrink_zone_entry(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

int trace_shrink_zone_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&tid);
    if (tsp == 0) {
        return 0;
    }
    
    // Latency in microseconds
    u64 latency_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    
    // Latency histogram key
    u64 latency_slot = bpf_log2l(latency_us);

    // Cap latency bucket at max value
    if (latency_slot > max_latency_slot) {
        latency_slot = max_latency_slot;
    }

    // Increment bucket key
    shrink_node_latency.increment(latency_slot);

    // Increment sum key
    shrink_node_latency.increment(max_latency_slot + 1, latency_us);

    // Remove started task
    start.delete(&tid);

    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="shrink_zone", fn_name="trace_shrink_zone_entry")
b.attach_kretprobe(event="shrink_zone", fn_name="trace_shrink_zone_return")

print("Tracing shrink zone... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("shrink_node_latency")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_log2_hist("", "");
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
