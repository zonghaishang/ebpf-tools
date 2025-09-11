#!/usr/bin/python3

from bcc import BPF
import sys
import time

program = r"""
BPF_HASH(counters);

int hello(void *ctx) {

    u64 count = 0;
    u64 uid;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counters.lookup(&uid);
    if (p != 0) {
        count = *p;
    }

    count++;
    counters.update(&uid, &count);


    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")


try:
    while True:
        time.sleep(2)
        s = ""
        if len(b["counters"].items()) > 0:
            for key, val in b["counters"].items():
                s += f"id: {key.value} count: {val.value}\t"
            print(s)
            continue
        print("no entry")
except KeyboardInterrupt:
    sys.exit(0)