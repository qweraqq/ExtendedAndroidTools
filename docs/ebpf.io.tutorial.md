## 0x00 Hello world
```bash
cd ~/bcc/libbpf-tools
make opensnoop
./opensnoop
```

`opensnoop` will now show output each time files are being opened

## 0x01 Deeper look into an eBPF program

### 1.1 elf
A few interesting things to observe
- Machine is "Linux BPF"
- There is BTF information included in this file
- After the section header named `.text` in the table, there are four executable sections starting with `tracepoint`. These correspond to four BPF programs.
```bash
readelf --section-details --headers .output/opensnoop.bpf.o

ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Linux BPF
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          11304 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         20
  Section header string table index: 19

Section Headers:
  [Nr] Name
       Type              Address          Offset            Link
       Size              EntSize          Info              Align
       Flags
  [ 0] 
       NULL             0000000000000000  0000000000000000  0
       0000000000000000 0000000000000000  0                 0
       [0000000000000000]: 
  [ 1] .text
       PROGBITS         0000000000000000  0000000000000040  0
       0000000000000000 0000000000000000  0                 4
       [0000000000000006]: ALLOC, EXEC
  [ 2] tracepoint/syscalls/sys_enter_open
       PROGBITS         0000000000000000  0000000000000040  0
       0000000000000178 0000000000000000  0                 8
       [0000000000000006]: ALLOC, EXEC
  [ 3] tracepoint/syscalls/sys_enter_openat
       PROGBITS         0000000000000000  00000000000001b8  0
       0000000000000178 0000000000000000  0                 8
       [0000000000000006]: ALLOC, EXEC
...
```



### 1.2 opensnoop.bpf.c
-  four different functions with names beginning with `int tracepoint__syscalls`... on lines 50, 68, 118 and 124
- Each of these is preceded by a `SEC()` macro which correspond to the executable sections listed by readelf
```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "opensnoop.h"

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile bool targ_failed = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}
	return true;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[0];
		args.flags = (int)ctx->args[1];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[1];
		args.flags = (int)ctx->args[2];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;
	int ret;
	u32 pid = bpf_get_current_pid_tgid();

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup;	/* want failed only */

	/* event data */
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
	event.flags = ap->flags;
	event.ret = ret;

	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";

```

## 0x02 See BPF programs in the Kernel
Now that we know we have BPF code running, let's have a look at the Kernel side of things. For this we are going to use `bpftool` to see what we have loaded into the Kernel.

Start `./opensnoop`

- four more BPF programs loaded Those correspond to the four opensnoop BPF programs mentioned earlier.
- They are all of type tracepoint. Note that the names are truncated so you can’t really see which is for entry or exit.
- However, they each refer to two or three map IDs, like `map_ids 11,8` (the numbers might be different). Let's use this information!
- At the start of each line, you see the ID of the corresponding BPF program. Take an ID of a tracepoint program, and dump the bytecode (in our run the number was 227, your number might be different):
```bash
bpftool prog list

227: tracepoint  name tracepoint__sys  tag 9f196d70d0c1964b  gpl
        loaded_at 2023-04-02T08:19:58+0000  uid 0
        xlated 248B  jited 140B  memlock 4096B  map_ids 11,8
        btf_id 40
229: tracepoint  name tracepoint__sys  tag 47b06acd3f9a5527  gpl
        loaded_at 2023-04-02T08:19:58+0000  uid 0
        xlated 248B  jited 140B  memlock 4096B  map_ids 11,8
        btf_id 40
230: tracepoint  name tracepoint__sys  tag 387291c2fb839ac6  gpl
        loaded_at 2023-04-02T08:19:58+0000  uid 0
        xlated 696B  jited 475B  memlock 4096B  map_ids 8,11,9
        btf_id 40
231: tracepoint  name tracepoint__sys  tag 387291c2fb839ac6  gpl
        loaded_at 2023-04-02T08:19:58+0000  uid 0
        xlated 696B  jited 475B  memlock 4096B  map_ids 8,11,9
        btf_id 40

```


- Observe that there is a hash table with name start and a perf event array with name events. 
- These are defined in the source code in ~/bcc/libbpf-tools/opensnoop.bpf.c lines 13-24. 
- There is also an array for opensnoop read-only data (array name opensnoo.rodata).
- Observe also that the map IDs at the start of each line correspond to the IDs referred to earlier by bpftool prog list
```bash
bpftool map list

8: hash  name start  flags 0x0
        key 4B  value 16B  max_entries 10240  memlock 245760B
        btf_id 40
9: perf_event_array  name events  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 4096B
11: array  name opensnoo.rodata  flags 0x480
        key 4B  value 13B  max_entries 1  memlock 4096B
        btf_id 40  frozen
```

- At the start of `bpftool prog list` each line, you see the ID of the corresponding BPF program. Take an ID of a tracepoint program, and dump the bytecode
```bash
bpftool prog dump xlated id 227 linum

int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter * ctx):
; int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx) [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:50 line_col:0]
   0: (bf) r6 = r1
; u64 id = bpf_get_current_pid_tgid(); [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:52 line_col:11]
   1: (85) call bpf_get_current_pid_tgid#139360
; u32 pid = id; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:55 line_col:6]
   2: (63) *(u32 *)(r10 -4) = r0
; if (targ_tgid && targ_tgid != tgid) [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:36 line_col:6]
   3: (18) r1 = map[id:11][0]+4
   5: (61) r2 = *(u32 *)(r1 +0)
; if (targ_pid && targ_pid != pid) [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:38 line_col:6]
   6: (18) r1 = map[id:11][0]+0
   8: (61) r2 = *(u32 *)(r1 +0)
; if (valid_uid(targ_uid)) { [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:40 line_col:16]
   9: (18) r7 = map[id:11][0]+8
  11: (61) r1 = *(u32 *)(r7 +0)
  12: (18) r2 = 0xffffffff
; if (targ_uid != uid) { [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:42 line_col:7]
  14: (b7) r1 = 0
; struct args_t args = {}; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:59 line_col:17]
  15: (7b) *(u64 *)(r10 -16) = r1
  16: (7b) *(u64 *)(r10 -24) = r1
; args.fname = (const char *)ctx->args[0]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:60 line_col:30]
  17: (79) r1 = *(u64 *)(r6 +16)
; args.fname = (const char *)ctx->args[0]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:60 line_col:14]
  18: (7b) *(u64 *)(r10 -24) = r1
; args.flags = (int)ctx->args[1]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:61 line_col:21]
  19: (79) r1 = *(u64 *)(r6 +24)
; args.flags = (int)ctx->args[1]; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:61 line_col:14]
  20: (63) *(u32 *)(r10 -16) = r1
  21: (bf) r2 = r10
; struct args_t args = {}; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:59 line_col:17]
  22: (07) r2 += -4
  23: (bf) r3 = r10
  24: (07) r3 += -24
; bpf_map_update_elem(&start, &pid, &args, 0); [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:62 line_col:3]
  25: (18) r1 = map[id:8]
  27: (b7) r4 = 0
  28: (85) call htab_map_update_elem#158512
; return 0; [file:/root/bcc/libbpf-tools/opensnoop.bpf.c line_num:64 line_col:2]
  29: (b7) r0 = 0
  30: (95) exit
```


## 0x03 Write our own code

### 3.1 Add your own trace message
- eBPF programs can write tracing messages for debugging purposes
- Those can be read from `/sys/kernel/debug/tracing/trace_pipe`


In eBPF code
```c
    bpf_printk("Hello world");
```

```bash
cat /sys/kernel/debug/tracing/trace_pipe

       opensnoop-3431    [000] dN..  1472.787106: bpf_trace_printk: Hello world
         systemd-1       [000] d...  1485.398373: bpf_trace_printk: Hello world
       opensnoop-3431    [000] d...  1485.398808: bpf_trace_printk: Hello world
```

Note that as well as showing the string you defined, the trace line includes other useful contextual information 
- for example, the name of the executable and the process ID that triggered the event that ran the program 
- in this example, `opensnoop` running as PID 3431