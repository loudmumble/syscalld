// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// ---------------------------------------------------------------------------
// Event type discriminators
// ---------------------------------------------------------------------------
#define EVENT_PROC_EXEC    1
#define EVENT_PROC_EXIT    2
#define EVENT_NET_CONNECT  3
#define EVENT_FS_OPEN      4
#define EVENT_MEM_MMAP     5
#define EVENT_MOD_LOAD     6
#define EVENT_SYSCALL      7

// ---------------------------------------------------------------------------
// Struct definitions
// ---------------------------------------------------------------------------

struct proc_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 ppid;
	__s32 action;
	__s32 exit_code;
	char  comm[16];
	char  filename[256];
};

struct net_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__s32 action;
	char  comm[16];
};

struct fs_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s32 flags;
	char  comm[16];
	char  filename[256];
};

struct mem_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u64 addr;
	__u64 len;
	__s32 prot;
	__s32 flags;
	char  comm[16];
};

struct mod_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	char  comm[16];
	char  mod_name[64];
};

struct syscall_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s64 nr;
	__u64 args[3];
	char  comm[16];
};

struct dns_data_t {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 daddr;
	__u16 dport;
	char  comm[16];
	char  query[128];
};

// ---------------------------------------------------------------------------
// Ringbuf maps
// ---------------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} proc_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} net_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} fs_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} mem_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} mod_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} syscall_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} dns_events SEC(".maps");

// Force BTF generation for all event struct types.
const struct proc_data_t    *unused_proc    __attribute__((unused));
const struct net_data_t     *unused_net     __attribute__((unused));
const struct fs_data_t      *unused_fs      __attribute__((unused));
const struct mem_data_t     *unused_mem     __attribute__((unused));
const struct mod_data_t     *unused_mod     __attribute__((unused));
const struct syscall_data_t *unused_syscall __attribute__((unused));
const struct dns_data_t     *unused_dns     __attribute__((unused));

// ---------------------------------------------------------------------------
// Process: exec
// ---------------------------------------------------------------------------

struct trace_event_raw_sched_process_exec {
	__u64 common_type;
	__u32 filename_loc;
	__u32 pid;
	__u32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct proc_data_t *data;
	data = bpf_ringbuf_reserve(&proc_events, sizeof(*data), 0);
	if (!data)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->ppid      = ctx->old_pid;
	data->action    = EVENT_PROC_EXEC;
	data->exit_code = 0;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));

	char *filename = (char *)ctx + (ctx->filename_loc & 0xFFFF);
	bpf_probe_read_user_str(data->filename, sizeof(data->filename), filename);

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Process: exit
// ---------------------------------------------------------------------------

struct trace_event_raw_sched_process_exit {
	__u64 common_type;
	__u32 pid;
	__u32 prio;
};

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
	struct proc_data_t *data;
	data = bpf_ringbuf_reserve(&proc_events, sizeof(*data), 0);
	if (!data)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->ppid      = 0;
	data->action    = EVENT_PROC_EXIT;
	data->exit_code = 0;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Network: tcp_v4_connect
// ---------------------------------------------------------------------------

SEC("kprobe/tcp_v4_connect")
int trace_tcp_v4_connect(struct pt_regs *ctx) {
	struct net_data_t *data;
	data = bpf_ringbuf_reserve(&net_events, sizeof(*data), 0);
	if (!data)
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->action    = EVENT_NET_CONNECT;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	data->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	data->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	data->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	data->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Network: tcp_v6_connect
// ---------------------------------------------------------------------------

SEC("kprobe/tcp_v6_connect")
int trace_tcp_v6_connect(struct pt_regs *ctx) {
	struct net_data_t *data;
	data = bpf_ringbuf_reserve(&net_events, sizeof(*data), 0);
	if (!data)
		return 0;

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->action    = EVENT_NET_CONNECT;
	data->saddr     = 0;
	data->daddr     = 0;
	data->sport     = BPF_CORE_READ(sk, __sk_common.skc_num);
	data->dport     = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	bpf_get_current_comm(&data->comm, sizeof(data->comm));

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Filesystem: sys_enter_openat
// ---------------------------------------------------------------------------

struct trace_event_raw_sys_enter_openat {
	__u64 common_type;
	__s32 __syscall_nr;
	__u32 pad;
	__s64 dfd;
	char *filename;
	__s64 flags;
	__s64 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_fs_openat(struct trace_event_raw_sys_enter_openat *ctx) {
	struct fs_data_t *data;
	data = bpf_ringbuf_reserve(&fs_events, sizeof(*data), 0);
	if (!data)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->flags     = (__s32)ctx->flags;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	bpf_probe_read_user_str(data->filename, sizeof(data->filename), ctx->filename);

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Memory: sys_enter_mmap
// ---------------------------------------------------------------------------

struct trace_event_raw_sys_enter_mmap {
	__u64 common_type;
	__s32 __syscall_nr;
	__u32 pad;
	__u64 addr;
	__u64 len;
	__s64 prot;
	__s64 flags;
	__s64 fd;
	__s64 off;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mem_mmap(struct trace_event_raw_sys_enter_mmap *ctx) {
	struct mem_data_t *data;
	data = bpf_ringbuf_reserve(&mem_events, sizeof(*data), 0);
	if (!data)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->addr      = ctx->addr;
	data->len       = ctx->len;
	data->prot      = (__s32)ctx->prot;
	data->flags     = (__s32)ctx->flags;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Module: do_init_module
// ---------------------------------------------------------------------------

struct module___partial {
	char name[64];
} __attribute__((preserve_access_index));

SEC("kprobe/do_init_module")
int trace_do_init_module(struct pt_regs *ctx) {
	struct mod_data_t *data;
	data = bpf_ringbuf_reserve(&mod_events, sizeof(*data), 0);
	if (!data)
		return 0;

	struct module___partial *mod = (struct module___partial *)PT_REGS_PARM1(ctx);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	bpf_probe_read_kernel_str(data->mod_name, sizeof(data->mod_name), mod->name);

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Syscall: raw_syscalls/sys_enter
// ---------------------------------------------------------------------------

struct trace_event_raw_sys_enter {
	__u64 common_type;
	__s64 id;
	__u64 args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
	struct syscall_data_t *data;
	data = bpf_ringbuf_reserve(&syscall_events, sizeof(*data), 0);
	if (!data)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->nr        = ctx->id;
	data->args[0]   = ctx->args[0];
	data->args[1]   = ctx->args[1];
	data->args[2]   = ctx->args[2];
	bpf_get_current_comm(&data->comm, sizeof(data->comm));

	bpf_ringbuf_submit(data, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// DNS: sys_enter_sendto — filter for UDP port 53 outbound queries
// ---------------------------------------------------------------------------

struct trace_event_raw_sys_enter_sendto {
	__u64 common_type;
	__s32 __syscall_nr;
	__u32 pad;
	__s64 fd;
	void  *buff;
	__u64 len;
	__s64 flags;
	struct sockaddr *addr;
	__s64 addr_len;
};

struct sockaddr_in___partial {
	__u16 sin_family;
	__u16 sin_port;
	__u32 sin_addr;
} __attribute__((preserve_access_index));

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_dns_sendto(struct trace_event_raw_sys_enter_sendto *ctx) {
	if (!ctx->addr)
		return 0;

	struct sockaddr_in___partial sa = {};
	bpf_probe_read_user(&sa, sizeof(sa), ctx->addr);

	if (sa.sin_family != 2 || bpf_ntohs(sa.sin_port) != 53)
		return 0;

	struct dns_data_t *data;
	data = bpf_ringbuf_reserve(&dns_events, sizeof(*data), 0);
	if (!data)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	data->timestamp = bpf_ktime_get_ns();
	data->pid       = pid_tgid >> 32;
	data->tid       = (__u32)pid_tgid;
	data->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data->daddr     = sa.sin_addr;
	data->dport     = 53;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));

	// DNS payload: query name starts at byte 12 (after 12-byte DNS header).
	if (ctx->buff && ctx->len > 12) {
		__u8 *dns_payload = (__u8 *)ctx->buff;
		bpf_probe_read_user(data->query, sizeof(data->query), dns_payload + 12);
	}

	bpf_ringbuf_submit(data, 0);
	return 0;
}
