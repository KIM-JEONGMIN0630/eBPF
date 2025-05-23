#include "vmlinux.h"
#include "event_struct.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr_in sa = {};
    struct tcp_event *e;

    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);

    if (sa.sin_family != AF_INET)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->base.type = 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->daddr = bpf_ntohl(sa.sin_addr.s_addr);  // 핵심
    e->dport = bpf_ntohs(sa.sin_port);         // 핵심

    bpf_ringbuf_submit(e, 0);
    return 0;
}