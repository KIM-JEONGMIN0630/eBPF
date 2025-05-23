#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tcpmon.skel.h"
#include "procmon.skel.h"
#include "filemon.skel.h"
#include "event_struct.h"

static volatile sig_atomic_t exiting = 0;

static int handle_event(void *ctx, void *data, size_t size) {
    uint8_t type = *(uint8_t *)data;
    char ip[INET_ADDRSTRLEN];

    if (type == 0) { // tcp
        struct tcp_event *e = data;
        inet_ntop(AF_INET, &e->daddr, ip, sizeof(ip));
        printf("{\"type\":\"tcp\",\"pid\":%u,\"comm\":\"%s\",\"daddr\":\"%s\",\"dport\":%u}\n",
               e->pid, e->comm, ip, e->dport);
    } else if (type == 1) { // process create
        struct process_event *e = data;
        printf("{\"type\":\"proc_create\",\"pid\":%u,\"ppid\":%u,\"comm\":\"%s\"}\n",
               e->pid, e->ppid, e->comm);
    } else if (type == 2) { // process exit
        struct process_event *e = data;
        printf("{\"type\":\"proc_exit\",\"pid\":%u,\"ppid\":%u,\"comm\":\"%s\"}\n",
               e->pid, e->ppid, e->comm);
    } else if (type == 3) { // file open
        struct file_event *e = data;
        printf("{\"type\":\"file_open\",\"pid\":%u,\"comm\":\"%s\",\"filename\":\"%s\"}\n",
               e->pid, e->comm, e->filename);
    } else {
        printf("{\"type\":\"unknown\"}\n");
    }

    return 0;
}

static void sig_handler(int signo) {
    exiting = 1;
}

int main() {
    struct tcpmon_bpf *tcpmon_skel = NULL;
    struct procmon_bpf *procmon_skel = NULL;
    struct filemon_bpf *filemon_skel = NULL;
    struct ring_buffer *rb = NULL;

    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. tcpmon
    tcpmon_skel = tcpmon_bpf__open();
    if (!tcpmon_skel || tcpmon_bpf__load(tcpmon_skel) || tcpmon_bpf__attach(tcpmon_skel)) {
        fprintf(stderr, "Failed to init tcpmon\n");
        return 1;
    }

    // 2. procmon
    procmon_skel = procmon_bpf__open();
    if (!procmon_skel || procmon_bpf__load(procmon_skel) || procmon_bpf__attach(procmon_skel)) {
        fprintf(stderr, "Failed to init procmon\n");
        return 1;
    }

    // 3. filemon
    filemon_skel = filemon_bpf__open();
    if (!filemon_skel || filemon_bpf__load(filemon_skel) || filemon_bpf__attach(filemon_skel)) {
        fprintf(stderr, "Failed to init filemon\n");
        return 1;
    }

    // 4. ring buffer 등록
    rb = ring_buffer__new(bpf_map__fd(tcpmon_skel->maps.events), handle_event, NULL, NULL);
    ring_buffer__add(rb, bpf_map__fd(procmon_skel->maps.events), handle_event, NULL);
    ring_buffer__add(rb, bpf_map__fd(filemon_skel->maps.events), handle_event, NULL);

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // 5. 이벤트 수집 루프
    while (!exiting)
        ring_buffer__poll(rb, 100);

    // 6. 정리
    ring_buffer__free(rb);
    tcpmon_bpf__destroy(tcpmon_skel);
    procmon_bpf__destroy(procmon_skel);
    filemon_bpf__destroy(filemon_skel);

    return 0;
}