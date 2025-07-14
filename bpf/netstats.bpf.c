#include <uapi/linux/ptrace.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义进程过滤列表（通过用户空间填充）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);      // PID
    __type(value, u8);     // 存在标记
} pid_filter SEC(".maps");

// 按进程和协议统计流量
struct flow_key {
    u32 pid;
    u8 protocol;           // IPPROTO_TCP, IPPROTO_UDP
};

struct flow_stats {
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_stats SEC(".maps");

// 追踪套接字发送
SEC("tracepoint/skb/skb_tx")
int trace_skb_tx(struct trace_event_raw_skb *ctx) {
    struct sk_buff *skb = ctx->skb;
    struct iphdr *iph;
    void *data;
    u32 pid;
    struct flow_key key = {};
    struct flow_stats *stats;
    u8 exists = 0;

    // 获取当前进程PID
    pid = bpf_get_current_pid_tgid() >> 32;

    // 检查是否在监控列表中
    if (bpf_map_lookup_elem(&pid_filter, &pid, &exists) != 0 || exists == 0) {
        return 0;
    }

    // 解析IP头
    data = (void *)(long)skb->head + skb->network_header;
    iph = data;

    // 仅处理IPv4
    if (iph->version != 4) {
        return 0;
    }

    // 更新统计信息
    key.pid = pid;
    key.protocol = iph->protocol;

    stats = bpf_map_lookup_elem(&flow_stats, &key);
    if (!stats) {
        struct flow_stats init = {};
        init.tx_packets = 1;
        init.tx_bytes = skb->len;
        bpf_map_update_elem(&flow_stats, &key, &init, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->tx_packets, 1);
        __sync_fetch_and_add(&stats->tx_bytes, skb->len);
    }

    return 0;
}

// 追踪套接字接收
SEC("tracepoint/skb/skb_rx")
int trace_skb_rx(struct trace_event_raw_skb *ctx) {
    // 与tx逻辑类似，只是更新rx_*字段
    // ... 代码省略（与tx逻辑类似）
    return 0;
}

// 收集TCP连接状态
struct tcp_conn_key {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct tcp_conn_value {
    u8 state;  // TCP状态
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tcp_conn_key);
    __type(value, struct tcp_conn_value);
} tcp_connections SEC(".maps");

// 追踪TCP状态变化
SEC("kprobe/tcp_set_state")
int kprobe_tcp_set_state(struct ptrace_regs *ctx) {
    // 收集TCP连接状态变化
    // ... 代码省略
    return 0;
}

char _license[] SEC("license") = "GPL";
