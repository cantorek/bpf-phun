#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <iproute2/bpf_elf.h>
#include <linux/kernel.h>


// BPF helpers
#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

// END OF BPF HELPERS

#define BPF_QUEUE_SIZE 1024 * 10
#define BPF_DENY_SIZE 1024

static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static int *BPF_FUNC(map_push_elem, void *map, const void *value, uint64_t flags);

// struct that we will expose through map
struct connection {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
};

// queue used for communication with userspace program
struct bpf_elf_map conn_map __section("maps") = {
    .type           = BPF_MAP_TYPE_QUEUE,
    .size_key       = 0,
    .size_value     = sizeof(struct connection),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = BPF_QUEUE_SIZE,
};

// deny hash
struct bpf_elf_map deny_hash  __section("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__be32),
    .size_value     = sizeof(int),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = BPF_DENY_SIZE,
};

int block(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP) header offset

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    int *bytes;

    if (data_end < data + l7_off)
        return TC_ACT_OK; // Not our packet, handover to kernel

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return TC_ACT_OK; // Not an IPv4 packet, handover to kernel

    struct iphdr *ip = (struct iphdr *)(data + l3_off);

    // above code duplication can be avoided by various different techniques, however for the sake of this task it's here for simplicity

    bytes = map_lookup_elem(&deny_hash, &ip->saddr); // lookup the ip address in blocked map
    if (bytes && *bytes == 1) { // if found
        return TC_ACT_SHOT; // drop the packet
    }
    
    return TC_ACT_OK; // pass
}

int track(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP) header offset

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    if (data_end < data + l7_off)
        return TC_ACT_OK; // Not our packet, handover to kernel

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return TC_ACT_OK; // Not an IPv4 packet, handover to kernel

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);

    struct connection conn = {
        .sip = ip->saddr,
        .dip = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest
    };

    if(!tcp->syn)
        return TC_ACT_OK; // skip if not SYN

    if(tcp->ack)
        return TC_ACT_OK; // skip if SYN-ACK

    printk("SYN %u %u \n", conn.sip, ip->saddr);
    int *err;
    err = map_push_elem(&conn_map, &conn, BPF_ANY); // BPF_ANY = update or add elements
    if(err)
        printk("ERROR BPF_QUEUE is full %d \n", err);

    return TC_ACT_OK; // we pass everything here
}

__section("out")
int egress(struct __sk_buff *skb) {
    return track(skb);
}

__section("in")
int ingress(struct __sk_buff *skb) {
    track(skb); //this never blocks
    return block(skb); // but this can
}


char __license[] __section("license") = "GPL";
