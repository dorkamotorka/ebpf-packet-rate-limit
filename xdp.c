//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "parse_helpers.h"

#define NSEC_PER_SEC 2000000000ULL

struct ipv6_key {
    __u8 addr[16];
};

// Per-client (IPv6) last-allowed timestamp (ns)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);   // IPv6 src address
    __type(value, __u64); // last allowed ts (ns)
} last_time SEC(".maps");

SEC("xdp") 
int xdp_program(struct xdp_md *ctx) {
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;
	struct hdr_cursor nh;
	nh.pos = data;

	// For simplicity we only showcase IPv6 ICMP rate-limiting
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6;
		int ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
		if ((void *)(ipv6 + 1) > data_end) {
			goto out;
		}

		if (ip_type == IPPROTO_ICMPV6) {
			// Parse ICMP header
			struct icmp6hdr *icmp6;
			int icmp6_type = parse_icmp6hdr(&nh, data_end, &icmp6);
			if ((void*)(icmp6 + 1) > data_end) {
				goto out;
			}

			if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST) {
				bpf_printk("We have captured an ICMPv6 packet");

				// Print as 4x32-bit chunks (hex)
				bpf_printk("IPv6 src: %x:%x:%x:%x:%x:%x:%x:%x",
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[0]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[1]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[2]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[3]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[4]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[5]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[6]),
					bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[7]));

			    bpf_printk("Echo id=%d seq=%d",
					bpf_ntohs(icmp6->icmp6_dataun.u_echo.identifier),
					bpf_ntohs(icmp6->icmp6_dataun.u_echo.sequence));

				// copy 16 bytes of IPv6 src into key
				struct ipv6_key key = {};
				__builtin_memcpy(&key.addr, &ipv6->saddr, sizeof(key.addr));

				__u64 now = bpf_ktime_get_ns();
				__u64 *lastp = bpf_map_lookup_elem(&last_time, &key);
				if (lastp) {
					if (now - *lastp < NSEC_PER_SEC) {
						// too soon for this client
						bpf_printk("RATE LIMIT HIT");
						bpf_printk("=================================="); // For nicer logging
						return XDP_DROP;
					} else {
						bpf_printk("OK");
						bpf_printk("=================================="); // For nicer logging
					}
					*lastp = now; // update allowed timestamp
				} else {
					// First time we see this client: allow and set timestamp
					bpf_map_update_elem(&last_time, &key, &now, BPF_ANY);
				}
			}
			goto out;
		}
	}
	
out:
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
