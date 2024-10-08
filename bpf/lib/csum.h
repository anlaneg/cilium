/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_CSUM_H_
#define __LIB_CSUM_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>

#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))

struct csum_offset {
	__u16 offset;/*协议存放checksum的位置*/
	__u16 flags;
};

/**
 * Determins the L4 checksum field offset and required flags
 * @arg nexthdr	L3 nextheader field
 * @arg off	Pointer to uninitialied struct csum_offset struct
 *
 * Sets off.offset to offset from start of L4 header to L4 checksum field
 * and off.flags to the required flags, namely BPF_F_MARK_MANGLED_0 for UDP.
 * For unknown L4 protocols or L4 protocols which do not have a checksum
 * field, off is initialied to 0.
 */
static __always_inline void csum_l4_offset_and_flags(__u8 nexthdr,
						     struct csum_offset *off)
{
    /*依据checksum字段位置，设置offset及flags(仅udp适用）*/
	switch (nexthdr) {
	case IPPROTO_TCP:
		off->offset = TCP_CSUM_OFF;
		break;

	case IPPROTO_UDP:
		off->offset = UDP_CSUM_OFF;
		off->flags = BPF_F_MARK_MANGLED_0;
		break;

	case IPPROTO_ICMPV6:
		off->offset = offsetof(struct icmp6hdr, icmp6_cksum);
		break;

	case IPPROTO_ICMP:
		break;
	}
}

/**
 * Helper to change L4 checksum
 * @arg ctx	Packet
 * @arg l4_off	Offset to L4 header
 * @arg csum	Pointer to csum_offset as extracted by csum_l4_offset_and_flags()
 * @arg from	From value or 0 if to contains csum diff
 * @arg to	To value or a csum diff
 * @arg flags	Additional flags to be passed to l4_csum_replace()
 */
static __always_inline int csum_l4_replace(struct __ctx_buff *ctx, __u64 l4_off/*到l4的偏移量*/,
					   const struct csum_offset *csum/*checksum对应在l4层的offset及控制用flags*/,
					   __be32 from, __be32 to, int flags)
{
	return l4_csum_replace(ctx, l4_off + csum->offset/*l4层checksum offset*/, from, to, flags | csum->flags/*合并flags*/);
}

#endif /* __LB_H_ */
