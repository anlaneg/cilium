/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2021 Authors of Cilium */

/* Simple NAT engine in BPF. */
#ifndef __LIB_NAT__
#define __LIB_NAT__

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "common.h"
#include "drop.h"
#include "signal.h"
#include "conntrack.h"
#include "conntrack_map.h"
#include "icmp6.h"

enum  nat_dir {
	NAT_DIR_EGRESS  = TUPLE_F_OUT,
	NAT_DIR_INGRESS = TUPLE_F_IN,
} __packed;

struct nat_entry {
	__u64 created;/*创建时间*/
	/*是否主机本地地址*/
	__u64 host_local;	/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

#define NAT_CONTINUE_XLATE	0

#ifdef HAVE_LRU_HASH_MAP_TYPE
# define NAT_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#else
# define NAT_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifdef HAVE_LARGE_INSN_LIMIT
# define SNAT_COLLISION_RETRIES		128
# define SNAT_SIGNAL_THRES		64
#else
# define SNAT_COLLISION_RETRIES		32
# define SNAT_SIGNAL_THRES		16
#endif

/*在start,end之间取一个伪随机值*/
static __always_inline __be16 __snat_clamp_port_range(__u16 start, __u16 end,
						      __u16 val)
{
	return (val % (__u16)(end - start)) + start;
}

static __always_inline __maybe_unused __be16
__snat_try_keep_port(__u16 start, __u16 end, __u16 val)
{
	return val >= start && val <= end ? val /*不转换，保持原样*/:
	       __snat_clamp_port_range(start, end, (__u16)get_prandom_u32())/*生成一个随机值*/;
}

static __always_inline __maybe_unused void *
__snat_lookup(const void *map, const void *tuple)
{
	return map_lookup_elem(map, tuple);
}

static __always_inline __maybe_unused int
__snat_update(const void *map, const void *otuple, const void *ostate,
	      const void *rtuple, const void *rstate)
{
	int ret;

    	/*连续添加两次hashtable*/
	ret = map_update_elem(map, rtuple, rstate, BPF_NOEXIST);
	if (!ret) {
		ret = map_update_elem(map, otuple, ostate, BPF_NOEXIST);
		if (ret)
			map_delete_elem(map, rtuple);
	}
	return ret;
}

//移除掉正向两方flow
static __always_inline __maybe_unused void
__snat_delete(const void *map, const void *otuple, const void *rtuple)
{
	map_delete_elem(map, otuple);
	map_delete_elem(map, rtuple);
}

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};

struct ipv4_nat_target {
	__be32 addr;
	//nat分配范围
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool src_from_world;
};

#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, NAT_MAP_TYPE);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
#ifndef HAVE_LRU_HASH_MAP_TYPE
	__uint(map_flags, CONDITIONAL_PREALLOC);
#endif
} SNAT_MAPPING_IPV4 __section_maps_btf;

#ifdef ENABLE_IP_MASQ_AGENT
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} IP_MASQ_AGENT_IPV4 __section_maps_btf;
#endif

//通过tuple查询ipv4 mapping
static __always_inline
struct ipv4_nat_entry *snat_v4_lookup(const struct ipv4_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV4, tuple);
}

static __always_inline int snat_v4_update(const struct ipv4_ct_tuple *otuple,
					  const struct ipv4_nat_entry *ostate,
					  const struct ipv4_ct_tuple *rtuple,
					  const struct ipv4_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV4, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline void snat_v4_delete(const struct ipv4_ct_tuple *otuple,
					   const struct ipv4_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV4, otuple, rtuple);
}

static __always_inline void snat_v4_swap_tuple(const struct ipv4_ct_tuple *otuple,
					       struct ipv4_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v4_reverse_tuple(const struct ipv4_ct_tuple *otuple,
						 struct ipv4_ct_tuple *rtuple)
{
	struct ipv4_nat_entry *ostate;

	ostate = snat_v4_lookup(otuple);
	if (ostate) {
		snat_v4_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

static __always_inline void snat_v4_ct_canonicalize(struct ipv4_ct_tuple *otuple)
{
	__be32 addr = otuple->saddr;

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	otuple->saddr = otuple->daddr;
	otuple->daddr = addr;
}

static __always_inline void snat_v4_delete_tuples(struct ipv4_ct_tuple *otuple)
{
	struct ipv4_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v4_ct_canonicalize(otuple);
	if (!snat_v4_reverse_tuple(otuple, &rtuple))
		snat_v4_delete(otuple, &rtuple);
}

static __always_inline int snat_v4_new_mapping(struct __ctx_buff *ctx,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv4_nat_entry rstate;
	struct ipv4_ct_tuple rtuple;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v4_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	if (otuple->saddr == target->addr) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v4_lookup(&rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V4);
	return !ret ? 0 : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v4_track_local(struct __ctx_buff *ctx,
					       const struct ipv4_ct_tuple *tuple,
					       const struct ipv4_nat_entry *state,
					       enum nat_dir dir, __u32 off,
					       const struct ipv4_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv4_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	enum ct_dir where;
	int ret;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
	    /*出方向,无ct,且srcip相等，需要创建ct*/
		if (tuple->saddr == target->addr)
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	memset(&ct_state, 0, sizeof(ct_state));
	memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup4(get_ct_map4(&tmp), &tmp, ctx, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create4(get_ct_map4(&tmp), NULL, &tmp, ctx,
				 where, &ct_state, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

static __always_inline int snat_v4_handle_mapping(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry **state,
						  struct ipv4_nat_entry *tmp,
						  enum nat_dir dir, __u32 off,
						  const struct ipv4_nat_target *target)
{
	int ret;

	*state = snat_v4_lookup(tuple);
	ret = snat_v4_track_local(ctx, tuple, *state, dir, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else if (dir == NAT_DIR_INGRESS)
		return tuple->nexthdr != IPPROTO_ICMP &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
	else
	    /*创建新的mapping*/
		return snat_v4_new_mapping(ctx, tuple, (*state = tmp), target);
}

static __always_inline int snat_v4_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry *state,
						  __u32 off/*到l4头部的偏移量*/, bool has_l4_header)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	/*无地址变换，直接返回*/
	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	/*转换前地址与转换后地址不同，执行checksum变更*/
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	if (has_l4_header) {
		csum_l4_offset_and_flags(tuple->nexthdr, &csum);

		if (state->to_sport != tuple->sport) {
			switch (tuple->nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				ret = l4_modify_port(ctx, off,
						     offsetof(struct tcphdr, source),
						     &csum, state->to_sport,
						     tuple->sport);
				if (ret < 0)
					return ret;
				break;
			case IPPROTO_ICMP: {
				__be32 from, to;

				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmphdr, un.echo.id),
						    &state->to_sport,
						    sizeof(state->to_sport), 0) < 0)
					return DROP_WRITE_ERROR;
				from = tuple->sport;
				to = state->to_sport;
				flags = 0; /* ICMPv4 has no pseudo-header */
				sum_l4 = csum_diff(&from, 4, &to, 4, 0);
				csum.offset = offsetof(struct icmphdr, checksum);
				break;
			}}
		}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

//完成地址，port转换,checksum调整
static __always_inline int snat_v4_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv4_ct_tuple *tuple,
						   struct ipv4_nat_entry *state,
						   __u32 off)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	if (state->to_daddr == tuple->daddr &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMP: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmphdr, un.echo.id),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->dport;
			to = state->to_dport;
			flags = 0; /* ICMPv4 has no pseudo-header */
			sum_l4 = csum_diff(&from, 4, &to, 4, 0);
			csum.offset = offsetof(struct icmphdr, checksum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &state->to_daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v4_can_skip(const struct ipv4_nat_target *target,
		 const struct ipv4_ct_tuple *tuple, enum nat_dir dir,
		 bool from_endpoint, bool icmp_echoreply)
{
	__u16 dport = bpf_ntohs(tuple->dport), sport = bpf_ntohs(tuple->sport);

	//出去方向，端port<min不处理
	if (dir == NAT_DIR_EGRESS &&
	    ((!from_endpoint && !target->src_from_world && sport < NAT_MIN_EGRESS) ||
	     icmp_echoreply))
		return true;
	//进来方向的报文，目的port不在池子范围，不处理。
	if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))
		return true;

	return false;
}

static __always_inline __maybe_unused int snat_v4_create_dsr(struct __ctx_buff *ctx,
							     __be32 to_saddr,
							     __be16 to_sport)
{
	void *data, *data_end;
	struct ipv4_ct_tuple tuple = {};
	struct ipv4_nat_entry state = {};
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->saddr;
	tuple.saddr = ip4->daddr;
	tuple.flags = NAT_DIR_EGRESS;

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.sport;
		tuple.sport = l4hdr.dport;
		break;
	default:
		/* NodePort svc can be reached only via TCP or UDP, so
		 * drop the rest.
		 */
		return DROP_NAT_UNSUPP_PROTO;
	}

	state.common.created = bpf_mono_now();
	state.to_saddr = to_saddr;
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV4, &tuple, &state, 0);
	if (ret)
		return ret;

	return CTX_ACT_OK;
}

static __always_inline __maybe_unused int
snat_v4_process(struct __ctx_buff *ctx, enum nat_dir dir/*ingress或egress点*/,
		const struct ipv4_nat_target *target/*地址池信息*/, bool from_endpoint)
{
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_nat_entry *state, tmp;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	bool icmp_echoreply = false;
	__u64 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data/*出参，报文起始位置*/, &data_end/*出参，报文终止位置*/, &ip4/*l3层头部指针*/))
		return DROP_INVALID;

	//构造tuple
	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	tuple.flags = dir;
	/*到l4头部的偏移量（从data开始）*/
	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);

	/*加载l4层端目的port*/
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		if (icmphdr.type != ICMP_ECHO &&
		    icmphdr.type != ICMP_ECHOREPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmphdr.type == ICMP_ECHO) {
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
		} else {
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	/*如果不需要做snat,则跳过*/
	if (snat_v4_can_skip(target, &tuple, dir, from_endpoint, icmp_echoreply))
		return NAT_PUNT_TO_STACK;

	ret = snat_v4_handle_mapping(ctx, &tuple, &state, &tmp, dir, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return dir == NAT_DIR_EGRESS ?
		/*egress做snat*/
	       snat_v4_rewrite_egress(ctx, &tuple, state, off, ipv4_has_l4_header(ip4)) :
	       /*egress做dnat*/
	       snat_v4_rewrite_ingress(ctx, &tuple, state, off);
}
#else
static __always_inline __maybe_unused
int snat_v4_process(struct __ctx_buff *ctx __maybe_unused,
		    enum nat_dir dir __maybe_unused,
		    const struct ipv4_nat_target *target __maybe_unused,
		    bool from_endpoint __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
void snat_v4_delete_tuples(struct ipv4_ct_tuple *tuple __maybe_unused)
{
}
#endif

struct ipv6_nat_entry {
	struct nat_entry common;
	union {
	    //转换后addr,port情况
		struct {
			union v6addr to_saddr;
			__be16       to_sport;
		};
		struct {
			union v6addr to_daddr;
			__be16       to_dport;
		};
	};
};

struct ipv6_nat_target {
	union v6addr addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool src_from_world;
};

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, NAT_MAP_TYPE);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ipv6_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV6_SIZE);
#ifndef HAVE_LRU_HASH_MAP_TYPE
	__uint(map_flags, CONDITIONAL_PREALLOC);
#endif
} SNAT_MAPPING_IPV6 __section_maps_btf;

/*用元组查询hashtable,确认对应session*/
static __always_inline
struct ipv6_nat_entry *snat_v6_lookup(struct ipv6_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV6, tuple);
}

static __always_inline int snat_v6_update(struct ipv6_ct_tuple *otuple/*源元组*/,
					  struct ipv6_nat_entry *ostate/*源方向session*/,
					  struct ipv6_ct_tuple *rtuple/*响应方元组*/,
					  struct ipv6_nat_entry *rstate/*响应方session*/)
{
	return __snat_update(&SNAT_MAPPING_IPV6, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline void snat_v6_delete(const struct ipv6_ct_tuple *otuple,
					   const struct ipv6_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV6, otuple, rtuple);
}

static __always_inline void snat_v6_swap_tuple(const struct ipv6_ct_tuple *otuple,
					       struct ipv6_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v6_reverse_tuple(struct ipv6_ct_tuple *otuple,
						 struct ipv6_ct_tuple *rtuple)
{
	struct ipv6_nat_entry *ostate;

	ostate = snat_v6_lookup(otuple);
	if (ostate) {
		snat_v6_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

static __always_inline void snat_v6_ct_canonicalize(struct ipv6_ct_tuple *otuple)
{
	union v6addr addr = {};

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	ipv6_addr_copy(&addr, &otuple->saddr);
	ipv6_addr_copy(&otuple->saddr, &otuple->daddr);
	ipv6_addr_copy(&otuple->daddr, &addr);
}

static __always_inline void snat_v6_delete_tuples(struct ipv6_ct_tuple *otuple)
{
	struct ipv6_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v6_ct_canonicalize(otuple);
	if (!snat_v6_reverse_tuple(otuple, &rtuple))
		snat_v6_delete(otuple, &rtuple);
}

static __always_inline int snat_v6_new_mapping(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *otuple/*源方向元素*/,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv6_nat_entry rstate;
	struct ipv6_ct_tuple rtuple;
	__u16 port;

	//清零
	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	//构造replay 方向元组
	snat_v6_swap_tuple(otuple, &rtuple);
	//随机选一个port
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	/*假设使用此port及此地址*/
	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	/*标记使用ip地址未发生变更*/
	if (!ipv6_addrcmp(&otuple->saddr, &rtuple.daddr)) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

#pragma unroll
	//进行多次尝试，检查是否有冲突（成功率 17/18=94.4%,但由于是full nat故成功率将大于此值）
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v6_lookup(&rtuple)) {
			/*sessin不存在，确认此端口可用*/
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			/*加入正反两方向session*/
			ret = snat_v6_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		/*尝试分配下一个port*/
		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	/*分配端口失败*/
	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V6);
	return !ret ? 0 : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v6_track_local(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *tuple,
					       const struct ipv6_nat_entry *state,
					       enum nat_dir dir, __u32 off,
					       const struct ipv6_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv6_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	int ret, where;

	if (state && state->common.host_local) {
	    /*ip使用host local,ct有效*/
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
	    /*出方向，无state,但其源ip与target ip相等，故其是host_local为true情况*/
		if (!ipv6_addrcmp(&tuple->saddr, (void *)&target->addr))
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	memset(&ct_state, 0, sizeof(ct_state));
	memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup6(get_ct_map6(&tmp), &tmp, ctx, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create6(get_ct_map6(&tmp), NULL, &tmp, ctx, where,
				 &ct_state, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

static __always_inline int snat_v6_handle_mapping(struct __ctx_buff *ctx,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry **state,
						  struct ipv6_nat_entry *tmp,
						  enum nat_dir dir, __u32 off,
						  const struct ipv6_nat_target *target)
{
	int ret;

	*state = snat_v6_lookup(tuple);
	ret = snat_v6_track_local(ctx, tuple, *state, dir, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else if (dir == NAT_DIR_INGRESS)
		return tuple->nexthdr != IPPROTO_ICMPV6 &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
	else
	    //执行port分配（full nat)
		return snat_v6_new_mapping(ctx, tuple, (*state = tmp)/*使用临时变量*/, target);
}

//完成地址，port转换,checksum调整
static __always_inline int snat_v6_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry *state,
						  __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_saddr, &tuple->saddr) &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 16, &state->to_saddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		    /*修改port,更新checksum*/
			ret = l4_modify_port(ctx, off, offsetof(struct tcphdr, source),
					     &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_sport,
					    sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->sport;
			to = state->to_sport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	/*修改ipv6地址*/
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &state->to_saddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	/*这里更新checksum.（由于ipv6地址发生了变更）此时from=0,而sum是相对之前checksum的diff
	 * 由于我们更新的是ip地址，故在ip_summed=complete情况下skb->csum并不需要发生变更
	 * 但这里传入了BPF_F_PSEUDO_HDR,这会导致skb->csum被更改，所以认为是一个bug*/
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

//完成地址，port转换,checksum调整
static __always_inline int snat_v6_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv6_ct_tuple *tuple,
						   struct ipv6_nat_entry *state,
						   __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_daddr, &tuple->daddr) &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 16, &state->to_daddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->dport;
			to = state->to_dport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &state->to_daddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v6_can_skip(const struct ipv6_nat_target *target,
		 const struct ipv6_ct_tuple *tuple, enum nat_dir dir,
		 bool icmp_echoreply)
{
	__u16 dport = bpf_ntohs(tuple->dport), sport = bpf_ntohs(tuple->sport);

	if (dir == NAT_DIR_EGRESS &&
	    ((!target->src_from_world && sport < NAT_MIN_EGRESS) ||
	     icmp_echoreply))
		return true;
	if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))
		return true;
	return false;
}

static __always_inline __maybe_unused int snat_v6_create_dsr(struct __ctx_buff *ctx,
							     union v6addr *to_saddr,
							     __be16 to_sport)
{
	void *data, *data_end;
	struct ipv6_ct_tuple tuple = {};
	struct ipv6_nat_entry state = {};
	struct ipv6hdr *ip6;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	int ret, hdrlen;
	__u32 off;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->daddr);
	tuple.flags = NAT_DIR_EGRESS;

	off = ((void *)ip6 - data) + hdrlen;

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.sport;
		tuple.sport = l4hdr.dport;
		break;
	default:
		/* NodePort svc can be reached only via TCP or UDP, so
		 * drop the rest.
		 */
		return DROP_NAT_UNSUPP_PROTO;
	}

	state.common.created = bpf_mono_now();
	ipv6_addr_copy(&state.to_saddr, to_saddr);
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV6, &tuple, &state, 0);
	if (ret)
		return ret;

	return CTX_ACT_OK;
}

static __always_inline __maybe_unused int
snat_v6_process(struct __ctx_buff *ctx, enum nat_dir dir,
		const struct ipv6_nat_target *target)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_nat_entry *state, tmp;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u8 nexthdr;
	__u32 off;
	bool icmp_echoreply = false;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, ETH_HLEN, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	//完成元组数据提取
	tuple.nexthdr = nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	tuple.flags = dir;
	off = ((void *)ip6 - data) + hdrlen;
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		/* Letting neighbor solicitation / advertisement pass through. */
		if (icmp6hdr.icmp6_type == ICMP6_NS_MSG_TYPE ||
			icmp6hdr.icmp6_type == ICMP6_NA_MSG_TYPE)
			return CTX_ACT_OK;
		if (icmp6hdr.icmp6_type != ICMPV6_ECHO_REQUEST &&
		    icmp6hdr.icmp6_type != ICMPV6_ECHO_REPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmp6hdr.icmp6_type == ICMPV6_ECHO_REQUEST) {
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
		} else {
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_can_skip(target, &tuple, dir, icmp_echoreply))
		return NAT_PUNT_TO_STACK;
	//执行nat转换及状态处理
	ret = snat_v6_handle_mapping(ctx, &tuple, &state, &tmp, dir, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	//完成地址及port，checksum更新
	return dir == NAT_DIR_EGRESS ?
	       snat_v6_rewrite_egress(ctx, &tuple, state, off) :
	       snat_v6_rewrite_ingress(ctx, &tuple, state, off);
}
#else
static __always_inline __maybe_unused
int snat_v6_process(struct __ctx_buff *ctx __maybe_unused,
		    enum nat_dir dir __maybe_unused,
		    const struct ipv6_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
void snat_v6_delete_tuples(struct ipv6_ct_tuple *tuple __maybe_unused)
{
}
#endif

static __always_inline __maybe_unused void
ct_delete4(const void *map, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx)
{
	int err;

	err = map_delete_elem(map, tuple);
	if (err < 0)
		cilium_dbg(ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v4_delete_tuples(tuple);
}

static __always_inline __maybe_unused void
ct_delete6(const void *map, struct ipv6_ct_tuple *tuple, struct __ctx_buff *ctx)
{
	int err;

	err = map_delete_elem(map, tuple);
	if (err < 0)
		cilium_dbg(ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v6_delete_tuples(tuple);
}

#endif /* __LIB_NAT__ */
