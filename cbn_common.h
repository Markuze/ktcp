#ifndef __CBN_COMMON_H__
#define __CBN_COMMON_H__

#include <linux/kernel.h>
#include <linux/printk.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#define KTCP_VERSION 	"__KTCP_VERSION__"

#define ALWAYS_FRESH		1
#define OPTIMISTIC_SYN_OFF 	2

#define CBN_PROBE_PORT		4 /* Lowest unassigned IANA port */

#define cbn_err(fmt, ...)	__cbn_err("%s: " fmt, __FUNCTION__, ##__VA_ARGS__);	\
				pr_err( "%s: " fmt, __FUNCTION__, ##__VA_ARGS__)

#define INIT_TRACE	char ___buff[512] = {0}; int ___idx = 0;
#define DUMP_TRACE	 if (___idx) {___buff[___idx] = '\n'; trace_printk(___buff);} ___buff[0] = ___idx = 0;

#define ERR_LINE() { pr_err("(%s): %d:%s \n", current->comm, __LINE__, __FUNCTION__);}

#define TRACE_DEBUG(fmt, ...)
#define TRACE_LINE()
//#define TRACE_QP(...)
//#define TRACE_LINE() {	 trace_printk("%d:%s (%s)\n", __LINE__, __FUNCTION__, current->comm);/*___idx += sprintf(&___buff[___idx], "\n\t\t%s:%d", __FUNCTION__, __LINE__);*/ }

//////////////////////// Switched TRACES
#ifndef TRACE_PRINT
#define TRACE_PRINT(fmt, ...) { /*pr_err("%s:%s:"fmt"\n", __FUNCTION__, current->comm,##__VA_ARGS__ );*/\
				 trace_printk("%d:%s:"fmt"\n", __LINE__, current->comm,##__VA_ARGS__ ); \
				 /*___idx += sprintf(&___buff[___idx], "\n\t\t%s:%d:"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); */}
#endif

#ifndef TRACE_ERROR
#define TRACE_ERROR(fmt, ...) {  pr_err("%s:%s:"fmt"\n", __FUNCTION__, current->comm,##__VA_ARGS__ );\
				 trace_printk("%d:%s:"fmt"\n", __LINE__, current->comm,##__VA_ARGS__ ); \
				}
#endif

#ifndef TRACE_QP
#define TRACE_QP(fmt, ...) { trace_printk("%d:%s:"fmt"\n", __LINE__, current->comm,##__VA_ARGS__ ); }
#endif

#ifndef TRACE_DEBUG
#define TRACE_DEBUG(fmt, ...) if (unlikely(0)) {trace_printk("%d:%s:"fmt"\n", __LINE__, current->comm,##__VA_ARGS__ );}
#endif
////////////////////////////////////////////

static inline void __cbn_err(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	trace_printk(fmt, args);
	va_end(args);
}

#define cbn_info(fmt, ...) trace_printk(fmt, ##__VA_ARGS__);
//__cbn_err(fmt, ##__VA_ARGS__)
//
static inline void hex_dump(const unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (!(i % 16))
			cbn_info("\n%lu\t:", i);
		cbn_info("%02x ", *(buf + i));
	}
	cbn_info("\n");
}

static inline const char *iphdr_flag(uint16_t flags)
{
	if (flags & BIT(14))
		return "DF";
	if (flags & BIT(13))
		return "MF";
	return "";
}

static inline const char *proto_string(u8 protocol)
{
	switch(protocol) {

	case 1: return "ICMP";
	case 4: return "IP";
	case 6: return "TCP";
	case 17: return "UDP";
	case 50: return "ESP";
	case 51: return "AH";
	}
	return "";
}

#define IP4N(x)		((const unsigned char*)(x))[0], ((const unsigned char*)(x))[1],((const unsigned char*)(x))[2],((const unsigned char*)(x))[3]
#define TCP4N(x, p)	((const unsigned char*)(x))[0], ((const unsigned char*)(x))[1],((const unsigned char*)(x))[2],((const unsigned char*)(x))[3], p
#define IP4	"%u.%u.%u.%u"
#define TCP4	"%u.%u.%u.%u:%u"

#define dump_iph(iphdr) 	idx += sprintf(&store[idx],"\t\tmark %d secmark %d\n\t\t"  \
		 "ihl %d ver %d tos %d total len %d\n\t\t"							\
		 "id %05d frag_off %05lu [%s]\n\t\t"								\
		 "ttl %d proto %s[%d] csum 0x%x\n\t\t"								\
		 "saddr "IP4" \n\t\t"										\
		 "daddr "IP4" \n"										\
			,skb->mark, skb->secmark,								\
			iphdr->ihl, iphdr->version,								\
			iphdr->tos, ntohs(iphdr->tot_len),							\
			ntohs(iphdr->id), ntohs(iphdr->frag_off) & (BIT(13) -1),				\
			iphdr_flag(ntohs(iphdr->frag_off)),							\
			iphdr->ttl, proto_string(iphdr->protocol), iphdr->protocol,				\
			iphdr->check, IP4N(&iphdr->saddr), IP4N(&iphdr->daddr)					\
			);

#define	dump_udphdr(udphdr)	idx += sprintf(&store[idx],"src : %05d  dst %05d\n"				\
						,ntohs(udphdr->source), ntohs(udphdr->dest));

#define dump_tcph(tcphdr)	idx += sprintf(&store[idx], "\n\t\t%d => %d "					\
						"\t\t%s %s %s\n"						\
						"\t\tseq %d ack %d window %d\n"					\
						,ntohs(tcphdr->source), ntohs(tcphdr->dest)			\
						, tcphdr->syn ? "SYN" : ""					\
						, tcphdr->ack ? "ACK" : ""					\
						, tcphdr->fin ? "FIN" : ""					\
						,ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq)			\
						,ntohs(tcphdr->window)						\
						);
//define TRACE_PACKETS
static inline void trace_only(struct sk_buff *skb, const char *str)
{
	struct iphdr *iphdr = ip_hdr(skb);
	int idx = 0;
	char store[512] = {0};

	idx += sprintf(&store[idx], "%s:\n",str);
	dump_iph(iphdr);

	if (iphdr->protocol == 6) {
		struct tcphdr *tcphdr = (struct tcphdr *)skb_transport_header(skb);
		dump_tcph(tcphdr);
	}
	if (iphdr->protocol == 17) {
		struct udphdr *udphdr = (struct udphdr *)skb_transport_header(skb);
		dump_udphdr(udphdr);
	}
#ifdef TRACE_PACKETS
	trace_printk(store);
#endif
}

static inline int trace_iph(struct sk_buff *skb, const char *str)
{
	struct iphdr *iphdr = ip_hdr(skb);
	int rc = 0;
#ifdef TRACE_PACKETS
	int idx = 0;
	char store[512] = {0};
#endif

	if (iphdr->protocol == 6) {
		struct tcphdr *tcphdr = (struct tcphdr *)skb_transport_header(skb);
		if (unlikely(tcphdr->syn && !tcphdr->ack)) {
			rc = 1;
#ifdef TRACE_PACKETS
			idx += sprintf(&store[idx], "%s:\n",str);
			dump_iph(iphdr);
			dump_tcph(tcphdr);
			trace_printk(store);
#endif
		}
	}
	return rc && skb->mark;
/*
	idx += sprintf(&store[idx],"\n\t\t>>>>>>>>>>>>>%s>>>>>>>>>>>>>>>>\n",str);
	if (skb->mark == 166)
		idx += sprintf(&store[idx],"\n\t\tMARK SET\n");
	dump_iph(iphdr);

	if (iphdr->saddr == 0 || iphdr->daddr == 0) {
		idx += sprintf(&store[idx],"WARNING: d/saddr are 0\n");
	}
	idx += sprintf(&store[idx],"\t\t%d %s\n", skb->skb_iif, (skb->dev) ? skb->dev->name : "NetDev not set");

	if (iphdr->protocol == 17) {
		struct udphdr *udphdr = (struct udphdr *)skb_transport_header(skb);
		idx += sprintf(&store[idx],"\t\t%p %p:\n\t\t src : %05d  dst %05d\n"
				, udphdr, iphdr,
				ntohs(udphdr->source), ntohs(udphdr->dest));
		if (ntohs(udphdr->dest) == 4500) {
			skb->mark = 166;
		}
	}
	idx += sprintf(&store[idx],"\n\t\t=================\n");
	trace_printk(store);
	*/
}
#endif /*__CBN_COMMON_H__*/
