#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include "hmac.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("suiyan");

#define NF_HOOKPORT 3260
#define IP_STRSIZE 	20

static unsigned char hopping_key[] = {
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff
};

static int ip_num2str(
	char *ip_str, 
	unsigned int len, 
	unsigned int ip_n
	)
{
	if(len >= IP_STRSIZE)
	{
		sprintf(ip_str, "%d.%d.%d.%d", 
			ip_n & 0xff, (ip_n >> 8) & 0xff, 
			(ip_n >> 16) & 0xff, (ip_n >> 24) & 0xff);
		return 0;
	}

	return -1;
}

static void sync_hopping(
	struct iphdr *ip_h, 
	struct tcphdr *tcp_h
	)
{
	unsigned char *text = (unsigned char *)tcp_h + 4 * tcp_h->doff;
	unsigned int len = htons(ip_h->tot_len) - 4 * ip_h->ihl - 4 * tcp_h->doff; 
	unsigned char hmac[MD5_DIGEST_SIZE];

	//phase 1: hopping
	hmac_md5(hopping_key, 64, text, len, hmac);

	//printk(KERN_ALERT "len: %d\n", len);

	ip_h->saddr ^= (hmac[0] << 24);
	ip_h->daddr ^= (hmac[4] << 24);

	tcp_h->source ^= *(unsigned short *)&hmac[8];
	tcp_h->dest ^= *(unsigned short *)&hmac[12];
}

static unsigned int nf_hook_dehop(
	void *priv, 
	struct sk_buff *skb, 
	const struct nf_hook_state *state
	)
{
	struct ethhdr 	*eth_h = NULL;
	struct iphdr 	*ip_h =NULL;
	struct tcphdr 	*tcp_h = NULL;
	// unsigned short 	 src_port = 0;
	// unsigned short 	 dst_port = 0;
	// unsigned char 	 src_ip[IP_STRSIZE+1];
	// unsigned char 	 dst_ip[IP_STRSIZE+1];

	if(!likely(skb))
	{
		printk(KERN_ALERT "NULL skb!\n");
		return NF_ACCEPT;
	}

	eth_h = eth_hdr(skb);

	/* not ip packet, just ignore it.*/
	if(eth_h->h_proto != htons(ETH_P_IP))
	{
		return NF_ACCEPT;
	}

	ip_h = (struct iphdr *)((char *)eth_h + sizeof(struct ethhdr));

	/* not tcp packet, just ignore it.*/
	if(ip_h->protocol != IPPROTO_TCP)
	{
		return NF_ACCEPT;
	}

	tcp_h = (struct tcphdr *)((char *)ip_h + 4 * ip_h->ihl);
	// src_port = htons(tcp_h->source);
	// dst_port = htons(tcp_h->dest);

	if(ip_h->tos == 1)
	{
		ip_h->tos = 0;
		sync_hopping(ip_h, tcp_h);

		// src_port = htons(tcp_h->source);
		// dst_port = htons(tcp_h->dest);
		// ip_num2str(src_ip, IP_STRSIZE, ip_h->saddr);
		// ip_num2str(dst_ip, IP_STRSIZE, ip_h->daddr);
		// printk(KERN_ALERT "%s(%d) => %s(%d)\n", src_ip, src_port, dst_ip, dst_port);
	}

	return NF_ACCEPT;
}

static unsigned int nf_hook_hop(
	void *priv, 
	struct sk_buff *skb, 
	const struct nf_hook_state *state
	)
{
	struct ethhdr 	*eth_h = NULL;
	struct iphdr 	*ip_h =NULL;
	struct tcphdr 	*tcp_h = NULL;
	unsigned short 	 src_port = 0;
	unsigned short 	 dst_port = 0;
	// unsigned char 	 src_ip[IP_STRSIZE+1];
	// unsigned char 	 dst_ip[IP_STRSIZE+1];

	if(!likely(skb))
	{
		printk(KERN_ALERT "NULL skb!\n");
		return NF_ACCEPT;
	}

	eth_h = eth_hdr(skb);

	/* not ip packet, just ignore it.*/
	if(eth_h->h_proto != htons(ETH_P_IP))
	{
		return NF_ACCEPT;
	}

	ip_h = (struct iphdr *)((char *)eth_h + sizeof(struct ethhdr));

	/* not tcp packet, just ignore it.*/
	if(ip_h->protocol != IPPROTO_TCP)
	{
		return NF_ACCEPT;
	}

	tcp_h = (struct tcphdr *)((char *)ip_h + 4 * ip_h->ihl);
	src_port = htons(tcp_h->source);
	dst_port = htons(tcp_h->dest);

	if(src_port == NF_HOOKPORT || dst_port == NF_HOOKPORT)
	{
		sync_hopping(ip_h, tcp_h);
		ip_h->tos = 1;

		// ip_num2str(src_ip, IP_STRSIZE, ip_h->saddr);
		// ip_num2str(dst_ip, IP_STRSIZE, ip_h->daddr);
		// src_port = htons(tcp_h->source);
		// dst_port = htons(tcp_h->dest);
		// printk(KERN_ALERT "%s(%d) => %s(%d)\n", src_ip, src_port, dst_ip, dst_port);
	}

	return NF_ACCEPT;
}


static struct nf_hook_ops nfops_dehop = 
{
	.hook = nf_hook_dehop,
	.hooknum = NF_BR_LOCAL_IN,
	.pf = NFPROTO_BRIDGE,
	.priority = NF_BR_PRI_FIRST
};

static struct nf_hook_ops nfops_hop = 
{
	.hook = nf_hook_hop,
	.hooknum = NF_BR_LOCAL_OUT,
	.pf = NFPROTO_BRIDGE,
	.priority = NF_BR_PRI_LAST
};

static int __init hopping_init(void)
{
	nf_register_net_hook(&init_net, &nfops_dehop);
	nf_register_net_hook(&init_net, &nfops_hop);

	printk(KERN_ALERT "start hopping mechanism...\n");
	return 0;
}

static void __exit hopping_exit(void)
{
	nf_unregister_net_hook(&init_net, &nfops_hop);
	nf_unregister_net_hook(&init_net, &nfops_dehop);

	printk(KERN_ALERT "stop hopping mechanism...\n");
}

module_init(hopping_init);
module_exit(hopping_exit);
