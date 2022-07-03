/* 
 * main.c
 * Copyright (C) 2010-2012 G. Elian Gidoni
 *               2012 Ed Wildgoose
 *               2014 Humberto Jucá <betolj@gmail.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/time.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack.h>

#ifndef NDPI_LIB_COMPILATION
#define NDPI_LIB_COMPILATION
#endif

#include "ndpi_main.h"
#include "xt_ndpi.h"

/* Debug param */
static int debug_dpi = 0;
module_param(debug_dpi, int, 0);
MODULE_PARM_DESC(debug_dpi, "Enable syslog debug");

static char *prot_long_str[] = { NDPI_PROTOCOL_LONG_STRING };

// Try to verify that this project has the same number of protocols as nDPI.
//
// Typically this will fail when nDPI added protocols.  When that happens,
// add the new protocols to:
// * NDPI_PROTOCOL_LONG_STRING and NDPI_PROTOCOL_SHORT_STRING in xt_ndpi.h
// * The list of protocol objects for xt_ndpi-y in Makefile
//
// (Both xt_ndpi.h and Makefile are in the same directory as this file.)
_Static_assert(sizeof(prot_long_str)/sizeof(char*)
	       == NDPI_LAST_IMPLEMENTED_PROTOCOL,
	       "nDPI and ndpi-netfilter protocol counts do not match.");


/* flow tracking */
struct osdpi_flow_node {
        struct rb_node node;
        struct nf_conn * ct;
        u_int64_t ndpi_timeout;  // detection timeout - detection 30s / connection 180s
        /* mark if done detecting flow proto - no more tries */
        u8 detection_completed;
	/* result only, not used for flow identification */
        ndpi_protocol detected_protocol;
        /* last pointer assigned at run time */
	struct ndpi_flow_struct *ndpi_flow;
};

u64 gc_interval_timeout = 0;
static u32 size_flow_struct = 0;

static struct rb_root osdpi_flow_root = RB_ROOT;

static struct kmem_cache *osdpi_flow_cache __read_mostly;

static NDPI_PROTOCOL_BITMASK protocols_bitmask;
static atomic_t protocols_cnt[NDPI_LAST_IMPLEMENTED_PROTOCOL];
static u8 nfndpi_protocols_http[NDPI_LAST_IMPLEMENTED_PROTOCOL];

DEFINE_SPINLOCK(flow_lock);
DEFINE_SPINLOCK(ipq_lock);


/* detection */
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static u32 detection_tick_resolution = 1000;

/* debug functions */

static void debug_printf(u32 protocol, void *id_struct,
                         ndpi_log_level_t log_level, const char *format, ...)
{
        /* do nothing */

        va_list args;
        va_start(args, format);
        switch (log_level)
        {
            case NDPI_LOG_ERROR: 
                vprintk(format, args);
                break;
            case NDPI_LOG_TRACE:
                vprintk(format, args);
                break;

            case NDPI_LOG_DEBUG:
                vprintk(format, args);
                break;
        }
        va_end(args);
}


/*
static void *malloc_wrapper(unsigned long size)
{
	return kmalloc(size, GFP_KERNEL);
}
*/

/*
static void free_wrapper(void *freeable)
{
	kfree(freeable);
}
*/


static struct osdpi_flow_node *
ndpi_flow_search(struct rb_root *root, struct nf_conn *ct)
{
        struct osdpi_flow_node *data;
  	struct rb_node *node = root->rb_node;

  	while (node) {
                data = rb_entry(node, struct osdpi_flow_node, node);

                if (ct < data->ct)
                        node = node->rb_left;
                else if (ct > data->ct)
                        node = node->rb_right;
                else
                        return data;
	}

	return NULL;
}


static int
ndpi_flow_insert(struct rb_root *root, struct osdpi_flow_node *data)
{
        struct osdpi_flow_node *this;
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

  	while (*new) {
                this = rb_entry(*new, struct osdpi_flow_node, node);

		parent = *new;
  		if (data->ct < this->ct)
  			new = &((*new)->rb_left);
  		else if (data->ct > this->ct)
  			new = &((*new)->rb_right);
  		else
  			return 0;
  	}
  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, root);

	return 1;
}


static struct osdpi_flow_node *
ndpi_alloc_flow (struct nf_conn * ct)
{
        struct osdpi_flow_node *flow;

	flow = kmem_cache_zalloc (osdpi_flow_cache, GFP_ATOMIC);
	//flow = kzalloc(sizeof(struct ndpi_flow_struct *) + size_flow_struct, GFP_KERNEL);

        if (flow == NULL) {
                pr_err("xt_ndpi: couldn't allocate new flow.\n");
                return NULL;
        }
	else {
	        flow->ct = ct;
	        flow->ndpi_flow = (struct ndpi_flow_struct *)
	                ((char*)&flow->ndpi_flow+sizeof(flow->ndpi_flow));
	        ndpi_flow_insert (&osdpi_flow_root, flow);
	}

        return flow;
}

static void
nfndpi_free_flow (struct nf_conn * ct, struct osdpi_flow_node * auxflow)
{
        struct osdpi_flow_node * flow;

	if (auxflow == NULL)
	        flow = ndpi_flow_search (&osdpi_flow_root, ct);
	else
		flow = auxflow;

        if (flow != NULL){
                rb_erase (&flow->node, &osdpi_flow_root);
	        kmem_cache_free (osdpi_flow_cache, flow);
                //kfree (flow);
        }
}


static void
ndpi_enable_protocols (const struct xt_ndpi_mtinfo*info)
{
        int i=0;

        for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++){
	        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0){
		        if (ndpi_struct->proto_defaults[i].protoIdx == 0){
				spin_lock_bh (&ipq_lock);

				//Force http or ssl detection for webserver host requests
	                        if (nfndpi_protocols_http[i-1]) {
					if (ndpi_struct->proto_defaults[NDPI_PROTOCOL_DNS].protoIdx == 0)
						 NDPI_ADD_PROTOCOL_TO_BITMASK(protocols_bitmask, NDPI_PROTOCOL_DNS);
					if (ndpi_struct->proto_defaults[NDPI_PROTOCOL_HTTP].protoIdx == 0)
						 NDPI_ADD_PROTOCOL_TO_BITMASK(protocols_bitmask, NDPI_PROTOCOL_HTTP);
					if (ndpi_struct->proto_defaults[NDPI_PROTOCOL_TLS].protoIdx == 0)
					 	 NDPI_ADD_PROTOCOL_TO_BITMASK(protocols_bitmask, NDPI_PROTOCOL_TLS);
				}

				atomic_inc(&protocols_cnt[i-1]);
				NDPI_ADD_PROTOCOL_TO_BITMASK(protocols_bitmask, i);
				ndpi_set_protocol_detection_bitmask2
		                        (ndpi_struct,&protocols_bitmask);

				spin_unlock_bh (&ipq_lock);
			}
                }
        }
}


static void
ndpi_disable_protocols (const struct xt_ndpi_mtinfo*info)
{
        int i;

        for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++){
                if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0){
		        spin_lock_bh (&ipq_lock);
                        if (atomic_dec_and_test(&protocols_cnt[i-1])){
                                NDPI_DEL_PROTOCOL_FROM_BITMASK(protocols_bitmask, i);
                                ndpi_set_protocol_detection_bitmask2
                                        (ndpi_struct, &protocols_bitmask);
                        }
		        spin_unlock_bh (&ipq_lock);
                }
        }
}


static void ndpi_kill_flow(struct nf_conn * ct, union nf_inet_addr *ipsrc, union nf_inet_addr *ipdst) {
	nfndpi_free_flow(ct, NULL);
}


static void ndpi_gc_flow(void)
{
	struct nf_conn * ct;
        struct rb_node * next;
        struct osdpi_flow_node *flow;
	union nf_inet_addr *ipdst;

        u64 t1;
        struct timespec64 tv;

        ktime_get_real_ts64(&tv);
        t1 = (uint64_t) tv.tv_sec;

	if (debug_dpi) pr_info ("xt_ndpi: call garbage collector.\n");
        next = rb_first(&osdpi_flow_root);
        while (next){
                flow = rb_entry(next, struct osdpi_flow_node, node);
                next = rb_next(&flow->node);
		if (flow && (t1 - flow->ndpi_timeout > 180)) {
	                ct = flow->ct;
			ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
			if (debug_dpi && flow->detected_protocol.app_protocol <= NDPI_LAST_NFPROTO)
				pr_info ("xt_ndpi: deleted by garbage collector - proto %s - dst %pI4\n", prot_long_str[flow->detected_protocol.app_protocol], ipdst);

			nfndpi_free_flow(ct, flow);
		}
        }
}


static u32
ndpi_process_packet(struct nf_conn * ct, const uint64_t time,
                      const struct iphdr *iph, uint16_t ipsize, const struct tcphdr *tcph)
{
	u32 proto = NDPI_PROTOCOL_UNKNOWN;
        union nf_inet_addr *ipsrc, *ipdst;
        struct osdpi_flow_node *flow, *curflow;

	u8 exist_flow=0;
        u64 t1;
        struct timespec64 tv;

	spin_lock_bh (&flow_lock);
        ipsrc = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
       	ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;

	flow = ndpi_flow_search (&osdpi_flow_root, ct);

	if (iph->protocol == IPPROTO_TCP) {
                if (tcph->syn) {
			spin_unlock_bh (&flow_lock);
			return proto;
		}
                else if ((tcph->fin || tcph->rst) && flow != NULL) {
			ndpi_kill_flow(ct, ipsrc, ipdst);
			spin_unlock_bh (&flow_lock);
			return proto;
		}
	}
	else if (iph->protocol == IPPROTO_ICMP) {
		spin_unlock_bh (&flow_lock);
		return NDPI_PROTOCOL_IP_ICMP;
	}
	else {
		if (nf_ct_is_dying(ct)) {
			ndpi_kill_flow(ct, ipsrc, ipdst);
			spin_unlock_bh (&flow_lock);
			return proto;
		}
	}

        ktime_get_real_ts64(&tv);
        t1 = (uint64_t) tv.tv_sec;

        if (flow == NULL) {
		if (!gc_interval_timeout) gc_interval_timeout = t1;
		else {
			if (t1 - gc_interval_timeout > 59) {
				ndpi_gc_flow();
				gc_interval_timeout = t1;
			}
		}

		flow = ndpi_alloc_flow(ct);
                if (flow == NULL) {
			spin_unlock_bh (&flow_lock);
			return NDPI_PROTOCOL_UNKNOWN;
		}
                else {
			/* Include flow timeouts */
			flow->ndpi_timeout = t1;  // 30s for DPI timeout  and 180 for connection
		        flow->detected_protocol.app_protocol = NDPI_PROTOCOL_UNKNOWN;
			flow->detection_completed = 0;
                }
        }
        else {
		/* Update timeouts */
		exist_flow=1;
		if (flow->detected_protocol.app_protocol) {
			proto = flow->detected_protocol.app_protocol;
			if (debug_dpi && flow->detected_protocol.app_protocol <= NDPI_LAST_NFPROTO)
				pr_info ("xt_ndpi: flow detected %s ( dst %pI4 )\n", prot_long_str[flow->detected_protocol.app_protocol], ipdst);
			flow->ndpi_timeout = t1;
			spin_unlock_bh (&flow_lock);
			return proto;
	        }
	        else if (!flow->detected_protocol.app_protocol && (t1 - flow->ndpi_timeout > 30)) {
			if (debug_dpi) pr_info ("xt_ndpi: dst %pI4 expired\n", ipdst);
			spin_unlock_bh (&flow_lock);
			return NDPI_PROTOCOL_UNKNOWN;
	        }
	}

	/* Invalid DPI flow */
	if (flow->ndpi_flow == NULL) {
		if (debug_dpi) pr_info ("xt_ndpi: dst %pI4 invalid\n", ipdst);
		ndpi_kill_flow(ct, ipsrc, ipdst);
		spin_unlock_bh (&flow_lock);
		return proto;
	}

	flow->ndpi_timeout = t1;

	/* Set current flow for temporary dump */
        curflow = kmem_cache_zalloc (osdpi_flow_cache, GFP_ATOMIC);
        curflow->ndpi_flow = (struct ndpi_flow_struct *)
                 ((char*)&curflow->ndpi_flow+sizeof(curflow->ndpi_flow));
        curflow->detected_protocol.app_protocol = NDPI_PROTOCOL_UNKNOWN;
        curflow->ndpi_flow = flow->ndpi_flow;
        spin_unlock_bh (&flow_lock);


        /* here the actual detection is performed */
	spin_lock_bh (&ipq_lock);
	curflow->detected_protocol = ndpi_detection_process_packet(ndpi_struct,
								   curflow->ndpi_flow,
								   (uint8_t *) iph, ipsize,
								   time);

	spin_unlock_bh (&ipq_lock);

	/* set detected protocol */
	spin_lock_bh (&flow_lock);
	if (flow != NULL) {
		proto = curflow->detected_protocol.app_protocol;
		flow->detected_protocol = curflow->detected_protocol;

	        if (proto > NDPI_LAST_IMPLEMENTED_PROTOCOL)
	                proto = NDPI_PROTOCOL_UNKNOWN;
		else {
		        if (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
				/* update timeouts */
				if (debug_dpi && proto <= NDPI_LAST_NFPROTO)
					pr_info ("xt_ndpi: protocol detected %s ( dst %pI4 )\n", prot_long_str[proto], ipdst);
				flow->ndpi_timeout = t1;
				flow->detection_completed = 1;

				/* reset detection */
				if (flow->ndpi_flow) memset(flow->ndpi_flow, 0, sizeof(*(flow->ndpi_flow)));
		        }
		}
	}
	kmem_cache_free (osdpi_flow_cache, curflow);
	spin_unlock_bh (&flow_lock);

	return proto;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static bool
ndpi_mt (const struct sk_buff *skb,
            const struct net_device *in,
            const struct net_device *out,
            const struct xt_match *match,
            const void *matchinfo,
            int offset,
            unsigned int protoff,
            bool *hotdrop)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static bool
ndpi_mt(const struct sk_buff *skb, const struct xt_match_param *par)
#else
static bool
ndpi_mt(const struct sk_buff *skb, struct xt_action_param *par)
#endif
{
	u32 proto = NDPI_PROTOCOL_UNKNOWN;
	u64 time;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	const struct xt_ndpi_mtinfo *info = matchinfo;
#else
	const struct xt_ndpi_mtinfo *info = par->matchinfo;
#endif

	enum ip_conntrack_info ctinfo;
	struct nf_conn * ct;
	struct timespec64 tv;
	struct sk_buff *linearized_skb = NULL;
	const struct sk_buff *skb_use = NULL;

        const struct iphdr *ip;
        const struct tcphdr *tcph;

	if (skb_is_nonlinear(skb)){
		linearized_skb = skb_copy(skb, GFP_ATOMIC);
		if (linearized_skb == NULL) {
			pr_info ("xt_ndpi: linearization failed.\n");
			return false;
		}
		skb_use = linearized_skb;
	} else {
		skb_use = skb;
	}


	ct = nf_ct_get (skb_use, &ctinfo);
	if (ct == NULL){
		if(linearized_skb != NULL)
			kfree_skb(linearized_skb);

		return false;
	} else if (!ct){
		pr_info ("xt_ndpi: ignoring untracked sk_buff.\n");
		return false;
	}


	/* process the packet */
        ip = ip_hdr(skb_use);
        tcph = (const void *)ip + ip_hdrlen(skb_use);

	ktime_get_real_ts64(&tv);
	time = ((uint64_t) tv.tv_sec) * detection_tick_resolution +
		tv.tv_nsec / (1000000000 / detection_tick_resolution);

	/* reset for new packets and solve ct collisions */
	if (ctinfo == IP_CT_NEW) {
		spin_lock_bh (&flow_lock);
		ndpi_kill_flow(ct, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3);
		spin_unlock_bh (&flow_lock);
        }

	proto = ndpi_process_packet(ct, time, ip_hdr(skb_use), skb_use->len, tcph);
	

	if(linearized_skb != NULL)
		kfree_skb(linearized_skb);

	spin_lock_bh (&ipq_lock);
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,proto) != 0) {
		spin_unlock_bh (&ipq_lock);
                return true;
	}
	spin_unlock_bh (&ipq_lock);

        return false;
}


static int
ndpi_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_ndpi_mtinfo *info = par->matchinfo;

        if (NDPI_BITMASK_IS_ZERO(info->flags)) {
                pr_info("xt_ndpi: None selected protocol.\n");
                return -EINVAL;
        }

	NDPI_BITMASK_RESET(protocols_bitmask);
        ndpi_enable_protocols (info);

	return 0;
}


static void 
ndpi_mt_destroy (const struct xt_mtdtor_param *par)
{
	const struct xt_ndpi_mtinfo *info = par->matchinfo;

        ndpi_disable_protocols (info);

}



static void ndpi_cleanup(void)
{
        struct rb_node * next;
        struct osdpi_flow_node *flow;

        //ndpi_exit_detection_module(ndpi_struct, free_wrapper);
        ndpi_exit_detection_module(ndpi_struct);

        /* free all objects before destroying caches */
        next = rb_first(&osdpi_flow_root);
        while (next){
                flow = rb_entry(next, struct osdpi_flow_node, node);
                next = rb_next(&flow->node);

                rb_erase(&flow->node, &osdpi_flow_root);
	        kmem_cache_free (osdpi_flow_cache, flow);
        }
        kmem_cache_destroy (osdpi_flow_cache);
}


static struct xt_match
ndpi_mt_reg __read_mostly = {
	.name = "ndpi",
	.revision = 0,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	.family = AF_INET,
#else
	.family = NFPROTO_IPV4,
#endif
	.match = ndpi_mt,
	.checkentry = ndpi_mt_check,
	.destroy = ndpi_mt_destroy,
	.matchsize = sizeof(struct xt_ndpi_mtinfo),
	.me = THIS_MODULE,
};


static int __init ndpi_mt_init(void)
{
        int ret=-ENOMEM, i;

	pr_info("xt_ndpi 4.2 (nDPI wrapper module).%s\n",
		debug_dpi ? " Debugging enabled." : "");

	/* init global detection structure
	//NDPI_PROTOCOL_BITMASK all;
	ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
                                                     malloc_wrapper, free_wrapper, debug_printf);
        */
	ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs);

	if (ndpi_struct == NULL) {
		pr_err("xt_ndpi: global structure initialization failed.\n");
                ret = -ENOMEM;
                goto err_out;
	}

        for (i = 0; i < NDPI_LAST_IMPLEMENTED_PROTOCOL; i++){
                atomic_set (&protocols_cnt[i], 0);

                // Set HTTP based protocols
                if ((i > 118 && i < 127) || (i > 139 && i < 146) || (i > 175 && i <= 218 ) || i == 70 || i == 133) nfndpi_protocols_http[i]=1;
                else nfndpi_protocols_http[i]=0;
        }

	/* disable all protocols */
	NDPI_BITMASK_RESET(protocols_bitmask);
	ndpi_set_protocol_detection_bitmask2(ndpi_struct, &protocols_bitmask);

	/* allocate memory for flow tracking */
        size_flow_struct = sizeof(struct ndpi_flow_struct);


        osdpi_flow_cache = kmem_cache_create("xt_ndpi_flows",
                                             sizeof(struct osdpi_flow_node) +
                                             size_flow_struct,
                                             0, 0, NULL);

        if (!osdpi_flow_cache){
                pr_err("xt_ndpi: error creating flow cache.\n");
                ret = -ENOMEM;
                goto err_ipq;
        }

        ret = xt_register_match(&ndpi_mt_reg);
        if (ret != 0){
                pr_err("xt_ndpi: error registering ndpi match.\n");
                ndpi_cleanup();
        }

        return ret;

err_flow:
        kmem_cache_destroy (osdpi_flow_cache);
err_ipq:
        //ndpi_exit_detection_module(ndpi_struct, free_wrapper);
        ndpi_exit_detection_module(ndpi_struct);
err_out:
        return ret;
}


static void __exit ndpi_mt_exit(void)
{
	pr_info("xt_ndpi 4.2 unload.\n");

	xt_unregister_match(&ndpi_mt_reg);
        ndpi_cleanup();
}


module_init(ndpi_mt_init);
module_exit(ndpi_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("G. Elian Gidoni (main code)");
MODULE_AUTHOR("Humberto Juca <betolj@gmail.com>");
MODULE_AUTHOR("Chris Nelson <Chris.Nelson.PE@gmail.com>");
MODULE_DESCRIPTION("nDPI wrapper");
MODULE_ALIAS("ipt_ndpi");
