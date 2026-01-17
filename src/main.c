/* * main.c - Optimized for Linux Kernel 6.2+
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
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

_Static_assert(sizeof(prot_long_str)/sizeof(char*)
           == NDPI_LAST_IMPLEMENTED_PROTOCOL,
           "nDPI and ndpi-netfilter protocol counts do not match.");

/* flow tracking */
struct osdpi_flow_node {
    struct rb_node node;
    struct nf_conn *ct;
    u_int64_t ndpi_timeout;
    u8 detection_completed;
    ndpi_protocol detected_protocol;
    struct ndpi_flow_struct *ndpi_flow;
};

/* id tracking */
struct osdpi_id_node {
    struct rb_node node;
    struct kref refcnt;
    union nf_inet_addr ip;
    struct ndpi_id_struct *ndpi_id;
};

u64 gc_interval_timeout = 0;
static u32 size_id_struct = 0;
static u32 size_flow_struct = 0;

static struct rb_root osdpi_flow_root = RB_ROOT;
static struct rb_root osdpi_id_root = RB_ROOT;

static struct kmem_cache *osdpi_flow_cache __read_mostly;
static struct kmem_cache *osdpi_id_cache __read_mostly;

static NDPI_PROTOCOL_BITMASK protocols_bitmask;
static atomic_t protocols_cnt[NDPI_LAST_IMPLEMENTED_PROTOCOL];
static u8 nfndpi_protocols_http[NDPI_LAST_IMPLEMENTED_PROTOCOL];

DEFINE_SPINLOCK(flow_lock);
DEFINE_SPINLOCK(ipq_lock);

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static u32 detection_tick_resolution = 1000;

/* --- Helpers --- */

static struct osdpi_flow_node *ndpi_flow_search(struct rb_root *root, struct nf_conn *ct) {
    struct osdpi_flow_node *data;
    struct rb_node *node = root->rb_node;
    while (node) {
        data = rb_entry(node, struct osdpi_flow_node, node);
        if (ct < data->ct) node = node->rb_left;
        else if (ct > data->ct) node = node->rb_right;
        else return data;
    }
    return NULL;
}

static int ndpi_flow_insert(struct rb_root *root, struct osdpi_flow_node *data) {
    struct osdpi_flow_node *this;
    struct rb_node **new = &(root->rb_node), *parent = NULL;
    while (*new) {
        this = rb_entry(*new, struct osdpi_flow_node, node);
        parent = *new;
        if (data->ct < this->ct) new = &((*new)->rb_left);
        else if (data->ct > this->ct) new = &((*new)->rb_right);
        else return 0;
    }
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 1;
}

static struct osdpi_id_node *ndpi_id_search(struct rb_root *root, union nf_inet_addr *ip) {
    int res;
    struct osdpi_id_node *data;
    struct rb_node *node = root->rb_node;
    while (node) {
        data = rb_entry(node, struct osdpi_id_node, node);
        res = memcmp(ip, &data->ip, sizeof(union nf_inet_addr));
        if (res < 0) node = node->rb_left;
        else if (res > 0) node = node->rb_right;
        else return data;
    }
    return NULL;
}

static int ndpi_id_insert(struct rb_root *root, struct osdpi_id_node *data) {
    int res;
    struct osdpi_id_node *this;
    struct rb_node **new = &(root->rb_node), *parent = NULL;
    while (*new) {
        this = rb_entry(*new, struct osdpi_id_node, node);
        res = memcmp(&data->ip, &this->ip, sizeof(union nf_inet_addr));
        parent = *new;
        if (res < 0) new = &((*new)->rb_left);
        else if (res > 0) new = &((*new)->rb_right);
        else return 0;
    }
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 1;
}

static void ndpi_id_release(struct kref *kref) {
    struct osdpi_id_node *id = container_of(kref, struct osdpi_id_node, refcnt);
    rb_erase(&id->node, &osdpi_id_root);
    kmem_cache_free(osdpi_id_cache, id);
}

static struct osdpi_flow_node *ndpi_alloc_flow(struct nf_conn *ct) {
    struct osdpi_flow_node *flow = kmem_cache_zalloc(osdpi_flow_cache, GFP_ATOMIC);
    if (!flow) return NULL;
    flow->ct = ct;
    flow->ndpi_flow = (struct ndpi_flow_struct *)((char*)flow + sizeof(struct osdpi_flow_node));
    ndpi_flow_insert(&osdpi_flow_root, flow);
    return flow;
}

static void nfndpi_free_flow(struct nf_conn *ct, struct osdpi_flow_node *auxflow) {
    struct osdpi_flow_node *flow = auxflow ? auxflow : ndpi_flow_search(&osdpi_flow_root, ct);
    if (flow) {
        rb_erase(&flow->node, &osdpi_flow_root);
        kmem_cache_free(osdpi_flow_cache, flow);
    }
}

static struct osdpi_id_node *ndpi_alloc_id(union nf_inet_addr *ip) {
    struct osdpi_id_node *id = kmem_cache_zalloc(osdpi_id_cache, GFP_ATOMIC);
    if (!id) return NULL;
    memcpy(&id->ip, ip, sizeof(union nf_inet_addr));
    id->ndpi_id = (struct ndpi_id_struct *)((char*)id + sizeof(struct osdpi_id_node));
    kref_init(&id->refcnt);
    ndpi_id_insert(&osdpi_id_root, id);
    return id;
}

static void nfndpi_free_id(union nf_inet_addr *ip) {
    struct osdpi_id_node *id = ndpi_id_search(&osdpi_id_root, ip);
    if (id) kref_put(&id->refcnt, ndpi_id_release);
}

static void ndpi_kill_flow(struct nf_conn *ct, union nf_inet_addr *ipsrc, union nf_inet_addr *ipdst) {
    nfndpi_free_id(ipsrc);
    nfndpi_free_id(ipdst);
    nfndpi_free_flow(ct, NULL);
}

/* Garbage Collector optimized for newer kernels */
static void ndpi_gc_flow(void) {
    struct rb_node *node, *next;
    struct osdpi_flow_node *flow;
    u64 now = ktime_get_real_seconds();

    node = rb_first(&osdpi_flow_root);
    while (node) {
        next = rb_next(node);
        flow = rb_entry(node, struct osdpi_flow_node, node);
        if (now - flow->ndpi_timeout > 180) {
            struct nf_conn *ct = flow->ct;
            nfndpi_free_id(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
            nfndpi_free_id(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3);
            nfndpi_free_flow(ct, flow);
        }
        node = next;
    }
}

/* Main detection logic */
static u32 ndpi_process_packet(struct nf_conn *ct, const uint64_t time_ms,
                             const struct iphdr *iph, uint16_t ipsize, const struct tcphdr *tcph) {
    u32 proto = NDPI_PROTOCOL_UNKNOWN;
    union nf_inet_addr *ipsrc, *ipdst;
    struct osdpi_id_node *src, *dst;
    struct osdpi_flow_node *flow;
    u64 now_sec = ktime_get_real_seconds();

    spin_lock_bh(&flow_lock);
    ipsrc = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
    ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;

    flow = ndpi_flow_search(&osdpi_flow_root, ct);

    if (iph->protocol == IPPROTO_TCP && tcph) {
        if (tcph->fin || tcph->rst) {
            if (flow) ndpi_kill_flow(ct, ipsrc, ipdst);
            spin_unlock_bh(&flow_lock);
            return NDPI_PROTOCOL_UNKNOWN;
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        spin_unlock_bh(&flow_lock);
        return NDPI_PROTOCOL_IP_ICMP;
    }

    if (!flow) {
        if (!gc_interval_timeout || (now_sec - gc_interval_timeout > 60)) {
            ndpi_gc_flow();
            gc_interval_timeout = now_sec;
        }
        flow = ndpi_alloc_flow(ct);
        if (!flow) { spin_unlock_bh(&flow_lock); return proto; }
        flow->ndpi_timeout = now_sec;
    } else {
        if (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            proto = flow->detected_protocol.app_protocol;
            flow->ndpi_timeout = now_sec;
            spin_unlock_bh(&flow_lock);
            return proto;
        }
    }

    src = ndpi_id_search(&osdpi_id_root, ipsrc);
    if (!src) src = ndpi_alloc_id(ipsrc);
    else kref_get(&src->refcnt);

    dst = ndpi_id_search(&osdpi_id_root, ipdst);
    if (!dst) dst = ndpi_alloc_id(ipdst);
    else kref_get(&dst->refcnt);

    if (!src || !dst) { spin_unlock_bh(&flow_lock); return proto; }

    /* Core DPI detection */
    spin_lock_bh(&ipq_lock);
    flow->detected_protocol = ndpi_detection_process_packet(ndpi_struct, flow->ndpi_flow,
                                          (uint8_t *)iph, ipsize, time_ms,
                                          src->ndpi_id, dst->ndpi_id);
    spin_unlock_bh(&ipq_lock);

    proto = flow->detected_protocol.app_protocol;
    flow->ndpi_timeout = now_sec;
    spin_unlock_bh(&flow_lock);

    return proto;
}

/* Netfilter Match function */
static bool ndpi_mt(const struct sk_buff *skb, struct xt_action_param *par) {
    const struct xt_ndpi_mtinfo *info = par->matchinfo;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;
    struct timespec64 tv;
    u64 time_ms;

    ct = nf_ct_get(skb, &ctinfo);
    if (!ct) return false;

    struct iphdr _iph;
    const struct iphdr *iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
    if (!iph) return false;

    struct tcphdr _tcph;
    const struct tcphdr *tcph = NULL;
    if (iph->protocol == IPPROTO_TCP) {
        tcph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
    }

    ktime_get_real_ts64(&tv);
    time_ms = (u64)tv.tv_sec * 1000 + tv.tv_nsec / 1000000;

    u32 proto = ndpi_process_packet(ct, time_ms, iph, skb->len, tcph);

    return (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, proto) != 0);
}

/* Initialization and Cleanup */
static int ndpi_mt_check(const struct xt_mtchk_param *par) {
    const struct xt_ndpi_mtinfo *info = par->matchinfo;
    if (NDPI_BITMASK_IS_ZERO(info->flags)) return -EINVAL;
    
    // Simple protocol enable logic
    int i;
    for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) {
            spin_lock_bh(&ipq_lock);
            NDPI_ADD_PROTOCOL_TO_BITMASK(protocols_bitmask, i);
            ndpi_set_protocol_detection_bitmask2(ndpi_struct, &protocols_bitmask);
            spin_unlock_bh(&ipq_lock);
        }
    }
    return 0;
}

static struct xt_match ndpi_mt_reg __read_mostly = {
    .name       = "ndpi",
    .revision   = 0,
    .family     = NFPROTO_IPV4,
    .match      = ndpi_mt,
    .checkentry = ndpi_mt_check,
    .matchsize  = sizeof(struct xt_ndpi_mtinfo),
    .me         = THIS_MODULE,
};

static int __init ndpi_mt_init(void) {
    ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs);
    if (!ndpi_struct) return -ENOMEM;

    size_id_struct = sizeof(struct ndpi_id_struct);
    size_flow_struct = sizeof(struct ndpi_flow_struct);

    osdpi_flow_cache = kmem_cache_create("xt_ndpi_flows", sizeof(struct osdpi_flow_node) + size_flow_struct, 0, 0, NULL);
    osdpi_id_cache = kmem_cache_create("xt_ndpi_ids", sizeof(struct osdpi_id_node) + size_id_struct, 0, 0, NULL);

    return xt_register_match(&ndpi_mt_reg);
}

static void __exit ndpi_mt_exit(void) {
    xt_unregister_match(&ndpi_mt_reg);
    ndpi_exit_detection_module(ndpi_struct);
    kmem_cache_destroy(osdpi_flow_cache);
    kmem_cache_destroy(osdpi_id_cache);
}

module_init(ndpi_mt_init);
module_exit(ndpi_mt_exit);
MODULE_LICENSE("GPL");