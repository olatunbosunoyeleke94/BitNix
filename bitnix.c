// ~/bitnix/kernel/bitnix.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BitNix");
MODULE_DESCRIPTION("BitNix: Bitcoin P2P (port 8333) detector via netfilter");
MODULE_VERSION("0.3");

#define PROC_NAME "bitnix"
#define BTC_PORT 8333
#define MAX_PEERS 64
#define OUTPUT_SZ 2048

static atomic64_t pkt_count_in = ATOMIC64_INIT(0);
static atomic64_t pkt_count_out = ATOMIC64_INIT(0);

static __be32 peers[MAX_PEERS];
static int peer_count = 0;
static spinlock_t peers_lock;

/* /proc buffer */
static char output[OUTPUT_SZ];

/* helper: add peer IP if not present, limited capacity */
static void add_peer(__be32 ip)
{
    int i;
    static int idx = 0;

    spin_lock(&peers_lock);
    for (i = 0; i < peer_count; ++i) {
        if (peers[i] == ip) {
            spin_unlock(&peers_lock);
            return;
        }
    }
    if (peer_count < MAX_PEERS) {
        peers[peer_count++] = ip;
    } else {
        /* rotate: overwrite oldest (simple ring) */
        peers[idx] = ip;
        idx = (idx + 1) % MAX_PEERS;
    }
    spin_unlock(&peers_lock);
}

/* netfilter hook for incoming packets (pre-routing) */
static unsigned int hook_fn_in(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr _tcph, *tcph;
    __be32 src, dst;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
    if (!tcph) return NF_ACCEPT;

    src = iph->saddr;
    dst = iph->daddr;

    if (ntohs(tcph->dest) == BTC_PORT) {
        atomic64_inc(&pkt_count_in);
        add_peer(src); /* remote peer */

        /* Log concise detection for easier debugging */
        pr_info("BITNIX: IN packet detected src=%pI4:%u -> dst=%pI4:%u\n",
                &src, ntohs(tcph->source), &dst, ntohs(tcph->dest));
    }

    return NF_ACCEPT;
}

/* netfilter hook for outgoing packets (local out) */
static unsigned int hook_fn_out(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr _tcph, *tcph;
    __be32 src, dst;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
    if (!tcph) return NF_ACCEPT;

    src = iph->saddr;
    dst = iph->daddr;

    if (ntohs(tcph->source) == BTC_PORT || ntohs(tcph->dest) == BTC_PORT) {
        atomic64_inc(&pkt_count_out);
        add_peer(dst); /* remote peer */

        /* Log concise detection for easier debugging */
        pr_info("BITNIX: OUT packet detected src=%pI4:%u -> dst=%pI4:%u\n",
                &src, ntohs(tcph->source), &dst, ntohs(tcph->dest));
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_in = {
    .hook = hook_fn_in,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_out = {
    .hook = hook_fn_out,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

/* /proc read implementation */
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
    int i, len = 0;
    char ipbuf[64];

    len += scnprintf(output + len, OUTPUT_SZ - len,
                     "BitNix Kernel Module Active\n"
                     "Bitcoin P2P monitor (port %d)\n\n", BTC_PORT);

    len += scnprintf(output + len, OUTPUT_SZ - len,
                     "packets_in: %lld\npackets_out: %lld\n\n",
                     (long long)atomic64_read(&pkt_count_in),
                     (long long)atomic64_read(&pkt_count_out));

    spin_lock(&peers_lock);
    len += scnprintf(output + len, OUTPUT_SZ - len,
                     "unique_peers_tracked: %d (max %d)\n", peer_count, MAX_PEERS);
    for (i = 0; i < peer_count && len < OUTPUT_SZ - 128; ++i) {
        snprintf(ipbuf, sizeof(ipbuf), "%pI4", &peers[i]); /* pretty print */
        len += scnprintf(output + len, OUTPUT_SZ - len, "peer[%d]: %s\n", i, ipbuf);
    }
    spin_unlock(&peers_lock);

    /* safety: ensure we never exceed length */
    if (len < 0) len = 0;
    if (len > OUTPUT_SZ) len = OUTPUT_SZ;

    return simple_read_from_buffer(buffer, count, pos, output, len);
}

static const struct proc_ops proc_file_ops = {
    .proc_read = proc_read,
};

static int __init bitnix_init(void)
{
    int ret;

    spin_lock_init(&peers_lock);

    /* create proc entry */
    if (!proc_create(PROC_NAME, 0444, NULL, &proc_file_ops)) {
        pr_err("bitnix: failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    /* register hooks */
    ret = nf_register_net_hook(&init_net, &nfho_in);
    if (ret) {
        pr_err("bitnix: nf_register_net_hook (in) failed: %d\n", ret);
        remove_proc_entry(PROC_NAME, NULL);
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &nfho_out);
    if (ret) {
        pr_err("bitnix: nf_register_net_hook (out) failed: %d\n", ret);
        nf_unregister_net_hook(&init_net, &nfho_in);
        remove_proc_entry(PROC_NAME, NULL);
        return ret;
    }

    pr_info("BitNix Loaded: Monitoring Bitcoin Traffic on port %d\n", BTC_PORT);
    return 0;
}

static void __exit bitnix_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_in);
    nf_unregister_net_hook(&init_net, &nfho_out);
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("BitNix Unloaded\n");
}

module_init(bitnix_init);
module_exit(bitnix_exit);
