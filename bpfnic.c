// SPDX-License-Identifier: GPL-2.0-only
/*
 *  drivers/net/bpfnic.c
 *
 *  Copyright (C) 2020 Red Hat Inc
 *  Copyright (C) 2020 Cambridge Greys Ltd
 *
 * Author: Anton Ivanov
 * Ethtool interface from: Eric W. Biederman <ebiederm@xmission.com>
 *
 */

#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/module.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf_trace.h>
#include <linux/net_tstamp.h>

#define DRV_NAME	"bpfnic"
#define DRV_VERSION	"0.1"

enum {
	BPFNIC_INFO_UNSPEC,
	BPFNIC_INFO_PEER,

	__BPFNIC_INFO_MAX
#define BPFNIC_INFO_MAX	(__BPFNIC_INFO_MAX - 1)
};


struct bpfnic_stats {
	u64	rx_drops;
};

struct bpfnic_priv {
	struct net_device __rcu	*peer;
	char 			*peername;	
	atomic64_t		dropped;
	struct bpfnic_rq		*rq;
	unsigned int		requested_headroom;
};

struct bpfnic_rq {
	struct net_device	*dev;
};


/*
 * ethtool interface
 */

struct bpfnic_q_stat_desc {
	char	desc[ETH_GSTRING_LEN];
	size_t	offset;
};

static char *target_iface = "";

#define BPFNIC_RQ_STAT(m)	offsetof(struct bpfnic_stats, m)

static const struct bpfnic_q_stat_desc bpfnic_rq_stats_desc[] = {
	{ "drops",		BPFNIC_RQ_STAT(rx_drops) },
};


#define BPFNIC_Q_STATS_LEN	ARRAY_SIZE(bpfnic_rq_stats_desc)

static void bpfnic_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static const struct ethtool_ops bpfnic_ethtool_ops = {
	.get_drvinfo		= bpfnic_get_drvinfo,
	.get_link		= ethtool_op_get_link,
};

/* general routines */
static netdev_tx_t bpfnic_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *rcv;
	int length = skb->len;

	rcu_read_lock();
	rcv = rcu_dereference(priv->peer);
	if (unlikely(!rcv)) {
		kfree_skb(skb);
		atomic64_inc(&priv->dropped);
	} else {
		skb_tx_timestamp(skb);
		if (likely(dev_forward_skb(rcv, skb) == NET_RX_SUCCESS)) {
			dev_lstats_add(dev, length);
		} else {
			atomic64_inc(&priv->dropped);
		}
	}

	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static u64 bpfnic_stats_tx(struct net_device *dev, u64 *packets, u64 *bytes)
{
	struct bpfnic_priv *priv = netdev_priv(dev);

	dev_lstats_read(dev, packets, bytes);
	return atomic64_read(&priv->dropped);
}

static void bpfnic_stats_rx(struct bpfnic_stats *result, struct net_device *dev)
{
	result->rx_drops = 0;
}

static void bpfnic_get_stats64(struct net_device *dev,
			     struct rtnl_link_stats64 *tot)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	struct bpfnic_stats rx;
	u64 packets, bytes;

	tot->tx_dropped = bpfnic_stats_tx(dev, &packets, &bytes);
	tot->tx_bytes = bytes;
	tot->tx_packets = packets;

	bpfnic_stats_rx(&rx, dev);

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (peer) {
		bpfnic_stats_tx(peer, &packets, &bytes);
		tot->rx_bytes += bytes;
		tot->rx_packets += packets;

		bpfnic_stats_rx(&rx, peer);
	}
	rcu_read_unlock();
}

/* fake multicast ability */
static void bpfnic_set_multicast_list(struct net_device *dev)
{
}

static struct net_device *bpfnic_peer_dev(struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);

	/* Callers must be under RCU read side. */
	return rcu_dereference(priv->peer);
}

static inline struct bpfnic_priv *bpfnic_peer_get_rcu(const struct net_device *dev)
{
	return rcu_dereference(dev->rx_handler_data);
}

/*
 * For now - tell the handler to rerun the stack as if the frame is
 * coming on the paired interface.
 */
static rx_handler_result_t bpfnic_handle_frame(struct sk_buff **pskb)
{
	struct bpfnic_priv *priv;
	struct sk_buff *skb = *pskb;

	priv = bpfnic_peer_get_rcu(skb->dev);

	/* bpf program invocation goes in here */

	if (priv) {
		skb->dev = priv->peer;
		skb_forward_csum(skb);
	} else {
		kfree_skb(skb);
		return RX_HANDLER_CONSUMED;
	}

	return RX_HANDLER_ANOTHER;
}

static int bpfnic_open(struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	if (!peer)
		return -ENOTCONN;

	if (peer->flags & IFF_UP) {
		netif_carrier_on(dev);
		netif_carrier_on(peer);
	}

	if (dev->netdev_ops->ndo_start_xmit == bpfnic_xmit) {
		netdev_err(dev, "Can not attach a bpfnic to another bpfnic");
		return -ELOOP;
	}

	if (netdev_rx_handler_register(priv->peer, bpfnic_handle_frame, priv))
		return -ENOTCONN;
	
	dev->features = peer->features;

	return 0;
}

static int bpfnic_close(struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	netif_carrier_off(dev);
	if (peer)
		netif_carrier_off(peer);

	return 0;
}

static int is_valid_bpfnic_mtu(int mtu)
{
	return mtu >= ETH_MIN_MTU && mtu <= ETH_MAX_MTU;
}

static int bpfnic_dev_init(struct net_device *dev)
{
	int err = 0;
	struct bpfnic_priv *priv = netdev_priv(dev);

	kernel_param_lock(THIS_MODULE);

	priv->peername = kstrdup(target_iface, GFP_KERNEL);

	if (!priv->peername)
		err = -ENOMEM;

	kernel_param_unlock(THIS_MODULE);

	rcu_read_lock();
	priv->peer = dev_get_by_name_rcu(&init_net, priv->peername);
	rcu_read_unlock();

	if (!priv->peer)
		err = -EINVAL;

	if (err != 0) {
		dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
		if (!dev->lstats)
			err = -ENOMEM;
	}
	return 0;
}

static void bpfnic_dev_free(struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	if (priv->peer)
		netdev_rx_handler_unregister(priv->peer);
	if (priv->peername)
		kfree(priv->peername);
	free_percpu(dev->lstats);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void bpfnic_poll_controller(struct net_device *dev)
{
	/* bpfnic only receives frames when its peer sends one
	 * Since it has nothing to do with disabling irqs, we are guaranteed
	 * never to have pending data when we poll for it so
	 * there is nothing to do here.
	 *
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
}
#endif	/* CONFIG_NET_POLL_CONTROLLER */

static int bpfnic_get_iflink(const struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int iflink;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	iflink = peer ? peer->ifindex : 0;
	rcu_read_unlock();

	return iflink;
}

static void bpfnic_set_rx_headroom(struct net_device *dev, int new_hr)
{
	struct bpfnic_priv *peer_priv, *priv = netdev_priv(dev);
	struct net_device *peer;

	if (new_hr < 0)
		new_hr = 0;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (unlikely(!peer))
		goto out;

	peer_priv = netdev_priv(peer);
	priv->requested_headroom = new_hr;
	new_hr = max(priv->requested_headroom, peer_priv->requested_headroom);
	dev->needed_headroom = new_hr;
	peer->needed_headroom = new_hr;

out:
	rcu_read_unlock();
}

static int bpfnic_set_features(struct net_device *dev,
	netdev_features_t features)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int ret = 0;

	peer = rcu_dereference(priv->peer);
	if (peer) {
		ret = peer->netdev_ops->ndo_set_features(dev, features);
		dev->features = peer->features;
	}
	return ret;
}
static netdev_features_t bpfnic_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	netdev_features_t ret = 0;

	peer = rcu_dereference(priv->peer);
	if (peer) {
		ret = peer->netdev_ops->ndo_set_features(dev, features);
	}
	return ret;
}


static const struct net_device_ops bpfnic_netdev_ops = {
	.ndo_init            = bpfnic_dev_init,
	.ndo_open            = bpfnic_open,
	.ndo_stop            = bpfnic_close,
	.ndo_start_xmit      = bpfnic_xmit,
	.ndo_get_stats64     = bpfnic_get_stats64,
	.ndo_set_rx_mode     = bpfnic_set_multicast_list,
	.ndo_set_mac_address = eth_mac_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= bpfnic_poll_controller,
#endif
	.ndo_get_iflink		= bpfnic_get_iflink,
	.ndo_fix_features	= bpfnic_fix_features,
	.ndo_set_features	= bpfnic_set_features,
	.ndo_features_check	= passthru_features_check,
	.ndo_set_rx_headroom	= bpfnic_set_rx_headroom,
	.ndo_get_peer_dev	= bpfnic_peer_dev,
};

#define BPFNIC_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM | \
		       NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_HIGHDMA | \
		       NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL | \
		       NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX | \
		       NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_STAG_RX )

static void bpfnic_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->priv_flags |= IFF_PHONY_HEADROOM;

	dev->netdev_ops = &bpfnic_netdev_ops;
	dev->ethtool_ops = &bpfnic_ethtool_ops;
	dev->features |= NETIF_F_LLTX;
	dev->features |= BPFNIC_FEATURES;
	dev->vlan_features = dev->features &
			     ~(NETIF_F_HW_VLAN_CTAG_TX |
			       NETIF_F_HW_VLAN_STAG_TX |
			       NETIF_F_HW_VLAN_CTAG_RX |
			       NETIF_F_HW_VLAN_STAG_RX);
	dev->needs_free_netdev = true;
	dev->priv_destructor = bpfnic_dev_free;
	dev->max_mtu = ETH_MAX_MTU;

	dev->hw_features = BPFNIC_FEATURES;
	dev->hw_enc_features = BPFNIC_FEATURES;
	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
}

/*
 * netlink interface
 */

static int bpfnic_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_bpfnic_mtu(nla_get_u32(tb[IFLA_MTU])))
			return -EINVAL;
	}
	return 0;
}

static struct rtnl_link_ops bpfnic_link_ops;

static int bpfnic_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	int err;
	struct net_device *peer;
	struct bpfnic_priv *priv;
	char ifname[IFNAMSIZ];
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp;
	unsigned char name_assign_type;
	struct ifinfomsg *ifmp;
	struct net *net;

	/*
	 * create and register peer first
	 */
	if (data != NULL && data[BPFNIC_INFO_PEER] != NULL) {
		struct nlattr *nla_peer;

		nla_peer = data[BPFNIC_INFO_PEER];
		ifmp = nla_data(nla_peer);
		err = rtnl_nla_parse_ifla(peer_tb,
					  nla_data(nla_peer) + sizeof(struct ifinfomsg),
					  nla_len(nla_peer) - sizeof(struct ifinfomsg),
					  NULL);
		if (err < 0)
			return err;

		err = bpfnic_validate(peer_tb, NULL, extack);
		if (err < 0)
			return err;

		tbp = peer_tb;
	} else {
		ifmp = NULL;
		tbp = tb;
	}

	if (ifmp && tbp[IFLA_IFNAME]) {
		nla_strscpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	} else {
		snprintf(ifname, IFNAMSIZ, DRV_NAME "%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	peer = rtnl_create_link(net, ifname, name_assign_type,
				&bpfnic_link_ops, tbp, extack);
	if (IS_ERR(peer)) {
		put_net(net);
		return PTR_ERR(peer);
	}

	if (!ifmp || !tbp[IFLA_ADDRESS])
		eth_hw_addr_random(peer);

	if (ifmp && (dev->ifindex != 0))
		peer->ifindex = ifmp->ifi_index;

	peer->gso_max_size = dev->gso_max_size;
	peer->gso_max_segs = dev->gso_max_segs;

	err = register_netdevice(peer);
	put_net(net);
	net = NULL;
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	err = rtnl_configure_link(peer, ifmp);
	if (err < 0)
		goto err_configure_peer;

	/*
	 * register dev last
	 *
	 * note, that since we've registered new device the dev's name
	 * should be re-allocated
	 */

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);

	/*
	 * tie the deviced together
	 */

	priv = netdev_priv(dev);
	rcu_assign_pointer(priv->peer, peer);

	priv = netdev_priv(peer);
	rcu_assign_pointer(priv->peer, dev);

	return 0;

err_register_dev:
	/* nothing to do */
err_configure_peer:
	unregister_netdevice(peer);
	return err;

err_register_peer:
	free_netdev(peer);
	return err;
}

static void bpfnic_dellink(struct net_device *dev, struct list_head *head)
{
	struct bpfnic_priv *priv;
	struct net_device *peer;

	priv = netdev_priv(dev);
	peer = rtnl_dereference(priv->peer);

	/* Note : dellink() is called from default_device_exit_batch(),
	 * before a rcu_synchronize() point. The devices are guaranteed
	 * not being freed before one RCU grace period.
	 */
	RCU_INIT_POINTER(priv->peer, NULL);
	unregister_netdevice_queue(dev, head);

	if (peer) {
		priv = netdev_priv(peer);
		RCU_INIT_POINTER(priv->peer, NULL);
		unregister_netdevice_queue(peer, head);
	}
}

static const struct nla_policy bpfnic_policy[BPFNIC_INFO_MAX + 1] = {
	[BPFNIC_INFO_PEER]	= { .len = sizeof(struct ifinfomsg) },
};

static struct net *bpfnic_get_link_net(const struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	return peer ? dev_net(peer) : dev_net(dev);
}

static struct rtnl_link_ops bpfnic_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct bpfnic_priv),
	.setup		= bpfnic_setup,
	.validate	= bpfnic_validate,
	.newlink	= bpfnic_newlink,
	.dellink	= bpfnic_dellink,
	.policy		= bpfnic_policy,
	.maxtype	= BPFNIC_INFO_MAX,
	.get_link_net	= bpfnic_get_link_net,
};

/*
 * init/fini
 */

static __init int bpfnic_init(void)
{
	return rtnl_link_register(&bpfnic_link_ops);
}

static __exit void bpfnic_exit(void)
{
	rtnl_link_unregister(&bpfnic_link_ops);
}

module_init(bpfnic_init);
module_exit(bpfnic_exit);

module_param(target_iface, charp, 0);
MODULE_PARM_DESC(target_iface, "Target interface");

MODULE_DESCRIPTION("Ethernet Leach");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
