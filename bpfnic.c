// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/net/bpfnic.c
 *
 *  Copyright (C) 2020 Red Hat Inc
 *  Copyright (C) 2020 Cambridge Greys Ltd
 *
 * Author: Anton Ivanov
 *
 */

#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/platform_device.h>
#include <net/dst.h>
#include <net/switchdev.h>
#include <net/xfrm.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/ctype.h>
#include <linux/net_tstamp.h>
#include "bpfnic_shared.h"

#define DRV_NAME	"bpfnic"
#define DRV_VERSION	"0.1"

#define MAX_QUEUES 128

enum {
	BPFNIC_INFO_UNSPEC,
	BPFNIC_INFO_PEER,

	__BPFNIC_INFO_MAX
#define BPFNIC_INFO_MAX	(__BPFNIC_INFO_MAX - 1)
};


struct bpfnic_stats {
	u64	rx_drops;
};

#define INGRESS_HOOK	0
#define EGRESS_HOOK	1
#define FDB_ADD_HOOK	2
#define FDB_DEL_HOOK	3
#define HOOKS_COUNT	4

struct bpfnic_info {
	char *peername;
	char **bpf_names;
	int unit;
};


struct bpfnic_priv {
	struct net_device __rcu	*peer;
	struct net_device	*dev;
	atomic64_t		rx_packets;
	atomic64_t		rx_bytes;
	atomic64_t		dropped;
	/* bpf hooks */
	struct			bpf_prog **bpf;
	struct bpfnic_info	*info;
	spinlock_t		lock;
	bool			opened;
	bool			running;
	bool			registered;
	struct list_head list;

};

static LIST_HEAD(bpfnic_devices);

static DEFINE_SPINLOCK(bpfnic_devices_lock);

static struct workqueue_struct *bpfnic_workq;

static char* prog_names[] = {
	"ingress",
	"egress",
	"fdb_add",
	"fdb_del",
	NULL
};

/* agrs and other information shared between all ports */

static struct bpfnic_info *default_bpfnic_info = NULL;
static bool init_done = false;

static struct bpfnic_priv *find_bpfnic_by_dev(struct net_device *dev)
{
	struct bpfnic_priv *device;
	struct list_head *ele;

	spin_lock(&bpfnic_devices_lock);
	list_for_each(ele, &bpfnic_devices) {
		device = list_entry(ele, struct bpfnic_priv, list);
		if (device->dev == dev)
			goto out;
	}
	device = NULL;
 out:
	spin_unlock(&bpfnic_devices_lock);
	return device;
}

static struct bpfnic_priv *find_bpfnic_by_name(char *name)
{
	struct bpfnic_priv *device;
	struct list_head *ele;

	spin_lock(&bpfnic_devices_lock);
	list_for_each(ele, &bpfnic_devices) {
		device = list_entry(ele, struct bpfnic_priv, list);
		if ((device->dev->name) &&
			(strcmp(device->dev->name, name) == 0))
			goto out;
	}
	device = NULL;
 out:
	spin_unlock(&bpfnic_devices_lock);
	return device;
}
#define to_bpfnic(cd)	((struct bpfnic_priv *)netdev_priv(to_net_dev(cd)))
#define to_maindev(cd)	(to_platform_device(cd))

static int reload_bpf(struct net_device *dev, int index)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct bpf_prog *prog;
	int ret = 0;

	priv->running = false;

	wmb();

	prog = bpf_prog_get_type_path(
			priv->info->bpf_names[index], BPF_PROG_TYPE_SOCKET_FILTER);
	if (IS_ERR(prog)){
		ret = -EINVAL;
		netdev_err(dev, "Cannot configure %s hook", prog_names[index]);
	} 

	if (!ret) {
		if (priv->bpf[index])
			bpf_prog_sub(priv->bpf[index], 1);
		priv->bpf[index] = prog;
	}

	priv->running = true;

	wmb();

	return ret;
}

static char *strip_and_dup(const char *buf, size_t len)
{
	char *result, *term_nl;
        ssize_t pos = 0;

	result = kstrdup(buf, GFP_ATOMIC);
	if (result) {
		term_nl = result;
		while ((*term_nl != 0) && (pos < len)) {
			if (isspace(*term_nl) || (*term_nl == '\n')) {
				*term_nl = '\0';
				break;
			}
			pos++;
			term_nl++;
		}
	}
	return result;
}

static int set_bpf_name(struct bpfnic_priv *priv, const char *buf, size_t len, int index)
{
	char *old;

	old = priv->info->bpf_names[index];
	priv->info->bpf_names[index] = strip_and_dup(buf, len);

	if (priv->opened) {
		if (reload_bpf(priv->dev, index)) {
			kfree(priv->info->bpf_names[index]);
			priv->info->bpf_names[index] = old;
			return -EINVAL;
		}
	}
	return len;
}


/* per port sysfs interface */

static ssize_t ingress_hook_show(struct device *d,
				 struct device_attribute *attr,
				 char *buf)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return sprintf(buf, "%s\n", priv->info->bpf_names[INGRESS_HOOK]);
}

static ssize_t ingress_hook_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return set_bpf_name(priv, buf, len, INGRESS_HOOK);
}

static DEVICE_ATTR_RW(ingress_hook);

static ssize_t egress_hook_show(struct device *d,
				 struct device_attribute *attr,
				 char *buf)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return sprintf(buf, "%s\n", priv->info->bpf_names[EGRESS_HOOK]);
}

static ssize_t egress_hook_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return set_bpf_name(priv, buf, len, EGRESS_HOOK);
}

static DEVICE_ATTR_RW(egress_hook);

static ssize_t fdb_add_hook_show(struct device *d,
				 struct device_attribute *attr,
				 char *buf)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return sprintf(buf, "%s\n", priv->info->bpf_names[FDB_ADD_HOOK]);
}

static ssize_t fdb_add_hook_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return set_bpf_name(priv, buf, len, FDB_ADD_HOOK);
}

static DEVICE_ATTR_RW(fdb_add_hook);

static ssize_t fdb_del_hook_show(struct device *d,
				 struct device_attribute *attr,
				 char *buf)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return sprintf(buf, "%s\n", priv->info->bpf_names[FDB_ADD_HOOK]);
}

static ssize_t fdb_del_hook_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return set_bpf_name(priv, buf, len, FDB_ADD_HOOK);
}

static DEVICE_ATTR_RW(fdb_del_hook);

static ssize_t peer_show(struct device *d,
				 struct device_attribute *attr,
				 char *buf)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	return sprintf(buf, "%s\n", priv->info->peername);
}

static ssize_t peer_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	struct bpfnic_priv *priv = to_bpfnic(d);
	int err = len;
	char *old; 
	
	spin_lock(&priv->lock);
	if (priv->opened) {
		err = -EBUSY;
		goto done;
	}
	
	old = priv->info->peername;
	priv->info->peername = strip_and_dup(buf, len);
	if ((!priv->info->peername) || (strlen(priv->info->peername) == 0)) {
		err = -EINVAL;
		kfree(priv->info->peername);
		priv->info->peername = old;
	}	

	spin_unlock(&priv->lock);
done:
	return err;
}

static DEVICE_ATTR_RW(peer);

static struct attribute *bpfnic_attrs[] = {
	&dev_attr_ingress_hook.attr,
	&dev_attr_egress_hook.attr,
	&dev_attr_fdb_add_hook.attr,
	&dev_attr_fdb_del_hook.attr,
	&dev_attr_peer.attr,
	NULL
};

#define SYSFS_BPFNIC_ATTR	"bpfhooks"

static const struct attribute_group bpfnic_group = {
	.name = SYSFS_BPFNIC_ATTR,
	.attrs = bpfnic_attrs,
};

static struct bpfnic_info *init_bpfnic_info(void)
{
	struct bpfnic_info *result;

	result = kzalloc(sizeof(struct bpfnic_info), GFP_KERNEL);

	if (!result) 
		return NULL;

	result->bpf_names = kzalloc(sizeof(char *) * HOOKS_COUNT, GFP_KERNEL);
	if (!result->bpf_names) {
		kfree(result);
		return NULL;
	}
	return result;
}

static void destroy_bpfnic_info(struct bpfnic_info *arg)
{
	int i;
	if (arg) {
		if (arg->bpf_names) {
			for (i = 0; i < HOOKS_COUNT; i++) {
				kfree(arg->bpf_names[i]);
			}
			kfree(arg->bpf_names);
		}
		kfree(arg);
	}
}

/*
 * Switchdev interface
 */


struct bpfnic_switchdev_event_work {
	struct work_struct work;
	struct switchdev_notifier_fdb_info fdb_info;
	struct bpfnic_priv *priv;
	unsigned long event;
};


static void
bpfnic_fdb_offload_notify(struct bpfnic_priv *priv,
			  struct switchdev_notifier_fdb_info *recv_info)
{
	struct switchdev_notifier_fdb_info info;

	info.addr = recv_info->addr;
	info.vid = recv_info->vid;
	info.offloaded = true;
	call_switchdev_notifiers(SWITCHDEV_FDB_OFFLOADED,
				 priv->dev, &info.info, NULL);
}

static void build_switchdev_context(struct bpfnic_notify_context *context,
		               struct switchdev_notifier_fdb_info *fdb_info)
{
	context->ifindex = fdb_info->info.dev->ifindex;
	ether_addr_copy((u8 *) &context->addr, fdb_info->addr);
	context->vid = fdb_info->vid;
	context->added_by_user = fdb_info->added_by_user;
	context->offloaded = fdb_info->offloaded;
}

static void bpfnic_switchdev_handle_work(struct work_struct *work)
{
	struct bpfnic_switchdev_event_work *switchdev_work =
		container_of(work, struct bpfnic_switchdev_event_work, work);
	struct bpfnic_priv *priv = switchdev_work->priv;
	struct switchdev_notifier_fdb_info *fdb_info;
	struct bpfnic_notify_context context;

	rtnl_lock();

	switch (switchdev_work->event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		fdb_info = &switchdev_work->fdb_info;
		build_switchdev_context(&context, fdb_info);
		netdev_dbg(priv->dev, "fdb add %0x:%0x:%0x:%0x:%0x:%0x",
				context.addr[0],
				context.addr[1],
				context.addr[2],
				context.addr[3],
				context.addr[4],
				context.addr[5]);  
		if (priv->bpf[FDB_ADD_HOOK]) {
			if (!BPF_PROG_RUN(priv->bpf[EGRESS_HOOK], &context)) {
				netdev_err(priv->dev, "fdb add failed");
			} else {
				bpfnic_fdb_offload_notify(priv, fdb_info);
			}

		}
		break;
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		fdb_info = &switchdev_work->fdb_info;
		build_switchdev_context(&context, fdb_info);
		netdev_dbg(priv->dev, "fdb del %0x:%0x:%0x:%0x:%0x:%0x",
				context.addr[0],
				context.addr[1],
				context.addr[2],
				context.addr[3],
				context.addr[4],
				context.addr[5]);  
		if (priv->bpf[FDB_DEL_HOOK]) {
			if(!BPF_PROG_RUN(priv->bpf[EGRESS_HOOK], &context))
				netdev_info(priv->dev, "fdb del failed");
		}
		break;
	};
	rtnl_unlock();
	kfree(switchdev_work->fdb_info.addr);
	kfree(switchdev_work);
	dev_put(priv->dev);
}

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
	struct net_device *peer;
	int bpf_ret = 1;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (unlikely((!peer) || (!priv->running))) {
		kfree_skb(skb);
		atomic64_inc(&priv->dropped);
	} else {
		skb_tx_timestamp(skb);
		netif_trans_update(dev);
		netif_wake_queue(dev);
		skb->dev = peer;
		if (priv->bpf[EGRESS_HOOK]) {
			bpf_ret = BPF_PROG_RUN(priv->bpf[EGRESS_HOOK], skb);
		}

		if ((bpf_ret > 0) && is_skb_forwardable(skb->dev, skb)) {
			dev_lstats_add(dev, skb->len);
			dev_queue_xmit(skb);
		} else {
			atomic64_inc(&priv->dropped);
			kfree_skb(skb);
		}
	}
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static void bpfnic_get_stats64(struct net_device *dev,
			     struct rtnl_link_stats64 *tot)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	u64 packets = 0, bytes = 0;

	if (!tot)
		return;
	dev_lstats_read(dev, &packets, &bytes);
	tot->tx_bytes += bytes;
	tot->tx_packets += packets;
	tot->rx_bytes += atomic64_read(&priv->rx_bytes);
	tot->rx_packets += atomic64_read(&priv->rx_packets);
	tot->tx_dropped += atomic64_read(&priv->dropped);
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
	int bpf_ret = 1;

	priv = bpfnic_peer_get_rcu(skb->dev);

	if (!priv->running) {
		kfree_skb(skb);
		return RX_HANDLER_CONSUMED;
	}

	/* bpf program invocation goes in here */

	if ((priv) && (priv->bpf[INGRESS_HOOK])) 
		bpf_ret = BPF_PROG_RUN(priv->bpf[INGRESS_HOOK], skb);

	if (priv && (bpf_ret > 0)) {
		atomic64_inc(&priv->rx_packets);
		atomic64_add(skb->len, &priv->rx_bytes);
		skb->dev = priv->dev;
		skb_forward_csum(skb);
		if (is_multicast_ether_addr(eth_hdr(skb)->h_dest) ||
				ether_addr_equal(eth_hdr(skb)->h_dest, priv->dev->dev_addr)) {
			netif_receive_skb(skb);
			return RX_HANDLER_CONSUMED;
		} 
	} else {
		kfree_skb(skb);
		return RX_HANDLER_CONSUMED;
		
	}
	return RX_HANDLER_ANOTHER;
}

static int bpfnic_open(struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	int ret = 0, i;

	spin_lock(&priv->lock);
	if (priv->opened) {
		netdev_err(dev, "Already opened");
		ret = -ENXIO;
		goto done_open;
	}

	if (!priv->info->peername) {
		netdev_err(dev, "No peer available");
		ret = -ENXIO;
		goto done_open;
	}

	
	rcu_read_lock();
	priv->peer = dev_get_by_name_rcu(&init_net, priv->info->peername);
	rcu_read_unlock();

	if (!priv->peer) {
		netdev_err(dev, "Cannot deref peer");
		ret = -ENOTCONN;
		goto done_open;
	}

	eth_hw_addr_inherit(dev, priv->peer);

	for (i = 0; i < HOOKS_COUNT; i++) { 
		if (priv->info->bpf_names[i]) {
			reload_bpf(dev, i);
		}
	}

	atomic64_set(&priv->dropped, 0);
	atomic64_set(&priv->rx_packets, 0);
	atomic64_set(&priv->rx_bytes, 0);


	netif_set_real_num_tx_queues(dev,
			priv->peer->real_num_tx_queues);
	netif_set_real_num_rx_queues(dev,
			priv->peer->real_num_rx_queues);
	
	if (priv->peer->netdev_ops->ndo_start_xmit == bpfnic_xmit) {
		ret = -ELOOP;
		goto done_open;
	}

	if (netdev_rx_handler_register(priv->peer, bpfnic_handle_frame, priv)) {
		ret = -ENOTCONN;
	}
	dev->features = priv->peer->features;
	dev->hw_features = priv->peer->hw_features;
	dev->hw_enc_features = priv->peer->hw_enc_features;
	dev->mpls_features = priv->peer->mpls_features;
	dev->wanted_features = priv->peer->wanted_features;

	if (!ret) {
		priv->opened = true;
		priv->running = true;
	}

	spin_unlock(&priv->lock);

done_open:
	return ret;
}

static int bpfnic_close(struct net_device *dev)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	int i;

	spin_lock(&priv->lock);
	if (priv->opened)
		goto done_close;

	netif_tx_stop_all_queues(dev);
	netif_carrier_off(dev);
	if (priv->peer && priv->opened) {
		netdev_rx_handler_unregister(priv->peer);
		for (i = 0; i < HOOKS_COUNT; i++) {
			if (priv->bpf[i]) {
				bpf_prog_sub(priv->bpf[i], 1);
			}
		}
		kfree(priv->bpf);
	}

	/* note - we do not deallocate bpf programs here as they may be
	 * in use by more than one port
	 */


	priv->opened = false;

done_close:

	spin_unlock(&priv->lock);

	return 0;
}

static int bpfnic_dev_init(struct net_device *dev)
{
	int err = 0;
	struct bpfnic_priv *priv = netdev_priv(dev);

	snprintf(dev->name, sizeof(dev->name), "bpfnic%d", default_bpfnic_info->unit++);

	priv->peer = NULL;
	spin_lock_init(&priv->lock);

	eth_hw_addr_random(dev);

	priv->opened = false;

	if (err == 0) {
		dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
		if (!dev->lstats)
			err = -ENOMEM;
	}

	return 0;
}

static void bpfnic_dev_uninit(struct net_device *dev)
{
	struct kobject *kobj = &dev->dev.kobj;
	sysfs_remove_group(kobj, &bpfnic_group);
}

static void bpfnic_dev_free(struct net_device *dev)
{
	bpfnic_close(dev);
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
	 * supports polling
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
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;

	if (new_hr < 0)
		new_hr = 0;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (unlikely(!peer))
		goto out;
	if (peer->netdev_ops->ndo_set_rx_headroom) 
		peer->netdev_ops->ndo_set_rx_headroom(peer, new_hr);
out:
	rcu_read_unlock();
}

static int bpfnic_set_features(struct net_device *dev,
	netdev_features_t features)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;

	peer = rcu_dereference(priv->peer);
	if (peer) {
		peer->wanted_features = features;
		netdev_update_features(peer);
		dev->features = peer->features;
	}
	return 0;
}

static netdev_features_t bpfnic_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;

	peer = rcu_dereference(priv->peer);
	if (peer) {
		if (peer->netdev_ops->ndo_fix_features)
			features = peer->netdev_ops->ndo_fix_features(dev, features);
	}
	return features;
}

static int bpfnic_vlan_rx_add_vid(struct net_device *dev,
						       __be16 proto, u16 vid)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int ret = -EINVAL;

	peer = rcu_dereference(priv->peer);
	if (peer) {
		if (peer->netdev_ops->ndo_vlan_rx_add_vid)
			ret = peer->netdev_ops->ndo_vlan_rx_add_vid(peer, proto, vid);
	}
	return ret;
}

static int bpfnic_vlan_rx_kill_vid(struct net_device *dev,
						       __be16 proto, u16 vid)
{
	struct bpfnic_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int ret = -EINVAL;

	peer = rcu_dereference(priv->peer);
	if (peer) {
		if (peer->netdev_ops->ndo_vlan_rx_kill_vid)
			ret = peer->netdev_ops->ndo_vlan_rx_kill_vid(peer, proto, vid);
	}
	return ret;
}


static const struct net_device_ops bpfnic_netdev_ops = {
	.ndo_init            = bpfnic_dev_init,
	.ndo_uninit          = bpfnic_dev_uninit,
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
	.ndo_vlan_rx_add_vid	= bpfnic_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid 	= bpfnic_vlan_rx_kill_vid,
};

static void bpfnic_setup(struct net_device *dev)
{

	ether_setup(dev);
	
	dev->netdev_ops = &bpfnic_netdev_ops;
	dev->ethtool_ops = &bpfnic_ethtool_ops;

	dev->needs_free_netdev = true;
	dev->priv_destructor = bpfnic_dev_free;

	dev->max_mtu = ETH_MAX_MTU;
	dev->features = 0;
	dev->hw_features = 0;
	dev->hw_enc_features = 0;
	dev->mpls_features = 0;
}
static void remove_one_port(struct bpfnic_priv *priv)
{
	if (priv->opened)
		bpfnic_close(priv->dev);
	rtnl_lock();
	destroy_bpfnic_info(priv->info);
	if (priv->registered) {
		unregister_netdevice(priv->dev);
		free_netdev(priv->dev);
	}
	rtnl_unlock();
}

static void remove_all_ports(void)
{
	struct list_head *ele, *next;
	struct bpfnic_priv *priv;
	list_for_each_safe(ele, next, &bpfnic_devices) {
		priv = list_entry(ele, struct bpfnic_priv, list);
		list_del(ele);
		remove_one_port(priv);
	}
}

static int bpfnic_switchdev_event(struct notifier_block *unused,
				  unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct switchdev_notifier_fdb_info *fdb_info = ptr;
	struct bpfnic_switchdev_event_work *switchdev_work;
	struct bpfnic_priv *priv;

	priv = find_bpfnic_by_dev(dev);
	if (!priv)
		return NOTIFY_DONE;

	switchdev_work = kzalloc(sizeof(*switchdev_work), GFP_ATOMIC);
	if (WARN_ON(!switchdev_work))
		return NOTIFY_BAD;

	INIT_WORK(&switchdev_work->work, bpfnic_switchdev_handle_work);
	switchdev_work->priv = priv;
	switchdev_work->event = event;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		memcpy(&switchdev_work->fdb_info, ptr,
		       sizeof(switchdev_work->fdb_info));
		switchdev_work->fdb_info.addr = kzalloc(ETH_ALEN, GFP_ATOMIC);
		if (unlikely(!switchdev_work->fdb_info.addr)) {
			kfree(switchdev_work);
			return NOTIFY_BAD;
		}

		ether_addr_copy((u8 *)switchdev_work->fdb_info.addr,
				fdb_info->addr);
		/* Take a reference on the rocker device */
		dev_hold(dev);
		break;
	default:
		kfree(switchdev_work);
		return NOTIFY_DONE;
	}

	queue_work(bpfnic_workq, &switchdev_work->work);
	return NOTIFY_DONE;

	
}

static struct notifier_block bpfnic_switchdev_notifier = {
	.notifier_call = bpfnic_switchdev_event,
};


static int new_bpfnic(void)
{
	struct net_device *dev;
	struct bpfnic_priv *priv = NULL;
	int err = 0, i;
	struct kobject *bpfnic_obj;

	dev = alloc_etherdev_mq(sizeof(struct bpfnic_priv), MAX_QUEUES);
	if (!dev) {
		err = -ENOMEM;
		goto fail_port;
	}


	priv = netdev_priv(dev);
	priv->info = init_bpfnic_info();
	priv->opened = false;
	priv->registered = false;
	priv->running = false;
	priv->peer = NULL;

	if (!priv->info)
		goto fail_port;

	priv->info->peername = NULL;
	priv->bpf = kzalloc(sizeof(struct bpf_prog *) * HOOKS_COUNT, GFP_KERNEL);
	if (!priv->bpf) {
		netdev_err(dev, "Cannot allocate BPF firmware hooks");
		err = -ENOMEM;
		goto fail_port;
	}

	priv->dev = dev;

	for (i = 0; i < HOOKS_COUNT; i++) {
		priv->info->bpf_names[i] =
			kstrdup(default_bpfnic_info->bpf_names[i], GFP_KERNEL);
	}

	bpfnic_setup(dev);

	INIT_LIST_HEAD(&priv->list);
	spin_lock(&bpfnic_devices_lock);
	list_add_tail(&priv->list, &bpfnic_devices);
	spin_unlock(&bpfnic_devices_lock);

	rtnl_lock();
	err = register_netdevice(dev);
	rtnl_unlock();

	if (err)
		goto fail_port;
	priv->registered = true;

	bpfnic_obj = &dev->dev.kobj;

	err = sysfs_create_group(bpfnic_obj, &bpfnic_group);
	if (err) {
		pr_info("%s: can't create group %s/%s\n",
			__func__, dev->name, bpfnic_group.name);
		goto fail_port;
	}
	return 0;
fail_port:
	if (priv)
		remove_one_port(priv);
	return err;
}
/* global sysfs interface */
static ssize_t add_interface_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	int err;
	err = new_bpfnic();
	if (err)
		return err;
	return len;
}

static DEVICE_ATTR_WO(add_interface);

static ssize_t del_interface_store(struct device *d,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	char  *iface;
	int err = len;
	struct bpfnic_priv *priv = NULL;

	iface = strip_and_dup(buf, len);
	if ((!iface) || (strlen(iface) == 0)) {
		err = -EINVAL;
	} else {
		priv = find_bpfnic_by_name(iface);
		if (priv) {
			if (priv->opened)
				err = -EBUSY;
			else
				remove_one_port(priv);
		} else {
			err = -ENOENT;
		}
	}
	kfree(iface);
	return err;
}

static DEVICE_ATTR_WO(del_interface);

static struct attribute *bpfctrl_attrs[] = {
	&dev_attr_add_interface.attr,
	&dev_attr_del_interface.attr,
	NULL
};

#define SYSFS_BPFCONTROL_ATTR	"interfaces"

static const struct attribute_group bpfctrl_group = {
	.name = SYSFS_BPFCONTROL_ATTR,
	.attrs = bpfctrl_attrs,
};


static int bpfnic_probe(struct platform_device *pdev)
{
	struct kobject *bpfctrl_obj;
	int err = -ENOMEM;

	default_bpfnic_info = init_bpfnic_info();
	if (!default_bpfnic_info)
		goto err_free;

	bpfnic_workq = alloc_ordered_workqueue(DRV_NAME, WQ_MEM_RECLAIM);

	if (!bpfnic_workq) {
		err = -ENOMEM;
		goto err_free;
	}

	bpfctrl_obj = &pdev->dev.kobj;
	err = sysfs_create_group(bpfctrl_obj, &bpfctrl_group);
	if (err) {
		printk(KERN_ERR "bpfnic - can't create control group\n");
		goto err_free;
	}
	err = register_switchdev_notifier(&bpfnic_switchdev_notifier);
	if (err) {
		printk(KERN_ERR "bpfnic - failed to register switchdev notifier\n");
		goto err_free;
	}
	
	return 0;

err_free:
	remove_all_ports();
	return err;
}

static int
bpfnic_remove(struct platform_device *pdev)
{

	if (init_done) {
		remove_all_ports();

		if (default_bpfnic_info)
			destroy_bpfnic_info(default_bpfnic_info);

		default_bpfnic_info = NULL;
		init_done = false;

	} else
		printk(KERN_ERR "Calling remove twice");
	return 0;
}

/* Platform driver */

static const struct of_device_id bpfnic_match[] = {
	{ .compatible = "bpfnic", },
	{}
};

static struct platform_driver bpfnic_driver = {
	.probe = bpfnic_probe,
	.remove = bpfnic_remove,
	.driver = {
		.name = "bpfnic",
		.of_match_table = bpfnic_match,
		.owner	= THIS_MODULE,
	},
};

MODULE_DEVICE_TABLE(of, bpfnic_match);

static struct platform_device *bpfnic;

static __init int bpfnic_init(void)
{
	int ret;  

	ret = platform_driver_register(&bpfnic_driver);

	if (ret) {
		pr_err("bpfnic: Error registering platform driver!");
		return ret;
	}

	bpfnic = platform_device_alloc("bpfnic", -1);

	if (!bpfnic) {
		ret = -ENOMEM;
		goto fail_init;
	} else {
		ret = platform_device_add(bpfnic);
		if (ret) {
			platform_device_put(bpfnic);
			goto fail_init;
		}
	}
	init_done = true;
	return 0;
fail_init:
	platform_driver_unregister(&bpfnic_driver);
	return ret;
}

static __exit void bpfnic_exit(void)
{
	if (init_done) {
		platform_device_del(bpfnic);
		platform_driver_unregister(&bpfnic_driver);
		unregister_switchdev_notifier(&bpfnic_switchdev_notifier);
		init_done = false;
	}
}

module_init(bpfnic_init);
module_exit(bpfnic_exit);

MODULE_AUTHOR("Anton Ivanov <anton.ivanov@cambridgegreys.com>");
MODULE_DESCRIPTION("Ethernet NIC with BPF 'firmware'");
MODULE_LICENSE("GPL");
