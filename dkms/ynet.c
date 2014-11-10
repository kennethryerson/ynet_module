/*
 * Yitran Y-net protocol driver
 * 
 * Author: Kenneth Ryerson
 * 
 * 
 * 
 * 
 * 
 */

#include <linux/module.h>
#include <linux/moduleparam.h>

#include <asm/uaccess.h>
#include <linux/bitops.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_slip.h>
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/slab.h>
#include "ynet.h"
#ifdef CONFIG_INET
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/slhc_vj.h>
#endif

#define YNET_VERSION	"0.1.0"
#define N_YNET 25

static struct net_device *ynet_dev;

static int ynet_esc(unsigned char *p, unsigned char *d, int len, unsigned short addr, unsigned short id, unsigned char pts);
static void ynet_unesc(struct ynet *yn, unsigned char c);

/********************************
*  Buffer administration routines:
*	yn_alloc_bufs()
*	yn_free_bufs()
*	yn_realloc_bufs()
*
* NOTE: yn_realloc_bufs != yn_free_bufs + yn_alloc_bufs, because
*	yn_realloc_bufs provides strong atomicity and reallocation
*	on actively running device.
*********************************/

/*
   Allocate channel buffers.
 */

static int yn_alloc_bufs(struct ynet *yn, int mtu)
{
	int err = -ENOBUFS;
	unsigned long len;
	char *rbuff = NULL;
	char *xbuff = NULL;
	char *rspbuff = NULL;

	/*
	 * Allocate the Y-net frame buffers:
	 *
	 * rbuff	Receive buffer.
	 * xbuff	Transmit buffer.
	 * rspbuff  Response buffer.
	 */
	len = mtu * 2;

	/*
	 * allow for arrival of larger UDP packets, even if we say not to
	 * also fixes a bug in which SunOS sends 512-byte packets even with
	 * an MSS of 128
	 */
	if(len < 576 * 2)
	{
		len = 576 * 2;
	}
	rbuff = kmalloc(len + 4, GFP_KERNEL);
	if(rbuff == NULL)
	{
		goto err_exit;
	}
	xbuff = kmalloc(len + 4, GFP_KERNEL);
	if(xbuff == NULL)
	{
		goto err_exit;
	}
	rspbuff = kmalloc(len + 4, GFP_KERNEL);
	if(rspbuff == NULL)
	{
		goto err_exit;
	}
	spin_lock_bh(&yn->lock);
	if(yn->tty == NULL)
	{
		spin_unlock_bh(&yn->lock);
		err = -ENODEV;
		goto err_exit;
	}
	yn->mtu	     = mtu;
	yn->buffsize = len;
	yn->rcount   = 0;
	yn->xleft    = 0;
	rbuff = xchg(&yn->rbuff, rbuff);
	xbuff = xchg(&yn->xbuff, xbuff);
	rspbuff = xchg(&yn->rspbuff, rspbuff);
	spin_unlock_bh(&yn->lock);
	err = 0;

	/* Cleanup */
err_exit:
	kfree(xbuff);
	kfree(rbuff);
	kfree(rspbuff);
	return err;
}

/* Free a Y-net channel buffers. */
static void yn_free_bufs(struct ynet *yn)
{
	/* Free all Y-net frame buffers. */
	kfree(xchg(&yn->rbuff, NULL));
	kfree(xchg(&yn->xbuff, NULL));
}

/*
   Reallocate Y-net channel buffers.
 */
static int yn_realloc_bufs(struct ynet *yn, int mtu)
{
	int err = 0;
	struct net_device *dev = yn->dev;
	unsigned char *xbuff, *rbuff;
	int len = mtu * 2;

/*
 * allow for arrival of larger UDP packets, even if we say not to
 * also fixes a bug in which SunOS sends 512-byte packets even with
 * an MSS of 128
 */
	if(len < 576 * 2)
	{
		len = 576 * 2;
	}

	xbuff = kmalloc(len + 4, GFP_ATOMIC);
	rbuff = kmalloc(len + 4, GFP_ATOMIC);

	if(xbuff == NULL || rbuff == NULL)
	{
		if(mtu >= yn->mtu)
		{
			printk(KERN_WARNING "%s: unable to grow Y-net buffers, MTU change cancelled.\n",
			       dev->name);
			err = -ENOBUFS;
		}
		goto done;
	}
	spin_lock_bh(&yn->lock);

	err = -ENODEV;
	if(yn->tty == NULL)
	{
		goto done_on_bh;
	}

	xbuff    = xchg(&yn->xbuff, xbuff);
	rbuff    = xchg(&yn->rbuff, rbuff);
	if(yn->xleft)
	{
		if(yn->xleft <= len)
		{
			memcpy(yn->xbuff, yn->xhead, yn->xleft);
		}
		else
		{
			yn->xleft = 0;
			dev->stats.tx_dropped++;
		}
	}
	yn->xhead = yn->xbuff;

	if(yn->rcount)
	{
		if(yn->rcount <= len)
		{
			memcpy(yn->rbuff, rbuff, yn->rcount);
		}
		else
		{
			yn->rcount = 0;
			dev->stats.rx_over_errors++;
			set_bit(YNF_ERROR, &yn->flags);
		}
	}
	yn->mtu      = mtu;
	dev->mtu      = mtu;
	yn->buffsize = len;
	err = 0;

done_on_bh:
	spin_unlock_bh(&yn->lock);

done:
	kfree(xbuff);
	kfree(rbuff);
	return err;
}


/* Set the "sending" flag.  This must be atomic hence the set_bit. */
static inline void yn_lock(struct ynet *yn)
{
	netif_stop_queue(yn->dev);
}


/* Clear the "sending" flag.  This must be atomic, hence the ASM. */
static inline void yn_unlock(struct ynet *yn)
{
	netif_wake_queue(yn->dev);
}

/* Send one completely decapsulated IP datagram to the IP layer. */
static void yn_bump(struct ynet *yn)
{
	struct net_device *dev = yn->dev;
	struct sk_buff *skb;
	unsigned char *payload = yn->rbuff;
	int count, addlen, i;
	unsigned char addtype;

	/* strip off RX packet header */
	count = yn->rcount;
	
	/* RX and modulation type */
	payload++;
	count--;
	
	/* Data service type */
	payload++;
	count--;
	
	/* Modulation rate */
	payload++;
	count--;
	
	/* Signal quality */
	payload++;
	count--;
	
	/* TX service */
	payload++;
	count--;
	
	/* Priority */
	payload++;
	count--;
	
	/* CW */
	payload++;
	count--;
	
	/* Repeated */
	payload++;
	count--;
	
	/* TX result */
	payload++;
	count--;
	
	/* Net ID */
	payload++;
	count--;
	payload++;
	count--;
	
	/* Source ID */
	payload++;
	count--;
	payload++;
	count--;
	
	/* Target ID */
	payload++;
	count--;
	payload++;
	count--;
	
	/* Origin ID type */
	addtype = *payload++;
	count--;
	
	/* Origin ID */
	addlen = addtype*14 + 2;
	for(i = 0; i < addlen; ++i)
	{
		payload++;
		count--;
	}
	
	/* Final ID */
	payload++;
	count--;
	payload++;
	count--;
	
	/* Source and target port */
	payload++;
	count--;

	dev->stats.rx_bytes += count;

	skb = dev_alloc_skb(count + sizeof(struct iphdr));
	if(skb == NULL)
	{
		printk(KERN_WARNING "%s: memory squeeze, dropping packet.\n", dev->name);
		dev->stats.rx_dropped++;
		return;
	}
	skb->dev = dev;
	
	/* copy data packet */
	memcpy(skb_put(skb, count), payload, count);
	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IP);
	netif_rx(skb);
	dev->stats.rx_packets++;
	clear_bit(YNF_DATARX,&yn->flags);
}

static void yn_handle_response(struct ynet *yn)
{
	unsigned char *payload = yn->rspbuff;
	int count;
	unsigned char status, resp_num, result;
	
	count = yn->rspcount;
	
	/* repsonse status */
	status = payload[0];
	
	if(yn->rxopcode == YNET_OPCODE_TX_PACKET)
	{
		/* response number */
		resp_num = payload[1];
		
		/* result */
		result = payload[2];
		
		if(resp_num == 1 && result == YNET_RESPONSE_DATA_RESULT1_ACCEPTED)
		{
			/* TODO: how to handle accepted packet? */
		}
		else if(resp_num == 3 && result == YNET_RESPONSE_DATA_RESULT2_SUCCESS)
		{
			/* TODO: how to handle transmitted packet? */
		}
	}
	
	clear_bit(YNF_RESP,&yn->flags);
}

/* Encapsulate one IP datagram and stuff into a TTY queue. */
static void yn_encaps(struct ynet *yn, unsigned char *icp, int len, unsigned short addr, unsigned short id, unsigned short ack)
{
	unsigned char *p;
	int actual, count;

	if(len > yn->mtu)		/* Sigh, shouldn't occur BUT ... */
	{
		printk(KERN_WARNING "%s: truncating oversized transmit packet!\n", yn->dev->name);
		yn->dev->stats.tx_dropped++;
		yn_unlock(yn);
		return;
	}

	p = icp;
	count = ynet_esc(p, (unsigned char *) yn->xbuff, len, addr, id, ack);

	/* Order of next two lines is *very* important.
	 * When we are sending a little amount of data,
	 * the transfer may be completed inside the ops->write()
	 * routine, because it's running with interrupts enabled.
	 * In this case we *never* got WRITE_WAKEUP event,
	 * if we did not request it before write operation.
	 *       14 Oct 1994  Dmitry Gorodchanin.
	 */
	set_bit(TTY_DO_WRITE_WAKEUP, &yn->tty->flags);
	actual = yn->tty->ops->write(yn->tty, yn->xbuff, count);
	yn->dev->trans_start = jiffies;
	yn->xleft = count - actual;
	yn->xhead = yn->xbuff + actual;
}

/*
 * Called by the driver when there's room for more data.  If we have
 * more packets to send, we send them here.
 */
static void ynet_write_wakeup(struct tty_struct *tty)
{
	int actual;
	struct ynet *yn = tty->disc_data;

	/* First make sure we're connected. */
	if(!yn || yn->magic != YNET_MAGIC || !netif_running(yn->dev))
	{
		return;
	}

	if(yn->xleft <= 0)
	{
		/* Now serial buffer is almost free & we can start
		 * transmission of another packet */
		yn->dev->stats.tx_packets++;
		clear_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
		yn_unlock(yn);
		return;
	}

	actual = tty->ops->write(tty, yn->xhead, yn->xleft);
	yn->xleft -= actual;
	yn->xhead += actual;
}

static void yn_tx_timeout(struct net_device *dev)
{
	struct ynet *yn = netdev_priv(dev);

	spin_lock(&yn->lock);

	if(netif_queue_stopped(dev))
	{
		if(!netif_running(dev))
		{
			goto out;
		}

		/* Maybe we must check transmitter timeout here ?
		 *      14 Oct 1994 Dmitry Gorodchanin.
		 */
		if(time_before(jiffies, dev_trans_start(dev) + 20 * HZ))
		{
			/* 20 sec timeout not reached */
			goto out;
		}
		printk(KERN_WARNING "%s: transmit timed out, %s?\n",
			dev->name,
			(tty_chars_in_buffer(yn->tty) || yn->xleft) ?
				"bad line quality" : "driver error");
		yn->xleft = 0;
		clear_bit(TTY_DO_WRITE_WAKEUP, &yn->tty->flags);
		yn_unlock(yn);
	}
out:
	spin_unlock(&yn->lock);
}


/* Encapsulate an IP datagram and kick it into a TTY queue. */
static netdev_tx_t
yn_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ynet *yn = netdev_priv(dev);
	struct iphdr *ih;
	unsigned short ynet_addr;
	unsigned short ynet_id;
	unsigned char ynet_ack_service;

	spin_lock(&yn->lock);
	if(!netif_running(dev))
	{
		spin_unlock(&yn->lock);
		printk(KERN_WARNING "%s: xmit call when iface is down\n", dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	if(yn->tty == NULL)
	{
		spin_unlock(&yn->lock);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	
	/* parse IP header */
	ih = ip_hdr(skb);
	ynet_addr = ntohl(ih->daddr) & 0xFF;
	ynet_id = ntohs(ih->id);
	
	switch(ih->protocol)
	{
	case IPPROTO_TCP:
		ynet_ack_service = YNET_PACKET_DATA_ACK;
		break;
	case IPPROTO_UDP:
		ynet_ack_service = YNET_PACKET_DATA_NOACK;
		break;
	default:
		/* ignore other protocols */
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	yn_lock(yn);
	dev->stats.tx_bytes += skb->len;
	yn_encaps(yn, skb->data, skb->len, ynet_addr, ynet_id, ynet_ack_service);
	spin_unlock(&yn->lock);

	dev_kfree_skb(skb);
	
	return NETDEV_TX_OK;
}


/******************************************
 *   Routines looking at netdevice side.
 ******************************************/

/* Netdevice UP -> DOWN routine */
static int yn_close(struct net_device *dev)
{
	struct ynet *yn = netdev_priv(dev);

	spin_lock_bh(&yn->lock);
	if(yn->tty)
	{
		/* TTY discipline is running. */
		clear_bit(TTY_DO_WRITE_WAKEUP, &yn->tty->flags);
	}
	netif_stop_queue(dev);
	yn->rcount   = 0;
	yn->xleft    = 0;
	spin_unlock_bh(&yn->lock);

	return 0;
}

/* Netdevice DOWN -> UP routine */
static int yn_open(struct net_device *dev)
{
	struct ynet *yn = netdev_priv(dev);

	if(yn->tty == NULL)
	{
		return -ENODEV;
	}

	yn->flags &= (1 << YNF_INUSE);
	netif_start_queue(dev);
	return 0;
}

/* Netdevice change MTU request */
static int yn_change_mtu(struct net_device *dev, int new_mtu)
{
	struct ynet *yn = netdev_priv(dev);

	if(new_mtu < 68 || new_mtu > 65534)
	{
		return -EINVAL;
	}

	if(new_mtu != dev->mtu)
	{
		return yn_realloc_bufs(yn, new_mtu);
	}
	return 0;
}

/* Netdevice get statistics request */

static struct rtnl_link_stats64 *
yn_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct net_device_stats *devstats = &dev->stats;
	unsigned long c_rx_dropped = 0;
	stats->rx_packets     = devstats->rx_packets;
	stats->tx_packets     = devstats->tx_packets;
	stats->rx_bytes       = devstats->rx_bytes;
	stats->tx_bytes       = devstats->tx_bytes;
	stats->rx_dropped     = devstats->rx_dropped + c_rx_dropped;
	stats->tx_dropped     = devstats->tx_dropped;
	stats->tx_errors      = devstats->tx_errors;
	stats->rx_errors      = devstats->rx_errors;
	stats->rx_over_errors = devstats->rx_over_errors;

	return stats;
}

/* Netdevice register callback */

static int yn_init(struct net_device *dev)
{
	struct ynet *yn = netdev_priv(dev);

	/*
	 *	Finish setting up the DEVICE info.
	 */

	dev->mtu		= yn->mtu;
	dev->type		= ARPHRD_SLIP;
	dev->watchdog_timeo	= 20*HZ;
	return 0;
}


static void yn_uninit(struct net_device *dev)
{
	struct ynet *yn = netdev_priv(dev);

	yn_free_bufs(yn);
}

/* Hook the destructor so we can free Y-net devices at the right point in time */
static void yn_free_netdev(struct net_device *dev)
{
	free_netdev(dev);
	ynet_dev = NULL;
}

static const struct net_device_ops yn_netdev_ops = {
	.ndo_init		= yn_init,
	.ndo_uninit	  	= yn_uninit,
	.ndo_open		= yn_open,
	.ndo_stop		= yn_close,
	.ndo_start_xmit		= yn_xmit,
	.ndo_get_stats64    = yn_get_stats64,
	.ndo_change_mtu		= yn_change_mtu,
	.ndo_tx_timeout		= yn_tx_timeout,	/* called when a transmit queue times out */
};


static void yn_setup(struct net_device *dev)
{
	dev->netdev_ops		= &yn_netdev_ops;
	dev->destructor		= yn_free_netdev;

	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 10;

	/* New-style flags. */
	dev->flags		= IFF_NOARP|IFF_POINTOPOINT|IFF_MULTICAST;
}

/******************************************
  Routines looking at TTY side.
 ******************************************/

/*
 * Handle the 'receiver data ready' interrupt.
 * This function is called by the 'tty_io' module in the kernel when
 * a block of Y-net data has been received, which can now be decapsulated
 * and sent on to some IP layer for further processing. This will not
 * be re-entered while running but other ldisc functions may be called
 * in parallel
 */
static void ynet_receive_buf(struct tty_struct *tty, const unsigned char *cp,
							char *fp, int count)
{
	struct ynet *yn = tty->disc_data;

	if(!yn || yn->magic != YNET_MAGIC || !netif_running(yn->dev))
	{
		return;
	}

	/* Read the characters out of the buffer */
	while(count--)
	{
		if(fp && *fp++)
		{
			if(!test_and_set_bit(YNF_ERROR, &yn->flags))
			{
				yn->dev->stats.rx_errors++;
			}
			cp++;
			continue;
		}
		ynet_unesc(yn, *cp++);
	}
}

/************************************
 *  ynet_open helper routines.
 ************************************/

/* Collect hanged up channels */
static void yn_sync(void)
{
	struct net_device *dev;
	struct ynet	  *yn;

	dev = ynet_dev;
	if(dev)
	{
		yn = netdev_priv(dev);
		if(!(yn->tty || yn->leased))
		{
			if(dev->flags & IFF_UP)
			{
				dev_close(dev);
			}
		}
	}
}

/* Check for free Y-net channel, and link in this `tty' line. */
static struct ynet *yn_alloc(dev_t line)
{
	int i = 0;
	struct net_device *dev = NULL;
	struct ynet       *yn;

	dev = ynet_dev;
	if(dev)
	{
		yn = netdev_priv(dev);
		if(test_bit(YNF_INUSE, &yn->flags))
		{
			unregister_netdevice(dev);
			dev = NULL;
			ynet_dev = NULL;
		}
	}

	if(!dev)
	{
		char name[IFNAMSIZ];
		sprintf(name, "yn%d", i);

		dev = alloc_netdev(sizeof(*yn), name, yn_setup);
		if(!dev)
		{
			return NULL;
		}
		dev->base_addr  = i;
	}

	yn = netdev_priv(dev);

	/* Initialize channel control data */
	yn->magic       = YNET_MAGIC;
	yn->dev	      	= dev;
	spin_lock_init(&yn->lock);
	ynet_dev = dev;
	return yn;
}

/*
 * Open the high-level part of the Y-net channel.
 * This function is called by the TTY module when the
 * Y-net line discipline is called for.  Because we are
 * sure the tty line exists, we only have to link it to
 * a free Y-net channel...
 *
 * Called in process context serialized from other ldisc calls.
 */
static int ynet_open(struct tty_struct *tty)
{
	struct ynet *yn;
	int err;

	if(!capable(CAP_NET_ADMIN))
	{
		return -EPERM;
	}

	if(tty->ops->write == NULL)
	{
		return -EOPNOTSUPP;
	}

	/* RTnetlink lock is misused here to serialize concurrent
	   opens of Y-net channels. There are better ways, but it is
	   the simplest one.
	 */
	rtnl_lock();

	/* Collect hanged up channels. */
	yn_sync();

	yn = tty->disc_data;

	err = -EEXIST;
	/* First make sure we're not already connected. */
	if(yn && yn->magic == YNET_MAGIC)
	{
		goto err_exit;
	}

	/* OK.  Find a free Y-net channel to use. */
	err = -ENFILE;
	yn = yn_alloc(tty_devnum(tty));
	if(yn == NULL)
	{
		goto err_exit;
	}

	yn->tty = tty;
	tty->disc_data = yn;
	yn->line = tty_devnum(tty);
	yn->pid = current->pid;

	if(!test_bit(YNF_INUSE, &yn->flags))
	{
		/* Perform the low-level Y-net initialization. */
		err = yn_alloc_bufs(yn, YN_MTU);
		if(err)
		{
			goto err_free_chan;
		}

		set_bit(YNF_INUSE, &yn->flags);

		err = register_netdevice(yn->dev);
		if(err)
		{
			goto err_free_bufs;
		}
	}

	/* Done.  We have linked the TTY line to a channel. */
	rtnl_unlock();
	tty->receive_room = 65536;	/* We don't flow control */

	/* TTY layer expects 0 on success */
	return 0;

err_free_bufs:
	yn_free_bufs(yn);

err_free_chan:
	yn->tty = NULL;
	tty->disc_data = NULL;
	clear_bit(YNF_INUSE, &yn->flags);

err_exit:
	rtnl_unlock();

	/* Count references from TTY module */
	return err;
}

/*
 * Close down the Y-net channel.
 * This means flushing out any pending queues, and then returning. This
 * call is serialized against other ldisc functions.
 *
 * We also use this method fo a hangup event
 */
static void ynet_close(struct tty_struct *tty)
{
	struct ynet *yn = tty->disc_data;

	/* First make sure we're connected. */
	if(!yn || yn->magic != YNET_MAGIC || yn->tty != tty)
	{
		return;
	}

	tty->disc_data = NULL;
	yn->tty = NULL;
	if(!yn->leased)
	{
		yn->line = 0;
	}

	/* Flush network side */
	unregister_netdev(yn->dev);
	/* This will complete via yn_free_netdev */
}

static int ynet_hangup(struct tty_struct *tty)
{
	ynet_close(tty);
	return 0;
}

/*****************************************************
 *			STANDARD Y-net ENCAPSULATION		  	 *
 *****************************************************/

static int ynet_esc(unsigned char *s, unsigned char *d, int len, unsigned short addr, unsigned short id, unsigned char pts)
{
	unsigned char *ptr = d;
	unsigned char c, chksm = 0;
	unsigned short ylen = len + 20;

	/* Start Byte */
	*ptr++ = YNET_ATTENTION;
	
	/* Length */
	chksm += *ptr++ = ylen & 0xFF;
	chksm += *ptr++ = (ylen >> 8) & 0xFF;
	
	/* Type */
	chksm += *ptr++ = YNET_PACKET_TYPE_REQUEST;
	
	/* Opcode */
	chksm += *ptr++ = YNET_OPCODE_TX_PACKET;
	
	/* Data service type */
	chksm += *ptr++ = YNET_PACKET_DATA_TYPE_INTRAUCAST;
	
	/* Packet priority */
	chksm += *ptr++ = YNET_PACKET_DATA_PRIORITY_NORMAL | 0x70;
	
	/* Packet transmission service */
	chksm += *ptr++ = pts;
	
	/* Hops */
	chksm += *ptr++ = 0;
	
	/* Gain */
	chksm += *ptr++ = 7;
	
	/* Tag */
	chksm += *ptr++ = id & 0xFF;
	chksm += *ptr++ = (id >> 8) & 0xFF;
	
	/* Encrypt flag */
	chksm += *ptr++ = 0;
	
	/* Destination port (must be 0) */
	chksm += *ptr++ = 0;
	
	/* Destination address */
	chksm += *ptr++ = addr & 0xFF;
	chksm += *ptr++ = (addr >> 8) & 0xFF;
	
	/* Modulation */
	chksm += *ptr++ = YNET_PACKET_MODULATION_DCSKT_5;
	
	/* Fragment size */
	chksm += *ptr++ = 0;
	chksm += *ptr++ = 0;
	
	/* Reserved */
	chksm += *ptr++ = 0;
	chksm += *ptr++ = 0;
	chksm += *ptr++ = 0;
	chksm += *ptr++ = 0;

	/* Payload */
	while(len-- > 0)
	{
		c = *s++;
		chksm += *ptr++ = c;
	}
	
	/* Checksum */
	*ptr++ = chksm;
	return ptr - d;
}

static void yn_fill_rsp_buffer(struct ynet *yn, unsigned char s)
{
	if(!test_bit(YNF_RESP,&yn->flags))
	{
		/* Save data byte into incoming response buffer */
		yn->rspbuff[yn->plidx - 2] = s;
		
		yn->plidx++;
		if(yn->plidx == yn->rxlength)
		{
			yn->rxstate = YNS_CHKSUM;
		}
	}
}

static void yn_fill_nl_buffer(struct ynet *yn, unsigned char s)
{
	/* ignore NL packets */
	
	yn->plidx++;
	if(yn->plidx == yn->rxlength)
	{
		yn->rxstate = YNS_CHKSUM;
	}
}

static void yn_fill_rx_buffer(struct ynet *yn, unsigned char s)
{				
	if(!test_bit(YNF_DATARX,&yn->flags))
	{
		/* Save data byte into incoming RX data buffer */
		yn->rbuff[yn->plidx - 2] = s;
		yn->plidx++;
		
		if(yn->plidx == yn->rxlength)
		{
			yn->rxstate = YNS_CHKSUM;
		}
	}
	else
	{
		/* ignore incoming data packet if previous one was not processed */
		yn->plidx++;
		if(yn->plidx == yn->rxlength)
		{
			yn->rxstate = YNS_CHKSUM;
		}
	}
}

static void ynet_unesc(struct ynet *yn, unsigned char s)
{
	switch(yn->rxstate)
	{
	case YNS_ATTN:
		if(s == YNET_ATTENTION)
		{
			yn->rxstate = YNS_LENL;
			yn->checksum = 0;
		}
		break;
	case YNS_LENL:
		yn->rxlength = s;
		yn->rxstate = YNS_LENH;
		yn->checksum += s;
		break;
	case YNS_LENH:
		yn->rxlength += ((unsigned short)s << 8);
		yn->rxstate = YNS_TYPE;
		yn->checksum += s;
		break;
	case YNS_TYPE:
		yn->rxtype = s;
		yn->rxstate = YNS_OPCODE;
		yn->checksum += s;
		break;
	case YNS_OPCODE:
		yn->rxopcode = s;
		yn->rxstate = YNS_PAYLOAD;
		yn->checksum += s;
		break;
	case YNS_PAYLOAD:
		yn->checksum += s;
		if(yn->rxlength > yn->plidx)
		{
			if((yn->plidx - 2) >= yn->buffsize)
			{
				yn->dev->stats.rx_over_errors++;
				set_bit(YNF_ERROR, &yn->flags);
			}
	
			if(test_and_clear_bit(YNF_ERROR, &yn->flags))
			{
				yn->rxstate = YNS_ATTN;
			}
			else
			{
				switch(yn->rxtype)
				{
				case YNET_PACKET_TYPE_RESPONSE:
					yn_fill_rsp_buffer(yn,s);
					break;
				case YNET_PACKET_TYPE_INDICATION:
					if((yn->rxopcode >> YNET_SERVICE_TYPE_SHIFT) == YNET_SERVICE_TYPE_MANAGEMENT_SA)
					{
						yn_fill_nl_buffer(yn,s);
					}
					else
					{
						yn_fill_rx_buffer(yn,s);
					}
					break;
				default:
					yn->rxstate = YNS_ATTN;
				}
			}
		}
		else
		{
			yn->rxstate = YNS_ATTN;
		}
		break;
	case YNS_CHKSUM:
		if(yn->checksum != s)
		{
			/* wrong checksum */
			yn->rxstate = YNS_ATTN;
			break;
		}
		
		if(yn->rxopcode == YNET_OPCODE_RESET)
		{
			set_bit(YNF_RST,&yn->flags);
		}
		
		switch(yn->rxtype)
		{
		case YNET_PACKET_TYPE_RESPONSE:
			yn->rspcount = yn->rxlength;
			set_bit(YNF_RESP,&yn->flags);
			yn_handle_response(yn);
			break;
		case YNET_PACKET_TYPE_INDICATION:
			if((yn->rxopcode >> YNET_SERVICE_TYPE_SHIFT) == YNET_SERVICE_TYPE_MANAGEMENT_SA)
			{
				/* NL indication received - ignore currently */
			}
			else
			{
				yn->rcount = yn->rxlength;
				set_bit(YNF_DATARX,&yn->flags);
				yn_bump(yn);
			}
			break;
		default:
			yn->rxstate = YNS_ATTN;
		}
		yn->rxstate = YNS_ATTN;
		break;
	default:
		yn->rxstate = YNS_ATTN;
	}
}

/* Perform I/O control on an active Y-net channel. */
static int ynet_ioctl(struct tty_struct *tty, struct file *file,
					unsigned int cmd, unsigned long arg)
{
	struct ynet *yn = tty->disc_data;
	unsigned int tmp;
	/*int __user *p = (int __user *)arg;*/

	/* First make sure we're connected. */
	if(!yn || yn->magic != YNET_MAGIC)
	{
		return -EINVAL;
	}

	switch(cmd)
	{
	case SIOCGIFNAME:
		tmp = strlen(yn->dev->name) + 1;
		if(copy_to_user((void __user *)arg, yn->dev->name, tmp))
		{
			return -EFAULT;
		}
		return 0;

	case SIOCSIFHWADDR:
		return -EINVAL;
		
	default:
		return tty_mode_ioctl(tty, file, cmd, arg);
	}
}

#ifdef CONFIG_COMPAT
static long ynet_compat_ioctl(struct tty_struct *tty, struct file *file,
					unsigned int cmd, unsigned long arg)
{
	switch (cmd)
	{
	case SIOCGIFNAME:
	case SIOCGIFENCAP:
	case SIOCSIFENCAP:
	case SIOCSIFHWADDR:
	case SIOCSKEEPALIVE:
	case SIOCGKEEPALIVE:
	case SIOCSOUTFILL:
	case SIOCGOUTFILL:
		return ynet_ioctl(tty, file, cmd,
				  (unsigned long)compat_ptr(arg));
	}

	return -ENOIOCTLCMD;
}
#endif

static struct tty_ldisc_ops ynet_ldisc = {
	.owner 		= THIS_MODULE,
	.magic 		= TTY_LDISC_MAGIC,
	.name 		= "ynet",
	.open 		= ynet_open,
	.close	 	= ynet_close,
	.hangup	 	= ynet_hangup,
	.ioctl		= ynet_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ynet_compat_ioctl,
#endif
	.receive_buf	= ynet_receive_buf,
	.write_wakeup	= ynet_write_wakeup,
};

static int __init ynet_init_module(void)
{
	int status;

	printk(KERN_INFO "Y-net: version %s.\n",YNET_VERSION);

	/* Fill in our line protocol discipline, and register it */
	status = tty_register_ldisc(N_YNET, &ynet_ldisc);
	if(status != 0)
	{
		printk(KERN_ERR "Y-net: can't register line discipline (err = %d)\n", status);
	}
	return status;
}

static void __exit ynet_exit(void)
{
	int i;
	struct net_device *dev;
	struct ynet *yn;
	unsigned long timeout = jiffies + HZ;
	int busy = 0;

	if(ynet_dev == NULL)
	{
		return;
	}

	/* First of all: check for active disciplines and hangup them. */
	do
	{
		if(busy)
		{
			msleep_interruptible(100);
		}

		busy = 0;
		
		dev = ynet_dev;
		if(dev)
		{
			yn = netdev_priv(dev);
			spin_lock_bh(&yn->lock);
			if(yn->tty)
			{
				busy++;
				tty_hangup(yn->tty);
			}
			spin_unlock_bh(&yn->lock);
		}
	} while(busy && time_before(jiffies, timeout));

	/* FIXME: hangup is async so we should wait when doing this second
	   phase */

	dev = ynet_dev;
	if(dev)
	{		
		ynet_dev = NULL;

		yn = netdev_priv(dev);
		if(yn->tty)
		{
			printk(KERN_ERR "%s: tty discipline still running\n",
			       dev->name);
			/* Intentionally leak the control block. */
			dev->destructor = NULL;
		}

		unregister_netdev(dev);
	}

	i = tty_unregister_ldisc(N_SLIP);
	if(i != 0)
	{
		printk(KERN_ERR "Y-net: can't unregister line discipline (err = %d)\n", i);
	}
}

module_init(ynet_init_module);
module_exit(ynet_exit);

MODULE_AUTHOR("Kenneth Ryerson");
MODULE_LICENSE("GPL");
MODULE_ALIAS_LDISC(N_YNET);
