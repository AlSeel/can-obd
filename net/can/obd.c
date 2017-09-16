/*
 * Copyright (c) 2008 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

/*
 * obd.c - implements ISO 15765-4, transport relevant part of ISO-15031-5 for protocol family CAN
 *
 * This module was derived from can-isotp module publiced by Oliver Hartkopp
 * (https://github.com/hartkopp/can-isotp.git).
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/hrtimer.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/can.h>
#include <linux/can/core.h>
#include <net/sock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#include "compat.h"
#endif


#define CAN_OBD	3

#define OBD_TRANSPORT_VERSION 	"0001"
static __initdata const char banner[] =
	KERN_INFO "can: obd protocol (rev " OBD_TRANSPORT_VERSION ")\n";

MODULE_DESCRIPTION("PF_CAN obd transport protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("alexanderseel86@googlemail.com");
//MODULE_ALIAS("obd-proto-1"); obsolet

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#error This modules needs hrtimers (available since Kernel 2.6.22)
#endif

#define DBG(fmt, args...) (printk(KERN_INFO "OBD: %s: " fmt, \
				   __func__, ##args))
#undef DBG
#define DBG(fmt, args...)

#define MAX_TELEGRAM_LENGTH 8200

#define N_PCI_SF	0x00 /* single frame */
#define N_PCI_FF	0x10 /* first frame */
#define N_PCI_CF	0x20 /* consecutive frame */
#define N_PCI_FC	0x30 /* flow control */

#define SOL_CAN_OBD (SOL_CAN_BASE + CAN_OBD)

#define CAN_OBD_RX_P2_CAN	1
#define CAN_OBD_RX_P2_CAN_EXT	2
#define CAN_OBD_TX_CANID	3
#define	CAN_OBD_TIMEDIFF	4


enum {
	OBD_TP_IDLE = 0,
	OBD_TP_RECEIVING,
	OBD_TP_RECEIVING_FINISHED
};

struct tpcon {
	canid_t txid;
	canid_t rxid;
	canid_t rx_mask;
	u8 neg_resp;
	ktime_t tx;
	ktime_t last_rx;
	unsigned int tel_len;                    // telegram length
	u8  state;
	canid_t can_id[8];
	unsigned int entry_limit[8];
	unsigned int current_p[8];
	u8  buf[MAX_TELEGRAM_LENGTH+1]; /*telegram buffer  ||CAN ID + LEN + SID + DATA| ... | ... ||
                                                                4      2     1     x                  */
};

struct obd_tp_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct net_device* dev;
	struct hrtimer rxtimer;
	unsigned long P2_CAN;
	long P2_CAN_EXT;
	struct tpcon telegram;
	struct notifier_block notifier;
	wait_queue_head_t wait;
	struct tasklet_struct rxtsklet;
};

union mesg_canid{
	canid_t id;
	u8 buf[4];
};

union mesg_len{
	u16 len;
	u8 buf[2];
};


static int obd_tp_send_fc(struct sock *sk,canid_t can_id);

static inline struct obd_tp_sock *obd_tp_sk(const struct sock *sk)
{
	return (struct obd_tp_sock *)sk;
}

static void obd_tp_rcv_skb(struct sk_buff *skb, struct sock *sk)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)skb->cb;

	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(struct sockaddr_can));


	DBG("called");

	memset(addr, 0, sizeof(struct sockaddr_can));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = skb->dev->ifindex;


	if (sock_queue_rcv_skb(sk, skb) < 0)
		kfree_skb(skb);
}

static enum hrtimer_restart obd_tp_rx_timer_handler(struct hrtimer *hrtimer)
{
	struct obd_tp_sock *so = container_of(hrtimer, struct obd_tp_sock, rxtimer);

	DBG("called");

	so->telegram.state = OBD_TP_RECEIVING_FINISHED;

	//trigger delivering of obd msg
	tasklet_schedule(&so->rxtsklet);

	return HRTIMER_NORESTART;
}

static void obd_tp_rx_timer_tsklet(unsigned long data)
{
	struct obd_tp_sock *so = (struct obd_tp_sock *)data;
	struct sock *sk = &so->sk;
	struct sk_buff *nskb;
	struct sockaddr_can *addr;

	DBG("called");

	if (so->telegram.tel_len == 0) {
		//no telegram received
		nskb = alloc_skb(6, gfp_any());
		if (!nskb) {
			return;
		}
		so->telegram.buf[0] = 0x20;
		so->telegram.buf[1] = 0x00;
		so->telegram.buf[2] = 0x00;
		so->telegram.buf[3] = 0x00;
		so->telegram.buf[4] = 0x00;
		so->telegram.buf[5] = 0x00;
		memcpy(skb_put(nskb, 6), so->telegram.buf, 6);
		DBG("return(%d): 0x%x 0x%x 0x%x 0x%x ...",4,nskb->data[0],nskb->data[1], nskb->data[2], nskb->data[3]);
	}
	else{
		nskb = alloc_skb(so->telegram.tel_len, gfp_any());
		if (!nskb) {
			return;
		}
		memcpy(skb_put(nskb, so->telegram.tel_len), so->telegram.buf, so->telegram.tel_len);
		DBG("return(%d): 0x%x 0x%x 0x%x 0x%x ...",so->telegram.tel_len,nskb->data[0],nskb->data[1], nskb->data[2], nskb->data[3]);
	}


	nskb->dev = so->dev;
	//obd_tp_rcv_skb(nskb, sk); somehow it cause an error (dereferencing NULL pointer)

	addr = (struct sockaddr_can *)nskb->cb;

	BUILD_BUG_ON(sizeof(nskb->cb) < sizeof(struct sockaddr_can));

	memset(addr, 0, sizeof(struct sockaddr_can));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = so->ifindex;

	so->telegram.last_rx = ktime_get();
	DBG("last_rx=%lld",so->telegram.last_rx);

	if (sock_queue_rcv_skb(sk, nskb) < 0)
		kfree_skb(nskb);


	memset(so->telegram.can_id,0xFF,sizeof(canid_t));
	memset(so->telegram.entry_limit,0,sizeof(unsigned int)*8);
	memset(so->telegram.current_p,0,sizeof(unsigned int)*8);
	so->telegram.tel_len = 0;
	so->telegram.neg_resp = 0;

	so->telegram.state = OBD_TP_IDLE;
	wake_up_interruptible(&so->wait);
}

static void obd_tp_skb_destructor(struct sk_buff *skb)
{
	DBG("called");

	sock_put(skb->sk);
}

static inline void obd_tp_skb_set_owner(struct sk_buff *skb, struct sock *sk)
{

	DBG("called");

	if (sk) {
		sock_hold(sk);
		skb->destructor = obd_tp_skb_destructor;
		skb->sk = sk;
	}
}

void obd_tp_rcv_sf(struct sk_buff *skb, void *data)
{
	struct can_frame *cf;
	canid_t can_id;
	u8 index;
	u32 telegram_len;
	u8 fault = 0;
	u16 part_len;
	union mesg_canid conv_id;
	union mesg_len conv_len;
	struct obd_tp_sock *so = obd_tp_sk((struct sock *)data);

	DBG("called");

	cf = (struct can_frame *) skb->data;
	can_id = cf->can_id;
	telegram_len = so->telegram.tel_len;

	for(index = 0; index < 8; index++){
		if(so->telegram.can_id[index] == can_id){
			fault = 1;
			break;
		}
		if(so->telegram.can_id[index] == 0xFFFFFFFF){
			break;
		}
	}

	if(index == 8 || fault == 1){
		//no space for more than 8 ECUs responses or invalid can id
		return;
	}

	if(cf->data[1] == 0x7F && cf->data[3] == 0x78){
		//neg responses
		//reset timer to 5000 ms
		//hrtimer_start(&so->rxtimer, ktime_set(30,0), HRTIMER_MODE_REL);
		hrtimer_start(&so->rxtimer, ktime_set(so->P2_CAN_EXT,0), HRTIMER_MODE_REL);
		so->telegram.neg_resp = 1;
		return;
	}

	//reset timer
	if( so->telegram.neg_resp ) {
		//reset timer to 5000 ms
		//hrtimer_start(&so->rxtimer, ktime_set(30,0), HRTIMER_MODE_REL);
		hrtimer_start(&so->rxtimer, ktime_set(so->P2_CAN_EXT,0), HRTIMER_MODE_REL);
	}
	else{
		//hrtimer_start(&so->rxtimer, ktime_set(10,0), HRTIMER_MODE_REL); // for test purpose
		hrtimer_start(&so->rxtimer, ktime_set(0,so->P2_CAN), HRTIMER_MODE_REL);
	}

	part_len = ((cf->data[0] & 0x0F) > 7)? 7 : (cf->data[0] & 0x0F);

	if((so->telegram.tel_len + 6 + part_len) > MAX_TELEGRAM_LENGTH){
		//no space more in reserved buffer
		return;
	}

#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
	//store CAN ID in the buffer
	conv_id.id = can_id & 0x1FFFFFFF;
	so->telegram.buf[telegram_len] = conv_id.buf[0];
	so->telegram.buf[telegram_len + 1] = conv_id.buf[1];
	so->telegram.buf[telegram_len + 2] = conv_id.buf[2];
	so->telegram.buf[telegram_len + 3] = conv_id.buf[3];

	//store LEN
	conv_len.len = (u16)(cf->data[0] & 0x0F);
	so->telegram.buf[telegram_len+4] = conv_len.buf[0];
	so->telegram.buf[telegram_len+5] = conv_len.buf[1];
#else
	//store CAN ID in the buffer
	conv_id.id = can_id & 0x1FFFFFFF;
	so->telegram.buf[telegram_len] = conv_id.buf[3];
	so->telegram.buf[telegram_len + 1] = conv_id.buf[2];
	so->telegram.buf[telegram_len + 2] = conv_id.buf[1];
	so->telegram.buf[telegram_len + 3] = conv_id.buf[0];

	//store LEN
	conv_len.len = (u16)(cf->data[0] & 0x0F);
	so->telegram.buf[telegram_len+4] = conv_len.buf[1];
	so->telegram.buf[telegram_len+5] = conv_len.buf[0];
#endif
	//copy data
	memcpy(&so->telegram.buf[telegram_len+6], &cf->data[1], part_len);

	//set new length
	so->telegram.tel_len += 6;
	so->telegram.tel_len += part_len;

	//remember can id
	so->telegram.can_id[index] = can_id;

	DBG("SF appended: 0x%x(%d)#data",so->telegram.can_id[index],so->telegram.tel_len);
}

void obd_tp_rcv_ff(struct sk_buff *skb, void *data)
{
	struct can_frame *cf;
	canid_t can_id;
	u8 index;
	u32 telegram_len;
	u16 ff_dl,part_len;
	u8 fault = 0;
	union mesg_canid conv_id;
	union mesg_len conv_len;
	struct obd_tp_sock *so = obd_tp_sk((struct sock *)data);

	DBG("called");

	//reset timer
	if( so->telegram.neg_resp ) {
		//reset timer to 5000 ms
		//hrtimer_start(&so->rxtimer, ktime_set(30,0), HRTIMER_MODE_REL);
		hrtimer_start(&so->rxtimer, ktime_set(so->P2_CAN_EXT,0), HRTIMER_MODE_REL);
	}
	else{
		//hrtimer_start(&so->rxtimer, ktime_set(10,0), HRTIMER_MODE_REL); // for test
		hrtimer_start(&so->rxtimer, ktime_set(0,so->P2_CAN), HRTIMER_MODE_REL);
	}

	cf = (struct can_frame *) skb->data;
	can_id = cf->can_id;
	telegram_len = so->telegram.tel_len;

	for(index = 0; index < 8; index++){
		if(so->telegram.can_id[index] == can_id){
			fault = 1;
			break;
		}
		if(so->telegram.can_id[index] == 0xFFFFFFFF){
			break;
		}
	}

	if(index == 8 || fault == 1){
		//no space for more than 8 ECUs responses or invalid can id
		return;
	}

	//calc LEN
	ff_dl = 0;
	ff_dl = (cf->data[0] & 0x0F)<<8;
	ff_dl |= cf->data[1];
	ff_dl &= 0x0FFF;

	if((so->telegram.tel_len + 6 + ff_dl) > MAX_TELEGRAM_LENGTH){
		//no space more in reserved buffer
		return;
	}

#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        //store CAN ID in the buffer
        conv_id.id = can_id & 0x1FFFFFFF;
        so->telegram.buf[telegram_len] = conv_id.buf[0];
        so->telegram.buf[telegram_len + 1] = conv_id.buf[1];
        so->telegram.buf[telegram_len + 2] = conv_id.buf[2];
        so->telegram.buf[telegram_len + 3] = conv_id.buf[3];

        //store LEN
        conv_len.len = (u16)ff_dl;
        so->telegram.buf[telegram_len+4] = conv_len.buf[0];
        so->telegram.buf[telegram_len+5] = conv_len.buf[1];
#else
        //store CAN ID in the buffer
        conv_id.id = can_id & 0x1FFFFFFF;
        so->telegram.buf[telegram_len] = conv_id.buf[3];
        so->telegram.buf[telegram_len + 1] = conv_id.buf[2];
        so->telegram.buf[telegram_len + 2] = conv_id.buf[1];
        so->telegram.buf[telegram_len + 3] = conv_id.buf[0];

        //store LEN
        conv_len.len = (u16)ff_dl;
        so->telegram.buf[telegram_len+4] = conv_len.buf[1];
        so->telegram.buf[telegram_len+5] = conv_len.buf[0];
#endif


	//send cf
	obd_tp_send_fc((struct sock *)data,can_id);

	part_len = (ff_dl<6)? ff_dl:6;
	//copy data
	memcpy(&so->telegram.buf[telegram_len+6], &cf->data[2], part_len);

	so->telegram.current_p[index] = so->telegram.tel_len + 6 + part_len;

	//store entry boundary
	so->telegram.entry_limit[index] = 6 + ff_dl + so->telegram.tel_len;

	//set new length
	so->telegram.tel_len += 6;
	so->telegram.tel_len += ff_dl;

	//remember can id
	so->telegram.can_id[index] = can_id;
}

int obd_tp_send_fc(struct sock *sk,canid_t can_id)
{
	struct net_device *dev;
	struct sk_buff *nskb;
	struct can_frame *cf;
	struct obd_tp_sock *so = obd_tp_sk(sk);

	DBG("called");

	nskb = alloc_skb(CAN_MTU, gfp_any());
	if (!nskb)
		return 1;

	dev = dev_get_by_index(&init_net, so->ifindex);
	if (!dev) {
		kfree_skb(nskb);
		return 1;
	}
	nskb->dev = dev;
	obd_tp_skb_set_owner(nskb, sk);
	cf = (struct can_frame *) nskb->data;
	skb_put(nskb, CAN_MTU);

	/* create & send flow control reply */
	if (can_id & CAN_EFF_FLAG) {
		cf->can_id = ((can_id & 0x000000FF ) << 8) | 0x18DA00F1;
	}
	else {
		cf->can_id = can_id - 8;
	}

	memset(cf->data,0xFF, CAN_MAX_DLEN);

	cf->data[0] = 0x30;
	cf->data[1] = 0x00;
	cf->data[2] = 0x00;
	//cf->data[3] = 0x00;

	cf->can_dlc = 3;

	can_send(nskb, 1);
	dev_put(dev);

	return 0;
}

void obd_tp_rcv_cf(struct sk_buff *skb, void *data)
{
	struct can_frame *cf;
	canid_t can_id;
	u8 index;
	int part_len;
	struct obd_tp_sock *so = obd_tp_sk((struct sock *)data);

	DBG("called");

	cf = (struct can_frame *) skb->data;
	can_id = cf->can_id;

	for(index = 0; index < 8; index++){
		if(so->telegram.can_id[index] == can_id){
			break;
		}
	}

	if(index == 8){
		//no can id found
		return;
	}

	part_len = so->telegram.entry_limit[index] - so->telegram.current_p[index];
	part_len = (part_len < 7)? part_len : 7;
	if( part_len <= 0){
		//no space more in reserved buffer
		return;
	}

	//copy data
	memcpy(&so->telegram.buf[so->telegram.current_p[index]], &cf->data[1], part_len);

	so->telegram.current_p[index] += part_len;
}

void obd_tp_rcv_error(struct sk_buff *skb, void *data)
{
	struct sk_buff *nskb;
	struct can_frame *cf;
	u8 len;
	union mesg_canid conv_id;
	union mesg_len conv_len;
	struct obd_tp_sock *so = obd_tp_sk((struct sock *)data);

	DBG("called");

	//stop timer
	hrtimer_cancel(&so->rxtimer);

	cf = (struct can_frame *) skb->data;
	len = cf->can_dlc;

	nskb = alloc_skb(len+6, gfp_any());
	if (!nskb)
		return ;

	memcpy(&so->telegram.buf[6], &cf->data[0], len);


#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
	//store CAN ID in the buffer
	conv_id.id = cf->can_id;
        so->telegram.buf[0] = conv_id.buf[0];
        so->telegram.buf[1] = conv_id.buf[1];
        so->telegram.buf[2] = conv_id.buf[2];
        so->telegram.buf[3] = conv_id.buf[3];

        //store LEN
        conv_len.len = (u16)len;
        so->telegram.buf[4] = conv_len.buf[0];
        so->telegram.buf[5] = conv_len.buf[1];
#else
        //store CAN ID in the buffer
	conv_id.id = cf->can_id;
        so->telegram.buf[0] = conv_id.buf[3];
        so->telegram.buf[1] = conv_id.buf[2];
        so->telegram.buf[2] = conv_id.buf[1];
        so->telegram.buf[3] = conv_id.buf[0];

        //store LEN
        conv_len.len = (u16)len;
        so->telegram.buf[4] = conv_len.buf[1];
        so->telegram.buf[5] = conv_len.buf[0];
#endif

	memcpy(skb_put(nskb, len+6), &so->telegram.buf[0], len+6);

	nskb->tstamp = skb->tstamp;
	nskb->dev = skb->dev;
	so->telegram.last_rx = ktime_get();
	DBG("last_rx=%lld",so->telegram.last_rx);

	obd_tp_rcv_skb(nskb, (struct sock *)data);

	memset(so->telegram.can_id,0xFF,sizeof(canid_t));
	memset(so->telegram.entry_limit,0,sizeof(unsigned int)*8);
	memset(so->telegram.current_p,0,sizeof(unsigned int)*8);
	so->telegram.tel_len = 0;
	so->telegram.neg_resp = 0;

	so->telegram.state = OBD_TP_IDLE;
	wake_up_interruptible(&so->wait);
}


static void obd_tp_rcv_handler(struct sk_buff *skb, void *data)
{
	struct sock *sk = (struct sock *)data;
	struct obd_tp_sock *so = obd_tp_sk(sk);
	struct can_frame *cf;
	u8 n_pci_type;

	DBG("called");

	cf = (struct can_frame *) skb->data;

	if(so->telegram.state != OBD_TP_RECEIVING){
		//obd response not expected
		return;
	}

	if(cf->can_id & CAN_ERR_FLAG){
		//Error frame
		obd_tp_rcv_error(skb,data);
	}

	//store last device for delivering obd msg
	so->dev = skb->dev;


	n_pci_type = cf->data[0] & 0xF0;

	switch (n_pci_type) {
		case N_PCI_SF:
			obd_tp_rcv_sf(skb,data);
			break;
		case N_PCI_FF:
			obd_tp_rcv_ff(skb,data);
			break;
		case N_PCI_CF:
			obd_tp_rcv_cf(skb,data);
			break;
		default:
			break;
	}

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
static int obd_tp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			 int flags)
#else
static int obd_tp_recvmsg(struct kiocb *iocb, struct socket *sock,
			 struct msghdr *msg, size_t size, int flags)
#endif
{
	struct sock *sk;
	struct sk_buff *skb;
	int err = 0;
	int noblock;

	DBG("called");

	if((sock == NULL) || (msg == NULL))
		return err;

	sk = sock->sk;

	noblock =  flags & MSG_DONTWAIT;
	flags   &= ~MSG_DONTWAIT;


	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		return err;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	err = memcpy_to_msg(msg, skb->data, size);
#else
	err = memcpy_toiovec(msg->msg_iov, skb->data, size);
#endif
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_timestamp(msg, sk, skb);

	if (msg->msg_name) {
		msg->msg_namelen = sizeof(struct sockaddr_can);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);

	return size;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
static int obd_tp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
#else
static int obd_tp_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size)
#endif
{
	struct sk_buff *skb;
	struct net_device *dev;
	int ifindex;
	int err;
	struct sockaddr_can *addr;
	struct sock *sk = sock->sk;
	struct obd_tp_sock *so = obd_tp_sk(sk);
	struct can_frame * frame;

	DBG("called");

	if (!so->bound)
		return -EADDRNOTAVAIL;

	if (msg->msg_name) {
		addr = (struct sockaddr_can *)msg->msg_name;
		if (msg->msg_namelen < sizeof(*addr))
			return -EINVAL;
		if (addr->can_family != AF_CAN)
			return -EINVAL;
		ifindex = addr->can_ifindex;
	} else{
		ifindex = so->ifindex;
	}


	if (size < 1 || size > 6 )
		return -EINVAL;

	if (so->telegram.state != OBD_TP_IDLE) {
		if (msg->msg_flags & MSG_DONTWAIT)
			return -EAGAIN;

		// wait for complete obd request
		wait_event_interruptible(so->wait, so->telegram.state == OBD_TP_IDLE);
	}


	dev = dev_get_by_index(&init_net, ifindex);
	if (!dev)
		return -ENXIO;

	skb = sock_alloc_send_skb(sk, sizeof(struct can_frame), msg->msg_flags & MSG_DONTWAIT,
				  &err);
	if (!skb)
		goto put_dev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	err = memcpy_from_msg(so->telegram.buf, msg, size);
#else
	err = memcpy_fromiovec(so->telegram.buf, msg->msg_iov, size);
#endif

	if (err < 0)
		goto free_skb;

	skb_put(skb, sizeof(struct can_frame));

	frame = (struct can_frame*) skb->data;
	frame-> can_dlc = 8;
	memset(frame->data,0x00,8);
	frame->can_id = so->telegram.txid;
	frame->data[0] = 0x00 | size;
	memcpy(&frame->data[1],so->telegram.buf,size);
	DBG("sending: 0x%x#%d#0x%x 0x%x ...",frame->can_id,frame->can_dlc,frame->data[0],frame->data[1]);

	so->telegram.state = OBD_TP_RECEIVING;
	memset(so->telegram.can_id,0xFF,sizeof(canid_t)*8);
	memset(so->telegram.entry_limit,0,sizeof(unsigned int)*8);
	memset(so->telegram.current_p,0,sizeof(unsigned int)*8);
	so->telegram.tel_len = 0;
	so->telegram.neg_resp = 0;

	so->telegram.tx = ktime_get();
	DBG("tx=%lld",so->telegram.tx);
	memset(so->telegram.buf,0,MAX_TELEGRAM_LENGTH);

	skb->dev = dev;
	skb->sk = sk;
	err = can_send(skb,1);
	dev_put(dev);
	if (err)
		goto send_failed;

	//hrtimer_start(&so->rxtimer, ktime_set(10,0), HRTIMER_MODE_REL); // for test
	hrtimer_start(&so->rxtimer, ktime_set(0,so->P2_CAN), HRTIMER_MODE_REL);

	return size;
free_skb:
	kfree_skb(skb);
put_dev:
	dev_put(dev);
send_failed:
	return err;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
static int obd_tp_notifier(struct notifier_block *nb, unsigned long msg,
			  void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#else
static int obd_tp_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *dev = (struct net_device *)data;
#endif
	struct obd_tp_sock *so = container_of(nb, struct obd_tp_sock, notifier);
	struct sock *sk = &so->sk;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (dev_net(dev) != &init_net)
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net)
		return NOTIFY_DONE;
#endif

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	if (so->ifindex != dev->ifindex)
		return NOTIFY_DONE;

	switch (msg) {

	case NETDEV_UNREGISTER:
		lock_sock(sk);
		/* remove current filters & unregister */
		if (so->bound)
			can_rx_unregister(dev, so->telegram.rxid,so->telegram.rx_mask,
					  obd_tp_rcv_handler, sk);

		so->ifindex = 0;
		so->bound   = 0;
		release_sock(sk);

		sk->sk_err = ENODEV;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;

	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	}

	return NOTIFY_DONE;
}


static int obd_tp_init(struct sock *sk)
{
	struct obd_tp_sock *so = obd_tp_sk(sk);

	DBG("called");

	so->ifindex = 0;
	so->bound = 0;

	so->P2_CAN = 50000000;   //ns
	so->P2_CAN_EXT = 5;      //sec

	so->telegram.state = OBD_TP_IDLE;

	hrtimer_init(&so->rxtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	so->rxtimer.function = obd_tp_rx_timer_handler;

	tasklet_init(&so->rxtsklet, obd_tp_rx_timer_tsklet, (unsigned long)so);
	init_waitqueue_head(&so->wait);

	so->notifier.notifier_call = obd_tp_notifier;
	register_netdevice_notifier(&so->notifier);

	return 0;
}

static int obd_tp_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct obd_tp_sock *so = obd_tp_sk(sk);
	int ifindex;
	struct net_device *dev;
	int err = 0;
	int notify_enetdown = 0;

	DBG("called");

	if (len < sizeof(*addr))
		return -EINVAL;


	if (addr->can_addr.tp.tx_id & CAN_EFF_FLAG){
		//extended frame format (EFF)
		if ((addr->can_addr.tp.tx_id == (0x18DB33F1|CAN_EFF_FLAG)) || ((addr->can_addr.tp.tx_id & 0x18DA00F1) == 0x18DA00F1)){
		}
		else{
			//return -EINVAL;
			addr->can_addr.tp.tx_id = 0x18DB33F1|CAN_EFF_FLAG;
		}
	}
	else{
		//standard frame format (SFF)
		if ((addr->can_addr.tp.tx_id == 0x7DF) || ((addr->can_addr.tp.tx_id & 0x7E8) == 0x7E0)){
		}
		else{
			//return -EINVAL;
			addr->can_addr.tp.tx_id = 0x7DF;
		}
	}

	if (addr->can_addr.tp.tx_id & (CAN_ERR_FLAG | CAN_RTR_FLAG))
		return -EADDRNOTAVAIL;

	if (!addr->can_ifindex)
		return -ENODEV;

	lock_sock(sk);

	if (so->bound && addr->can_ifindex == so->ifindex)
		goto out;

	dev = dev_get_by_index(&init_net, addr->can_ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}
	if (dev->type != ARPHRD_CAN) {
		dev_put(dev);
		err = -ENODEV;
		goto out;
	}
	if (dev->mtu < CAN_MTU) {
		dev_put(dev);
		err = -EINVAL;
		goto out;
	}
	if (!(dev->flags & IFF_UP))
		notify_enetdown = 1;

	ifindex = dev->ifindex;

	if (so->bound) {
		/* unregister old filter */
		if (so->ifindex) {
			dev = dev_get_by_index(&init_net, so->ifindex);
			if (dev) {
				can_rx_unregister(dev, so->telegram.rxid,
						  so->telegram.rx_mask,
						  obd_tp_rcv_handler, sk);

				can_rx_unregister(dev,0x3FFFFFFF,
						0x3FFFFFFF,
						obd_tp_rcv_handler, sk);

				dev_put(dev);
			}
		}
	}

	//TODO:
	if (addr->can_addr.tp.tx_id & CAN_EFF_FLAG){
		so->telegram.rxid = 0x18DAF100 | CAN_EFF_FLAG;
		so->telegram.rx_mask = 0x9FFFFF00;
	}
	else{
		so->telegram.rxid = 0x7E8;
		so->telegram.rx_mask = 0x000007F8;
	}
	can_rx_register(dev, so->telegram.rxid,
			so->telegram.rx_mask,
			obd_tp_rcv_handler, sk, "obd_tp");

	//TODO: register for error frames
	can_rx_register(dev, 0x3FFFFFFF,
			0x3FFFFFFF,
			obd_tp_rcv_handler, sk, "obd_tp");

	dev_put(dev);

	/* switch to new settings */
	so->ifindex = ifindex;
	so->telegram.txid = addr->can_addr.tp.tx_id;
	so->bound = 1;

 out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static int obd_tp_setsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, unsigned int optlen)
#else
static int obd_tp_setsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int optlen)
#endif
{
	struct sock *sk = sock->sk;
	struct obd_tp_sock *so = obd_tp_sk(sk);
	int ret = 0;
	struct net_device *dev;
	canid_t new_tx_canid;

	DBG("called");

	if (level != SOL_CAN_OBD)
		return -EINVAL;
	if (optlen < 0)
		return -EINVAL;

	switch (optname) {

	case CAN_OBD_RX_P2_CAN:
		//P2_CAN in ms
		if (optlen != sizeof(unsigned long))
			return -EINVAL;

		if (copy_from_user(&so->P2_CAN, optval, optlen))
			return -EFAULT;

		if(so->P2_CAN == 0){
			so->P2_CAN = 50000000;
		}
		else{
			//so->P2_CAN *= 1e6;  // danger of overflow
		}
		DBG("new P2_CAN = %lu",so->P2_CAN);
		break;

	case CAN_OBD_RX_P2_CAN_EXT:
		//P2_CAN_EXT in s
		if (optlen != sizeof(long))
			return -EINVAL;

		if (copy_from_user(&so->P2_CAN_EXT, optval, optlen))
			return -EFAULT;

		if(so->P2_CAN_EXT <= 0){
			so->P2_CAN_EXT = 5;
		}

		DBG("new P2_CAN_EXT = %lu",so->P2_CAN_EXT);
		break;

	case CAN_OBD_TX_CANID:
		if (optlen != sizeof(canid_t))
			return -EINVAL;
		else{

			if (copy_from_user(&new_tx_canid, optval, optlen))
				return -EFAULT;

			DBG("new tx can id = 0x%x",new_tx_canid);

			if (new_tx_canid & CAN_EFF_FLAG){
				//extended frame format (EFF)
				if ((new_tx_canid == (0x18DB33F1|CAN_EFF_FLAG)) || ((new_tx_canid & 0x18DA00F1) == 0x18DA00F1)){
					so->telegram.txid = new_tx_canid;
				}
				else{
					return -EINVAL;
				}
			}
			else{
				//standard frame format (SFF)
				if ((new_tx_canid == 0x7DF) || ((new_tx_canid & 0x7E8) == 0x7E0)){
					so->telegram.txid = new_tx_canid;
				}
				else{
					return -EINVAL;
				}
			}

			//unregister old frames
			dev = dev_get_by_index(&init_net, so->ifindex);

			if (!dev) {
				return -EFAULT;
			}
			can_rx_unregister(dev, so->telegram.rxid,
						so->telegram.rx_mask,
						obd_tp_rcv_handler, sk);

			dev_put(dev);

			//TODO:
			//register for new frames
			if (so->telegram.txid & CAN_EFF_FLAG){
				so->telegram.rxid = 0x18DAF100 | CAN_EFF_FLAG;
				so->telegram.rx_mask = 0x9FFFFF00;
				DBG("registered for EFF");
			}
			else{
				so->telegram.rxid = 0x7E8;
				so->telegram.rx_mask = 0x000007F8;
				DBG("registered for SFF");
			}
			can_rx_register(dev, so->telegram.rxid,
							so->telegram.rx_mask,
							obd_tp_rcv_handler, sk, "obd_tp");

			dev_put(dev);

		}
		break;

	default:
		ret = -ENOPROTOOPT;
	}

	DBG("new parameter: tx=0x%x rx_masked=0x%x p2can=%lu p2canext=%lu",so->telegram.txid,(so->telegram.rxid&so->telegram.rx_mask),so->P2_CAN,so->P2_CAN_EXT);

	return ret;
}

static int obd_tp_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct obd_tp_sock *so = obd_tp_sk(sk);
	int len;
	void *val;
	u64 timediff;

	DBG("called");

	if (level != SOL_CAN_OBD)
		return -EINVAL;
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {

	case CAN_OBD_RX_P2_CAN:
		len = min_t(int, len, sizeof(unsigned long));
		val = &so->P2_CAN;
		break;

	case CAN_OBD_RX_P2_CAN_EXT:
		len = min_t(int, len, sizeof(long));
		val = &so->P2_CAN_EXT;
		break;

	case CAN_OBD_TX_CANID:
		len = min_t(int, len, sizeof(canid_t));
		val = &so->telegram.txid;
		break;

	case CAN_OBD_TIMEDIFF:
		timediff = ktime_to_ns(ktime_sub(so->telegram.last_rx,so->telegram.tx));
		DBG("ktimediff=%lld",timediff);
		len = min_t(int, len, sizeof(u64));
		val = &timediff;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, val, len))
		return -EFAULT;
	return 0;
}

static int obd_tp_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct obd_tp_sock *so = obd_tp_sk(sk);

	DBG("called");

	if (peer)
		return -EOPNOTSUPP;

	addr->can_family  = AF_CAN;
	addr->can_ifindex = so->ifindex;

	*len = sizeof(*addr);

	return 0;
}

static int obd_tp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct obd_tp_sock *so;

	DBG("called");

	if (!sk)
		return 0;

	so = obd_tp_sk(sk);

	/* wait for complete transmission of current pdu */
	wait_event_interruptible(so->wait, so->telegram.state == OBD_TP_IDLE);

	unregister_netdevice_notifier(&so->notifier);

	lock_sock(sk);

	hrtimer_cancel(&so->rxtimer);
	tasklet_kill(&so->rxtsklet);

	/* remove current filters & unregister */
	if (so->bound) {
		if (so->ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(&init_net, so->ifindex);
			if (dev) {
				can_rx_unregister(dev, so->telegram.rxid,
						  so->telegram.rx_mask,
						  obd_tp_rcv_handler, sk);

				can_rx_unregister(dev, CAN_ERR_FLAG,
						CAN_ERR_FLAG,
						obd_tp_rcv_handler, sk);

				dev_put(dev);
			}
		}
	}

	so->ifindex = 0;
	so->bound   = 0;

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}



static const struct proto_ops obd_tp_ops = {
	.family        = PF_CAN,
	.release       = obd_tp_release,
	.bind          = obd_tp_bind,
	.connect       = sock_no_connect,
	.socketpair    = sock_no_socketpair,
	.accept        = sock_no_accept,
	.getname       = obd_tp_getname,
	.poll          = datagram_poll,
	.ioctl         = can_ioctl,	/* use can_ioctl() from af_can.c */
	.listen        = sock_no_listen,
	.shutdown      = sock_no_shutdown,
	.setsockopt    = obd_tp_setsockopt,
	.getsockopt    = obd_tp_getsockopt,
	.sendmsg       = obd_tp_sendmsg,
	.recvmsg       = obd_tp_recvmsg,
	.mmap          = sock_no_mmap,
	.sendpage      = sock_no_sendpage,
};

static struct proto obd_tp_proto __read_mostly = {
	.name       = "CAN_OBD",
	.owner      = THIS_MODULE,
	.obj_size   = sizeof(struct obd_tp_sock),
	.init       = obd_tp_init,
};

static const struct can_proto obd_tp_can_proto = {
	.type       = SOCK_DGRAM,
	.protocol   = CAN_OBD,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	.capability = -1,
#endif
	.ops        = &obd_tp_ops,
	.prot       = &obd_tp_proto,
};

static __init int obd_module_init(void)
{
	int err;

	printk(banner);

	err = can_proto_register(&obd_tp_can_proto);
	if (err < 0)
		printk(KERN_ERR "can: registration of obd transport protocol failed\n");

	return err;
}

static __exit void obd_module_exit(void)
{
	can_proto_unregister(&obd_tp_can_proto);
}

module_init(obd_module_init);
module_exit(obd_module_exit);
