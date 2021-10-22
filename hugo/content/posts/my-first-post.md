---
title: "Kernel GRE bug post-mortem"
date: 2021-07-27T15:27:57+03:00
draft: false
disableComments: true
---


At the time of writing this post, I am part of the Infra group of [Drivenets](https://drivenets.com/).
Some time ago we started to upgrade our Ubuntu machines at work to the latest LTS, Ubuntu 20.04.

For a few weeks, everything was fine; but peace is only ever temporary.

![badly drawn jira ticket with title "very bug i don’t have IPv4 traffic on some of our machines this is a very real bug title oh boi"](/images/bug-report.png "A real screenshot")

*just* ipv4, but *all* ipv4?

Oh no.

## Initial Analysis ##

Arriving to the crime scene, there were clear signs of foul play.

We make heavy usage of L2-[GRE](https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation)s in some of our products,
usually assigning them a MAC address matching one of an actual physical interface somewhere.

A cursory glance at `tcpdump`'s output for the faulty GRE interface shows that IPv4 traffic *does* reach us, and it even _seems_ to have the correct MAC and IP addresses.
Why would the kernel ignore this ICMP request?

```python
19:05:17.680821 18:be:92:a0:6c:06 > 18:bd:92:a0:ee:26, IPv4, length 98: (tos 0x0, ttl ...
    130.130.130.1 > 130.130.130.2: ICMP echo request, id 20718, seq 1, length 64
```

Oh wait 😯 both mac addresses are slightly wrong; no wonder the kernel drops these.
If we inspect the packet as it gets sent...
```python
22:29:49.000231 18:be:92:a0:6c:05 > 18:be:92:a0:ee:26, IPv4, length 98: (tos 0x0, ttl ...
    130.130.130.1 > 130.130.130.2: ICMP echo request, id 20718, seq 1, length 64
```

> "well boss, I found the problem, we're off by 3 bits —
> 
> — oh, I also have to fix that?"

## First Clue ##

After contemplating my existence for a bit, trying to figure out if life is worth debugging this, I started opening various log files.

Running `dmesg`, I saw an endless stream of
```dmesg
[78005.657058] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78005.657127] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78005.657170] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78005.657252] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78005.657884] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78010.657871] net_ratelimit: 10 callbacks suppressed
[78010.657873] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78010.657887] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78010.657922] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78010.657971] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78010.658008] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
[78010.658035] ip_tunnel: non-ECT from 10.254.3.1 with TOS=0x1
```

Suspicious. When is this logged?
After cloning vanilla Linux kernel and checking out the v5.4 tag, I found the source:

```c
// net/ipv4/ip_tunnel.c ~L393
    skb_reset_network_header(skb);

    err = IP_ECN_decapsulate(iph, skb);
    if (unlikely(err)) {
        if (log_ecn_error)
            net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
                    &iph->saddr, iph->tos);
        if (err > 1) {
            ++tunnel->dev->stats.rx_frame_errors;
            ++tunnel->dev->stats.rx_errors;
            goto drop;
        }
    }
```

Going further into `IP_ECN_decapsulate`: (skipping a few layers for brevity)
```c
/*
 * RFC 6040 4.2
 *  To decapsulate the inner header at the tunnel egress, a compliant
 *  tunnel egress MUST set the outgoing ECN field to the codepoint at the
 *  intersection of the appropriate arriving inner header (row) and outer
 *  header (column) in Figure 4
 *
 *      +---------+------------------------------------------------+
 *      |Arriving |            Arriving Outer Header               |
 *      |   Inner +---------+------------+------------+------------+
 *      |  Header | Not-ECT | ECT(0)     | ECT(1)     |     CE     |
 *      +---------+---------+------------+------------+------------+
 *      | Not-ECT | Not-ECT |Not-ECT(!!!)|Not-ECT(!!!)| <drop>(!!!)|
 *      |  ECT(0) |  ECT(0) | ECT(0)     | ECT(1)     |     CE     |
 *      |  ECT(1) |  ECT(1) | ECT(1) (!) | ECT(1)     |     CE     |
 *      |    CE   |      CE |     CE     |     CE(!!!)|     CE     |
 *      +---------+---------+------------+------------+------------+
 *
 *             Figure 4: New IP in IP Decapsulation Behaviour
 *
 *  returns 0 on success
 *          1 if something is broken and should be logged (!!! above)
 *          2 if packet should be dropped
 */
static inline int __INET_ECN_decapsulate(__u8 outer, __u8 inner, bool *set_ce)
{
    if (INET_ECN_is_not_ect(inner)) {
        switch (outer & INET_ECN_MASK) {
        case INET_ECN_NOT_ECT:
            return 0;
        case INET_ECN_ECT_0:
        case INET_ECN_ECT_1:
            return 1;
        case INET_ECN_CE:
            return 2;
        }
    }

    *set_ce = INET_ECN_is_ce(outer);
    return 0;
}
```

So it looks like that in order for the log to be triggered, the inner IPv4 header's ECT bits
need to be 0, and the outer's need to be either ECT, or CE.

*What are those terms, anyway?*

[ECN](https://en.wikipedia.org/wiki/Explicit_Congestion_Notification), or Explicit Congestion Notification, is a network feature that is used between routers to notify of
congestion.

ECT stands for ECN-Capabale-Transport.

In the IP header, the lower 2bits of the TOS field are used to indicate one of the following:
 - 00 - Non ECN-Capable Transport, Non-ECT
 - 10 - ECN Capable Transport, ECT(0)
 - 01 - ECN Capable Transport, ECT(1)
 - 11 - Congestion Encountered, CE.

So when a packet arrives where the external header has any bits set, and the internal one has none, we would see this log.
It seems to happen quite a lot, and it was easily verified with tcpdump:
**All packets** had `ECT(1)` on the outer header and `Non-ECT` on the inner.

This alone, however, should not cause traffic to drop.
Sorry, slip of the tongue - traffic wasn't dropped, per se, and you could see no trace of drops in `ip -s link`.

## Minimal reproducer ##

Well, nothing more could be done on a production environment.
Our product is too large and complex - our logs' SNR is too low.

Time to try and reproduce this in a vaccum:

```bash
$ ip netns add A
$ ip netns add B
$ ip -n A link add _v0 type veth peer name _v1 netns B
$ ip -n A link set _v0 up
$ ip -n A addr add dev _v0 10.254.3.1/24
$ ip -n A route add default dev _v0 scope global
$ ip -n B link set _v1 up
$ ip -n B addr add dev _v1 10.254.1.6/24
$ ip -n B route add default dev _v1 scope global
$ ip -n B link add gre1 type gretap local 10.254.1.6 remote 10.254.3.1 key 0x49000000
$ ip -n B link set gre1 up

# Now send an IPv4/GRE/Eth/IPv4 frame where the outer header has ECT(1),
# and the inner header has no ECT bits set:

$ cat send_pkt.py
    #!/usr/bin/env python3
    from scapy.all import *

    pkt = IP(b'E\x01\x00\xa7\x00\x00\x00\x00@/`%\n\xfe\x03\x01\n\xfe\x01\x06 \x00eXI\x00'
             b'\x00\x00\x18\xbe\x92\xa0\xee&\x18\xb0\x92\xa0l&\x08\x00E\x00\x00}\x8b\x85'
             b'@\x00\x01\x01\xe4\xf2\x82\x82\x82\x01\x82\x82\x82\x02\x08\x00d\x11\xa6\xeb'
             b'3\x1e\x1e\\xf3\\xf7`\x00\x00\x00\x00ZN\x00\x00\x00\x00\x00\x00\x10\x11\x12'
             b'\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\ ()*+,-./01234'
             b'56789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ')

    send(pkt)
$ sudo ip netns exec B tcpdump -neqlllvi gre1 icmp & ; sleep 1
$ sudo ip netns exec A python3 send_pkt.py
```

This packet is an `IPv4/GRE/Ethernet/IPv4/ICMP(echo request)` packet - a ping over an L2-GRE.
Sure enough, this was enough to trigger this bug on my Ubuntu 20.04 machine (Kernel v5.4), and on a few of my friends' machines (Kernel v5.12).

Running this script on the previous version of Ubuntu we used, 18.04 (Kernel 4.15), did not trigger the bug.

Want to try it yourself? If `tcpdump` reports a packet with a destination of `18:be:92:a0:ee:26`, you're golden.
If you see `18:bd:92:a0:ee:26` instead; oh well.

## What a coincidence ##

Haha, what are the chances? The bits in the destination MAC address that were overriden are in the same offset within the ethernet address as the ECT bits are in the IPv4 header

```
 Ethernet Header
┌─────────────────────────┬────────────────────────── - - -
│Dest (6B)                │Src (6B)
│                         │
└─────────────────────────┴────────────────────────── - - -
 IPv4 Header
┌───┬──────────┬───────────────────────────────────── - - -
│Ver│TOS       │
│1B │(2B)      │
└───┴──────────┴───────────────────────────────────── - - -
```

That's obviously related, but we couldn't find anything related to it in the code we've inspected.

## Finding the culprit ##
So now we now we know that somewhere between Ubuntu 18.04 and Ubuntu 20.04, or more precisely, between kernel versions 4.15 and 5.4,
someone submitted a patch introducing this bug.

We started by looking at `git log --grep=' ECT' v4.15...v5.4`'s output, and certainly found some interesting stuff,
but nothing that would explain the bug.

Before going further into code-reading mode, we wanted to narrow down the bug's location even further, so we set up some vagrant boxes and
found that Ubuntu 19.04 (Kernel Version 5.0) is free of the bug, and that Ubuntu 19.10 (5.3) is already bugged.

Can we narrow it down even further with minimal effort, without going over the code?

<span title="Narrator: they couldn't" style="border-bottom: 1px dotted #000;">Sure we can!</span>
Ubuntu even supplies [this handy guide](https://wiki.ubuntu.com/Kernel/MainlineBuilds) for installing *mainline* kernel versions.

Starting with an Ubuntu 19.04 we started to upgrade our kernel version minor-by-minor, waiting for the bug to reproduce.
 - 5.1: CLEAR!
 - 5.2: CLEAR!
 - 5.2.10: CLEAR!
 - 5.2.21: CLEAR!

Wow! v5.2.21 is the last version before v5.3.
```
$ git log --grep=' ECT' v5.2.21..v5.3
```
Nothing.

Out of curiosity, I went back to the vagrant box and installed the deb package for kernel v5.3, the one we know is bugged.

No reproduction.

v5.4? No reproduction.

What?...

## Ubuntu Kernel != Vanilla Kernel ##

Okay, so I've messed up.
You might have guessed it, but all of this time I've been operating under this implicit assumption
that the kernel that's shipped with with Ubuntu is the regular, mainline, vanilla, stock kernel.

Good ol' kernel.

But this is obviously false - Ubuntu's release model doesn't allow it to just upgrade any software to its next major version.
But if the software stays the same over time, it will not get any security fixes or bug fixes.
So Ubuntu's maintainers do what any reasonable maintainer does - they backport patchsets from newer kernel versions.

The kernels that come with Ubuntu out-of-the-box are patched, but the kernels that are provided in https://wiki.ubuntu.com/Kernel/MainlineBuilds, are, well, mainline.

So this bug, presumably, was either backported from a later version, or introduced by a botched application of a patch.

We also know that this bug was reproduced on my friends' machines (BTW they run Arch); both of them with newer kernels, so the latter option can be eliminated.

Time to keep bisecting.

**20 minutes later**

```bash
❯ git log --grep=' ECT' v5.6..v5.7
commit b723748750ece7d844cdf2f52c01d37f83387208
Author: Toke Høiland-Jørgensen <toke@redhat.com>
Date:   Mon Apr 27 16:11:05 2020 +0200

    tunnel: Propagate ECT(1) when decapsulating as recommended by RFC6040

    RFC 6040 recommends propagating an ECT(1) mark from an outer tunnel header
    to the inner header if that inner header is already marked as ECT(0). When
    RFC 6040 decapsulation was implemented, this case of propagation was not
    added. This simply appears to be an oversight, so let's fix that.

    Fixes: eccc1bb8d4b4 ("tunnel: drop packet if ECN present with not-ECT")
    Reported-by: Bob Briscoe <ietf@bobbriscoe.net>
    Reported-by: Olivier Tilmans <olivier.tilmans@nokia-bell-labs.com>
    Cc: Dave Taht <dave.taht@gmail.com>
    Cc: Stephen Hemminger <stephen@networkplumber.org>
    Signed-off-by: Toke Høiland-Jørgensen <toke@redhat.com>
    Signed-off-by: David S. Miller <davem@davemloft.net>
```

haha, hey there 👉👈

Well, the description does not fit our scenario exactly, if we look at the IPv4 headers.
But evidently the kernel doesn't look at the inner IPv4 header either, it looks at the Ethernet header.

Considering this, not much mystery is left:

When Toke's code is seeing our IPv4 packets, it tries to read the TOS field to extract the ECT bits.
Due to some confusion, it extracts the second byte of the destination MAC address, and later conditionally modifies it.

Since we set a different MAC address on the GRE depending on the machine we're running on, this bug would not reproduce in all setups.
IPv6 traffic is also presumably affected, it's just that the ECT bits are in a *slightly* different offset.

## Finding a fix ##
Enough talk, let's look at some code.

Toke's code modifies `IP_ECN_decapsulate` to apply the RFC6040 recommendation.
`IP_ECN_decapsulate` receives the outer ip-header as an argument, as well as an `struct sk_buff *skb`, from which it extracts the inner header.

An `skb` is a struct used inside the kernel to process packets. <sup>[[1]](http://vger.kernel.org/~davem/skb.html)</sup>
```
struct sk_buff {
/* members truncated */
    __be16          protocol;           // Current protocol in process
    __u16           transport_header;   // Offset to the transport header
    __u16           network_header;     // Offset to the network header
    __u16           mac_header;         // Offset to the mac header
/* members truncated */
    unsigned char       *head,          // Pointer to the start of the packet
                *data;                  // Cursor pointing to the current poisition in the buffer
/* members truncated */
};
```

Toke's using the `ip_hdr` function to extract the inner header from the skb:
```
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *)skb_network_header(skb);
}

// ...

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
    return skb->head + skb->network_header;
}
```

It looks like `skb->network_header` is set to the wrong offset in our case, where is that little set?
Oh, it turns out we've been here before:
```c
// net/ipv4/ip_tunnel.c ~L393
    skb_reset_network_header(skb); // <<<<<<<<<<<<
    // ^^^^^^^^^^^^^^^^^^^^^^^^^^

    err = IP_ECN_decapsulate(iph, skb);
    if (unlikely(err)) {
        if (log_ecn_error)
            net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
                    &iph->saddr, iph->tos);
        if (err > 1) {
            ++tunnel->dev->stats.rx_frame_errors;
            ++tunnel->dev->stats.rx_errors;
            goto drop;
        }
    }

// ...

// Gilad: Set the offset of the network header to the cursor
static inline void skb_reset_network_header(struct sk_buff *skb)
{
    skb->network_header = skb->data - skb->head;
}
```

At this point in the processing pipeline, the kernel just stripped the tunnel header and starts to process the next header.
When the tunnel is a regular L3-GRE (probably most of the time), the next header is a network header (IPv4/IPv6/etc.), so setting the network header offset to the cursor makes sense.

Since we use L2-GRE (probably rare), the next header is sadly, an Ethernet header, rendering this reset incorrect.
We need to make sure that the correct offset is set:
```diff
-	skb_reset_network_header(skb);
+	skb_set_network_header(skb, (tunnel->dev->type == ARPHRD_ETHER) ? ETH_HLEN : 0);
```

## tl;dr ##
Kernel got confused between headers; [patched via one line](https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=227adfb2b1df).

## The correct fix ##
A friend of m**I**ne which u**S**u**A**lly w**A**nts to remain anonymous, noti**C**ed that problem is a bit larger than that particular piece of code in `ip_tunnel.c`.

For a brief moment in the pipeline, the `skb` struct is invalid: `skb->protocol` tells us that the next protocol is IPv4, but `data` points to the start of the Ethernet header.

He proposed the following patch and asked me to send it to the mailing list, but sadly I'm too lazy to do so.
```diff
diff --git a/net/ipv4/ip_tunnel.c b/net/ipv4/ip_tunnel.c
index 0dca00745ac3..1bd14fa66d74 100644
--- a/net/ipv4/ip_tunnel.c
+++ b/net/ipv4/ip_tunnel.c
@@ -390,6 +390,19 @@ int ip_tunnel_rcv(struct ip_tunnel *tunnel, struct sk_buff *skb,
 		tunnel->i_seqno = ntohl(tpi->seq) + 1;
 	}
 
+	if (tunnel->dev->type == ARPHRD_ETHER) {
+		if (!pskb_may_pull(skb, ETH_HLEN)) {
+			tunnel->dev->stats.rx_length_errors++;
+			tunnel->dev->stats.rx_errors++;
+			goto drop;
+		}
+
+		skb->protocol = eth_type_trans(skb, tunnel->dev);
+		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
+	} else {
+		skb->dev = tunnel->dev;
+	}
+
 	skb_reset_network_header(skb);
 
 	err = IP_ECN_decapsulate(iph, skb);
@@ -407,13 +420,6 @@ int ip_tunnel_rcv(struct ip_tunnel *tunnel, struct sk_buff *skb,
 	dev_sw_netstats_rx_add(tunnel->dev, skb->len);
 	skb_scrub_packet(skb, !net_eq(tunnel->net, dev_net(tunnel->dev)));
 
-	if (tunnel->dev->type == ARPHRD_ETHER) {
-		skb->protocol = eth_type_trans(skb, tunnel->dev);
-		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
-	} else {
-		skb->dev = tunnel->dev;
-	}
-
 	if (tun_dst)
 		skb_dst_set(skb, (struct dst_entry *)tun_dst);
 
diff --git a/net/ipv4/ip_tunnel_core.c b/net/ipv4/ip_tunnel_core.c
index 6b2dc7b2b612..c9010cebb936 100644
--- a/net/ipv4/ip_tunnel_core.c
+++ b/net/ipv4/ip_tunnel_core.c
@@ -105,7 +105,7 @@ int __iptunnel_pull_header(struct sk_buff *skb, int hdr_len,
 
 		eh = (struct ethhdr *)skb->data;
 		if (likely(eth_proto_is_802_3(eh->h_proto)))
-			skb->protocol = eh->h_proto;
+			skb->protocol = htons(ETH_P_802_3);
 		else
 			skb->protocol = htons(ETH_P_802_2);
 
diff --git a/net/ipv6/ip6_tunnel.c b/net/ipv6/ip6_tunnel.c
index 322698d9fcf4..afeba4ebc6e2 100644
--- a/net/ipv6/ip6_tunnel.c
+++ b/net/ipv6/ip6_tunnel.c
@@ -822,8 +822,6 @@ static int __ip6_tnl_rcv(struct ip6_tnl *tunnel, struct sk_buff *skb,
 		tunnel->i_seqno = ntohl(tpi->seq) + 1;
 	}
 
-	skb->protocol = tpi->proto;
-
 	/* Warning: All skb pointers will be invalidated! */
 	if (tunnel->dev->type == ARPHRD_ETHER) {
 		if (!pskb_may_pull(skb, ETH_HLEN)) {
```