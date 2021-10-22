+++
title = "Kernel GRE bug post-mortem"
date = 2021-07-27
+++
[GRE](https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation) is lightweight and stateless tunneling protocol that rides over a network protocol (IPv4/6), and can encapsulate either a another network layer (L3-GRE), or another link layer (L2-GRE).
When the next layer is another link layer, the interface is referred to as `gretap` in Linux.

A GRE tunnel is defined by a remote endpoint and a "key", which is used to differentiate distinct tunnels between the same 2 endpoints.
You can think of the key like a UDP/TCP port, in essence, just for GRE

Like any other network interface, it can also have a network address assigned to it.

When a userspace program sends a packet/frame through a GRE interface, the kernel prepands it with a GRE header with the matching key, and sends *that* over the underlying link to the remote endpoint.

![f](/imgs/packet-build.png)

On the destination endpoint, the kernel peels the different layers and uses the key to deliver
the data to the correct endpoint.

![f](/imgs/packet-peel.png)
