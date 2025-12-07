# BitNix: A Kernel-Level Bitcoin P2P Monitoring Module

BitNix is a **Linux kernel module** designed to study and observe Bitcoin peer-to-peer (P2P) network behaviour at the kernel level.
It leverages the Netfilter framework to identify and analyse TCP traffic on Bitcoin’s default P2P port (8333),
enabling low-level inspection of Bitcoin networking activity without relying on user-space packet sniffers.

This project was implemented and tested in a **Debian 13 Virtual Machine (VirtualBox) on macOS Intel hardware**,
as part of research into operating-system-level visibility of decentralized protocols.



## Abstract

Bitcoin operates as a decentralized peer-to-peer network where communication between nodes occurs over TCP port 8333.
Traditional analysis of Bitcoin network traffic is typically conducted using user-space monitoring tools such as Wireshark or tcpdump.

This research proposes an alternate approach: **kernel-level traffic monitoring**,
providing earlier-stage packet interception, 
reduced user-space overhead, 
and greater OS-level visibility. 

By integrating with Netfilter hooks, BitNix demonstrates real-time detection, classification, and logging of Bitcoin-relevant network traffic.

This project explores the feasibility, efficiency, and research implications of monitoring decentralized protocol traffic in the Linux kernel.


## Contributions

- Design and implementation of a **Netfilter-based Bitcoin traffic detector**.
- Kernel-level tracking of outgoing Bitcoin packets.
- Unique peer identification without reliance on user-space tools.
- A `/proc/bitnix` interface for safe, user-space access to kernel data.
- Demonstration of Bitcoin kernel-network behaviour inside a controlled VM environment.


## Sys. Arch.

 Component and Role 

 **Linux Kernel Module** - Hooks into Netfilter to monitor TCP traffic 
 **Netfilter (LOCAL_OUT & PRE_ROUTING)** - Captures outbound and inbound Bitcoin packets 
 **Atomic counters** -  Tracks packet statistics 
 **Spinlocks** - Protects shared peer-table memory 
 **/proc filesystem** - Exposes metrics to user space 


**Target Port:** `8333`  
**Max peer list:** `64` entries  
**Tracking:** Per-IP, IPv4 only (v0.2)


## Environment

VirtualBox, Debian 13, Bitcoin Core installed using snapd.

## How to Run

## Installation

```bash
# Clone repository
git clone https://github.com/<your-username>/bitnix.git
cd bitnix/kernel

# Build module
make

# Load module (as root)
sudo insmod bitnix.ko

# Check kernel log
sudo dmesg -w
```

#PS: I had to run a node locally to see the packets in action, I tried public facing nodes but there was no network handshake to confirm the connection. because of the very secure nature of Bitcoin's Blockchain, which this was tested on.
