/*
 * NWEN302 Lab 1
 * Brendan Goodenough
 * 300289046
 *
 * Base code by David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap
 *
 * Usage:
 * 1) tcpdump -s0 -w - | ./sniffer -
 * -or-
 * 2) ./sniffer <some file captured from tcpdump or wireshark>
 *
 * References:
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h
 * https://www.eecis.udel.edu/~sunshine/expcs/code/pcap_packet_read.c
 * http://www.tcpdump.org/sniffex.c
 * https://dl.packetstormsecurity.net/sniffers/ipdump.c
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <pcap.h>
#include <stdio.h>

#define IPV4 4
#define IPV6 6
#define IPV4_SIZE 20
#define IPV6_SIZE 40

void print_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);
void print_tcp(const struct tcphdr *tcp);
void print_udp(const struct udphdr *udp);
void print_icmp(const struct icmphdr *icmp);
void print_icmp6(const struct icmp6hdr *icmp6);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
 * Prints a line of the packet.
 *
 * Based on: http://www.tcpdump.org/sniffex.c
 */
void print_line(const u_char *payload, int len, int offset) {
  int i;
  int gap;
  const u_char *ch;

  printf("%05d ", offset);

  ch = payload;
  for (i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;

    if (i == 7) {
      printf(" ");
    }
  }

  if (len < 8) {
    printf(" ");
  }

  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf(" ");
    }
  }
  printf(" ");

  ch = payload;
  for (i = 0; i < len; i++) {
    if (isprint(*ch)) {
      printf("%c", *ch);
    } else {
      printf(".");
    }
    ch++;
  }

  printf("\n");
}

/*
 * Prints the payload to the screen.
 *
 * Based on: http://www.tcpdump.org/sniffex.c
 */
void print_payload(const u_char *payload, int len) {
  int len_rem = len;
  int line_width = 16;
  int line_len;
  int offset = 0;
  const u_char *ch = payload;

  if (len <= 0) {
    return;
  }

  if (len <= line_width) {
    print_line(ch, len, offset);
    return;
  }

  for (;;) {
    line_len = line_width % len_rem;
    print_line(ch, line_len, offset);
    len_rem = len_rem - line_len;

    ch = ch + line_len;
    offset = offset + line_width;
    if (len_rem <= line_width) {
      print_line(ch, len_rem, offset);
      break;
    }
  }
}

/*
 * Prints TCP header information.
 */
void print_tcp(const struct tcphdr *tcp) {
  printf("Protocol: TCP\n");

  // Print source and destination ports
  printf("Source Port: %d\n", ntohs(tcp->source));
  printf("Destination Port: %d\n", ntohs(tcp->dest));
}

/*
 * Prints UDP header information.
 */
void print_udp(const struct udphdr *udp) {
  printf("Protocol: UDP\n");

  // Print source and destination ports
  printf("Source Port: %d\n", ntohs(udp->source));
  printf("Destination Port: %d\n", ntohs(udp->dest));
}

/*
 * Prints ICMP header information.
 */
void print_icmp(const struct icmphdr *icmp) {
  printf("Protocol: ICMP\n");
  char *type;

  // https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h
  switch (icmp->type) {
    case ICMP_ECHOREPLY:
      type = "Echo Reply";
      break;
    case ICMP_DEST_UNREACH:
      type = "Destination Unreachable";
      break;
    case ICMP_SOURCE_QUENCH:
      type = "Source Quench";
      break;
    case ICMP_REDIRECT:
      type = "Redirect (change route)";
      break;
    case ICMP_ECHO:
      type = "Echo Request";
      break;
    case ICMP_TIME_EXCEEDED:
      type = "Time Exceeded";
      break;
    case ICMP_PARAMETERPROB:
      type = "Parameter Problem";
      break;
    case ICMP_TIMESTAMP:
      type = "Timestamp Request";
      break;
    case ICMP_TIMESTAMPREPLY:
      type = "Timestamp Reply";
      break;
    case ICMP_INFO_REQUEST:
      type = "Information Request";
      break;
    case ICMP_INFO_REPLY:
      type = "Information Reply";
      break;
    case ICMP_ADDRESS:
      type = "Address Mask Request";
      break;
    case ICMP_ADDRESSREPLY:
      type = "Address Mask Reply";
      break;
    default:
      type = "Must've missed this one. Lol.";
      break;
  }

  printf("Type: %s\n", type);
}

/*
 * Print ICMPv6 header information.
 */
void print_icmp6(const struct icmp6hdr *icmp6) {
  printf("Protocol: ICMPv6\n");
  char *type;

  // https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmpv6.h
  switch (icmp6->icmp6_type) {
    case ICMP_ECHOREPLY:
      type = "Echo Reply";
      break;
    case ICMP_DEST_UNREACH:
      type = "Destination Unreachable";
      break;
    case ICMP_SOURCE_QUENCH:
      type = "Source Quench";
      break;
    case ICMP_REDIRECT:
      type = "Redirect (change route)";
      break;
    case ICMP_ECHO:
      type = "Echo Request";
      break;
    case ICMP_TIME_EXCEEDED:
      type = "Time Exceeded";
      break;
    case ICMP_PARAMETERPROB:
      type = "Parameter Problem";
      break;
    case ICMP_TIMESTAMP:
      type = "Timestamp Request";
      break;
    case ICMP_TIMESTAMPREPLY:
      type = "Timestamp Reply";
      break;
    case ICMP_INFO_REQUEST:
      type = "Information Request";
      break;
    case ICMP_INFO_REPLY:
      type = "Information Reply";
      break;
    case ICMP_ADDRESS:
      type = "Address Mask Request";
      break;
    case ICMP_ADDRESSREPLY:
      type = "Address Mask Reply";
      break;
    default:
      type = "Must've missed this one. Lol.";
      break;
  }

  printf("Type: %s\n", type);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  static int count = 1;

  struct ethhdr *ethernet;
  struct iphdr *ip;
  struct ipv6hdr *ipv6;
  struct in_addr src, dst;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct icmphdr *icmp;
  struct icmp6hdr *icmp6;

  char srcv6[INET6_ADDRSTRLEN];
  char dstv6[INET6_ADDRSTRLEN];
  char *payload;
  int size_tcp, size_udp;
  int size_payload;

  // Print packet number
  // http://www.tcpdump.org/sniffex.c
  printf("\nPacket #: %d\n", count);
  count++;

  ethernet = (struct ethhdr*)(packet);
  ip = (struct iphdr*)(packet + ETH_HLEN);
  ipv6 = (struct ipv6hdr*)(packet + ETH_HLEN);

  size_payload = 0;

  if (ip->version == IPV4) {
    printf("Type: IPv4\n");

    // Print source and destination addresses
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;
    printf("Source: %s\n", inet_ntoa(src));
    printf("Destination: %s\n", inet_ntoa(dst));

    size_payload = header->len;
    printf("Size Payload: %d\n", size_payload);

    // Determine packet protocol
    switch (ip->protocol) {
      case IPPROTO_IP:
      case IPPROTO_TCP:
        tcp = (struct tcphdr*)(packet + ETH_HLEN + IPV4_SIZE);
        size_payload = header->len - ETH_HLEN - IPV4_SIZE - (tcp->doff * 4);
        payload = (u_char *)(packet + ETH_HLEN + IPV4_SIZE + (tcp->doff * 4));

        print_tcp(tcp);
        break;
      case IPPROTO_UDP:
        udp = (struct udphdr*)(packet + ETH_HLEN + IPV4_SIZE);
        size_payload = header->len - ETH_HLEN - IPV4_SIZE - 8;
        payload = (u_char *)(packet + ETH_HLEN + IPV4_SIZE + 8);

        print_udp(udp);
        break;
      case IPPROTO_ICMP:
        icmp = (struct icmphdr*)(packet + ETH_HLEN + IPV4_SIZE);
        size_payload = header->len - ETH_HLEN - IPV4_SIZE;
        payload = (u_char *)(packet + ETH_HLEN + IPV4_SIZE);

        print_icmp(icmp);
        break;
      default:
        printf("Protocol: Unknown\n");
        size_payload = header->len - ETH_HLEN - IPV4_SIZE;
        payload = (u_char *)(packet + ETH_HLEN + IPV4_SIZE);
        break;
    }
  } else if (ip->version == IPV6) {
    printf("Type: IPv6\n");

    // http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html
    inet_ntop(AF_INET6, &ipv6->saddr, srcv6, sizeof(srcv6));
    inet_ntop(AF_INET6, &ipv6->daddr, dstv6, sizeof(dstv6));
    printf("Source: %s\n", srcv6);
    printf("Destination: %s\n", dstv6);

    switch (ipv6->nexthdr) {
      case IPPROTO_IP:
      case IPPROTO_TCP:
        tcp = (struct tcphdr*)(packet + ETH_HLEN + IPV6_SIZE);
        size_payload = header->len - ETH_HLEN - IPV6_SIZE - (tcp->doff * 4);
        payload = (u_char *)(packet + ETH_HLEN + IPV6_SIZE + (tcp->doff * 4));

        print_tcp(tcp);
        break;
      case IPPROTO_UDP:
        udp = (struct udphdr*)(packet + ETH_HLEN + IPV6_SIZE);
        size_payload = header->len - ETH_HLEN - IPV6_SIZE - 8;
        payload = (u_char *)(packet + ETH_HLEN + IPV6_SIZE + 8);

        print_udp(udp);
        break;
      case IPPROTO_ICMPV6:
        icmp6 = (struct icmp6hdr*)(packet + ETH_HLEN + IPV6_SIZE);
        size_payload = header->len - ETH_HLEN - IPV6_SIZE;
        payload = (u_char *)(packet + ETH_HLEN + IPV6_SIZE);

        print_icmp6(icmp6);
        break;
      default:
        printf("Protocol: Unknown\n");
        size_payload = header->len + ETH_HLEN - IPV6_SIZE;
        payload = (u_char *)(packet + ETH_HLEN + IPV6_SIZE);
        break;
    }
  }

  // Payload
  printf("\n");
  if (size_payload > 0) {
    printf("Payload (%d bytes):\n", size_payload);
    print_payload(payload, size_payload);
  }
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "Must have an argument, either a file name or '-'\n");
    return -1;
  }

  pcap_t *handle = pcap_open_offline(argv[1], NULL);
  pcap_loop(handle, 1024*1024, got_packet, NULL);
  pcap_close(handle);

  return 0;
}
