#ifdef __linux__
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef USE_NETLIB
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <arpa/inet.h>

#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include "defines.h"
#ifdef USE_NETLIB
#include <netlib.h>
#endif

#include "check.h"
#include "lib.h"

struct pseudo_header {
  in_addr_t saddr;
  in_addr_t daddr;
  pkt_uint8 zero;
  pkt_uint8 protocol;
  pkt_uint16 len;
};

struct pseudo6_header {
  struct in6_addr saddr;
  struct in6_addr daddr;
  pkt_uint32 len;
  pkt_uint8 zero[3];
  pkt_uint8 nexthdr;
};

static int check_arp(unsigned long flags, char *buffer, int size)
{
  struct arphdr arphdr;
  char *p;

  if (size < sizeof(arphdr))
    return -1;
  memcpy(&arphdr, buffer, sizeof(arphdr));

  if (size < sizeof(struct arphdr) + arphdr.ar_hln * 2 + arphdr.ar_pln * 2)
    return -1;

  p = buffer + sizeof(struct arphdr);

  size = p - buffer;

  return size;
}

static int check_icmp(unsigned long flags, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  if (size < total_size)
    return -1;

  if (flags & PKT_CHECK_FLAG_CHECKSUM) {
    /* This is compatible with FreeBSD */
    if (ip_checksum(icmphdr, total_size) != 0xffff)
      return -1;
  }

  s = sizeof(*icmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int check_igmp(unsigned long flags, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  if (size < total_size)
    return -1;

  if (flags & PKT_CHECK_FLAG_CHECKSUM) {
    /* This is compatible with FreeBSD */
    if (ip_checksum(igmphdr, sizeof(struct igmp)) != 0xffff)
      return -1;
  }

  s = sizeof(*igmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int check_tcp(unsigned long flags, char *buffer, int size, int total_size, int pchksum)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;
  unsigned short sum[2];

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  if (size < total_size)
    return -1;

  if (flags & PKT_CHECK_FLAG_CHECKSUM) {
    /* This is compatible with FreeBSD */
    sum[0] = pchksum; /* Unneed htons() */
    sum[1] = ip_checksum(tcphdr, total_size); /* Unneed htons() */
    if (ip_checksum(sum, 4) != 0xffff)
      return -1;
  }

  s = sizeof(*tcphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int check_udp(unsigned long flags, char *buffer, int size, int total_size, int pchksum)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;
  unsigned short sum[2];

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  if (size < total_size)
    return -1;

  if (flags & PKT_CHECK_FLAG_CHECKSUM) {
    /* This is compatible with FreeBSD */
    if (udphdr->uh_sum != 0) {
      sum[0] = pchksum; /* Unneed htons() */
      sum[1] = ip_checksum(udphdr, total_size); /* Unneed htons() */
      if (ip_checksum(sum, 4) != 0xffff)
	return -1;
    }
  }

  s = sizeof(*udphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int check_ip(unsigned long flags, char *buffer, int size)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip *iphdr;
  int hdrsize, paysize;
  struct pseudo_header phdr;
  int pchksum;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  memset(&phdr, 0, sizeof(phdr));
  phdr.saddr = iphdr->ip_src.s_addr;
  phdr.daddr = iphdr->ip_dst.s_addr;
  phdr.protocol = iphdr->ip_p;
  phdr.len = htons(paysize);
  pchksum = ip_checksum(&phdr, sizeof(phdr));

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = check_icmp(flags, p, s, paysize); break;
    case IPPROTO_IGMP: r = check_igmp(flags, p, s, paysize); break;
    case IPPROTO_TCP:  r = check_tcp( flags, p, s, paysize, pchksum); break;
    case IPPROTO_UDP:  r = check_udp( flags, p, s, paysize, pchksum); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  if (size < hdrsize)
    return -1;

  if (flags & PKT_CHECK_FLAG_CHECKSUM) {
    /* This is compatible with FreeBSD */
    if (ip_checksum(iphdr, hdrsize) != 0xffff)
      return -1;
  }

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  memcpy(buffer, pktbuf, r);

  return r;
}

static int check_icmp6(unsigned long flags, char *buffer, int size, int total_size, int pchksum)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;
  unsigned short sum[2];

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  if (size < total_size)
    return -1;

  if (flags & PKT_CHECK_FLAG_CHECKSUM) {
    /* This is compatible with FreeBSD */
    sum[0] = pchksum; /* Unneed htons() */
    sum[1] = ip_checksum(icmp6hdr, total_size); /* Unneed htons() */
    if (ip_checksum(sum, 4) != 0xffff)
      return -1;
  }

  s = sizeof(*icmp6hdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int check_ip6(unsigned long flags, char *buffer, int size)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip6_hdr *ip6hdr;
  int hdrsize, paysize;
  int nexthdr, exthdrsize;
  struct ip6_ext *ip6exthdr;
  struct ip6_rthdr *ip6rthdr;
  struct ip6_frag *ip6fraghdr = NULL;
  struct pseudo6_header phdr;
  int pchksum;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*ip6hdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  ip6hdr = (struct ip6_hdr *)pktbuf;

  hdrsize = sizeof(struct ip6_hdr);
  paysize = ntohs(ip6hdr->ip6_plen);

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;

  while (1) {
    exthdrsize = 0;
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
      if (s < sizeof(*ip6exthdr))
	return -1;
      ip6exthdr = (struct ip6_ext *)p;
      nexthdr = ip6exthdr->ip6e_nxt;
      exthdrsize = (ip6exthdr->ip6e_len + 1) << 3;
      break;
    case IPPROTO_ROUTING:
      if (s < sizeof(*ip6rthdr))
	return -1;
      ip6rthdr = (struct ip6_rthdr *)p;
      nexthdr = ip6rthdr->ip6r_nxt;
      exthdrsize = (ip6rthdr->ip6r_len + 1) << 3;
      break;
    case IPPROTO_FRAGMENT:
      if (s < sizeof(*ip6fraghdr))
	return -1;
      ip6fraghdr = (struct ip6_frag *)p;
      nexthdr = ip6fraghdr->ip6f_nxt;
      exthdrsize = sizeof(*ip6fraghdr);
      break;
    case IPPROTO_NONE:
    default:
      break;
    }
    if (exthdrsize == 0)
      break;
    if (s < exthdrsize)
      return -1;
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
  }

  memset(&phdr, 0, sizeof(phdr));
  memcpy(&phdr.saddr, &ip6hdr->ip6_src, sizeof(struct in6_addr));
  memcpy(&phdr.daddr, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
  phdr.len = htonl(paysize);
  phdr.nexthdr = nexthdr;
  pchksum = ip_checksum(&phdr, sizeof(phdr));

  if (ip6fraghdr == NULL) {
    switch (nexthdr) {
    case IPPROTO_ICMPV6: r = check_icmp6(flags, p, s, paysize, pchksum); break;
    case IPPROTO_TCP:    r = check_tcp(  flags, p, s, paysize, pchksum); break;
    case IPPROTO_UDP:    r = check_udp(  flags, p, s, paysize, pchksum); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  memcpy(buffer, pktbuf, r);

  return r;
}

int pkt_check_ethernet(unsigned long flags, char *buffer, int size)
{
  char *p;
  int s, r = 0;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;

  if (size < ETHER_HDR_LEN)
    return -1;
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  type = ntohs(ehdr.ether_type);
  p = buffer + ETHER_HDR_LEN;
  s = size   - ETHER_HDR_LEN;

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

  while (type == ETHERTYPE_VLAN) {
    if (s < sizeof(vlantag))
      return -1;
    memcpy(&vlantag, p, sizeof(vlantag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  ehdr.ether_type = htons(type);

  switch (type) {
  case ETHERTYPE_ARP:  r = check_arp(flags, p, s); break;
  case ETHERTYPE_IP:   r = check_ip( flags, p, s); break;
  case ETHERTYPE_IPV6: r = check_ip6(flags, p, s); break;
  default: break;
  }

  if (r < 0)
    return r;

  if (p > buffer + ETHER_HDR_LEN) {
    memcpy(&vlantag, p - sizeof(vlantag), sizeof(vlantag));
    vlantag.proto = ehdr.ether_type;
    memcpy(p - sizeof(vlantag), &vlantag, sizeof(vlantag));
    ehdr.ether_type = htons(ETHERTYPE_VLAN);
  }

  memcpy(buffer, &ehdr, ETHER_HDR_LEN);

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}
