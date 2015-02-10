/**
 * @file
 * Egress encoder/decoder for icmp
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

static eg_buffer_t *eg_enc_encode_icmp_echo(eg_elem_t *elems, void *lower);

/**
 * fields for icmp
 */
enum {
    EG_ENC_ICMP_TYPE = 1,
    EG_ENC_ICMP_CODE,
    EG_ENC_ICMP_CHECKSUM,
    EG_ENC_ICMP_ID,
    EG_ENC_ICMP_SEQUENCE,
    EG_ENC_ICMP_GATEWAY,
    EG_ENC_ICMP_MTU,

    EG_ENC_ICMP_ECHO,
    EG_ENC_ICMP_DATA,
};

/**
 * field encoder for icmp
 */
static eg_enc_encoder_t eg_enc_icmp_field_encoders[] = {
    {
        .id = EG_ENC_ICMP_TYPE,
        .name = "TYPE",
        .desc = "type",
    },
    {
        .id = EG_ENC_ICMP_CODE,
        .name = "CODE",
        .desc = "code",
    },
    {
        .id = EG_ENC_ICMP_CHECKSUM,
        .name = "CHECKSUM",
        .desc = "checksum",
    },
    {}
};

/**
 * field encoder for icmp echo request/response
 */
static eg_enc_encoder_t eg_enc_icmp_echo_field_encoders[] = {
    /* echo datagram */
    {
        .id = EG_ENC_ICMP_ID,
        .name = "ID",
        .desc = "ID",
    },
    {
        .id = EG_ENC_ICMP_SEQUENCE,
        .name = "SEQUENCE",
        .desc = "sequence",
    },
    {}
};

/**
 * block encoder for icmp
 */
static eg_enc_encoder_t eg_enc_icmp_block_encoders[] = {
    {
        .id = EG_ENC_ICMP_ECHO,
        .name = "ECHO",
        .desc = "ICMP echo request/response",
        .encode = eg_enc_encode_icmp_echo,
    },
    {
        .id = EG_ENC_ICMP_DATA,
        .name = "DATA",
        .desc = "ICMP data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * ICMP type definition
 */
static eg_enc_vals_t icmptypes[] = {
    {
        .name = "ECHOREPLY",
        .desc = "echo reply",
        .val = ICMP_ECHOREPLY, /* 0 */
    },
    {
        .name = "UNREACH",
        .desc = "destination unreachable",
        .val = ICMP_UNREACH, /* 3 */
    },
    {
        .name = "SOURCEQUENCH",
        .desc = "source quench",
        .val = ICMP_SOURCEQUENCH, /* 4 */
    },
    {
        .name = "REDIRECT",
        .desc = "redirect (change route)",
        .val = ICMP_REDIRECT, /* 5 */
    },
    {
        .name = "ECHO",
        .desc = "echo request",
        .val = ICMP_ECHO, /* 8 */
    },
    {
        .name = "ROUTERADVERT",
        .desc = "router advertisement",
        .val = ICMP_ROUTERADVERT, /* 9 */
    },
    {
        .name = "ROUTERSOLICIT",
        .desc = "router solicitation",
        .val = ICMP_ROUTERSOLICIT, /* 10 */
    },
    {
        .name = "TIMXCEED",
        .desc = "time exceeded",
        .val = ICMP_TIMXCEED, /* 11 */
    },
    {
        .name = "PARAMPROB",
        .desc = "parameter problem",
        .val = ICMP_PARAMPROB, /* 12 */
    },
    {
        .name = "TSTAMP",
        .desc = "timestamp request",
        .val = ICMP_TSTAMP, /* 13 */
    },
    {
        .name = "TSTAMPREPLY",
        .desc = "timestamp reply",
        .val = ICMP_TSTAMPREPLY, /* 14 */
    },
    {
        .name = "IREQ",
        .desc = "information request",
        .val = ICMP_IREQ, /* 15 */
    },
    {
        .name = "IREQREPLY",
        .desc = "information reply",
        .val = ICMP_IREQREPLY, /* 16 */
    },
    {
        .name = "MASKREQ",
        .desc = "address mask request",
        .val = ICMP_MASKREQ, /* 17 */
    },
    {
        .name = "MASKREPLY",
        .desc = "address mask reply",
        .val = ICMP_MASKREPLY, /* 18 */
    },
    {},
};

/**
 * ICMP code definition
 */
static eg_enc_vals_t icmpcodes[] = {
    {
        .name = "UNREACH_NET",
        .desc = "network unreachable",
        .val = ICMP_UNREACH_NET, /* 0 */
    },
    {
        .name = "UNREACH_HOST",
        .desc = "host unreachable",
        .val = ICMP_UNREACH_HOST, /* 1 */
    },
    {
        .name = "UNREACH_PROTOCOL",
        .desc = "protocol unreachable",
        .val = ICMP_UNREACH_PROTOCOL, /* 2 */
    },
    {
        .name = "UNREACH_PORT",
        .desc = "port unreachable",
        .val = ICMP_UNREACH_PORT, /* 3 */
    },
    {
        .name = "UNREACH_NEEDFRAG",
        .desc = "fragmentation needed/DF set",
        .val = ICMP_UNREACH_NEEDFRAG, /* 4 */
    },
    {
        .name = "UNREACH_SRCFAIL",
        .desc = "source route failed",
        .val = ICMP_UNREACH_SRCFAIL, /* 5 */
    },
    {
        .name = "UNREACH_NET_UNKNOWN",
        .desc = "net unknown",
        .val = ICMP_UNREACH_NET_UNKNOWN, /* 6 */
    },
    {
        .name = "UNREACH_HOST_UNKNOWN",
        .desc = "host unknwon",
        .val = ICMP_UNREACH_HOST_UNKNOWN, /* 7 */
    },
    {
        .name = "UNREACH_ISOLATED",
        .desc = "src host isolated",
        .val = ICMP_UNREACH_ISOLATED, /* 8 */
    },
    {
        .name = "UNREACH_NET_PROHIB",
        .desc = "net denied",
        .val = ICMP_UNREACH_NET_PROHIB, /* 9 */
    },
    {
        .name = "ICMP_UNREACH_HOST_PROHIB",
        .desc = "host denied",
        .val = ICMP_UNREACH_HOST_PROHIB, /* 10 */
    },
    {
        .name = "UNREACH_TOSNET",
        .desc = "bad tos for net",
        .val = ICMP_UNREACH_TOSNET, /* 11 */
    },
    {
        .name = "UNREACH_TOSHOST",
        .desc = "bad tos for host",
        .val = ICMP_UNREACH_TOSHOST, /* 12 */
    },
    {
        .name = "ICMP_UNREACH_FILTER_PROHIB",
        .desc = "admin prohibited/packet filtered",
        .val = ICMP_UNREACH_FILTER_PROHIB, /* 13 */
    },
    {
        .name = "UNREACH_HOST_PRECEDENCE",
        .desc = "host precedence violation",
        .val = ICMP_UNREACH_HOST_PRECEDENCE, /* 14 */
    },
    {
        .name = "UNREACH_PRECEDENCE_CUTOFF",
        .desc = "precedence cut off",
        .val = ICMP_UNREACH_PRECEDENCE_CUTOFF, /* 15 */
    },

    /* Codes for REDIRECT. */
    {
        .name = "REDIRECT_NET",
        .desc = "redirect net",
        .val = ICMP_REDIRECT_NET, /* 0 */
    },
    {
        .name = "REDIRECT_HOST",
        .desc = "redirect host",
        .val = ICMP_REDIRECT_HOST, /* 1 */
    },
    {
        .name = "REDIRECT_TOSNET",
        .desc = "redirect net for TOS",
        .val = ICMP_REDIRECT_TOSNET, /* 2 */
    },
    {
        .name = "REDIRECT_TOSHOST",
        .desc = "redirect host for TOS",
        .val = ICMP_REDIRECT_TOSHOST, /* 3 */
    },

    /* Codes for TIME_EXCEEDED. */
    {
        .name = "TIMXCEED_INTRANS",
        .desc = "TTL count exceeded in transit",
        .val = ICMP_TIMXCEED_INTRANS, /* 0 */
    },
    {
        .name = "TIMXCEED_REASS",
        .desc = "fragment reass time exceeded",
        .val = ICMP_TIMXCEED_REASS, /* 1 */
    },

    /* Codes for PARAMPROB. */
    {
        .name = "PARAMPROB_OPTABSENT",
        .desc = "req. opt. absent",
        .val = ICMP_PARAMPROB_OPTABSENT, /* 1 */
    },
    {},
};

/**
 * encode ICMP echo request/response
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmp_echo(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(4);
    if (buf == NULL) {
        return NULL;
    }

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmp_echo_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMP_ID:
            ret = eg_enc_encode_uint16((u_int16_t *)buf->ptr, elem->val);
            break;
        case EG_ENC_ICMP_SEQUENCE:
            ret = eg_enc_encode_uint16((u_int16_t *)(buf->ptr + 2), elem->val);
            break;
        default:
            goto err;
        }
        if (ret < 0) {
            goto err;
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * encode ICMP
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_icmp(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct icmp *icmph;
    int hlen = 4;
#define AUTOFLAG_CSUM   (1 << 0)
    u_int32_t autoflags = (AUTOFLAG_CSUM);  /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int len;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    icmph = (struct icmp *)buf->ptr;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmp_field_encoders);
        switch (enc->id) {
        case EG_ENC_ICMP_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(&icmph->icmp_type, elem->val, icmptypes);
            } else {
                ret = eg_enc_encode_uint8(&icmph->icmp_type, elem->val);
            }
            break;
        case EG_ENC_ICMP_CODE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(&icmph->icmp_code, elem->val, icmpcodes);
            } else {
                ret = eg_enc_encode_uint8(&icmph->icmp_code, elem->val);
            }
            break;
        case EG_ENC_ICMP_CHECKSUM:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_CSUM;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_CSUM;
                ret = eg_enc_encode_uint16(&icmph->icmp_cksum, elem->val);
            }
            break;
        default:
            goto err;
        }
        if (ret < 0) {
            goto err;
        }
    }

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmp_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, icmph);
        if (bufn == NULL) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMP_DATA:
            buf = eg_buffer_merge(buf, bufn, -1);
            break;
        default:
            /* insert extra header field */
            len = bufn->len;
            buf = eg_buffer_merge(buf, bufn, hlen);
            hlen += len;
            break;
        }
    }

    /* fix ICMP checksum */
    if (autoflags & AUTOFLAG_CSUM) {
        if (lower) {
            struct ip *iph = (struct ip *)lower;
            struct ip6_hdr *ip6h = (struct ip6_hdr *)lower;
            if (iph->ip_v == 4) {
                /* IPv4 */
                icmph->icmp_cksum = htons(~ip_checksum(icmph, buf->len));
            } else if (iph->ip_v == 6) {
                /* IPv6 */
                struct ipv6_pseudo_header phdr;
                memset(&phdr, 0, sizeof(phdr));
                phdr.src = ip6h->ip6_src;
                phdr.dst = ip6h->ip6_dst;
                phdr.plen = htonl(buf->len);
                phdr.nxt = IPPROTO_ICMPV6;
                icmph->icmp_cksum = htons(ip_checksum(&phdr, sizeof(phdr)));
                icmph->icmp_cksum = htons(~ip_checksum(icmph, buf->len));
            }
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
