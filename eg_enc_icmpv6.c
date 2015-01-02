/**
 * @file
 * Egress encoder/decoder for icmp
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * fields for icmpv6
 */
enum {
    EG_ENC_ICMPV6_TYPE = 1,
    EG_ENC_ICMPV6_CODE,
    EG_ENC_ICMPV6_CHECKSUM,
    EG_ENC_ICMPV6_DATA,
};

/**
 * field encoder for icmpv6
 */
static eg_enc_encoder_t eg_enc_icmpv6_field_encoders[] = {
    {
        .id = EG_ENC_ICMPV6_TYPE,
        .name = "TYPE",
        .desc = "type",
    },
    {
        .id = EG_ENC_ICMPV6_CODE,
        .name = "CODE",
        .desc = "code",
    },
    {
        .id = EG_ENC_ICMPV6_CHECKSUM,
        .name = "CHECKSUM",
        .desc = "checksum",
    },
    {}
};

/**
 * block encoder for icmpv6
 */
static eg_enc_encoder_t eg_enc_icmpv6_block_encoders[] = {
    {
        .name = "DATA",
        .desc = "ICMPv6 data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * ICMPv6 type definition
 */
static eg_enc_vals_t icmpv6types[] = {
    {
        .name = "DST_UNREACH",
        .desc = "Destination Unreachable",
        .val = ICMP6_DST_UNREACH,
    },
    {
        .name = "PACKET_TOO_BIG",
        .desc = "Packet Too Big",
        .val = ICMP6_PACKET_TOO_BIG,
    },
    {
        .name = "TIME_EXCEEDED",
        .desc = "Time Exceeded",
        .val = ICMP6_TIME_EXCEEDED,
    },
    {
        .name = "PARAM_PROB",
        .desc = "Parameter Problem",
        .val = ICMP6_PARAM_PROB,
    },
    {
        .name = "ECHO_REQUEST",
        .desc = "Echo Request",
        .val = ICMP6_ECHO_REQUEST,
    },
    {
        .name = "ECHO_REPLY",
        .desc = "Echo Reply",
        .val = ICMP6_ECHO_REPLY,
    },
    {
        .name = "MLD_LISTENER_QUERY",
        .desc = "Multicast Listener Query",
        .val = MLD_LISTENER_QUERY,
    },
    {
        .name = "MLD_LISTENER_REPORT",
        .desc = "Multicast Listener Report",
        .val = MLD_LISTENER_REPORT,
    },
    {
        .name = "MLD_LISTENER_REDUCTION",
        .desc = "Multicast Listener Done",
        .val = MLD_LISTENER_REDUCTION,
    },
    {},
};

/**
 * ICMPv6 code definition
 */
static eg_enc_vals_t icmpv6codes[] = {
    /* Codes for DST_UNREACH. */
    {
        .name = "DST_UNREACH_NOROUTE",
        .desc = "no route to destination",
        .val = ICMP6_DST_UNREACH_NOROUTE,
    },
    {
        .name = "DST_UNREACH_ADMIN",
        .desc = "communication with destination administratively prohibited",
        .val = ICMP6_DST_UNREACH_ADMIN,
    },
    {
        .name = "DST_UNREACH_BEYONDSCOPE",
        .desc = "beyond scope of source address",
        .val = ICMP6_DST_UNREACH_BEYONDSCOPE,
    },
    {
        .name = "DST_UNREACH_ADDR",
        .desc = "address unreachable",
        .val = ICMP6_DST_UNREACH_ADDR,
    },
    {
        .name = "DST_UNREACH_NOPORT",
        .desc = "bad port",
        .val = ICMP6_DST_UNREACH_NOPORT,
    },

    /* Codes for TIME_EXCEEDED. */
    {
        .name = "TIME_EXCEED_TRANSIT",
        .desc = "Hop Limit == 0 in transit",
        .val = ICMP6_TIME_EXCEED_TRANSIT,
    },
    {
        .name = "TIME_EXCEED_REASSEMBLY",
        .desc = "Reassembly time out",
        .val = ICMP6_TIME_EXCEED_REASSEMBLY,
    },

    /* Codes for PARAM_PROB. */
    {
        .name = "PARAMPROB_HEADER",
        .desc = "erroneous header field",
        .val = ICMP6_PARAMPROB_HEADER,
    },
    {
        .name = "PARAMPROB_NEXTHEADER",
        .desc = "unrecognized Next Header",
        .val = ICMP6_PARAMPROB_NEXTHEADER,
    },
    {
        .name = "PARAMPROB_OPTION",
        .desc = "unrecognized IPv6 option",
        .val = ICMP6_PARAMPROB_OPTION,
    },
    {},
};

/**
 * encode ICMPv6
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_icmpv6(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf, *bufn;
    struct icmp6_hdr *icmp6h;
    int hlen = 4;
#define AUTOFLAG_CSUM   (1 << 0)
    u_int32_t autoflags = (AUTOFLAG_CSUM);  /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    icmp6h = (struct icmp6_hdr *)buf->ptr;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_field_encoders);
        switch (enc->id) {
        case EG_ENC_ICMPV6_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(&icmp6h->icmp6_type, elem->val, icmpv6types);
            } else {
                ret = eg_enc_encode_uint8(&icmp6h->icmp6_type, elem->val);
            }
            break;
        case EG_ENC_ICMPV6_CODE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(&icmp6h->icmp6_code, elem->val, icmpv6codes);
            } else {
                ret = eg_enc_encode_uint8(&icmp6h->icmp6_code, elem->val);
            }
            break;
        case EG_ENC_ICMPV6_CHECKSUM:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_CSUM;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_CSUM;
                ret = eg_enc_encode_uint16(&icmp6h->icmp6_cksum, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, icmp6h);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix ICMP checksum */
    if (autoflags & AUTOFLAG_CSUM) {
        if (upper) {
            struct ip *iph = (struct ip *)upper;
            struct ip6_hdr *ip6h = (struct ip6_hdr *)upper;
            if (iph->ip_v == 4) {
                /* IPv4 */
                icmp6h->icmp6_cksum = htons(~ip_checksum(icmp6h, buf->len));
            } else if (iph->ip_v == 6) {
                /* IPv6 */
                struct ipv6_pseudo_header phdr;
                memset(&phdr, 0, sizeof(phdr));
                phdr.src = ip6h->ip6_src;
                phdr.dst = ip6h->ip6_dst;
                phdr.plen = htonl(buf->len);
                phdr.nxt = IPPROTO_ICMPV6;
                icmp6h->icmp6_cksum = htons(ip_checksum(&phdr, sizeof(phdr)));
                icmp6h->icmp6_cksum = htons(~ip_checksum(icmp6h, buf->len));
            }
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
