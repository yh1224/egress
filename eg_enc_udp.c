/**
 * @file
 * Egress encoder/decoder for udp
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * fields for udp
 */
enum {
    EG_ENC_UDP_SRCPORT = 1,
    EG_ENC_UDP_DSTPORT,
    EG_ENC_UDP_LENGTH,
    EG_ENC_UDP_CHECKSUM,
};

/**
 * field encoder for udp
 */
static eg_enc_encoder_t eg_enc_udp_field_encoders[] = {
    {
        .id = EG_ENC_UDP_SRCPORT,
        .name = "SRCPORT",
        .desc = "source port"
    },
    {
        .id = EG_ENC_UDP_DSTPORT,
        .name = "DSTPORT",
        .desc = "destination port"
    },
    {
        .id = EG_ENC_UDP_LENGTH,
        .name = "LENGTH",
        .desc = "length (default: auto)"
    },
    {
        .id = EG_ENC_UDP_CHECKSUM,
        .name = "CHECKSUM",
        .desc = "checksum (default: auto)"
    },
    {}
};

/**
 * block encoders under udp
 */
static eg_enc_encoder_t eg_enc_udp_block_encoders[] = {
    {
        .name = "PAYLOAD",
        .desc = "payload",
        .func = eg_enc_encode_raw,
    },
    {}
};

/**
 * pseudo header for calculate IPv4 UDP checksum
 */
struct ipv4_pseudo_header {
    struct in_addr src;
    struct in_addr dst;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t len;
};

/**
 * pseudo header for calculate IPv6 UDP checksum
 */
struct ipv6_pseudo_header {
    struct in6_addr src;
    struct in6_addr dst;
    u_int32_t plen;
    u_int8_t zero[3];
    u_int8_t nxt;
};

#define AUTOFLAG_LENGTH (1 << 0)
#define AUTOFLAG_CSUM   (1 << 1)

/**
 * encode UDP
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_udp(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf, *bufn;
    struct udphdr *udph;
    int len = sizeof(*udph);
    u_int32_t autoflags = (AUTOFLAG_LENGTH | AUTOFLAG_CSUM);   /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*udph));
    if (buf == NULL) {
        return NULL;
    }
    udph = (struct udphdr *)buf->ptr;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_udp_field_encoders);
        switch (enc->id) {
        case EG_ENC_UDP_SRCPORT:
            ret = eg_enc_encode_uint16(&udph->uh_sport, elem->val);
            break;
        case EG_ENC_UDP_DSTPORT:
            ret = eg_enc_encode_uint16(&udph->uh_dport, elem->val);
            break;
        case EG_ENC_UDP_LENGTH:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_LENGTH;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_LENGTH;
                ret = eg_enc_encode_uint16(&udph->uh_ulen, elem->val);
            }
            break;
        case EG_ENC_UDP_CHECKSUM:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_CSUM;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_CSUM;
                ret = eg_enc_encode_uint16(&udph->uh_sum, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_udp_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->func(elem->elems, udph);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix UDP length */
    if (autoflags & AUTOFLAG_LENGTH) {
        udph->uh_ulen = htobe16((u_int16_t)len);
    }

    /* fix UDP checksum */
    if (autoflags & AUTOFLAG_CSUM) {
        if (upper) {
            struct ip *iph = (struct ip *)upper;
            struct ip6_hdr *ip6h = (struct ip6_hdr *)upper;
            if (iph->ip_v == 4) {
                /* IPv4 */
                struct ipv4_pseudo_header phdr;
                memset(&phdr, 0, sizeof(phdr));
                phdr.src = iph->ip_src;
                phdr.dst = iph->ip_dst;
                phdr.protocol = IPPROTO_UDP;
                phdr.len = htons(len);
                udph->uh_sum = htobe16(ip_checksum(&phdr, sizeof(phdr)));
                udph->uh_sum = htobe16(~ip_checksum(udph, len));
            } else if (iph->ip_v == 6) {
                /* IPv6 */
                struct ipv6_pseudo_header phdr;
                memset(&phdr, 0, sizeof(phdr));
                phdr.src = ip6h->ip6_src;
                phdr.dst = ip6h->ip6_dst;
                phdr.plen = htobe32(len);
                phdr.nxt = IPPROTO_UDP;
                udph->uh_sum = htobe16(ip_checksum(&phdr, sizeof(phdr)));
                udph->uh_sum = htobe16(~ip_checksum(udph, len));
            }
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}