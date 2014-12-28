/**
 * @file
 * Egress encoder/decoder for ipv6
 */
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * fields for ipv6
 */
enum {
    EG_ENC_IPV6_VER = 1,
    EG_ENC_IPV6_TC,
    EG_ENC_IPV6_FLOWLABEL,
    EG_ENC_IPV6_LENGTH,
    EG_ENC_IPV6_HOPLIMIT,
    EG_ENC_IPV6_NEXTHEADER,
    EG_ENC_IPV6_SRCADDR,
    EG_ENC_IPV6_DSTADDR,
};

/**
 * field encoder for ipv6
 */
static eg_enc_encoder_t eg_enc_ipv6_field_encoders[] = {
    {
        .id = EG_ENC_IPV6_VER,
        .name = "VER",
        .desc = "version (default: 6)",
    },
    {
        .id = EG_ENC_IPV6_TC,
        .name = "TRAFFICCLASS",
        .desc = "traffic class",
    },
    {
        .id = EG_ENC_IPV6_FLOWLABEL,
        .name = "FLOWLABEL",
        .desc = "flow label",
    },
    {

        .id = EG_ENC_IPV6_LENGTH,
        .name = "LENGTH",
        .desc = "length (default: auto)",
    },
    {
        .id = EG_ENC_IPV6_HOPLIMIT,
        .name = "HOPLIMIT",
        .desc = "hop limit",
    },
    {
        .id = EG_ENC_IPV6_NEXTHEADER,
        .name = "NEXTHEADER",
        .desc = "next header (default: auto)",
    },
    {
        .id = EG_ENC_IPV6_SRCADDR,
        .name = "SRCADDR",
        .desc = "source address",
    },
    {
        .id = EG_ENC_IPV6_DSTADDR,
        .name = "DSTADDR",
        .desc = "destination address",
    },
    {}
};

/**
 * block encoders under ipv6
 */
static eg_enc_encoder_t eg_enc_ipv6_block_encoders[] = {
    {
        .name = "TCP",
        .desc = "TCP",
        .encode = eg_enc_encode_tcp,
    },
    {
        .name = "UDP",
        .desc = "UDP",
        .encode = eg_enc_encode_udp,
    },
    {
        .name = "IPV4",
        .desc = "IPv4",
        .encode = eg_enc_encode_ipv4,
    },
    {
        .name = "IPV6",
        .desc = "IPv6",
        .encode = eg_enc_encode_ipv6,
    },
    {
        .name = "ICMPV6",
        .desc = "ICMPv6",
        .encode = eg_enc_encode_icmpv6,
    },

    /* alias */
    {
        .name = "IP",
        .encode = eg_enc_encode_ipv4,
    },
    {}
};

/**
 * IPv6 protocol definition
 */
static eg_enc_vals_t ipv6protocols[] = {
    {
        .name = "ICMPV6",
        .desc = "ICMPv6",
        .val = IPPROTO_ICMPV6,
    },
    {
        .name = "TCP",
        .desc = "TCP",
        .val = IPPROTO_TCP,
    },
    {
        .name = "UDP",
        .desc = "UDP",
        .val = IPPROTO_UDP,
    },
    {},
};

#define AUTOFLAG_PLEN   (1 << 0)
#define AUTOFLAG_NH     (1 << 1)

/**
 * encode IPv6
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_ipv6(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf, *bufn;
    struct ip6_hdr *ip6h;
    int hlen = sizeof(*ip6h);
    u_int32_t num;
    u_int32_t autoflags = (AUTOFLAG_PLEN | AUTOFLAG_NH);    /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*ip6h));
    if (buf == NULL) {
        return NULL;
    }
    ip6h = (struct ip6_hdr *)buf->ptr;

    memset(ip6h, 0, sizeof(*ip6h));
    ip6h->ip6_vfc = 6 << 4;
    ip6h->ip6_hlim = 128;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ipv6_field_encoders);
        switch (enc->id) {
        case EG_ENC_IPV6_VER:
            ret = eg_enc_encode_uint(&num, elem->val, 0, 0xf);
            ip6h->ip6_vfc &= ~(0xf << 4);
            ip6h->ip6_vfc = (u_int8_t)(num << 4);
            break;
        case EG_ENC_IPV6_TC:
            ret = eg_enc_encode_uint(&num, elem->val, 0, 0xff);
            ip6h->ip6_flow &= ~htonl(0xff << 20);
            ip6h->ip6_flow |= htonl((u_int32_t)(num << 20));
            break;
        case EG_ENC_IPV6_FLOWLABEL:
            ret = eg_enc_encode_uint(&num, elem->val, 0, 0xfffff);
            ip6h->ip6_flow &= ~htonl(0xfffff);
            ip6h->ip6_flow |= htonl((u_int32_t)num);
            break;
        case EG_ENC_IPV6_LENGTH:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_PLEN;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_PLEN;
                ret = eg_enc_encode_uint16(&ip6h->ip6_plen, elem->val);
            }
            break;
        case EG_ENC_IPV6_HOPLIMIT:
            ret = eg_enc_encode_uint8(&ip6h->ip6_hlim, elem->val);
            break;
        case EG_ENC_IPV6_NEXTHEADER:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_NH;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_NH;
                if (elem->val->type == EG_TYPE_KEYWORD) {
                    ret = eg_enc_encode_name_uint8(&ip6h->ip6_nxt, elem->val, ipv6protocols);
                } else {
                    ret = eg_enc_encode_uint8(&ip6h->ip6_nxt, elem->val);
                }
            }
            break;
        case EG_ENC_IPV6_SRCADDR:
            ret = eg_enc_encode_ipv6addr(&ip6h->ip6_src, elem->val);
            break;
        case EG_ENC_IPV6_DSTADDR:
            ret = eg_enc_encode_ipv6addr(&ip6h->ip6_dst, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ipv6_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, ip6h);
        if (bufn == NULL) {
            goto err;
        }
        /* auto fill next header */
        if (autoflags & AUTOFLAG_NH) {
            autoflags &= ~AUTOFLAG_NH;
            eg_elem_val_t v;
            v.str = elem->name;
            eg_enc_encode_name_uint8(&ip6h->ip6_nxt, &v, ipv6protocols);
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix payload length */
    if (autoflags & AUTOFLAG_PLEN) {
        ip6h->ip6_plen = htons(buf->len - hlen);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
