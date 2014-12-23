/**
 * @file
 * Egress encoder/decoder for ipv4
 */
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * fields for ipv4
 */
enum {
    EG_ENC_IPV4_VER = 1,
    EG_ENC_IPV4_HLEN,
    EG_ENC_IPV4_TOS,
    EG_ENC_IPV4_LENGTH,
    EG_ENC_IPV4_ID,
    EG_ENC_IPV4_FLAGS,
    EG_ENC_IPV4_OFFSET,
    EG_ENC_IPV4_TTL,
    EG_ENC_IPV4_PROTO,
    EG_ENC_IPV4_CHECKSUM,
    EG_ENC_IPV4_SRCIP,
    EG_ENC_IPV4_DSTIP,
    EG_ENC_IPV4_OPTION,
};

/**
 * field encoder for ipv4
 */
static eg_enc_encoder_t eg_enc_ipv4_field_encoders[] = {
    {
        .id = EG_ENC_IPV4_VER,
        .name = "VER",
        .desc = "version (default: 4)"
    },
    {
        .id = EG_ENC_IPV4_HLEN,
        .name = "HLEN",
        .desc = "header length (default: auto)"
    },
    {
        .id = EG_ENC_IPV4_TOS,
        .name = "TOS",
        .desc = "type of service"
    },
    {
        .id = EG_ENC_IPV4_LENGTH,
        .name = "LENGTH",
        .desc = "length (default: auto)"
    },
    {
        .id = EG_ENC_IPV4_ID,
        .name = "ID",
        .desc = "identification"
    },
    {
        .id = EG_ENC_IPV4_FLAGS,
        .name = "FLAGS",
        .desc = "flags"
    },
    {
        .id = EG_ENC_IPV4_OFFSET,
        .name = "OFFSET",
        .desc = "offset"
    },
    {
        .id = EG_ENC_IPV4_TTL,
        .name = "TTL",
        .desc = "time to live"
    },
    {
        .id = EG_ENC_IPV4_PROTO,
        .name = "PROTOCOL",
        .desc = "protocol (default: auto)"
    },
    {
        .id = EG_ENC_IPV4_CHECKSUM,
        .name = "CHECKSUM",
        .desc = "checksum (default: auto)"
    },
    {
        .id = EG_ENC_IPV4_SRCIP,
        .name = "SRC",
        .desc = "source address"
    },
    {
        .id = EG_ENC_IPV4_DSTIP,
        .name = "DSTIP",
        .desc = "destination address"
    },

    /* alias */
    { .name = "DLENGTH",            .id = EG_ENC_IPV4_LENGTH,       },
    { .name = "SRCADDR",            .id = EG_ENC_IPV4_SRCIP,        },
    { .name = "SRCIP",              .id = EG_ENC_IPV4_SRCIP,        },
    { .name = "SRCIPV4",            .id = EG_ENC_IPV4_SRCIP,        },
    { .name = "DSTADDR",            .id = EG_ENC_IPV4_DSTIP,        },
    { .name = "DSTIP",              .id = EG_ENC_IPV4_DSTIP,        },
    { .name = "DSTIPV4",            .id = EG_ENC_IPV4_DSTIP,        },
    {}
};

/**
 * block encoders under ipv4
 */
static eg_enc_encoder_t eg_enc_ipv4_block_encoders[] = {
    {
        .id = EG_ENC_IPV4_OPTION,
        .name = "OPTION",
        .desc = "IPv4 option",
        .func = eg_enc_encode_ipv4opt,
    },

    {
        .name = "ICMP",
        .desc = "ICMP",
        .func = eg_enc_encode_icmp,
    },
    {
        .name = "TCP",
        .desc = "TCP",
        .func = eg_enc_encode_tcp,
    },
    {
        .name = "UDP",
        .desc = "UDP",
        .func = eg_enc_encode_udp,
    },
    {
        .name = "IPV4",
        .desc = "IPv4",
        .func = eg_enc_encode_ipv4,
    },
    {
        .name = "IPV6",
        .desc = "IPv6",
        .func = eg_enc_encode_ipv6,
    },

    /* alias */
    { .name = "IP",                 .func = eg_enc_encode_ipv4,     },
    {}
};

/**
 * IPv4 protocol definition
 */
static eg_enc_name_t ipv4protocols[] = {
    { "ICMP",               IPPROTO_ICMP            },
    { "TCP",                IPPROTO_TCP             },
    { "UDP",                IPPROTO_UDP             },
    {},
};

/**
 * IPv4 flags definition
 */
static eg_enc_flags_t ipv4flags[] = {
    { "RF",     IP_RF   },
    { "DF",     IP_DF   },
    { "MF",     IP_MF   },
    {},
};

#define AUTOFLAG_HLEN   (1 << 0)
#define AUTOFLAG_DLEN   (1 << 1)
#define AUTOFLAG_CSUM   (1 << 2)
#define AUTOFLAG_PROT   (1 << 3)
#define AUTOFLAG_PAD    (1 << 4)

/**
 * encode IPv4
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_ipv4(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf, *bufn;
    struct ip *ip4h;
    int hlen = sizeof(*ip4h);
    u_int32_t autoflags = (AUTOFLAG_HLEN | AUTOFLAG_DLEN | AUTOFLAG_CSUM | AUTOFLAG_PROT | AUTOFLAG_PAD);  /* auto flags */
    u_int16_t flag;
    u_int32_t num;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int optlen = 0;
    int len;
    int ret;

    buf = eg_buffer_create(sizeof(*ip4h));
    if (buf == NULL) {
        return NULL;
    }
    ip4h = (struct ip *)buf->ptr;

    memset(ip4h, 0, sizeof(*ip4h));
    ip4h->ip_v = 4;
    ip4h->ip_ttl = 0x80;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ipv4_field_encoders);
        switch (enc->id) {
        case EG_ENC_IPV4_VER:
            ret = eg_enc_encode_uint(&num, elem->val, 0, 0x0f);
            ip4h->ip_v = num;
            break;
        case EG_ENC_IPV4_HLEN:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_HLEN;
                ret = 0;
            } else {
                ret = eg_enc_encode_uint(&num, elem->val, 0, 0x0f);
                ip4h->ip_hl = num;
                autoflags &= ~AUTOFLAG_HLEN;
            }
            break;
        case EG_ENC_IPV4_TOS:
            ret = eg_enc_encode_uint8(&ip4h->ip_tos, elem->val);
            break;
        case EG_ENC_IPV4_LENGTH:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_DLEN;
                ret = 0;
            } else {
                ret = eg_enc_encode_uint16(&ip4h->ip_len, elem->val);
                autoflags &= ~AUTOFLAG_DLEN;
            }
            break;
        case EG_ENC_IPV4_ID:
            ret = eg_enc_encode_uint16(&ip4h->ip_id, elem->val);
            break;
        case EG_ENC_IPV4_FLAGS:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags_uint16(&flag, elem->val, ipv4flags);
            } else {
                ret = eg_enc_encode_uint(&num, elem->val, 0, 7);
                flag = (u_int16_t)num;
            }
            ip4h->ip_off |= flag;
            break;
        case EG_ENC_IPV4_OFFSET:
            ret = eg_enc_encode_uint(&num, elem->val, 0, 0x1fff);
            ip4h->ip_off |= num;
            break;
        case EG_ENC_IPV4_TTL:
            ret = eg_enc_encode_uint8(&ip4h->ip_ttl, elem->val);
            break;
        case EG_ENC_IPV4_PROTO:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_PROT;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_PROT;
                if (elem->val->type == EG_TYPE_KEYWORD) {
                    ret = eg_enc_encode_name_uint8(&ip4h->ip_p, elem->val, ipv4protocols);
                } else {
                    ret = eg_enc_encode_uint8(&ip4h->ip_p, elem->val);
                }
            }
            break;
        case EG_ENC_IPV4_CHECKSUM:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_CSUM;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_CSUM;
                ret = eg_enc_encode_uint16(&ip4h->ip_sum, elem->val);
            }
            break;
        case EG_ENC_IPV4_SRCIP:
            ret = eg_enc_encode_ipv4addr(&ip4h->ip_src, elem->val);
            break;
        case EG_ENC_IPV4_DSTIP:
            ret = eg_enc_encode_ipv4addr(&ip4h->ip_dst, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ipv4_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->func(elem->elems, ip4h);
        if (bufn == NULL) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IPV4_OPTION:
            /* insert IPv4 option */
            len = bufn->len;
            buf = eg_buffer_merge(buf, bufn, sizeof(*ip4h) + optlen);
            optlen += len;
            break;
        default:
            /* auto fill protocol */
            if (autoflags & AUTOFLAG_PROT) {
                autoflags &= ~AUTOFLAG_PROT;
                eg_elem_val_t v;
                v.str = elem->name;
                eg_enc_encode_name_uint8(&ip4h->ip_p, &v, ipv4protocols);
            }
            buf = eg_buffer_merge(buf, bufn, -1);
            break;
        }
    }

#if 1
    if (optlen > 0) {
        /* insert IPv4 option padding */
        if (autoflags & AUTOFLAG_PAD) {
            if ((optlen % 4) > 0) {
                buf = eg_buffer_merge(buf, eg_buffer_create(4 - (optlen % 4)), sizeof(*ip4h) + optlen);
                optlen += 4 - (optlen % 4);
            }
        }
        hlen += optlen;
    }
#endif

    /* fix header length */
    if (autoflags & AUTOFLAG_HLEN) {
        ip4h->ip_hl = hlen >> 2;
    }

    /* fix datagram length */
    if (autoflags & AUTOFLAG_DLEN) {
        ip4h->ip_len = htons(buf->len);
    }

    /* fix checksum */
    if (autoflags & AUTOFLAG_CSUM) {
        ip4h->ip_sum = 0;
        ip4h->ip_sum = htons((u_int16_t)~ip_checksum(ip4h, hlen));
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * fields for ipv4 option
 */
enum {
    EG_ENC_IPV4OPT_TYPE = 1,
    EG_ENC_IPV4OPT_LEN,
    EG_ENC_IPV4OPT_DATA,
};

/**
 * field encoder for ipv4 option
 */
static eg_enc_encoder_t eg_enc_ipv4opt_field_encoders[] = {
    {
        .id = EG_ENC_IPV4OPT_TYPE,
        .name = "TYPE",
        .desc = "IPv4 option type"
    },
    {
        .id = EG_ENC_IPV4OPT_LEN,
        .name = "LENGTH",
        .desc = "IPv4 option length"
    },
    {
        .id = EG_ENC_IPV4OPT_DATA,
        .name = "DATA",
        .desc = "IPv4 option data"
    },
    {}
};

#define AUTOFLAG_OPTLEN (1 << 8)

/**
 * encode IPv4 option
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_ipv4opt(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf;
    u_int32_t autoflags = (AUTOFLAG_OPTLEN);  /* auto flags */
    int datalen = 0;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(256);
    if (buf == NULL) {
        return NULL;
    }

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ipv4opt_field_encoders);
        switch (enc->id) {
        case EG_ENC_IPV4OPT_TYPE:
            ret = eg_enc_encode_uint8(buf->ptr, elem->val);
            break;
        case EG_ENC_IPV4OPT_LEN:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_OPTLEN;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_OPTLEN;
                ret = eg_enc_encode_uint8(buf->ptr + 1, elem->val);
            }
            break;
        case EG_ENC_IPV4OPT_DATA:
            ret = eg_enc_encode_hex(buf->ptr + 2, elem->val, 0, 254);
            datalen = ret;
            break;
        default:
            goto err;
        }
        if (ret < 0) {
            goto err;
        }
    }

    /* fix option length */
    if (autoflags & AUTOFLAG_OPTLEN) {
        *(buf->ptr + 1) = 2 + datalen; /* type + len + data */
    }

    /* fix buffer length */
    if (*(buf->ptr) < 2) {
        buf->len = 1; /* no length */
    } else {
        buf->len = 2 + datalen; /* type + len + data */
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
