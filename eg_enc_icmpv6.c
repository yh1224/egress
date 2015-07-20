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

static eg_buffer_t *eg_enc_encode_icmpv6_rs(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_icmpv6_ra(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_icmpv6_ns(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_icmpv6_na(eg_elem_t *elems, void *lower);

/**
 * block encoder for icmpv6
 */
static eg_enc_encoder_t eg_enc_icmpv6_block_encoders[] = {
    {
        .name = "ND_NEIGHBOR_SOLICIT",
        .desc = "Neighbor Solicit",
        .encode = eg_enc_encode_icmpv6_ns,
    },
    {
        .name = "ND_NEIGHBOR_ADVERT",
        .desc = "Neighbor Advertisement",
        .encode = eg_enc_encode_icmpv6_na,
    },
    {
        .name = "ND_ROUTER_SOLICIT",
        .desc = "Router Solicit",
        .encode = eg_enc_encode_icmpv6_rs,
    },
    {
        .name = "ND_ROUTER_ADVERT",
        .desc = "Router Advertisement",
        .encode = eg_enc_encode_icmpv6_ra,
    },
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
        .val = ICMP6_DST_UNREACH, /* 1 */
    },
    {
        .name = "PACKET_TOO_BIG",
        .desc = "Packet Too Big",
        .val = ICMP6_PACKET_TOO_BIG, /* 2*/
    },
    {
        .name = "TIME_EXCEEDED",
        .desc = "Time Exceeded",
        .val = ICMP6_TIME_EXCEEDED, /* 3 */
    },
    {
        .name = "PARAM_PROB",
        .desc = "Parameter Problem",
        .val = ICMP6_PARAM_PROB, /* 4 */
    },
    {
        .name = "ECHO_REQUEST",
        .desc = "Echo Request",
        .val = ICMP6_ECHO_REQUEST, /* 128 */
    },
    {
        .name = "ECHO_REPLY",
        .desc = "Echo Reply",
        .val = ICMP6_ECHO_REPLY, /* 129 */
    },
    {
        .name = "MLD_LISTENER_QUERY",
        .desc = "Listener Query",
        .val = MLD_LISTENER_QUERY, /* 130 */
    },
    {
        .name = "MLD_LISTENER_REPORT",
        .desc = "Listener Report",
        .val = MLD_LISTENER_REPORT, /* 131 */
    },
    {
        .name = "MLD_LISTENER_REDUCTION",
        .desc = "Listener Done",
        .val = MLD_LISTENER_REDUCTION, /* 132 */
    },
    {
        .name = "ND_ROUTER_SOLICIT",
        .desc = "Router Solicit",
        .val = ND_ROUTER_SOLICIT, /* 133 */
    },
    {
        .name = "ND_ROUTER_ADVERT",
        .desc = "Router Advertisement",
        .val = ND_ROUTER_ADVERT, /* 134 */
    },
    {
        .name = "ND_NEIGHBOR_SOLICIT",
        .desc = "Neighbor Solicit",
        .val = ND_NEIGHBOR_SOLICIT, /* 135 */
    },
    {
        .name = "ND_NEIGHBOR_ADVERT",
        .desc = "Neighbor Advertisement",
        .val = ND_NEIGHBOR_ADVERT, /* 136 */
    },
    {
        .name = "ND_REDIRECT",
        .desc = "Redirect",
        .val = ND_REDIRECT, /* 137 */
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
        .val = ICMP6_DST_UNREACH_NOROUTE, /* 0 */
    },
    {
        .name = "DST_UNREACH_ADMIN",
        .desc = "communication with destination administratively prohibited",
        .val = ICMP6_DST_UNREACH_ADMIN, /* 1 */
    },
    {
        .name = "DST_UNREACH_BEYONDSCOPE",
        .desc = "beyond scope of source address",
        .val = ICMP6_DST_UNREACH_BEYONDSCOPE, /* 2 */
    },
    {
        .name = "DST_UNREACH_ADDR",
        .desc = "address unreachable",
        .val = ICMP6_DST_UNREACH_ADDR, /* 3 */
    },
    {
        .name = "DST_UNREACH_NOPORT",
        .desc = "bad port",
        .val = ICMP6_DST_UNREACH_NOPORT, /* 4 */
    },

    /* Codes for TIME_EXCEEDED. */
    {
        .name = "TIME_EXCEED_TRANSIT",
        .desc = "Hop Limit == 0 in transit",
        .val = ICMP6_TIME_EXCEED_TRANSIT, /* 0 */
    },
    {
        .name = "TIME_EXCEED_REASSEMBLY",
        .desc = "Reassembly time out",
        .val = ICMP6_TIME_EXCEED_REASSEMBLY, /* 1 */
    },

    /* Codes for PARAM_PROB. */
    {
        .name = "PARAMPROB_HEADER",
        .desc = "erroneous header field",
        .val = ICMP6_PARAMPROB_HEADER, /* 0 */
    },
    {
        .name = "PARAMPROB_NEXTHEADER",
        .desc = "unrecognized Next Header",
        .val = ICMP6_PARAMPROB_NEXTHEADER, /* 1 */
    },
    {
        .name = "PARAMPROB_OPTION",
        .desc = "unrecognized IPv6 option",
        .val = ICMP6_PARAMPROB_OPTION, /* 2 */
    },
    {},
};

/**
 * encode ICMPv6
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_icmpv6(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct icmp6_hdr *icmp6h;
    int hlen = 4;
#define AUTOFLAG_TYPE   (1 << 0)
#define AUTOFLAG_CSUM   (1 << 1)
    u_int32_t autoflags = (AUTOFLAG_TYPE | AUTOFLAG_CSUM);  /* auto flags */
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
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMPV6_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                    autoflags |= AUTOFLAG_TYPE;
                    ret = 0;
                } else {
                    autoflags &= ~AUTOFLAG_TYPE;
                    ret = eg_enc_encode_name_uint8(&icmp6h->icmp6_type, elem->val, icmpv6types);
                }
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
        /* auto fill type */
        if (autoflags & AUTOFLAG_TYPE) {
            autoflags &= ~AUTOFLAG_TYPE;
            eg_elem_val_t v;
            v.str = elem->name;
            eg_enc_encode_name_uint8(&icmp6h->icmp6_type, &v, icmpv6types);
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix ICMP checksum */
    if (autoflags & AUTOFLAG_CSUM) {
        if (lower) {
            struct ip *iph = (struct ip *)lower;
            struct ip6_hdr *ip6h = (struct ip6_hdr *)lower;
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

/**
 * fields for icmpv6 neighbor solicit
 */
enum {
    EG_ENC_ICMPV6_NS_TARGET = 1,
};

/**
 * field encoder for icmpv6 neighbor solicit
 */
static eg_enc_encoder_t eg_enc_icmpv6_ns_field_encoders[] = {
    {
        .id = EG_ENC_ICMPV6_NS_TARGET,
        .name = "TARGET",
        .desc = "Target",
    },
    {}
};

static eg_buffer_t *eg_enc_encode_icmpv6_nd_option(eg_elem_t *elems, void *lower);

/**
 * block encoder for icmpv6 neighbor solicit
 */
static eg_enc_encoder_t eg_enc_icmpv6_ns_block_encoders[] = {
    {
        .name = "OPTION",
        .desc = "ICMPv6 Neighbor Discovery option",
        .encode = eg_enc_encode_icmpv6_nd_option,
    },
    {
        .name = "DATA",
        .desc = "ICMPv6 data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * encode ICMPv6 Neighbor Solicit
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmpv6_ns(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct nd_neighbor_solicit *nsh;
    int hlen = sizeof(*nsh) - 4; /* excludes icmpv6 common header */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    nsh = (struct nd_neighbor_solicit *)(buf->ptr - 4);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_ns_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMPV6_NS_TARGET:
            ret = eg_enc_encode_ipv6addr(&nsh->nd_ns_target, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_ns_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, nsh);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * fields for icmpv6 neighbor solicit
 */
enum {
    EG_ENC_ICMPV6_NA_TARGET = 1,
    EG_ENC_ICMPV6_NA_FLAGS,
};

/**
 * field encoder for icmpv6 neighbor solicit
 */
static eg_enc_encoder_t eg_enc_icmpv6_na_field_encoders[] = {
    {
        .id = EG_ENC_ICMPV6_NA_TARGET,
        .name = "TARGET",
        .desc = "Target",
    },
    {
        .id = EG_ENC_ICMPV6_NA_FLAGS,
        .name = "FLAGS",
        .desc = "Flags",
    },
    {}
};

/**
 * block encoder for icmpv6 neighbor solicit
 */
static eg_enc_encoder_t eg_enc_icmpv6_na_block_encoders[] = {
    {
        .name = "OPTION",
        .desc = "ICMPv6 Neighbor Discovery option",
        .encode = eg_enc_encode_icmpv6_nd_option,
    },
    {
        .name = "DATA",
        .desc = "ICMPv6 data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * neighbor advertisement flags definition
 */
static eg_enc_vals_t naflags[] = {
    {
        .name = "ROUTER",
        .desc = "Router",
        .val =0x80000000,
    },
    {
        .name = "SOLICITED",
        .desc = "Solicited",
        .val = 0x40000000,
    },
    {
        .name = "OVERRIDE",
        .desc = "Override",
        .val = 0x20000000,
    },
    {},
};

/**
 * encode ICMPv6 Neighbor Advertisement
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmpv6_na(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct nd_neighbor_advert *nah;
    int hlen = sizeof(*nah) - 4; /* excludes icmpv6 common header */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    nah = (struct nd_neighbor_advert *)(buf->ptr - 4);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_na_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMPV6_NA_TARGET:
            ret = eg_enc_encode_ipv6addr(&nah->nd_na_target, elem->val);
            break;
        case EG_ENC_ICMPV6_NA_FLAGS:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags_uint32(&nah->nd_na_flags_reserved, elem->val, naflags);
            } else {
                ret = eg_enc_encode_uint32(&nah->nd_na_flags_reserved, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_na_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, nah);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * block encoder for icmpv6 router solicit
 */
static eg_enc_encoder_t eg_enc_icmpv6_rs_block_encoders[] = {
    {
        .name = "OPTION",
        .desc = "ICMPv6 Neighbor Discovery option",
        .encode = eg_enc_encode_icmpv6_nd_option,
    },
    {
        .name = "DATA",
        .desc = "ICMPv6 data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * encode ICMPv6 Router Solicit
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmpv6_rs(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct nd_router_solicit *rsh;
    int hlen = sizeof(*rsh) - 4; /* excludes icmpv6 common header */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    rsh = (struct nd_router_solicit *)(buf->ptr - 4);

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_rs_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, rsh);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * fields for icmpv6 router advertisement
 */
enum {
    EG_ENC_ICMPV6_RA_HOPLIMIT = 1,
    EG_ENC_ICMPV6_RA_FLAGS,
    EG_ENC_ICMPV6_RA_LIFETIME,
    EG_ENC_ICMPV6_RA_REACHABLE,
    EG_ENC_ICMPV6_RA_RETRANSMIT,
};

/**
 * field encoder for icmpv6 router advertisement
 */
static eg_enc_encoder_t eg_enc_icmpv6_ra_field_encoders[] = {
    {
        .id = EG_ENC_ICMPV6_RA_HOPLIMIT,
        .name = "HOPLIMIT",
        .desc = "Current Hop Limit",
    },
    {
        .id = EG_ENC_ICMPV6_RA_FLAGS,
        .name = "FLAGS",
        .desc = "Autoconfig Flags",
    },
    {
        .id = EG_ENC_ICMPV6_RA_LIFETIME,
        .name = "LIFETIME",
        .desc = "Router Lifetime",
    },
    {
        .id = EG_ENC_ICMPV6_RA_REACHABLE,
        .name = "REACHABLE",
        .desc = "Reachable Time",
    },
    {
        .id = EG_ENC_ICMPV6_RA_RETRANSMIT,
        .name = "RETRANSMIT",
        .desc = "Retransmit Timer",
    },
    {}
};

/**
 * block encoder for icmpv6 router advertisement
 */
static eg_enc_encoder_t eg_enc_icmpv6_ra_block_encoders[] = {
    {
        .name = "OPTION",
        .desc = "ICMPv6 Neighbor Discovery option",
        .encode = eg_enc_encode_icmpv6_nd_option,
    },
    {
        .name = "DATA",
        .desc = "ICMPv6 data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * autoconfig flags definition
 */
static eg_enc_vals_t autoconfflags[] = {
    {
        .name = "MANAGED",
        .aliases = "M\0",
        .desc = "Managed",
        .val = 0x80,
    },
    {
        .name = "OTHER",
        .aliases = "O\0",
        .desc = "Other option",
        .val = 0x40,
    },
    {
        .name = "HA",
        .desc = "HA",
        .val = 0x20,
    },
    {},
};

/**
 * encode ICMPv6 Router Advertisement
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmpv6_ra(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct nd_router_advert *rah;
    int hlen = sizeof(*rah) - 4; /* excludes icmpv6 common header */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    rah = (struct nd_router_advert *)(buf->ptr - 4);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_ra_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMPV6_RA_HOPLIMIT:
            ret = eg_enc_encode_uint8(&rah->nd_ra_curhoplimit, elem->val);
            break;
        case EG_ENC_ICMPV6_RA_FLAGS:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags_uint8(&rah->nd_ra_flags_reserved, elem->val, autoconfflags);
            } else {
                ret = eg_enc_encode_uint8(&rah->nd_ra_flags_reserved, elem->val);
            }
            break;
        case EG_ENC_ICMPV6_RA_LIFETIME:
            ret = eg_enc_encode_uint16(&rah->nd_ra_router_lifetime, elem->val);
            break;
        case EG_ENC_ICMPV6_RA_REACHABLE:
            ret = eg_enc_encode_uint32(&rah->nd_ra_reachable, elem->val);
            break;
        case EG_ENC_ICMPV6_RA_RETRANSMIT:
            ret = eg_enc_encode_uint32(&rah->nd_ra_retransmit, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6_ra_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, rah);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * fields for icmpv6 neighbor discovery option
 */
enum {
    EG_ENC_ICMPV6NDOPT_TYPE = 1,
    EG_ENC_ICMPV6NDOPT_LEN,
    EG_ENC_ICMPV6NDOPT_DATA,
};

/**
 * field encoder for icmpv6 neighbor discovery option
 */
static eg_enc_encoder_t eg_enc_icmpv6ndopt_field_encoders[] = {
    {
        .id = EG_ENC_ICMPV6NDOPT_TYPE,
        .name = "TYPE",
        .desc = "ICMPv6 Neighbor Discovery option type",
    },
    {
        .id = EG_ENC_ICMPV6NDOPT_LEN,
        .name = "LENGTH",
        .aliases = "LEN\0",
        .desc = "ICMPv6 Neighbor Discovery option length",
    },
    {
        .id = EG_ENC_ICMPV6NDOPT_DATA,
        .name = "DATA",
        .desc = "ICMPv6 Neighbor Discovery option data",
    },
    {}
};

/**
 * block encoder for dhcpv6 option
 */
static eg_enc_encoder_t eg_enc_icmpv6ndopt_block_encoders[] = {
    {
        .name = "DATA",
        .desc = "ICMPv6 Neighbor Discovery option data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * icmpv6 neighbor discovery option type definition
 */
static eg_enc_vals_t icmpv6ndopttypes[] = {
    {
        .name = "SOURCE_LINKADDR",
        .desc = "SOURCE_LINKADDR",
        .val = 1,
    },
    {
        .name = "TARGET_LINKADDR",
        .desc = "TARGET_LINKADDR",
        .val = 2,
    },
    {
        .name = "PREFIX_INFORMATION",
        .desc = "PREFIX_INFORMATION",
        .val = 3,
    },
    {
        .name = "REDIRECTED_HEADER",
        .desc = "REDIRECTED_HEADER",
        .val = 4,
    },
    {
        .name = "MTU",
        .desc = "MTU",
        .val = 5,
    },
    {
        .name = "ADV_INTERVAL",
        .desc = "ADV_INTERVAL",
        .val = 7,
    },
    {
        .name = "HA_INFORMATION",
        .desc = "HA_INFORMATION",
        .val = 8,
    },
    {},
};

/**
 * encode Neighbor Discovery option
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmpv6_nd_option(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
#define AUTOFLAG_OPTLEN (1 << 8)
    u_int32_t autoflags = (AUTOFLAG_OPTLEN);  /* auto flags */
    int datalen = 0;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(2);
    if (buf == NULL) {
        return NULL;
    }

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6ndopt_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ICMPV6NDOPT_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(buf->ptr, elem->val, icmpv6ndopttypes);
            } else {
                ret = eg_enc_encode_uint8(buf->ptr, elem->val);
            }
            break;
        case EG_ENC_ICMPV6NDOPT_LEN:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_OPTLEN;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_OPTLEN;
                ret = eg_enc_encode_uint8(buf->ptr + 1, elem->val);
            }
            break;
        case EG_ENC_ICMPV6NDOPT_DATA:
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

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_icmpv6ndopt_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
        if (bufn == NULL) {
            goto err;
        }
        datalen += bufn->len;
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix option length */
    datalen = ((datalen + 2 + 7) / 8) * 8; /* type + len + data  units of 8 octets */
    if (autoflags & AUTOFLAG_OPTLEN) {
        *(buf->ptr + 1) = datalen / 8;
    }

    buf->len = datalen;

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
