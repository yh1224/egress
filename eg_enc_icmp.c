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
#include <netinet/ip_icmp.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

static eg_buffer_t *eg_enc_encode_icmp_echo(eg_elem_t *elems, void *upper);

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
        .desc = "Echo Reply",
        .val = ICMP_ECHOREPLY,
    },
    {
        .name = "DEST_UNREACH",
        .desc = "Destination Unreachable",
        .val = ICMP_DEST_UNREACH,
    },
    {
        .name = "SOURCE_QUENCH",
        .desc = "Source Quench",
        .val = ICMP_SOURCE_QUENCH,
    },
    {
        .name = "REDIRECT",
        .desc = "Redirect (change route)",
        .val = ICMP_REDIRECT,
    },
    {
        .name = "ECHO",
        .desc = "Echo Request",
        .val = ICMP_ECHO,
    },
    {
        .name = "TIME_EXCEEDED",
        .desc = "Time Exceeded",
        .val = ICMP_TIME_EXCEEDED,
    },
    {
        .name = "PARAMETERPROB",
        .desc = "Parameter Problem",
        .val = ICMP_PARAMETERPROB,
    },
    {
        .name = "TIMESTAMP",
        .desc = "Timestamp Request",
        .val = ICMP_TIMESTAMP,
    },
    {
        .name = "TIMESTAMPREPLY",
        .desc = "Timestamp Reply",
        .val = ICMP_TIMESTAMPREPLY,
    },
    {
        .name = "INFO_REQUEST",
        .desc = "Information Request",
        .val = ICMP_INFO_REQUEST,
    },
    {
        .name = "INFO_REPLY",
        .desc = "Information Reply",
        .val = ICMP_INFO_REPLY,
    },
    {
        .name = "ADDRESS",
        .desc = "Address Mask Request",
        .val = ICMP_ADDRESS,
    },
    {
        .name = "ADDRESSREPLY",
        .desc = "Address Mask Reply",
        .val = ICMP_ADDRESSREPLY,
    },
    {},
};

/**
 * ICMP code definition
 */
static eg_enc_vals_t icmpcodes[] = {
    {
        .name = "NET_UNREACH",
        .desc = "Network Unreachable",
        .val = 0,
    },
    {
        .name = "HOST_UNREACH",
        .desc = "Host Unreachable",
        .val = 1,
    },
    {
        .name = "PROT_UNREACH",
        .desc = "Protocol Unreachable",
        .val = 2,
    },
    {
        .name = "PORT_UNREACH",
        .desc = "Port Unreachable",
        .val = 3,
    },
    {
        .name = "FRAG_NEEDED",
        .desc = "Fragmentation Needed/DF set",
        .val = 4,
    },
    {
        .name = "SR_FAILED",
        .desc = "Source Route failed",
        .val = 5,
    },
    {
        .name = "NET_UNKNOWN",
        .desc = "Net Unknown",
        .val = 6,
    },
    {
        .name = "HOST_UNKNOWN",
        .desc = "Host Unknwon",
        .val = 7,
    },
    {
        .name = "HOST_ISOLATED",
        .desc = "Host Isolated",
        .val = 8,
    },
    {
        .name = "NET_ANO",
        .desc = "",
        .val = 9,
    },
    {
        .name = "NET_ANO",
        .desc = "",
        .val = 10,
    },
    {
        .name = "NET_UNR_TOS",
        .desc = "",
        .val = 11,
    },
    {
        .name = "HOST_UNR_TOS",
        .desc = "",
        .val = 12,
    },
    {
        .name = "PKT_FILTERED",
        .desc = "Packet filtered",
        .val = 13,
    },
    {
        .name = "PREC_VIOLATION",
        .desc = "Precedence violation",
        .val = 14,
    },
    {
        .name = "PREC_CUTOFF",
        .desc = "Precedence cut off",
        .val = 15,
    },

    /* Codes for REDIRECT. */
    {
        .name = "REDIR_NET",
        .desc = "Redirect Net",
        .val = 0,
    },
    {
        .name = "REDIR_HOST",
        .desc = "Redirect Host",
        .val = 1,
    },
    {
        .name = "REDIR_NETTOS",
        .desc = "Redirect Net for TOS",
        .val = 2,
    },
    {
        .name = "REDIR_HOSTTOS",
        .desc = "Redirect Host for TOS",
        .val = 3,
    },

    /* Codes for TIME_EXCEEDED. */
    {
        .name = "EXC_TTL",
        .desc = "TTL count exceeded",
        .val = 0,
    },
    {
        .name = "EXC_FRAGTIME",
        .desc = "Fragment Reass time exceeded",
        .val = 1,
    },
    {},
};

#define AUTOFLAG_CSUM   (1 << 0)

/**
 * encode ICMP echo request/response
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_icmp_echo(eg_elem_t *elems, void *upper)
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
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_icmp(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf, *bufn;
    struct icmphdr *icmph;
    int hlen = 4;
    u_int32_t autoflags = (AUTOFLAG_CSUM);  /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int len;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    icmph = (struct icmphdr *)buf->ptr;

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
                ret = eg_enc_encode_name_uint8(&icmph->type, elem->val, icmptypes);
            } else {
                ret = eg_enc_encode_uint8(&icmph->type, elem->val);
            }
            break;
        case EG_ENC_ICMP_CODE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(&icmph->code, elem->val, icmpcodes);
            } else {
                ret = eg_enc_encode_uint8(&icmph->code, elem->val);
            }
            break;
        case EG_ENC_ICMP_CHECKSUM:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_CSUM;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_CSUM;
                ret = eg_enc_encode_uint16(&icmph->checksum, elem->val);
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
        if (upper) {
            struct ip *iph = (struct ip *)upper;
            struct ip6_hdr *ip6h = (struct ip6_hdr *)upper;
            if (iph->ip_v == 4) {
                /* IPv4 */
                icmph->checksum = htons(~ip_checksum(icmph, buf->len));
            } else if (iph->ip_v == 6) {
                /* IPv6 */
                struct ipv6_pseudo_header phdr;
                memset(&phdr, 0, sizeof(phdr));
                phdr.src = ip6h->ip6_src;
                phdr.dst = ip6h->ip6_dst;
                phdr.plen = htonl(buf->len);
                phdr.nxt = IPPROTO_ICMPV6;
                icmph->checksum = htons(ip_checksum(&phdr, sizeof(phdr)));
                icmph->checksum = htons(~ip_checksum(icmph, buf->len));
            }
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
