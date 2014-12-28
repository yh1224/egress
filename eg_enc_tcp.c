/**
 * @file
 * Egress encoder/decoder for tcp
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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * fields for tcp
 */
enum {
    EG_ENC_TCP_SRCPORT = 1,
    EG_ENC_TCP_DSTPORT,
    EG_ENC_TCP_SEQ,
    EG_ENC_TCP_ACK,
    EG_ENC_TCP_OFFSET,
    EG_ENC_TCP_FLAGS,
    EG_ENC_TCP_WINDOW,
    EG_ENC_TCP_CHECKSUM,
    EG_ENC_TCP_URP,
};

/**
 * field encoder for tcp
 */
static eg_enc_encoder_t eg_enc_tcp_field_encoders[] = {
    {
        .id = EG_ENC_TCP_SRCPORT,
        .name = "SRCPORT",
        .desc = "source port",
    },
    {
        .id = EG_ENC_TCP_DSTPORT,
        .name = "DSTPORT",
        .desc = "destination port",
    },
    {
        .id = EG_ENC_TCP_SEQ,
        .name = "SEQ",
        .desc = "sequence number",
    },
    {
        .id = EG_ENC_TCP_ACK,
        .name = "ACK",
        .desc = "acknowledgement number",
    },
    {
        .id = EG_ENC_TCP_OFFSET,
        .name = "OFFSET",
        .desc = "offset (default: auto)",
    },
    {
        .id = EG_ENC_TCP_FLAGS,
        .name = "FLAGS",
        .desc = "flags",
    },
    {
        .id = EG_ENC_TCP_WINDOW,
        .name = "WINDOW",
        .desc = "window",
    },
    {
        .id = EG_ENC_TCP_CHECKSUM,
        .name = "CHECKSUM",
        .desc = "checksum (default: auto)",
    },
    {
        .id = EG_ENC_TCP_URP,
        .name = "URP",
        .desc = "urgent pointer",
    },
    {}
};

/**
 * block encoders under tcp
 */
static eg_enc_encoder_t eg_enc_tcp_block_encoders[] = {
    {
        .name = "PAYLOAD",
        .desc = "payload",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * TCP flags definition
 */
static eg_enc_vals_t tcpflags[] = {
    {
        .name = "FIN",
        .desc = "FIN",
        .val = TH_FIN,
    },
    {
        .name = "SYN",
        .desc = "SYN",
        .val = TH_SYN,
    },
    {
        .name = "RST",
        .desc = "RST",
        .val = TH_RST,
    },
    {
        .name = "PUSH",
        .desc = "PUSH",
        .val = TH_PUSH,
    },
    {
        .name = "ACK",
        .desc = "ACK",
        .val = TH_ACK,
    },
    {
        .name = "URG",
        .desc = "URG",
        .val = TH_URG,
    },
    {},
};

#define AUTOFLAG_OFFSET (1 << 0)
#define AUTOFLAG_CSUM   (1 << 1)

/**
 * encode TCP
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_tcp(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf, *bufn;
    struct tcphdr *tcph;
    int hlen = sizeof(*tcph);
    u_int32_t autoflags = (AUTOFLAG_OFFSET | AUTOFLAG_CSUM);    /* auto flags */
    u_int32_t num;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*tcph));
    if (buf == NULL) {
        return NULL;
    }
    tcph = (struct tcphdr *)buf->ptr;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_tcp_field_encoders);
        switch (enc->id) {
        case EG_ENC_TCP_SRCPORT:
            ret = eg_enc_encode_uint16(&tcph->th_sport, elem->val);
            break;
        case EG_ENC_TCP_DSTPORT:
            ret = eg_enc_encode_uint16(&tcph->th_dport, elem->val);
            break;
        case EG_ENC_TCP_SEQ:
            ret = eg_enc_encode_uint32(&tcph->th_seq, elem->val);
            break;
        case EG_ENC_TCP_ACK:
            ret = eg_enc_encode_uint32(&tcph->th_ack, elem->val);
            break;
        case EG_ENC_TCP_OFFSET:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_OFFSET;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_OFFSET;
                ret = eg_enc_encode_uint(&num, elem->val, 0, 15);
                tcph->th_off = (u_int8_t)num;
            }
            break;
        case EG_ENC_TCP_FLAGS:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags_uint8(&tcph->th_flags, elem->val, tcpflags);
            } else {
                ret = eg_enc_encode_uint8(&tcph->th_flags, elem->val);
            }
            break;
        case EG_ENC_TCP_WINDOW:
            ret = eg_enc_encode_uint16(&tcph->th_win, elem->val);
            break;
        case EG_ENC_TCP_CHECKSUM:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_CSUM;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_CSUM;
                ret = eg_enc_encode_uint16(&tcph->th_sum, elem->val);
            }
            break;
        case EG_ENC_TCP_URP:
            ret = eg_enc_encode_uint16(&tcph->th_urp, elem->val);
            break;
        default:
            goto err;
        }
        if (ret < 0) {
            goto err;
        }
    }

    // TODO: TCP option

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_tcp_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, tcph);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix TCP offset */
    if (autoflags & AUTOFLAG_OFFSET) {
        tcph->th_off = hlen >> 2;
    }

    /* fix TCP checksum */
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
                phdr.protocol = IPPROTO_TCP;
                phdr.len = htons(buf->len);
                tcph->th_sum = htons(ip_checksum(&phdr, sizeof(phdr)));
                tcph->th_sum = htons(~ip_checksum(tcph, buf->len));
            } else if (iph->ip_v == 6) {
                /* IPv6 */
                struct ipv6_pseudo_header phdr;
                memset(&phdr, 0, sizeof(phdr));
                phdr.src = ip6h->ip6_src;
                phdr.dst = ip6h->ip6_dst;
                phdr.plen = htonl(buf->len);
                phdr.nxt = IPPROTO_TCP;
                tcph->th_sum = htons(ip_checksum(&phdr, sizeof(phdr)));
                tcph->th_sum = htons(~ip_checksum(tcph, buf->len));
            }
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
