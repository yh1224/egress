/**
 * @file
 * Egress encoder/decoder for tcp
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
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
    EG_ENC_TCP_OPTION,
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

static eg_buffer_t *eg_enc_encode_tcpopt(struct eg_elem *, void *lower);

/**
 * block encoders under tcp
 */
static eg_enc_encoder_t eg_enc_tcp_block_encoders[] = {
    {
        .id = EG_ENC_TCP_OPTION,
        .name = "OPTION",
        .desc = "TCP option",
        .encode = eg_enc_encode_tcpopt,
    },
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

/**
 * encode TCP
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_tcp(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct tcphdr *tcph;
    int hlen = sizeof(*tcph);
#define AUTOFLAG_OFFSET (1 << 0)
#define AUTOFLAG_CSUM   (1 << 1)
#define AUTOFLAG_PAD    (1 << 2)
    u_int32_t autoflags = (AUTOFLAG_OFFSET | AUTOFLAG_CSUM | AUTOFLAG_PAD); /* auto flags */
    u_int32_t num;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int optlen = 0;
    int len;
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
        switch (enc->id) {
        case EG_ENC_TCP_OPTION:
            /* insert IPv4 option */
            len = bufn->len;
            buf = eg_buffer_merge(buf, bufn, sizeof(*tcph) + optlen);
            optlen += len;
            break;
        default:
            buf = eg_buffer_merge(buf, bufn, -1);
            break;
        }
    }

    if (optlen > 0) {
        /* insert TCP option padding */
        if (autoflags & AUTOFLAG_PAD) {
            if ((optlen % 4) > 0) {
                buf = eg_buffer_merge(buf, eg_buffer_create(4 - (optlen % 4)), sizeof(*tcph) + optlen);
                optlen += 4 - (optlen % 4);
            }
        }
        hlen += optlen;
    }

    /* fix TCP offset */
    if (autoflags & AUTOFLAG_OFFSET) {
        tcph->th_off = hlen >> 2;
    }

    /* fix TCP checksum */
    if (autoflags & AUTOFLAG_CSUM) {
        if (lower) {
            struct ip *iph = (struct ip *)lower;
            struct ip6_hdr *ip6h = (struct ip6_hdr *)lower;
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

/**
 * fields for TCP option
 */
enum {
    EG_ENC_TCPOPT_TYPE = 1,
    EG_ENC_TCPOPT_LEN,
    EG_ENC_TCPOPT_DATA,
};

/**
 * field encoder for TCP option
 */
static eg_enc_encoder_t eg_enc_tcpopt_field_encoders[] = {
    {
        .id = EG_ENC_TCPOPT_TYPE,
        .name = "TYPE",
        .desc = "TCP option type",
    },
    {
        .id = EG_ENC_TCPOPT_LEN,
        .name = "LENGTH",
        .desc = "TCP option length",
    },
    {
        .id = EG_ENC_TCPOPT_DATA,
        .name = "DATA",
        .desc = "TCP option data",
    },
    {}
};

/**
 * block encoder for TCP option
 */
static eg_enc_encoder_t eg_enc_tcpopt_block_encoders[] = {
    {
        .id = EG_ENC_TCPOPT_DATA,
        .name = "DATA",
        .desc = "TCP option data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * TCP option type definition
 */
static eg_enc_vals_t tcpopttypes[] = {
    {
        .name = "EOL",
        .desc = "end of options",
        .val = TCPOPT_EOL, /* 0 */
    },
    {
        .name = "NOP",
        .desc = "no-op",
        .val = TCPOPT_NOP, /* 1 */
    },
    {
        .name = "MAXSEG",
        .desc = "MSS (maximum segment size)",
        .val = TCPOPT_MAXSEG, /* 2 */
    },
    {
        .name = "WINDOW",
        .desc = "window size",
        .val = TCPOPT_WINDOW, /* 3 */
    },
    {
        .name = "SACK_PERMITTED",
        .desc = "selective acknowledgment permitted",
        .val = TCPOPT_SACK_PERMITTED, /* 4 */
    },
    {
        .name = "SACK",
        .desc = "selective acknowledgment",
        .val = TCPOPT_SACK, /* 5 */
    },
    {
        .name = "TIMESTAMP",
        .desc = "TCP timestamp",
        .val = TCPOPT_TIMESTAMP, /* 8 */
    },
    {},
};

/**
 * encode TCP option
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_tcpopt(eg_elem_t *elems, void *lower)
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_tcpopt_field_encoders);
        switch (enc->id) {
        case EG_ENC_TCPOPT_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(buf->ptr, elem->val, tcpopttypes);
            } else {
                ret = eg_enc_encode_uint8(buf->ptr, elem->val);
            }
            break;
        case EG_ENC_TCPOPT_LEN:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_OPTLEN;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_OPTLEN;
                ret = eg_enc_encode_uint8(buf->ptr + 1, elem->val);
            }
            break;
        case EG_ENC_TCPOPT_DATA:
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_tcpopt_block_encoders);
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
