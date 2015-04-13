/**
 * @file
 * Egress encoder/decoder for ether
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <net/ethernet.h>
#include "eg_enc.h"

/**
 * fields for ether
 */
enum {
    EG_ENC_ETHER_SRCMAC = 1,
    EG_ENC_ETHER_DSTMAC,
    EG_ENC_ETHER_TYPE,
    EG_ENC_ETHER_VLAN,
};

/**
 * field encoder for ether
 */
static eg_enc_encoder_t eg_enc_ether_field_encoders[] = {
    {
        .id = EG_ENC_ETHER_SRCMAC,
        .name = "SRCMAC",
        .desc = "source address",
    },
    {
        .id = EG_ENC_ETHER_DSTMAC,
        .name = "DSTMAC",
        .desc = "destination address",
    },
    {
        .id = EG_ENC_ETHER_TYPE,
        .name = "TYPE",
        .desc = "ethernet type (default: auto)",
    },
    {}
};

/**
 * block encoders under ether
 */
static eg_enc_encoder_t eg_enc_ether_block_encoders[] = {
    {
        .id = EG_ENC_ETHER_VLAN,
        .name = "VLAN",
        .desc = "VLAN tag",
        .encode = eg_enc_encode_vlan,
    },

    {
        .name = "PPPOE-SESSION",
        .desc = "PPPoE",
        .encode = eg_enc_encode_pppoe_session,
    },
    {
        .name = "ARP",
        .desc = "ARP",
        .encode = eg_enc_encode_arp,
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
        .name = "RAW",
        .desc = "raw data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * ethertype definition
 */
static eg_enc_vals_t ethertypes[] = {
    {
        .name = "PPPOE-DISCOVERY",
        .desc = "PPPoE discovery",
        .val = 0x8863,
    },
    {
        .name = "PPPOE-SESSION",
        .desc = "PPPoE session",
        .val = 0x8864,
    },
    {
        .name = "ARP",
        .desc = "ARP",
        .val = ETHERTYPE_ARP, /* 0x0806 */
    },
    {
        .name = "IPV4",
        .desc = "IPv4",
        .val = ETHERTYPE_IP, /* 0x0800 */
    },
    {
        .name = "IPV6",
        .desc = "IPv6",
        .val = ETHERTYPE_IPV6, /* 0x86dd */
    },
    {},
};

/**
 * encode ether
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_ether(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct ether_header *eh;
#define AUTOFLAG_TYPE   (1 << 0)
    u_int32_t autoflags = (AUTOFLAG_TYPE);  /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*eh));
    if (buf == NULL) {
        return NULL;
    }
    eh = (struct ether_header *)buf->ptr;

    memset(eh, 0, sizeof(*eh));
    memset(eh->ether_dhost, -1, ETHER_ADDR_LEN);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ether_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ETHER_SRCMAC:
            ret = eg_enc_encode_macaddr((u_int8_t *)&eh->ether_shost, elem->val);
            break;
        case EG_ENC_ETHER_DSTMAC:
            ret = eg_enc_encode_macaddr((u_int8_t *)&eh->ether_dhost, elem->val);
            break;
        case EG_ENC_ETHER_TYPE:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_TYPE;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_TYPE;
                if (elem->val->type == EG_TYPE_KEYWORD) {
                    ret = eg_enc_encode_name_uint16(&eh->ether_type, elem->val, ethertypes);
                } else {
                    ret = eg_enc_encode_uint16(&eh->ether_type, elem->val);
                }
            }
            break;
        default:
            fprintf(stderr, "ETHER: Unknown field: %s\n", elem->name);
            goto err;
        }
        if (ret < 0) {
            fprintf(stderr, "ETHER: Unexpected field: %s\n", elem->name);
            goto err;
        }
    }

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_ether_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, eh);
        if (bufn == NULL) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ETHER_VLAN:
            /* insert vlan tag */
            buf = eg_buffer_merge(buf, bufn, buf->len - 2);
            break;
        default:
            /* auto fill protocol */
            if (autoflags & AUTOFLAG_TYPE) {
                autoflags &= ~AUTOFLAG_TYPE;
                eg_elem_val_t v;
                v.str = elem->name;
                eg_enc_encode_name_uint16((u_int16_t *)(buf->ptr + buf->len - 2), &v, ethertypes);
            }
            buf = eg_buffer_merge(buf, bufn, -1);
            break;
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
