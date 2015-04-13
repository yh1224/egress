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
 * fields for vlan
 */
enum {
    EG_ENC_VLAN_TPID = 1,
    EG_ENC_VLAN_PCP,
    EG_ENC_VLAN_CFI,
    EG_ENC_VLAN_VID,
    EG_ENC_VLAN_ARP,
    EG_ENC_VLAN_IPV4,
    EG_ENC_VLAN_IPV6,
    EG_ENC_VLAN_VLAN,
};

/**
 * field encoder for vlan
 */
static eg_enc_encoder_t eg_enc_vlan_field_encoders[] = {
    {
        .id = EG_ENC_VLAN_TPID,
        .name = "TPID",
        .desc = "Tag Protocol Identifier (default: 0x8100)",
    },
    {
        .id = EG_ENC_VLAN_PCP,
        .name = "PCP",
        .desc = "Protocol Code Point",
    },
    {
        .id = EG_ENC_VLAN_CFI,
        .name = "CFI",
        .desc = "Canonical Format indicator",
    },
    {
        .id = EG_ENC_VLAN_VID,
        .name = "VID",
        .desc = "VLAN Identifier",
    },
    {}
};

/**
 * block encoders under vlan
 */
static eg_enc_encoder_t eg_enc_ether_block_encoders[] = {
    {
        .id = EG_ENC_VLAN_VLAN,
        .name = "VLAN",
        .desc = "VLAN",
        .encode = eg_enc_encode_vlan,
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
    {}
};

/**
 * encode vlan
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_vlan(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int8_t *vh;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(4);
    if (buf == NULL) {
        return NULL;
    }
    vh = (u_int8_t *)buf->ptr;

    memset(vh, 0, 4);
    *((u_int16_t *)vh) = htons(ETHERTYPE_VLAN); /* TPID */

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_vlan_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_VLAN_TPID:
            ret = eg_enc_encode_uint16((u_int16_t *)vh, elem->val);
            break;
        case EG_ENC_VLAN_PCP:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0x7);
            *(u_int16_t *)(vh + 2) &= ~htons(0x7 << 13);
            *(u_int16_t *)(vh + 2) |= htons((ntohl(num) & 0x7) << 13);
            break;
        case EG_ENC_VLAN_CFI:
            ret = eg_enc_encode_num(&num, elem->val, 0, 1);
            *(u_int16_t *)(vh + 2) &= ~htons(0x1 << 12);
            *(u_int16_t *)(vh + 2) |= htons((ntohl(num) & 0x1) << 12);
            break;
        case EG_ENC_VLAN_VID:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xfff);
            *(u_int16_t *)(vh + 2) &= ~htons(0xfff);
            *(u_int16_t *)(vh + 2) |= htons(ntohl(num) & 0xfff);
            break;
        default:
            fprintf(stderr, "VLAN: Unknown field: %s\n", elem->name);
            goto err;
        }
        if (ret < 0) {
            fprintf(stderr, "VLAN: Unexpected field: %s\n", elem->name);
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
        bufn = enc->encode(elem->elems, vh);
        if (bufn == NULL) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_VLAN_VLAN:
            /* insert vlan tag */
            buf = eg_buffer_merge(buf, bufn, -1);
            break;
        default:
            break;
        }
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
