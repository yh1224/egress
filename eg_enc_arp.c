/**
 * @file
 * Egress encoder/decoder for arp
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "eg_enc.h"

/**
 * fields for arp
 */
enum {
    EG_ENC_ARP_HW = 1,
    EG_ENC_ARP_PROTO,
    EG_ENC_ARP_HLEN,
    EG_ENC_ARP_PLN,
    EG_ENC_ARP_OPCODE,
    EG_ENC_ARP_SENDERMAC,
    EG_ENC_ARP_SENDERIP,
    EG_ENC_ARP_TARGETMAC,
    EG_ENC_ARP_TARGETIP,
};

/**
 * field encoder for udp
 */
static eg_enc_encoder_t eg_enc_arp_field_encoders[] = {
    {
        .id = EG_ENC_ARP_HW,
        .name = "HW",
        .desc = "hardware type (default: 1)"
    },
    {
        .id = EG_ENC_ARP_PROTO,
        .name = "PROTO",
        .desc = "protocol type (default: 0x0800)"
    },
    {
        .id = EG_ENC_ARP_HLEN,
        .name = "HLEN",
        .desc = "hardware address length (default: 6)"
    },
    {
        .id = EG_ENC_ARP_PLN,
        .name = "PLN",
        .desc = "protocol address length (default: 4)"
    },
    {
        .id = EG_ENC_ARP_OPCODE,
        .name = "OPCODE",
        .desc = "operation (default: 1)"
    },
    {
        .id = EG_ENC_ARP_SENDERMAC,
        .name = "SENDERMAC",
        .desc = "sender hardware address"
    },
    {
        .id = EG_ENC_ARP_SENDERIP,
        .name = "SENDERIP",
        .desc = "sender IP address"
    },
    {
        .id = EG_ENC_ARP_TARGETMAC,
        .name = "TARGETMAC",
        .desc = "target hardware address"
    },
    {
        .id = EG_ENC_ARP_TARGETIP,
        .name = "TARGETIP",
        .desc = "target IP address"
    },
    {}
};

/**
 * opcode definition
 */
static eg_enc_vals_t opcodes[] = {
    {
        .name = "REQUEST",
        .desc = "ARP Request",
        .val = 1,
    },
    {
        .name = "REPLY",
        .desc = "ARP Reply",
        .val = 2,
    },
    {},
};

/**
 * encode opcode
 *
 * @param[out] buf buffer to write
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
static int eg_enc_encode_opcode(u_int16_t *buf, eg_elem_val_t *val)
{
    int ret;

    if (val->type == EG_TYPE_KEYWORD) {
        ret = eg_enc_encode_name_uint16(buf, val, opcodes);
    } else {
        ret = eg_enc_encode_uint16(buf, val);
    }
    if (ret < 0) {
        return ret;
    }
    return ret;
}

/**
 * encode ARP
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_arp(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf;
    struct ether_arp *arph;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*arph));
    if (buf == NULL) {
        return NULL;
    }
    arph = (struct ether_arp *)buf->ptr;

    memset(arph, 0, sizeof(*arph));
    arph->arp_hrd = htons(1);
    arph->arp_pro = htons(ETHERTYPE_IP);
    arph->arp_hln = ETHER_ADDR_LEN;
    arph->arp_pln = 4;
    arph->arp_op  = htons(1);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_arp_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ARP_HW:
              ret = eg_enc_encode_uint16(&arph->arp_hrd, elem->val);
            break;
        case EG_ENC_ARP_PROTO:
            ret = eg_enc_encode_uint16(&arph->arp_pro, elem->val);
            break;
        case EG_ENC_ARP_HLEN:
            ret = eg_enc_encode_uint8(&arph->arp_hln, elem->val);
            break;
        case EG_ENC_ARP_PLN:
            ret = eg_enc_encode_uint8(&arph->arp_pln, elem->val);
            break;
        case EG_ENC_ARP_OPCODE:
            ret = eg_enc_encode_opcode(&arph->arp_op, elem->val);
            break;
        case EG_ENC_ARP_SENDERMAC:
            ret = eg_enc_encode_macaddr((u_int8_t *)&arph->arp_sha, elem->val);
            break;
        case EG_ENC_ARP_SENDERIP:
            ret = eg_enc_encode_ipv4addr((struct in_addr *)&arph->arp_spa, elem->val);
            break;
        case EG_ENC_ARP_TARGETMAC:
            ret = eg_enc_encode_macaddr((u_int8_t *)&arph->arp_tha, elem->val);
            break;
        case EG_ENC_ARP_TARGETIP:
            ret = eg_enc_encode_ipv4addr((struct in_addr *)&arph->arp_tpa, elem->val);
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
