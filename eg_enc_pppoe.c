/**
 * @file
 * Egress encoder/decoder for pppoe
 */
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkttools/defines.h"
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * pppoe header
 */
struct pppoe_hdr {
    u_int8_t vertype;
    u_int8_t code;
    u_int16_t sid;
    u_int16_t length;
    u_int16_t proto;
} __attribute__((packed));

/**
 * fields for pppoe
 */
enum {
    EG_ENC_PPPOE_VER = 1,
    EG_ENC_PPPOE_TYPE,
    EG_ENC_PPPOE_CODE,
    EG_ENC_PPPOE_SID,
    EG_ENC_PPPOE_LENGTH,
    EG_ENC_PPPOE_PROTO,
};

/**
 * field encoder for pppoe
 */
static eg_enc_encoder_t eg_enc_pppoe_field_encoders[] = {
    {
        .id = EG_ENC_PPPOE_VER,
        .name = "VERSION",
        .desc = "version (default: 1)",
    },
    {
        .id = EG_ENC_PPPOE_TYPE,
        .name = "TYPE",
        .desc = "type (default: 1)",
    },
    {
        .id = EG_ENC_PPPOE_CODE,
        .name = "CODE",
        .desc = "code",
    },
    {
        .id = EG_ENC_PPPOE_SID,
        .name = "SESSIONID",
        .desc = "session id",
    },
    {
        .id = EG_ENC_PPPOE_LENGTH,
        .name = "LENGTH",
        .aliases = "LEN\0",
        .desc = "length (default: auto)",
    },
    {
        .id = EG_ENC_PPPOE_PROTO,
        .name = "PROTOCOL",
        .desc = "protocol",
    },
    {}
};

/**
 * block encoders under pppoe
 */
static eg_enc_encoder_t eg_enc_pppoe_block_encoders[] = {
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
 * pppprotocol definition
 */
static eg_enc_vals_t pppprotocols[] = {
    {
        .name = "IPV4",
        .desc = "IPv4",
        .val = 0x0021,
    },
    {},
};

/**
 * encode PPPoE
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_pppoe_session(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct pppoe_hdr *pppoeh;
#define AUTOFLAG_LENGTH (1 << 0)
#define AUTOFLAG_PPPPROTOCOL (1 << 1)
    u_int32_t autoflags = (AUTOFLAG_LENGTH | AUTOFLAG_PPPPROTOCOL);   /* auto flags */
    u_int32_t num;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*pppoeh));
    if (buf == NULL) {
        return NULL;
    }
    pppoeh = (struct pppoe_hdr *)buf->ptr;

    memset(pppoeh, 0, sizeof(*pppoeh));
    pppoeh->vertype = 0x11;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_pppoe_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_PPPOE_VER:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0x0f);
            pppoeh->vertype &= 0x0f;
            pppoeh->vertype |= (num << 4);
            break;
        case EG_ENC_PPPOE_TYPE:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0x0f);
            pppoeh->vertype &= 0xf0;
            pppoeh->vertype |= num;
            break;
        case EG_ENC_PPPOE_CODE:
            ret = eg_enc_encode_uint8(&pppoeh->code, elem->val);
            break;
        case EG_ENC_PPPOE_SID:
            ret = eg_enc_encode_uint16(&pppoeh->sid, elem->val);
            break;
        case EG_ENC_PPPOE_LENGTH:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_LENGTH;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_LENGTH;
                ret = eg_enc_encode_uint16(&pppoeh->length, elem->val);
            }
            break;
        case EG_ENC_PPPOE_PROTO:
            ret = eg_enc_encode_uint16(&pppoeh->proto, elem->val);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_pppoe_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, pppoeh);
        if (bufn == NULL) {
            goto err;
        }
        /* auto fill protocol */
        if (autoflags & AUTOFLAG_PPPPROTOCOL) {
            autoflags &= ~AUTOFLAG_PPPPROTOCOL;
            eg_elem_val_t v;
            v.str = elem->name;
            eg_enc_encode_name_uint16(&pppoeh->proto, &v, pppprotocols);
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix PPPoE length */
    if (autoflags & AUTOFLAG_LENGTH) {
        pppoeh->length = htons((u_int16_t)buf->len - sizeof(*pppoeh) + 2/* protocol field */);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
