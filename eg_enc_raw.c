/**
 * @file
 * Egress encoder/decoder for raw
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

/**
 * fields for raw
 */
enum {
    EG_ENC_RAW_UINT32 = 1,
    EG_ENC_RAW_UINT16,
    EG_ENC_RAW_UINT8,
    EG_ENC_RAW_HEX,
    EG_ENC_RAW_MACADDR,
    EG_ENC_RAW_IPV4ADDR,
    EG_ENC_RAW_IPV6ADDR,
};

/**
 * field encoder for raw
 */
static eg_enc_encoder_t eg_enc_raw_field_encoders[] = {
    {
        .id = EG_ENC_RAW_UINT32,
        .name = "UINT32",
        .desc = "32-bit unsigned number"
    },
    {
        .id = EG_ENC_RAW_UINT16,
        .name = "UINT16",
        .desc = "16-bit unsigned number"
    },
    {
        .id = EG_ENC_RAW_UINT8,
        .name = "UINT8",
        .desc = "8-bit unsigned number"
    },
    {
        .id = EG_ENC_RAW_HEX,
        .name = "HEX",
        .desc = "byte sequence"
    },
    {
        .id = EG_ENC_RAW_MACADDR,
        .name = "MACADDR",
        .desc = "MAC address"
    },
    {
        .id = EG_ENC_RAW_IPV4ADDR,
        .name = "IPV4ADDR",
        .desc = "IPv4 address"
    },
    {
        .id = EG_ENC_RAW_IPV6ADDR,
        .name = "IPV6ADDR",
        .desc = "IPv6 address"
    },
    {}
};

/**
 * encode RAW
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_raw(eg_elem_t *elems, void *upper)
{
    eg_buffer_t *buf;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int8_t *p;
    int len = 0;
    int ret;

    // TODO: buffer size
    buf = eg_buffer_create(1000);
    if (buf == NULL) {
        return NULL;
    }
    p = buf->ptr;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_raw_field_encoders);
        switch (enc->id) {
        case EG_ENC_RAW_UINT32:
            ret = eg_enc_encode_uint32((u_int32_t *)p, elem->val);
            break;
        case EG_ENC_RAW_UINT16:
            ret = eg_enc_encode_uint16((u_int16_t *)p, elem->val);
            break;
        case EG_ENC_RAW_UINT8:
            ret = eg_enc_encode_uint8(p, elem->val);
            break;
        case EG_ENC_RAW_HEX:
            ret = eg_enc_encode_hex(p, elem->val, 0, 0);
            break;
        case EG_ENC_RAW_MACADDR:
            ret = eg_enc_encode_macaddr(p, elem->val);
            break;
        case EG_ENC_RAW_IPV4ADDR:
            ret = eg_enc_encode_ipv4addr((struct in_addr *)p, elem->val);
            break;
        case EG_ENC_RAW_IPV6ADDR:
            ret = eg_enc_encode_ipv6addr((struct in6_addr *)p, elem->val);
            break;
         default:
            goto err;
        }
        if (ret < 0) {
            goto err;
        }
        p += ret;
        len += ret;
    }
    buf->len = len;

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
