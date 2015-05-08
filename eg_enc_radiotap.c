/**
 * @file
 * Egress encoder/decoder for radiotap
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
#include "eg_enc.h"

struct ieee80211_radiotap_header {
   u_int8_t it_version;
   u_int8_t it_pad;
   u_int16_t it_len;
   u_int32_t it_present;
} __attribute__((__packed__));

/**
 * fields for radiotap
 */
enum {
    EG_ENC_ETHER_VERSION = 1,
    EG_ENC_ETHER_LENGTH,
    EG_ENC_ETHER_PRESENT,
};

/**
 * field encoder for radiotap
 */
static eg_enc_encoder_t eg_enc_radiotap_field_encoders[] = {
    {
        .id = EG_ENC_ETHER_VERSION,
        .name = "VERSION",
        .aliases = "VER\0",
        .desc = "radiotap version",
    },
    {
        .id = EG_ENC_ETHER_LENGTH,
        .name = "LENGTH",
        .aliases = "LEN\0",
        .desc = "header length",
    },
    {
        .id = EG_ENC_ETHER_PRESENT,
        .name = "PRESENT",
        .desc = "present flags (bitmap)",
    },
    {}
};

/**
 * block encoders under radiotap
 */
static eg_enc_encoder_t eg_enc_radiotap_block_encoders[] = {
    {
        .name = "IEEE80211",
        .desc = "IEEE802.11",
        .encode = eg_enc_encode_ieee80211,
    },
    {
        .name = "RAW",
        .desc = "raw data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * encode radiotap
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_radiotap(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct ieee80211_radiotap_header *rh;
    int hlen = sizeof(*rh);
#define AUTOFLAG_LENGTH         (1 << 0)
#define AUTOFLAG_PRESENT        (1 << 1)
    u_int32_t autoflags = (AUTOFLAG_LENGTH | AUTOFLAG_PRESENT);  /* auto flags */
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*rh));
    if (buf == NULL) {
        return NULL;
    }
    rh = (struct ieee80211_radiotap_header *)buf->ptr;

    memset(rh, 0, sizeof(*rh));

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_radiotap_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_ETHER_VERSION:
            ret = eg_enc_encode_uint8(&rh->it_version, elem->val);
            break;
        case EG_ENC_ETHER_LENGTH:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_LENGTH;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_LENGTH;
                ret = eg_enc_encode_uint16(&rh->it_len, elem->val);
                rh->it_len = ntohs(rh->it_len);
            }
            break;
        case EG_ENC_ETHER_PRESENT:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_PRESENT;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_PRESENT;
                ret = eg_enc_encode_uint32(&rh->it_present, elem->val);
                rh->it_present = ntohl(rh->it_present);
            }
            break;
        default:
            fprintf(stderr, "RADIOTAP: Unknown field: %s\n", elem->name);
            goto err;
        }
        if (ret < 0) {
            fprintf(stderr, "RADIOTAP: Unexpected field: %s\n", elem->name);
            goto err;
        }
    }

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_radiotap_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, rh);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    /* fix header length */
    if (autoflags & AUTOFLAG_LENGTH) {
        rh->it_len = (u_int16_t)hlen;
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
