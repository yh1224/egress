/**
 * @file
 * Egress encoder/decoder for ieee80211
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <sys/types.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

struct ieee80211_hdr {
#define IEEE80211_ADDR_LEN 6
        uint8_t         i_fc[2];
        uint8_t         i_dur[2];
        uint8_t         i_addr1[IEEE80211_ADDR_LEN];
        uint8_t         i_addr2[IEEE80211_ADDR_LEN];
        uint8_t         i_addr3[IEEE80211_ADDR_LEN];
        uint8_t         i_seq[2];
        /*
         * possibly followed by
         * uint8_t         i_addr4[IEEE80211_ADDR_LEN];
         * uint8_t         i_qos[2];
         */
} __attribute__((__packed__));

/**
 * fields for ieee80211
 */
enum {
    EG_ENC_IEEE80211_VERSION = 1,
    EG_ENC_IEEE80211_TYPE,
    EG_ENC_IEEE80211_SUBTYPE,
    EG_ENC_IEEE80211_FLAGS,
    EG_ENC_IEEE80211_DURATION,
    EG_ENC_IEEE80211_ADDRESS1,
    EG_ENC_IEEE80211_ADDRESS2,
    EG_ENC_IEEE80211_ADDRESS3,
    EG_ENC_IEEE80211_ADDRESS4,
    EG_ENC_IEEE80211_FRAGMENT,
    EG_ENC_IEEE80211_SEQUENCE,
};

/**
 * field encoder for ieee80211
 */
static eg_enc_encoder_t eg_enc_ieee80211_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_VERSION,
        .name = "VER",
        .desc = "version",
    },
    {
        .id = EG_ENC_IEEE80211_TYPE,
        .name = "TYPE",
        .desc = "type",
    },
    {
        .id = EG_ENC_IEEE80211_SUBTYPE,
        .name = "SUBTYPE",
        .desc = "subtype",
    },
    {
        .id = EG_ENC_IEEE80211_FLAGS,
        .name = "FLAGS",
        .desc = "flags",
    },
    {
        .id = EG_ENC_IEEE80211_DURATION,
        .name = "DURATION",
        .desc = "duration",
    },
    {
        .id = EG_ENC_IEEE80211_ADDRESS1,
        .name = "ADDRESS1",
        .desc = "address 1",
    },
    {
        .id = EG_ENC_IEEE80211_ADDRESS2,
        .name = "ADDRESS2",
        .desc = "address 2",
    },
    {
        .id = EG_ENC_IEEE80211_ADDRESS3,
        .name = "ADDRESS3",
        .desc = "address 3",
    },
    {
        .id = EG_ENC_IEEE80211_ADDRESS4,
        .name = "ADDRESS4",
        .desc = "address 4",
    },
    {
        .id = EG_ENC_IEEE80211_FRAGMENT,
        .name = "FRAGMENT",
        .desc = "fragment number",
    },
    {
        .id = EG_ENC_IEEE80211_SEQUENCE,
        .name = "SEQUENCE",
        .desc = "sequence number",
    },
    {}
};

/**
 * block encoders under ieee80211
 */
static eg_enc_encoder_t eg_enc_ieee80211_block_encoders[] = {
    {
        .name = "IPV4",
        .desc = "IEEE802.11",
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
 * IEEE802.11 frame types definition
 */
static eg_enc_vals_t ieee80211types[] = {
    {
        .name = "MGT",
        .desc = "management frame",
        .val = 0,
    },
    {
        .name = "CTL",
        .desc = "control frame",
        .val = 1,
    },
    {
        .name = "DATA",
        .desc = "data frame",
        .val = 2,
    },
    {},
};

/**
 * IEEE802.11 frame subtypes definition
 */
static eg_enc_vals_t ieee80211subtypes[] = {
    /* for TYPE_MGT */
    {
        .name = "ASSOC_REQ",
        .desc = "Association Request",
        .val = 0,
    },
    {
        .name = "ASSOC_RESP",
        .desc = "Association Response",
        .val = 1,
    },
    {
        .name = "REASSOC_REQ",
        .desc = "Reassociation Request",
        .val = 2,
    },
    {
        .name = "REASSOC_RESP",
        .desc = "Reassociation Response",
        .val = 3,
    },
    {
        .name = "PROBE_REQ",
        .desc = "Probe Request",
        .val = 4,
    },
    {
        .name = "PROBE_RESP",
        .desc = "Probe Response",
        .val = 5,
    },
    {
        .name = "BEACON",
        .desc = "Beacon",
        .val = 8,
    },
    {
        .name = "ATIM",
        .desc = "ATIM",
        .val = 9,
    },
    {
        .name = "DISASSOC",
        .desc = "Disassociation",
        .val = 10,
    },
    {
        .name = "AUTH",
        .desc = "Authentication",
        .val = 11,
    },
    {
        .name = "DEAUTH",
        .desc = "Deauthentication",
        .val = 12,
    },
    {
        .name = "ACTION",
        .desc = "Action",
        .val = 13,
    },

    /* for TYPE_CTL */
    {
        .name = "BAR",
        .desc = "BAR",
        .val = 8,
    },
    {
        .name = "PS_POLL",
        .desc = "PS_Poll",
        .val = 10,
    },
    {
        .name = "RTS",
        .desc = "Request-To-Send",
        .val = 11,
    },
    {
        .name = "CTS",
        .desc = "Clear-To-Send",
        .val = 12,
    },
    {
        .name = "ACK",
        .desc = "Ack",
        .val = 13,
    },
    {
        .name = "CF_END",
        .desc = "CF_END",
        .val = 14,
    },
    {
        .name = "CF_END_ACK",
        .desc = "CF_END_ACK",
        .val = 15,
    },

    /* for TYPE_DATA (bit combination) */
    {
        .name = "DATA",
        .desc = "DATA",
        .val = 0,
    },
    {
        .name = "CF_ACK",
        .desc = "CF_ACK",
        .val = 1,
    },
    {
        .name = "CF_POLL",
        .desc = "CF_POLL",
        .val = 2,
    },
    {
        .name = "CF_ACPL",
        .desc = "CF_ACPL",
        .val = 3,
    },
    {
        .name = "NODATA",
        .desc = "NODATA",
        .val = 4,
    },
    {
        .name = "CFACK",
        .desc = "CFACK",
        .val = 5,
    },
    {
        .name = "CFPOLL",
        .desc = "CFPOLL",
        .val = 6,
    },
    {
        .name = "CF_ACK_CF_ACK",
        .desc = "CF_ACK_CF_ACK",
        .val = 7,
    },
    {
        .name = "QOS",
        .desc = "QOS",
        .val = 8,
    },
    {
        .name = "QOS_NULL",
        .desc = "QOS_NULL",
        .val = 12,
    },

    {},
};

/**
 * IEEE802.11 flags definition
 */
static eg_enc_vals_t ieee80211flags[] = {
    {
        .name = "TODS",
        .desc = "To DS",
        .val = 0x01
    },
    {
        .name = "FROMDS",
        .desc = "From DS",
        .val = 0x02
    },
    {
        .name = "MORE_FRAG",
        .desc = "More Fragments",
        .val = 0x04
    },
    {
        .name = "RETRY",
        .desc = "Retry",
        .val = 0x08,
    },
    {
        .name = "PWR_MGT",
        .desc = "Power Management",
        .val = 0x10,
    },
    {
        .name = "MORE_DATA",
        .desc = "More Data",
        .val = 0x20,
    },
    {
        .name = "WEP",
        .desc = "Protected",
        .val = 0x40,
    },
    {
        .name = "ORDER",
        .desc = "Order",
        .val = 0x80,
    },
    {},
};

/**
 * encode IEEE802.11
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_ieee80211(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct ieee80211_hdr *wh;
    u_int32_t num;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(sizeof(*wh));
    if (buf == NULL) {
        return NULL;
    }
    wh = (struct ieee80211_hdr *)buf->ptr;

    memset(wh, 0, sizeof(*wh));

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_VERSION:
            ret = eg_enc_encode_num(&num, elem->val, 0, 3);
            wh->i_fc[0] |= num & 3;
            break;
        case EG_ENC_IEEE80211_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name(&num, elem->val, ieee80211types);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 3);
            }
            wh->i_fc[0] |= num << 2;
            break;
        case EG_ENC_IEEE80211_SUBTYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name(&num, elem->val, ieee80211subtypes);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 15);
            }
            wh->i_fc[0] |= num << 4;
            break;
        case EG_ENC_IEEE80211_FLAGS:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags_uint8(&wh->i_fc[1], elem->val, ieee80211flags);
            } else {
                ret = eg_enc_encode_uint8(&wh->i_fc[1], elem->val);
            }
            break;
        case EG_ENC_IEEE80211_DURATION:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)&wh->i_dur[0]) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_ADDRESS1:
            ret = eg_enc_encode_macaddr(wh->i_addr1, elem->val);
            break;
        case EG_ENC_IEEE80211_ADDRESS2:
            ret = eg_enc_encode_macaddr(wh->i_addr2, elem->val);
            break;
        case EG_ENC_IEEE80211_ADDRESS3:
            ret = eg_enc_encode_macaddr(wh->i_addr3, elem->val);
            break;
        case EG_ENC_IEEE80211_FRAGMENT:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xf);
            wh->i_seq[0] |= num & 0xf;
            break;
        case EG_ENC_IEEE80211_SEQUENCE:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xfff);
            *(uint16_t*)wh->i_seq |= htole16(num & 0xfff) << 4;
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, wh);
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

