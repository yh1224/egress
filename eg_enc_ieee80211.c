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
    uint8_t     i_fc[2];
    uint8_t     i_dur[2];
    uint8_t     i_addr1[IEEE80211_ADDR_LEN];
    uint8_t     i_addr2[IEEE80211_ADDR_LEN];
    uint8_t     i_addr3[IEEE80211_ADDR_LEN];
    uint8_t     i_seq[2];
    /*
     * possibly followed by
     * uint8_t     i_addr4[IEEE80211_ADDR_LEN];
     * uint8_t     i_qos[2];
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

static eg_buffer_t *eg_enc_encode_ieee80211_common(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_beacon(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_auth(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_deauth(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_assocreq(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_assocresp(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_reassocreq(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_disassoc(eg_elem_t *elems, void *lower);
static eg_buffer_t *eg_enc_encode_ieee80211_ie(eg_elem_t *elems, void *lower);

/**
 * block encoders under ieee80211
 */
static eg_enc_encoder_t eg_enc_ieee80211_block_encoders[] = {
    {
        .name = "ASSOC_REQ",
        .desc = "Association Request",
        .encode = eg_enc_encode_ieee80211_assocreq,
    },
    {
        .name = "ASSOC_RESP",
        .desc = "Association Response",
        .encode = eg_enc_encode_ieee80211_assocresp,
    },
    {
        .name = "REASSOC_REQ",
        .desc = "Reassociation Request",
        .encode = eg_enc_encode_ieee80211_reassocreq,
    },
    {
        .name = "REASSOC_RESP",
        .desc = "Reassociation Response",
        .encode = eg_enc_encode_ieee80211_assocresp,
    },
    {
        .name = "PROBE_REQ",
        .desc = "Probe Request",
        .encode = eg_enc_encode_ieee80211_common,
    },
    {
        .name = "PROBE_RESP",
        .desc = "Probe Response",
        .encode = eg_enc_encode_ieee80211_beacon,
    },
    {
        .name = "BEACON",
        .desc = "Beacon",
        .encode = eg_enc_encode_ieee80211_beacon,
    },
#if 0 // TODO
    {
        .name = "ATIM",
        .desc = "ATIM",
        .encode = eg_enc_encode_ieee80211_atim,
    },
#endif
    {
        .name = "DISASSOC",
        .desc = "Disassociation",
        .encode = eg_enc_encode_ieee80211_disassoc,
    },
    {
        .name = "AUTH",
        .desc = "Authentication",
        .encode = eg_enc_encode_ieee80211_auth,
    },
    {
        .name = "DEAUTH",
        .desc = "Deauthentication",
        .encode = eg_enc_encode_ieee80211_deauth,
    },
#if 0 // TODO
    {
        .name = "ACTION",
        .desc = "Action",
        .encode = eg_enc_encode_ieee80211_action,
    },
#endif

    {
        .name = "IE",
        .desc = "Information Element",
        .encode = eg_enc_encode_ieee80211_ie,
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
        .aliases = "ASSOC_REQ\0ASSOC_RESP\0REASSOC_REQ\0REASSOC_RESP\0PROBE_REQ\0PROBE_RESP\0BEACON\0ATIM\0DISASSOC\0AUTH\0DEAUTH\0ACTION\0",
        .val = 0,
    },
    {
        .name = "CTL",
        .desc = "control frame",
        .aliases = "BAR\0PS_POLL\0RTS\0CTS\0ACK\0CF_END\0CF_END_ACK\0",
        .val = 1,
    },
    {
        .name = "DATA",
        .desc = "data frame",
        .aliases = "DATA\0DATA+CF_ACK\0DATA+CF_POLL\0DATA+CF_ACK_POLL\0NULL\0CF_ACK\0CF_POLL\0CF_ACK_POLL\0QOS\0QOS+CF_ACK\0QOS+CF_POLL\0QOS+CF_ACK_POLL\0QOS_NULL\0",
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
        .desc = "BAR (Block Ack Request)",
        .val = 8,
    },
    {
        .name = "PS_POLL",
        .desc = "PS-Poll",
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
        .desc = "CF-End",
        .val = 14,
    },
    {
        .name = "CF_END_ACK",
        .desc = "CF-End + CF-Ack",
        .val = 15,
    },

    /* for TYPE_DATA (bit combination) */
    {
        .name = "DATA",
        .desc = "Data",
        .val = 0,
    },
    {
        .name = "DATA+CF_ACK",
        .desc = "Data + CF-Ack",
        .val = 1,
    },
    {
        .name = "DATA+CF_POLL",
        .desc = "Data + CF-Poll",
        .val = 2,
    },
    {
        .name = "DATA+CF_ACK_POLL",
        .desc = "Data + CF-Ack + CF-Poll",
        .val = 3,
    },
    {
        .name = "NULL",
        .desc = "Null Data",
        .val = 4,
    },
    {
        .name = "CF_ACK",
        .desc = "CF-Ack",
        .val = 5,
    },
    {
        .name = "CF_POLL",
        .desc = "CF-Poll",
        .val = 6,
    },
    {
        .name = "CF_ACK_POLL",
        .desc = "CF-Ack + CF-Poll",
        .val = 7,
    },
    {
        .name = "QOS",
        .desc = "QoS Data",
        .val = 8,
    },
    {
        .name = "QOS+CF_ACK",
        .desc = "QoS Data + CF-Ack",
        .val = 9,
    },
    {
        .name = "QOS+CF_POLL",
        .desc = "QoS Data + CF-Poll",
        .val = 10,
    },
    {
        .name = "QOS+CF_ACK_POLL",
        .desc = "QoS Data + CF-Ack + CF-Poll",
        .val = 11,
    },
    {
        .name = "QOS_NULL",
        .desc = "QOS Null",
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
 * IEEE802.11 capability flags definition
 */
static eg_enc_vals_t ieee80211caps[] = {
    {
        .name = "ESS",
        .desc = "ESS",
        .val = 0x0001,
    },
    {
        .name = "IBSS",
        .desc = "IBSS",
        .val = 0x0002,
    },
    {
        .name = "CF_POLLABLE",
        .desc = "CF-Pollable",
        .val = 0x0004,
    },
    {
        .name = "CF_POLLREQ",
        .desc = "CF-PollReq",
        .val = 0x0008,
    },
    {
        .name = "PRIVACY",
        .desc = "Privacy",
        .val = 0x0010,
    },
    {
        .name = "SHORT_PREAMBLE",
        .desc = "Short Preamble",
        .val = 0x0020,
    },
    {
        .name = "PBCC",
        .desc = "PBCC",
        .val = 0x0040,
    },
    {
        .name = "CHNL_AGILITY",
        .desc = "Channel Agility",
        .val = 0x0080,
    },
    {
        .name = "SPECTRUM_MGMT",
        .desc = "Spectrum Management",
        .val = 0x0100,
    },
    {
        .name = "SHORT_SLOTTIME",
        .desc = "Short Slottime",
        .val = 0x0400,
    },
    {
        .name = "RSN",
        .desc = "RSN",
        .val = 0x0800,
    },
    {
        .name = "DSSSOFDM",
        .desc = "DSSS-OFDM",
        .val = 0x2000,
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
#define AUTOFLAG_TYPE       (1 << 0)
#define AUTOFLAG_SUBTYPE    (1 << 1)
    u_int32_t autoflags = (AUTOFLAG_TYPE | AUTOFLAG_SUBTYPE);  /* auto flags */
    u_int8_t type;
    u_int8_t subtype;
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
            wh->i_fc[0] &= ~0x03;
            wh->i_fc[0] |= (u_int8_t)num;
            break;
        case EG_ENC_IEEE80211_TYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name(&num, elem->val, ieee80211types);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 3);
            }
            wh->i_fc[0] &= ~0x0c;
            wh->i_fc[0] |= (u_int8_t)(num << 2);
            break;
        case EG_ENC_IEEE80211_SUBTYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name(&num, elem->val, ieee80211subtypes);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 15);
            }
            wh->i_fc[0] &= ~0xf0;
            wh->i_fc[0] |= (u_int8_t)(num << 4);
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
        case EG_ENC_IEEE80211_ADDRESS4:
            ret = eg_enc_encode_macaddr((u_int8_t *)(wh + 1), elem->val);
            buf->len = sizeof(*wh) + 6;
            break;
        case EG_ENC_IEEE80211_FRAGMENT:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xf);
            wh->i_seq[0] |= num & 0xf;
            break;
        case EG_ENC_IEEE80211_SEQUENCE:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xfff);
            *(uint16_t*)wh->i_seq |= htole16((u_int16_t)num) << 4;
            break;
        default:
            goto err;
        }
        if (ret < 0) {
            goto err;
        }
    }

    // XXX: fix length for CTL frame
    type = (wh->i_fc[0] >> 2) & 0x3;
    subtype = (wh->i_fc[0] >> 4) & 0xf;
    if (type == 1/* CTL */) {
        switch (subtype) {
        case 10/* PS-Poll */:
        case 11/* RTS */:
        case 14/* CF-End */:
        case 15/* CF-End + CF-Ack */:
            buf->len = 16;      /* strip: addr3, seq and addr4 */
            break;
        case 12/* CTS */:
        case 13/* ACK */:
            buf->len = 10;      /* strip: addr2, addr3, seq and addr4 */
            break;
        default:
            break;
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
        /* auto fill type */
        if (autoflags & AUTOFLAG_TYPE) {
            autoflags &= ~AUTOFLAG_TYPE;
            eg_elem_val_t v;
            v.str = elem->name;
            if (eg_enc_encode_name(&num, &v, ieee80211types) >= 0) {
                wh->i_fc[0] &= ~0x0c;
                wh->i_fc[0] |= (u_int8_t)(num << 2);
            }
        }
        /* auto fill subtype */
        if (autoflags & AUTOFLAG_SUBTYPE) {
            autoflags &= ~AUTOFLAG_SUBTYPE;
            eg_elem_val_t v;
            v.str = elem->name;
            if (eg_enc_encode_name(&num, &v, ieee80211subtypes) >= 0) {
                wh->i_fc[0] &= ~0xf0;
                wh->i_fc[0] |= (u_int8_t)(num << 4);
            }
        }
        buf = eg_buffer_merge(buf, bufn, -1);
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * block encoders under ieee80211 common
 */
static eg_enc_encoder_t eg_enc_ieee80211_common_block_encoders[] = {
    {
        .name = "IE",
        .desc = "Information Element",
        .encode = eg_enc_encode_ieee80211_ie,
    },
    {
        .name = "RAW",
        .desc = "raw data",
        .encode = eg_enc_encode_raw,
    },
    {}
};
/**
 * encode IEEE802.11 common
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_common(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;

    buf = eg_buffer_create(0);
    if (buf == NULL) {
        return NULL;
    }

    /* encode blocks */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            continue;   /* skip field */
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Beacon
 */
enum {
    EG_ENC_IEEE80211_BEACON_TIMESTAMP = 1,
    EG_ENC_IEEE80211_BEACON_INTERVAL,
    EG_ENC_IEEE80211_BEACON_CAPABILITY,
};

/**
 * field encoder for Beacon
 */
static eg_enc_encoder_t eg_enc_ieee80211_beacon_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_BEACON_TIMESTAMP,
        .name = "TIMESTAMP",
        .desc = "Timestamp",
    },
    {
        .id = EG_ENC_IEEE80211_BEACON_INTERVAL,
        .name = "INTERVAL",
        .desc = "Beacon Interval",
    },
    {
        .id = EG_ENC_IEEE80211_BEACON_CAPABILITY,
        .name = "CAPABILITY",
        .desc = "Capability Information",
    },
    {}
};

/**
 * encode IEEE802.11 Beacon
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_beacon(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(12);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 12);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_beacon_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_BEACON_TIMESTAMP:
            ret = eg_enc_encode_hex((u_int8_t *)buf->ptr, elem->val, 8, 8); // TODO: make little endian
            break;
        case EG_ENC_IEEE80211_BEACON_INTERVAL:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 8)) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_BEACON_CAPABILITY:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags(&num, elem->val, ieee80211caps);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            }
            *((u_int16_t *)(buf->ptr + 10)) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Authentication
 */
enum {
    EG_ENC_IEEE80211_AUTH_ALGORITHM = 1,
    EG_ENC_IEEE80211_AUTH_SEQUENCE,
    EG_ENC_IEEE80211_AUTH_STATUS,
};

/**
 * field encoder for Authentication
 */
static eg_enc_encoder_t eg_enc_ieee80211_auth_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_AUTH_ALGORITHM,
        .name = "ALGORITHM",
        .desc = "Authentication Algorithm Number",
    },
    {
        .id = EG_ENC_IEEE80211_AUTH_SEQUENCE,
        .name = "SEQUENCE",
        .desc = "Transaction Sequence Number",
    },
    {
        .id = EG_ENC_IEEE80211_AUTH_STATUS,
        .name = "STATUS",
        .desc = "Status Code",
    },
    {}
};

/**
 * encode IEEE802.11 Authentication
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_auth(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(6);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 6);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_auth_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_AUTH_ALGORITHM:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)buf->ptr) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_AUTH_SEQUENCE:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 2)) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_AUTH_STATUS:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 4)) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Deauthentication
 */
enum {
    EG_ENC_IEEE80211_DEAUTH_STATUS = 1,
};

/**
 * field encoder for Deauthentication
 */
static eg_enc_encoder_t eg_enc_ieee80211_deauth_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_DEAUTH_STATUS,
        .name = "STATUS",
        .desc = "Status Code",
    },
    {}
};

/**
 * encode IEEE802.11 Beacon
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_deauth(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(2);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 2);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_deauth_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_DEAUTH_STATUS:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)buf->ptr) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Association Request
 */
enum {
    EG_ENC_IEEE80211_ASSOCREQ_CAPABILITY = 1,
    EG_ENC_IEEE80211_ASSOCREQ_LI,
};

/**
 * field encoder for Association Request
 */
static eg_enc_encoder_t eg_enc_ieee80211_assocreq_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_ASSOCREQ_CAPABILITY,
        .name = "CAPABILITY",
        .desc = "Capability Information",
    },
    {
        .id = EG_ENC_IEEE80211_ASSOCREQ_LI,
        .name = "LISTEN_INTERVAL",
        .desc = "Listen Interval",
    },
    {}
};

/**
 * encode IEEE802.11 Association Request
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_assocreq(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(4);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 4);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_assocreq_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_ASSOCREQ_CAPABILITY:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags(&num, elem->val, ieee80211caps);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            }
            *((u_int16_t *)buf->ptr) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_ASSOCREQ_LI:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 2)) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Association Response
 */
enum {
    EG_ENC_IEEE80211_ASSOCRESP_CAPABILITY = 1,
    EG_ENC_IEEE80211_ASSOCRESP_STATUS,
    EG_ENC_IEEE80211_ASSOCRESP_AID,
};

/**
 * field encoder for Association Response
 */
static eg_enc_encoder_t eg_enc_ieee80211_assocresp_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_ASSOCRESP_CAPABILITY,
        .name = "CAPABILITY",
        .desc = "Capability Information",
    },
    {
        .id = EG_ENC_IEEE80211_ASSOCRESP_STATUS,
        .name = "STATUS",
        .desc = "Status Code",
    },
    {
        .id = EG_ENC_IEEE80211_ASSOCRESP_AID,
        .name = "AID",
        .desc = "Association ID",
    },
    {}
};

/**
 * encode IEEE802.11 Association Response
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_assocresp(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(6);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 6);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_assocresp_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_ASSOCRESP_CAPABILITY:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags(&num, elem->val, ieee80211caps);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            }
            *((u_int16_t *)buf->ptr) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_ASSOCRESP_STATUS:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 2)) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_ASSOCRESP_AID:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 4)) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Reassociation Request
 */
enum {
    EG_ENC_IEEE80211_REASSOCREQ_CAPABILITY = 1,
    EG_ENC_IEEE80211_REASSOCREQ_LI,
    EG_ENC_IEEE80211_REASSOCREQ_CURRENT,
};

/**
 * field encoder for Reassociation Request
 */
static eg_enc_encoder_t eg_enc_ieee80211_reassocreq_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_REASSOCREQ_CAPABILITY,
        .name = "CAPABILITY",
        .desc = "Capability Information",
    },
    {
        .id = EG_ENC_IEEE80211_REASSOCREQ_LI,
        .name = "LISTEN_INTERVAL",
        .desc = "Listen Interval",
    },
    {
        .id = EG_ENC_IEEE80211_REASSOCREQ_CURRENT,
        .name = "CURRENT",
        .desc = "Current AP Address",
    },
    {}
};

/**
 * encode IEEE802.11 Reassociation Request
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_reassocreq(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(4);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 4);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_reassocreq_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_REASSOCREQ_CAPABILITY:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_flags(&num, elem->val, ieee80211caps);
            } else {
                ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            }
            *((u_int16_t *)buf->ptr) = htole16((u_int16_t)num);
            break;
        case EG_ENC_IEEE80211_REASSOCREQ_LI:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)(buf->ptr + 2)) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for Disassociation
 */
enum {
    EG_ENC_IEEE80211_DISASSOC_STATUS = 1,
};

/**
 * field encoder for Disassociation
 */
static eg_enc_encoder_t eg_enc_ieee80211_disassoc_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_DISASSOC_STATUS,
        .name = "STATUS",
        .desc = "Status Code",
    },
    {}
};

/**
 * encode IEEE802.11 Beacon
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_disassoc(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    u_int32_t num;
    int ret;

    buf = eg_buffer_create(2);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf->ptr, 0, 2);

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_disassoc_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_DISASSOC_STATUS:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffff);
            *((u_int16_t *)buf->ptr) = htole16((u_int16_t)num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_common_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, NULL);
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

/**
 * fields for ieee80211 informatino element
 */
enum {
    EG_ENC_IEEE80211_IE_ID = 1,
    EG_ENC_IEEE80211_IE_LEN,
    EG_ENC_IEEE80211_IE_DATA,
};

/**
 * field encoder for ieee80211 informatino element
 */
static eg_enc_encoder_t eg_enc_ieee80211_ie_field_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_IE_ID,
        .name = "ID",
        .desc = "Element ID",
    },
    {
        .id = EG_ENC_IEEE80211_IE_LEN,
        .name = "LENGTH",
        .aliases = "LEN\0",
        .desc = "Element length",
    },
    {
        .id = EG_ENC_IEEE80211_IE_DATA,
        .name = "DATA",
        .desc = "data",
    },
    {}
};

/**
 * block encoder for ieee80211 informatino element
 */
static eg_enc_encoder_t eg_enc_ieee80211_ie_block_encoders[] = {
    {
        .id = EG_ENC_IEEE80211_IE_DATA,
        .name = "DATA",
        .desc = "data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * IEEE802.11 Element ID definition
 */
static eg_enc_vals_t ieee80211elemids[] = {
    {
        .name = "SSID",
        .desc = "SSID",
        .val = 0,
    },
    {
        .name = "RATES",
        .desc = "Supported Rates",
        .val = 1,
    },
    {
        .name = "FHPARMS",
        .desc = "FH Parameter Set",
        .val = 2,
    },
    {
        .name = "DSPARMS",
        .desc = "DS Parameter Set",
        .val = 3,
    },
    {
        .name = "CFPARMS",
        .desc = "CF Parameter Set",
        .val = 4,
    },
    {
        .name = "TIM",
        .desc = "TIM",
        .val = 5,
    },
    {
        .name = "IBSSPARMS",
        .desc = "IBSS Parameter Set",
        .val = 6,
    },
    {
        .name = "COUNTRY",
        .desc = "Country",
        .val = 7,
    },
    {
        .name = "CHALLENGE",
        .desc = "Challenge Text",
        .val = 16,
    },
    {
        .name = "PWRCNSTR",
        .desc = "Power Constraint",
        .val = 32,
    },
    {
        .name = "PWRCAP",
        .desc = "PWRCAP",
        .val = 33,
    },
    {
        .name = "TPCREQ",
        .desc = "TPCREQ",
        .val = 34,
    },
    {
        .name = "TPCREP",
        .desc = "TPCREP",
        .val = 35,
    },
    {
        .name = "SUPPCHAN",
        .desc = "SUPPCHAN",
        .val = 36,
    },
    {
        .name = "CHANSWITCHANN",
        .desc = "Channel Switch Announcement",
        .val = 37,
    },
    {
        .name = "MEASREQ",
        .desc = "MEASREQ",
        .val = 38,
    },
    {
        .name = "MEASREP",
        .desc = "MEASREP",
        .val = 39,
    },
    {
        .name = "QUIET",
        .desc = "QUIET",
        .val = 40,
    },
    {
        .name = "IBSSDFS",
        .desc = "IBSS DFS",
        .val = 41,
    },
    {
        .name = "ERP",
        .desc = "ERP Information",
        .val = 42,
    },
    {
        .name = "HTCAP",
        .desc = "HT Capability",
        .val = 45,
    },
    {
        .name = "RSN",
        .desc = "RSN",
        .val = 48,
    },
    {
        .name = "XRATES",
        .desc = "Extended Supported Rates",
        .val = 50,
    },
    {
        .name = "HTINFO",
        .desc = "HTINFO",
        .val = 61,
    },
    {
        .name = "TPC",
        .desc = "TPC",
        .val = 150,
    },
    {
        .name = "CCKM",
        .desc = "CCKM",
        .val = 156,
    },
    {
        .name = "VENDOR",
        .desc = "Vendor Specific",
        .val = 221,
    },
    {}
};

/**
 * encode IPv6 extension header
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_ieee80211_ie(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
#define AUTOFLAG_LEN (1 << 8)
    u_int32_t autoflags = (AUTOFLAG_LEN);  /* auto flags */
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_ie_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_IEEE80211_IE_ID:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(buf->ptr, elem->val, ieee80211elemids);
            } else {
                ret = eg_enc_encode_uint8(buf->ptr, elem->val);
            }
            break;
        case EG_ENC_IEEE80211_IE_LEN:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_LEN;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_LEN;
                ret = eg_enc_encode_uint8(buf->ptr + 1, elem->val);
            }
            break;
        case EG_ENC_IEEE80211_IE_DATA:
            ret = eg_enc_encode_hex(buf->ptr + 2, elem->val, 0, 255);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_ieee80211_ie_block_encoders);
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
    if (autoflags & AUTOFLAG_LEN) {
        *(buf->ptr + 1) = datalen;
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
