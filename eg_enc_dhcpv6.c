/**
 * @file
 * Egress encoder/decoder for dhcpv6
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "pkttools/lib.h"
#include "eg_enc.h"

struct dhcp6 {
	union {
		u_int8_t m;
		u_int32_t x;
	} dh6_msgtypexid;
	/* options follow */
} __attribute__((packed));
#define dh6_msgtype	dh6_msgtypexid.m
#define dh6_xid		dh6_msgtypexid.x
#define DH6_XIDMASK	0x00ffffff

/**
 * fields for dhcpv6
 */
enum {
    EG_ENC_DHCPV6_MSGTYPE = 1,
    EG_ENC_DHCPV6_XID,
};

/**
 * field encoder for dhcpv6
 */
static eg_enc_encoder_t eg_enc_dhcpv6_field_encoders[] = {
    {
        .id = EG_ENC_DHCPV6_MSGTYPE,
        .name = "MSGTYPE",
        .desc = "Message Type",
    },
    {
        .id = EG_ENC_DHCPV6_XID,
        .name = "TRANSACTION_ID",
        .desc = "Transcation ID",
    },
    {}
};

static eg_buffer_t *eg_enc_encode_dhcpv6_option(eg_elem_t *elems, void *lower);

/**
 * block encoder for dhcpv6
 */
static eg_enc_encoder_t eg_enc_dhcpv6_block_encoders[] = {
    {
        .name = "OPTION",
        .desc = "DHCPv6 option",
        .encode = eg_enc_encode_dhcpv6_option,
    },
    {}
};

/**
 * DHCPv6 msg type definition
 */
static eg_enc_vals_t dhcpv6msgtypes[] = {
    {
        .name = "SOLICIT",
        .desc = "Solicit",
        .val = 1,
    },
    {
        .name = "ADVERTISE",
        .desc = "Advertise",
        .val = 2,
    },
    {
        .name = "REQUEST",
        .desc = "Request",
        .val = 3,
    },
    {
        .name = "CONFIRM",
        .desc = "Confirm",
        .val = 4,
    },
    {
        .name = "RENEW",
        .desc = "Renew",
        .val = 5,
    },
    {
        .name = "REBIND",
        .desc = "Rebind",
        .val = 6,
    },
    {
        .name = "REPLY",
        .desc = "Reply",
        .val = 7,
    },
    {
        .name = "RELEASE",
        .desc = "Release",
        .val = 8,
    },
    {
        .name = "DECLINE",
        .desc = "Decline",
        .val = 9,
    },
    {
        .name = "RECONFIGURE",
        .desc = "Reconfigure",
        .val = 10,
    },
    {
        .name = "INFORMATION_REQUEST",
        .desc = "Information-Request",
        .val = 11,
    },
    {
        .name = "RELAY_FORW",
        .desc = "Relay-Forward",
        .val = 12,
    },
    {
        .name = "RELAY_REPL",
        .desc = "Relay-Reply",
        .val = 13,
    },
    {},
};

/**
 * encode DHCPv6
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_dhcpv6(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
    struct dhcp6 *dh6;
    int hlen = 4;
    u_int32_t num;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(hlen);
    if (buf == NULL) {
        return NULL;
    }
    dh6 = (struct dhcp6 *)buf->ptr;

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_dhcpv6_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_DHCPV6_MSGTYPE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint8(&dh6->dh6_msgtype, elem->val, dhcpv6msgtypes);
            } else {
                ret = eg_enc_encode_uint8(&dh6->dh6_msgtype, elem->val);
            }
            break;
        case EG_ENC_DHCPV6_XID:
            ret = eg_enc_encode_num(&num, elem->val, 0, 0xffffff);
            dh6->dh6_xid &= ~htonl(DH6_XIDMASK);
            dh6->dh6_xid |= htonl(num);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_dhcpv6_block_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->encode(elem->elems, dh6);
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
 * fields for dhcpv6 option
 */
enum {
    EG_ENC_DHCPV6OPT_CODE = 1,
    EG_ENC_DHCPV6OPT_LEN,
    EG_ENC_DHCPV6OPT_DATA,
};

/**
 * field encoder for dhcpv6 option
 */
static eg_enc_encoder_t eg_enc_dhcpv6opt_field_encoders[] = {
    {
        .id = EG_ENC_DHCPV6OPT_CODE,
        .name = "CODE",
        .desc = "DHCPv6 option type",
    },
    {
        .id = EG_ENC_DHCPV6OPT_LEN,
        .name = "LENGTH",
        .desc = "DHCPv6 option length",
    },
    {
        .id = EG_ENC_DHCPV6OPT_DATA,
        .name = "DATA",
        .desc = "DHCPv6 option data",
    },
    {}
};

/**
 * block encoder for dhcpv6 option
 */
static eg_enc_encoder_t eg_enc_dhcpv6opt_block_encoders[] = {
    {
        .name = "OPTION",
        .desc = "DHCPv6 option",
        .encode = eg_enc_encode_dhcpv6_option,
    },
    {
        .name = "DATA",
        .desc = "DHCPv6 option data",
        .encode = eg_enc_encode_raw,
    },
    {}
};

/**
 * dhcpv6 option code definition
 */
static eg_enc_vals_t dhcpv6optcodes[] = {
    {
        .name = "CLIENTID",
        .desc = "Client Identifier Option",
        .val = 1, /* RFC 3315 */
    },
    {
        .name = "SERVERID",
        .desc = "Server Identifier Option",
        .val = 2, /* RFC 3315 */
    },
    {
        .name = "IA_NA",
        .desc = "Identity Association for Non-temporary Addresses Option",
        .val = 3, /* RFC 3315 */
    },
    {
        .name = "IA_TA",
        .desc = "Identity Association for Temporary Addresses Option",
        .val = 4, /* RFC 3315 */
    },
    {
        .name = "IAADDR",
        .desc = "IA Address Option",
        .val = 5, /* RFC 3315 */
    },
    {
        .name = "ORO",
        .desc = "Option Request Option",
        .val = 6, /* RFC 3315 */
    },
    {
        .name = "PREFERENCE",
        .desc = "Preference Option",
        .val = 7, /* RFC 3315 */
    },
    {
        .name = "ELAPSED_TIME",
        .desc = "Elapsed Time Option",
        .val = 8, /* RFC 3315 */
    },
    {
        .name = "RELAY_MSG",
        .desc = "Relay Message Option",
        .val = 9, /* RFC 3315 */
    },
    {
        .name = "AUTH",
        .desc = "Authentication Option",
        .val = 11, /* RFC 3315 */
    },
    {
        .name = "UNICAST",
        .desc = "Server Unicast Option",
        .val = 12, /* RFC 3315 */
    },
    {
        .name = "STATUS_CODE",
        .desc = "Status Code Option",
        .val = 13, /* RFC 3315 */
    },
    {
        .name = "RAPID_COMMIT",
        .desc = "Rapid Commit Option",
        .val = 14, /* RFC 3315 */
    },
    {
        .name = "USER_CLASS",
        .desc = "User Class Option",
        .val = 15, /* RFC 3315 */
    },
    {
        .name = "VENDOR_CLASS",
        .desc = "Vendor Class Option",
        .val = 16, /* RFC 3315 */
    },
    {
        .name = "VENDOR_OPTS",
        .desc = "Vendor-specific Information Option",
        .val = 17, /* RFC 3315 */
    },
    {
        .name = "INTERFACE_ID",
        .desc = "Interface-Id Option",
        .val = 18, /* RFC 3315 */
    },
    {
        .name = "RECONF_MSG",
        .desc = "Reconfigure Message Option",
        .val = 19, /* RFC 3315 */
    },
    {
        .name = "RECONF_ACCEPT",
        .desc = "Reconfigure Accept Option",
        .val = 20, /* RFC 3315 */
    },
    {
        .name = "SIP_SERVER_D",
        .desc = "SIP Servers Domain Name List",
        .val = 21, /* RFC 3319 */
    },
    {
        .name = "SIP_SERVER_A",
        .desc = "SIP Servers IPv6 Address List",
        .val = 22, /* RFC 3319 */
    },
    {
        .name = "DNS_SERVERS",
        .desc = "DNS Recursive Name Server option",
        .val = 23, /* RFC 3646 */
    },
    {
        .name = "DOMAIN_LIST",
        .desc = "Domain Search List option",
        .val = 24, /* RFC 3646 */
    },
    {
        .name = "IA_PD",
        .desc = "Identity Association for Prefix Delegation Option",
        .val = 25, /* RFC3633 */
    },
    {
        .name = "IAPREFIX",
        .desc = "IA_PD Prefix option",
        .val = 26, /* RFC3633 */
    },
    {
        .name = "NIS_SERVERS",
        .desc = "Network Information Service (NIS) Servers Option",
        .val = 27, /* RFC 3898 */
    },
    {
        .name = "NISP_SERVERS",
        .desc = "Network Information Service V2 (NIS+) Servers Option",
        .val = 28, /* RFC 3898 */
    },
    {
        .name = "NIS_DOMAIN_NAME",
        .desc = "Network Information Service (NIS) Domain Name Option",
        .val = 29, /* RFC 3898 */
    },
    {
        .name = "NISP_DOMAIN_NAME",
        .desc = "Network Information Service V2 (NIS+) Domain Name Option",
        .val = 30, /* RFC 3898 */
    },
    {
        .name = "SNTP_SERVERS",
        .desc = "Simple Network Time Protocol (SNTP) Servers Option",
        .val = 31, /* RFC 4075 */
    },
    {
        .name = "INFORMATION_REFRESH_TIME",
        .desc = "Information Refresh Time Option",
        .val = 32, /* RFC 4242 */
    },
    {},
};

/**
 * encode DHCPv6 option
 *
 * @param[in] elems element list to encode
 * @param[in] lower lower protocol header
 *
 * @return buffer
 */
static eg_buffer_t *eg_enc_encode_dhcpv6_option(eg_elem_t *elems, void *lower)
{
    eg_buffer_t *buf, *bufn;
#define AUTOFLAG_OPTLEN (1 << 8)
    u_int32_t autoflags = (AUTOFLAG_OPTLEN);  /* auto flags */
    int datalen = 0;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;
    int ret;

    buf = eg_buffer_create(4);
    if (buf == NULL) {
        return NULL;
    }

    /* encode fields */
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val == NULL) {
            continue;   /* skip block */
        }
        ret = -1;
        enc = eg_enc_get_encoder(elem->name, eg_enc_dhcpv6opt_field_encoders);
        if (!enc) {
            goto err;
        }
        switch (enc->id) {
        case EG_ENC_DHCPV6OPT_CODE:
            if (elem->val->type == EG_TYPE_KEYWORD) {
                ret = eg_enc_encode_name_uint16((u_int16_t *)buf->ptr, elem->val, dhcpv6optcodes);
            } else {
                ret = eg_enc_encode_uint16((u_int16_t *)buf->ptr, elem->val);
            }
            break;
        case EG_ENC_DHCPV6OPT_LEN:
            if (eg_enc_val_is_keyword(elem->val, "AUTO")) {
                autoflags |= AUTOFLAG_OPTLEN;
                ret = 0;
            } else {
                autoflags &= ~AUTOFLAG_OPTLEN;
                ret = eg_enc_encode_uint16((u_int16_t *)buf->ptr + 2, elem->val);
            }
            break;
        case EG_ENC_DHCPV6OPT_DATA:
            ret = eg_enc_encode_hex(buf->ptr + 4, elem->val, 0, 254);
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
        enc = eg_enc_get_encoder(elem->name, eg_enc_dhcpv6opt_block_encoders);
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
        *((u_int16_t *)(buf->ptr + 2)) = htons(datalen);
    }

    buf->len = 4 + datalen; /* code + len + data */

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}
