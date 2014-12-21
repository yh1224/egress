/**
 * @file
 * Egress encoder/decoder
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <net/ethernet.h>
#include "eg_enc.h"

/**
 * top level block encoders
 */
eg_enc_encoder_t eg_enc_encoders[] = {
    {
        .name = "ETHER",
        .desc = "Ethernet frame",
        .func = eg_enc_encode_ether,
    },
    {
        .name = "IPV4",
        .desc = "IPv4 packet",
        .func = eg_enc_encode_ipv4,
    },
    {
        .name = "IPV6",
        .desc = "IPv6 packet",
        .func = eg_enc_encode_ipv6,
    },

    /* alias */
    { .name = "IP",         .func = eg_enc_encode_ipv4,             },
    {}
};

/**
 * get encoder
 *
 * @param[in] name element name
 * @param[in] encoders encoders list
 *
 * @return encoder (NULL: not found)
 */
eg_enc_encoder_t *eg_enc_get_encoder(char *name, eg_enc_encoder_t *encoders)
{
    eg_enc_encoder_t *enc;
    eg_enc_encoder_t *submatch = NULL;
    int nmatch = 0;

    for (enc = encoders; enc->name != NULL; enc++) {
        if (!strcasecmp(enc->name, name)) {
            return enc;
        }
        if (!strncasecmp(enc->name, name, strlen(name))) {
            submatch = enc;
            nmatch++;
        }
    }
    if (nmatch == 1) {
        return submatch;
    }
    fprintf(stderr, "unknown element: %s\n", name);
    fprintf(stderr, "element allowed one of the followings:\n");
    for (enc = encoders; enc->name != NULL; enc++) {
        if (enc->desc != NULL) {
            fprintf(stderr, "   %-12s  %s\n", enc->name, enc->desc);
        }
    }
    return NULL;
}

/**
 * encode
 *
 * @param[in] elems element list to encode
 *
 * @return buffer (NULL: failed)
 */
eg_buffer_t *eg_enc_encode(eg_elem_t *elems)
{
    eg_buffer_t *buf, *bufn;
    eg_elem_t *elem;
    eg_enc_encoder_t *enc;

    buf = NULL;
    for (elem = elems; elem != NULL; elem = elem->next) {
        if (elem->val != NULL) {
            fprintf(stderr, "Unexpected element: %s\n", elem->name);
            goto err;
        }
        enc = eg_enc_get_encoder(elem->name, eg_enc_encoders);
        if (!enc) {
            goto err;
        }
        bufn = enc->func(elem->elems, NULL);
        if (bufn == NULL) {
            goto err;
        }
        buf = eg_buffer_chain(buf, bufn);
    }
    return buf;

err:
    if (buf != NULL) {
        eg_buffer_destroy(buf);
    }
    return NULL;
}
