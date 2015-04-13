/**
 * @file
 * Egress encoder/decoder common functions
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include "eg_enc.h"

/**
 * print help name definition
 *
 * @param[in] encnames number definition
 */
static void eg_help_vals(eg_enc_vals_t *vals)
{
    eg_enc_vals_t *p;
    char tmpstr[16];
    int namelen = 0;
    int declen = 0;
    int hexlen = 0;

    /* calc length */
    for (p = vals; p->name != NULL; p++) {
        if (namelen < strlen(p->name)) {
            namelen = strlen(p->name);
        }
        sprintf(tmpstr, "%d", p->val);
        if (declen < strlen(tmpstr)) {
            declen = strlen(tmpstr);
        }
        sprintf(tmpstr, "%x", p->val);
        if (hexlen < strlen(tmpstr)) {
            hexlen = strlen(tmpstr);
        }
    }
    if ((hexlen % 2)  == 1) {
        hexlen++;
    }

    fprintf(stderr, "name allowed one of the followings:\n");
    for (p = vals; p->name != NULL; p++) {
        if (p->desc != NULL) {
            fprintf(stderr, "  %-*s  %*d(0x%0*x)  %s\n", namelen, p->name, declen, p->val, hexlen, p->val, p->desc);
        }
    }
}

/**
 * string to unsigned long
 *
 * @param[out] result
 * @param[in] str
 *
 * @retval 0 success
 * @retval <0 fail
 */
static int eg_enc_strtoul(unsigned long *result, char *str)
{
    char *endptr;
    unsigned long num;

    if (!strncmp(str, "0x", 2)) {
        num = strtoul(str, &endptr, 16); /* hex */
    } else {
        num = strtoul(str, &endptr, 10); /* dec */
    }
    if (*endptr != '\0') {
        return -1; /* format error (overflow) */
    }
    *result = num;
    return 0;
}

/**
 * encode number (uint32 host byte order with range)
 *
 * @param[out] result result
 * @param[in] val encode string
 * @param[in] min minimum value
 * @param[in] max maximum value
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_num(u_int32_t *result, eg_elem_val_t *val, u_int32_t min, u_int32_t max)
{
    unsigned long num;

    if (val == NULL) {
        num = 0;
    } else if (val->type == EG_TYPE_NUMBER) {
        if (eg_enc_strtoul(&num, val->str) < 0) {
            fprintf(stderr, "number out of range: %s\n", val->str);
            return -1; /* format error (overflow) */
        }
        if (num < min || num > max) {
            fprintf(stderr, "number out of range: %s\n", val->str);
            return -1; /* out of range */
        }
    } else {
        fprintf(stderr, "number out of range: %s\n", val->str);
        return -1; /* type mismatch */
    }

    *result = (u_int32_t)num;
    return sizeof(*result);
}

/**
 * encode number (uint32)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_uint32(uint32_t *result, eg_elem_val_t *val)
{
    u_int32_t num;
    int ret;

    ret = eg_enc_encode_num(&num, val, 0, 0xffffffff);
    if (ret < 0) {
        return ret;
    }
    *result = htonl(num);
    return sizeof(*result);
}

/**
 * encode number (uint16)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_uint16(u_int16_t *result, eg_elem_val_t *val)
{
    u_int32_t num;
    int ret;

    ret = eg_enc_encode_num(&num, val, 0, 0xffff);
    if (ret < 0) {
        return ret;
    }
    *result = htons((u_int16_t)num);
    return sizeof(*result);
}

/**
 * encode number (uint8)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_uint8(u_int8_t *result, eg_elem_val_t *val)
{
    u_int32_t num;
    int ret;

    ret = eg_enc_encode_num(&num, val, 0, 0xff);
    if (ret < 0) {
        return ret;
    }
    *result = (u_int8_t)num;
    return sizeof(*result);
}

/**
 * encode mac address (with range)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] min minimum octets
 * @param[in] max maximum octets (0:unlimited)
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_hex(u_int8_t *result, eg_elem_val_t *val, int min, int max)
{
    u_int8_t *presult = result;
    char *p;
    int len = 0;
    u_int8_t c;
    int start, end;
    int i;

    if (val->type == EG_TYPE_NUMBER && !strncmp(val->str, "0x", 2)) {
        p = val->str + 2;
        len = 0;
        start = strlen(p) & 1;
        end = start + strlen(p);
        for (i = 0; i < min - (end / 2); i++) {
            *presult++ = 0;
            len++;
        }
        c = 0;
        for (i = start; i < end; i++) {
            c <<= 4;
            if (isdigit(*p)) {
                c += *p - '0';
            } else if (*p >= 'a' || *p <= 'f') {
                c += *p - 'a' + 10;
            } else if (*p >= 'A' || *p <= 'F') {
                c += *p - 'A' + 10;
            }
            if (i & 1) {
                if (max && len >= max) {
                    return -1;  // exceed max
                }
                *presult++ = c;
                len++;
                c = 0;
            }
            p++;
        }
    } else {
        fprintf(stderr, "invalid hex string: %s\n", val->str);
        return -1; /* type mismatch */
    }
    return len;
}

/**
 * encode mac address
 *
 * @param[out] result result
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_macaddr(u_int8_t *result, eg_elem_val_t *val)
{
    u_int8_t *presult;
    char *p;
    u_int8_t c;
    int ret;
    int i;

    if (val == NULL) {
        ;
    } else if (val->type == EG_TYPE_NUMBER) {
        ret = eg_enc_encode_hex(result, val, ETHER_ADDR_LEN, ETHER_ADDR_LEN);
        if (ret < 0) {
            return ret;
        }
    } else if (val->type == EG_TYPE_MACADDR) {
        presult = result;
        p = val->str;
        c = 0;
        for (i = 0; i < ETHER_ADDR_LEN; ) {
            if (*p == ':' || *p == '\0') {
                *presult++ = c;
                i++;
                c = 0;
            } else {
                c <<= 4;
                if (isdigit(*p)) {
                    c += *p - '0';
                } else if (*p >= 'a' || *p <= 'f') {
                    c += *p - 'a' + 10;
                } else if (*p >= 'A' || *p <= 'F') {
                    c += *p - 'A' + 10;
                }
            }
            p++;
        }
    } else {
        fprintf(stderr, "invalid mac address: %s\n", val->str);
        return -1; /* type mismatch */
    }
    return ETHER_ADDR_LEN;
}

/**
 * encode IPv4 address
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_ipv4addr(struct in_addr *result, eg_elem_val_t *val)
{
    int ret;

    if (val == NULL) {
        ;
    } else if (val->type == EG_TYPE_NUMBER) {
        ret = eg_enc_encode_hex((u_int8_t *)result, val, sizeof(*result), sizeof(*result));
        if (ret < 0) {
            return ret;
        }
    } else if (val->type == EG_TYPE_IPV4ADDR) {
        ret = inet_pton(AF_INET, val->str, result);
        if (ret != 1) {
            fprintf(stderr, "invalid IPv4 address: %s\n", val->str);
            return ret;
        }
    } else {
        fprintf(stderr, "invalid IPv4 address: %s\n", val->str);
        return -1; /* type mismatch */
    }
    return sizeof(*result);
}

/**
 * encode IPv6 address
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_ipv6addr(struct in6_addr *result, eg_elem_val_t *val)
{
    int ret;

    if (val == NULL) {
        ;
    } else if (val->type == EG_TYPE_NUMBER) {
        ret = eg_enc_encode_hex((u_int8_t *)result, val, sizeof(*result), sizeof(*result));
        if (ret < 0) {
            return ret;
        }
    } else if (val->type == EG_TYPE_IPV6ADDR) {
        ret = inet_pton(AF_INET6, val->str, result);
        if (ret != 1) {
            fprintf(stderr, "invalid IPv6 address: %s\n", val->str);
            return ret;
        }
    } else {
        fprintf(stderr, "invalid IPv6 address: %s\n", val->str);
        return -1; /* type mismatch */
    }
    return sizeof(*result);
}

/**
 * get number (uint32 host byte order)
 *
 * @param[out] result number
 * @param[in] val encode string
 * @param[in] encnames number definition
 *
 * @retval 0 success
 * @retval <0 fail
 */
static int eg_enc_encode_name(u_int32_t *result, eg_elem_val_t *val, eg_enc_vals_t *encnames)
{
    eg_enc_vals_t *p;
    char *alias;
#if defined(EG_ENC_NAME_SUBMATCH)
    u_int32_t submatch = 0;
    int nmatch = 0;
#endif

    for (p = encnames; p->name != NULL; p++) {
        if (!strcasecmp(p->name, val->str)) {
            *result = p->val;
            return 0;
        }
#if defined(EG_ENC_NAME_SUBMATCH)
        if (!strncasecmp(p->name, val->str, strlen(val->str))) {
            submatch = p->val;
            nmatch++;
        }
#endif
        for (alias = p->aliases; alias != NULL && *alias != '\0'; alias += strlen(alias) +1) {
            if (!strcasecmp(alias, val->str)) {
                *result = p->val;
                return 0;
            }
#if defined(EG_ENC_ENCODER_SUBMATCH)
            if (!strncasecmp(alias, val->str, strlen(val->str))) {
                submatch = enc;
                nmatch++;
            }
#endif
        }
    }
#if defined(EG_ENC_NAME_SUBMATCH)
    if (nmatch == 1) {
        *result = submatch;
        return 0;
    }
#endif
    fprintf(stderr, "unknown name: %s\n", val->str);
    eg_help_vals(encnames);
    return -1;
}

/**
 * encode name (uint32)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] encnames number definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_name_uint32(u_int32_t *result, eg_elem_val_t *val, eg_enc_vals_t *encnames)
{
    u_int32_t number;
    int ret;

    ret = eg_enc_encode_name(&number, val, encnames);
    if (ret < 0) {
        return ret;
    }
    *result = htonl(number);
    return sizeof(*result);
}

/**
 * encode name (uint16)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] encnames number definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_name_uint16(u_int16_t *result, eg_elem_val_t *val, eg_enc_vals_t *encnames)
{
    u_int32_t number;
    int ret;

    ret = eg_enc_encode_name(&number, val, encnames);
    if (ret < 0) {
        return ret;
    }
    *result = htons((u_int16_t)number);
    return sizeof(*result);
}

/**
 * encode name (uint8)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] encnames number definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_name_uint8(u_int8_t *result, eg_elem_val_t *val, eg_enc_vals_t *encnames)
{
    u_int32_t number;
    int ret;

    ret = eg_enc_encode_name(&number, val, encnames);
    if (ret < 0) {
        return ret;
    }
    *result = (u_int8_t)number;
    return sizeof(*result);
}

/**
 * get flags value (uint32 host byte order)
 *
 * @param[out] result flags value
 * @param[in] val encode string
 * @param[in] encflags flags definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
static int eg_enc_encode_flags(u_int32_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags)
{
    static char * const delim = ",";
    eg_enc_vals_t *p;
    char *namebuf, *pname, *saveptr;
    int ret = sizeof(*result);
    char *alias;
#if defined(EG_ENC_NAME_SUBMATCH)
    u_int32_t submatch;
    int nmatch;
#endif

    namebuf = malloc(strlen(val->str) + 1);
    strcpy(namebuf, val->str);

    *result = 0;
    pname = strtok_r(namebuf, delim, &saveptr);
    do {
#if defined(EG_ENC_NAME_SUBMATCH)
        submatch = nmatch = 0;
#endif
        for (p = encflags; p->name != NULL; p++) {
            if (!strcasecmp(p->name, pname)) {
                *result |= p->val;
                goto found;
            }
#if defined(EG_ENC_NAME_SUBMATCH)
            if (!strncasecmp(p->name, pname, strlen(pname))) {
                submatch = p->val;
                nmatch++;
            }
#endif
            for (alias = p->aliases; alias != NULL && *alias != '\0'; alias += strlen(alias) +1) {
                if (!strcasecmp(alias, pname)) {
                    *result |= p->val;
                    goto found;
                }
#if defined(EG_ENC_ENCODER_SUBMATCH)
                if (!strncasecmp(alias, pname, strlen(name))) {
                    submatch = p->val;
                    nmatch++;
                }
#endif
            }
        }
found:
        if (p->name == NULL) {
#if defined(EG_ENC_NAME_SUBMATCH)
            if (nmatch == 1) {
                *result |= submatch;
                continue;
            }
#endif
            fprintf(stderr, "unknown flag: %s\n", pname);
            eg_help_vals(encflags);
            ret = -1;
            goto end;
        }
    } while ((pname = strtok_r(NULL, delim, &saveptr)) != NULL);

end:
    free(namebuf);
    return ret;
}

/**
 * get flags value (uint32)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] encflags flags definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_flags_uint32(u_int32_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags)
{
    u_int32_t flags;
    int ret;

    ret = eg_enc_encode_flags(&flags, val, encflags);
    if (ret < 0) {
        return ret;
    }
    *result = htonl(flags);
    return sizeof(*result);
}

/**
 * get flags value (uint16)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] encflags flags definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_flags_uint16(u_int16_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags)
{
    u_int32_t flags;
    int ret;

    ret = eg_enc_encode_flags(&flags, val, encflags);
    if (ret < 0) {
        return ret;
    }
    *result = htons((u_int16_t)flags);
    return sizeof(*result);
}

/**
 * get flags value (uint8)
 *
 * @param[out] result buffer to write
 * @param[in] val encode string
 * @param[in] encflags flags definition
 *
 * @retval >=0 encoded length
 * @retval <0 fail
 */
int eg_enc_encode_flags_uint8(u_int8_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags)
{
    u_int32_t flags;
    int ret;

    ret = eg_enc_encode_flags(&flags, val, encflags);
    if (ret < 0) {
        return ret;
    }
    *result = (u_int8_t)flags;
    return sizeof(*result);
}
