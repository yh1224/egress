/**
 * @file
 * Egress encoder/decoder buffer operation
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eg_enc.h"

#define EG_BUFFER_MAXSIZE 4096

/**
 * create buffer
 *
 * @param[in] name buffer name
 * @param[in] len buffer length
 *
 * @return buffer (NULL: failed)
 */
eg_buffer_t *eg_buffer_create(int len)
{
    eg_buffer_t *buf;
    
    buf = (eg_buffer_t *)malloc(sizeof(*buf));
    if (buf == NULL) {
        fprintf(stderr, "out of memory.");
        return NULL;
    }

    memset(buf, 0, sizeof(*buf));
    if (len > 0) {
        buf->size = EG_BUFFER_MAXSIZE;
        buf->ptr = (u_int8_t *)malloc(EG_BUFFER_MAXSIZE);
        if (buf->ptr == NULL) {
            fprintf(stderr, "out of memory.");
            goto err;
        }
        memset(buf->ptr, 0, len);
        buf->len = len;
    }

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * resize buffer
 *
 * @param[in] buf buffer
 * @param[in] len new length
 *
 * @return buffer (NULL: failed)
 */
eg_buffer_t *eg_buffer_resize(eg_buffer_t *buf, int newlen)
{
    u_int8_t *newptr;

#if 0
    newptr = (u_int8_t *)malloc(newlen);
    if (newptr == NULL) {
        fprintf(stderr, "out of memory.");
        goto err;
    }
    memset(newptr, 0, newlen);
    if (buf->ptr != NULL) {
        if (newlen > buf->len) {
            memcpy(newptr, buf->ptr, buf->len);
        } else {
            memcpy(newptr, buf->ptr, newlen);
        }
        free(buf->ptr);
    }
    buf->ptr = newptr;
#else
    if (newlen > buf->size) {
        goto err;
    }
    if (newlen > buf->len) {
        memset(buf->ptr + buf->len, 0, newlen - buf->len);
    }
#endif
    buf->len = newlen;

    return buf;

err:
    eg_buffer_destroy(buf);
    return NULL;
}

/**
 * destroy buffer chain
 *
 * @param[in] buf buffer
 */
void eg_buffer_destroy(eg_buffer_t *buf)
{
    if (buf->next != NULL) {
        eg_buffer_destroy(buf->next);
    }
    if (buf->ptr != NULL) {
        free(buf->ptr);
    }
    memset(buf, 0, sizeof(*buf));
    free(buf);
}

/**
 * chain buffer
 *
 * @param[in] buf1 first buffer
 * @param[in] buf2 second buffer
 *
 * @return new buffer
 */
eg_buffer_t *eg_buffer_chain(eg_buffer_t *buf1, eg_buffer_t *buf2)
{
    eg_buffer_t *pbuf;

    if (buf1 == NULL) {
        return buf2;
    }
    for (pbuf = buf1; pbuf->next != NULL; pbuf = pbuf->next) {}
    pbuf->next = buf2;
    return buf1;
}

/**
 * merge buffer
 *
 * @param[in] buf buffer
 * @param[in] buf2 buffer to merge
 * @param[in] offset insert offset (-1:append tail)
 *
 * @return buffer
 */
eg_buffer_t *eg_buffer_merge(eg_buffer_t *buf, eg_buffer_t *buf2, int offset)
{
    int orglen = buf->len;

    if (offset < 0 || offset > orglen) {
        offset = orglen;
    }

    buf = eg_buffer_resize(buf, orglen + buf2->len);
    if (buf == NULL) {
        return NULL;
    }

    if (offset < orglen) {
        memmove(buf->ptr + offset + buf2->len, buf->ptr + offset, orglen - offset);
    }
    memcpy(buf->ptr + offset, buf2->ptr, buf2->len);
    eg_buffer_destroy(buf2);

    return buf;
}
