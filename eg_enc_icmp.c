/**
 * @file
 * Egress encoder/decoder for icmp
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "eg_enc.h"

/**
 * encode ICMP
 *
 * @param[in] elems element list to encode
 * @param[in] upper upper protocol header
 *
 * @return buffer
 */
eg_buffer_t *eg_enc_encode_icmp(eg_elem_t *elems, void *upper)
{
    // TODO
    return 0;
}
