/**
 * @file
 * Egress command main for eg encode
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "pkttools/lib.h"
#include "pkttools/pcap.h"
#include "eg_enc.h"

/**
 * print usage
 */
static void usage()
{
    printf("usage: eg encode [-c <input>]\n");
}

/**
 * eg_encode main
 *
 * @param[in] argc arguments count
 * @param[in] argv arguments value
 */
int eg_encode_main(int argc, char *argv[])
{
    extern FILE *yyin;
    char *instr = NULL;
    struct timeval tv;
    eg_buffer_t *buf;
    int opt;
    int ret;

    while ((opt = getopt(argc, argv, "c:h?")) != -1) {
        switch (opt) {
        case 'c':
            instr = optarg;
            break;
        case 'h':
        case '?':
            usage();
            exit(EXIT_SUCCESS);
        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }

    if (instr) {
        yyin = fmemopen(instr, strlen(instr), "r");
    }
    ret = yyparse();
    if (ret) {
        exit(EXIT_FAILURE); /* parse failure */
    }

    buf = eg_enc_encode(get_element_top());
    if (buf == NULL) {
        exit(EXIT_FAILURE); /* encode failure */
    }

    tv.tv_sec = tv.tv_usec = 0;
    pkt_pcap_write(stdout, (char *)buf->ptr, buf->len, buf->len, &tv);

    exit(EXIT_SUCCESS);
}
