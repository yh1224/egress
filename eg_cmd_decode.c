/**
 * @file
 * Egress command main for eg decode
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
    printf("usage: eg decode [-r <infile>]\n");
}

/**
 * print element
 */
static void print_element(eg_elem_t *elem, char *name, int level)
{
    char namebuf[256];
    eg_elem_t *e;
    int i;

    for (e = elem; e; e = e->next) {
        namebuf[0] = '\0';
        for (i = 0; i < level; i++) {
            strcat(namebuf, "  ");
        }      
#if 0
        if (name) {
            strcat(namebuf, name);
            strcat(namebuf, ".");
        }
#endif
        strcat(namebuf, e->name);
        if (e->elems) {
            printf("%s\n", namebuf);
            print_element(e->elems, namebuf, level + 1);
        } else if (e->val) {
            printf("%s = (%d)%s\n", namebuf, e->val->type, e->val->str);
        } else {
            printf("%s\n", namebuf);
        }
    }
}

/**
 * eg_decode main
 *
 * @param[in] argc arguments count
 * @param[in] argv arguments value
 */
int eg_decode_main(int argc, char *argv[])
{
    char *infile = NULL;
    int c;

    while ((c = getopt(argc, argv, "r:h?")) != -1) {
        switch (c) {
        case 'r':
            infile = optarg;
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

    // TODO

    exit(EXIT_SUCCESS);
}
