/**
 * @file
 * Egress command main for eg inject
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pkttools/lib.h"
#include "pkttools/pcap.h"
#include "pcap.h"
#include "eg_enc.h"

/**
 * print usage
 */
static void usage()
{
    printf("usage: eg inject [-c] -i <device>\n");
    printf("\n");
    printf("    -c                    auto complete sender MAC address\n");
    printf("    -i <device>           interface to inject\n");
}

enum {
    EG_FILETYPE_PCAP = 0,  /* pcap format (default) */
    EG_FILETYPE_RAW = 1,   /* raw frame */
};

/**
 * eg_inject main
 *
 * @param[in] argc arguments count
 * @param[in] argv arguments value
 */
int eg_inject_main(int argc, char *argv[])
{
    static char buf[2000];
    unsigned long sendflags = 0;
    char *ifname = NULL;
    char *infile = NULL;
    int filetype = EG_FILETYPE_PCAP;
    int c;
    FILE *in;
    int out;
    int len;
    struct timeval tv;

    while ((c = getopt(argc, argv, "ct:r:i:h?")) != -1) {
        switch (c) {
        case 'c':
            sendflags |= PKT_SEND_FLAG_COMPLETE;
            break;
        case 't':
            if (strncasecmp("PCAP", optarg, strlen(optarg)) == 0) {
                filetype = EG_FILETYPE_PCAP;
            } else if (strncasecmp("RAW", optarg, strlen(optarg)) == 0) {
                filetype = EG_FILETYPE_RAW;
            } else {
                fprintf(stderr, "invalid file type: %s\n", optarg);
                usage();
                exit(EXIT_SUCCESS);
            }
            break;
        case 'r':
            infile = optarg;
            break;
        case 'i':
            ifname = optarg;
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
    if (ifname == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (infile != NULL) {
        in = fopen(infile, "r");
        if (!in) {
            fprintf(stderr, "Failed to open: %s\n", infile);
        }
    } else {
        in = stdin;
    }

    out = pkthandler.open_send(ifname, sendflags);
    if (filetype == EG_FILETYPE_PCAP) {
        while (pkt_pcap_read(in, buf, sizeof(buf), &len, NULL, &tv) > 0) {
            pkthandler.send(out, buf, len);
        }
    } else {
        while ((len = fread(buf, 1, sizeof(buf), in)) > 0) {
            pkthandler.send(out, buf, len);
        }
    }

    exit(EXIT_SUCCESS);
}
