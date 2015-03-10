/**
 * @file
 * Egress command main for eg inject
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
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
    printf("usage: eg inject [-qc] [-w <usec>] -i <device>\n");
    printf("\n");
    printf("    -c                    auto complete sender MAC address\n");
    printf("    -q                    quiet mode\n");
    printf("    -w <usec>             sending interval\n");
    printf("    -i <device>           interface to inject\n");
}

enum {
    EG_FILETYPE_PCAP = 0,  /* pcap format (default) */
    EG_FILETYPE_RAW = 1,   /* raw frame */
};

/**
 * print hexadecimal dump
 */
void print_hexdump(const char *hexbin, int len) {
  int i;
  const char *p;

  p = hexbin;
  for (i = 0; i < len; i++) {
    if (i != 0 && i % 32 == 0) {
      printf("\n");
    }
    if ((i % 8) == 0) {
      printf(" ");
    }
    printf("%02x", (unsigned char)*p);
    p++;
  }
  printf("\n");

  return;
}

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
    int interval = 0;
    int qflag = 0;
    int c;
    FILE *in;
    int out;
    int len;
    struct timeval tv;

    while ((c = getopt(argc, argv, "cw:t:r:i:qh?")) != -1) {
        switch (c) {
        case 'c':
            sendflags |= PKT_SEND_FLAG_COMPLETE;
            break;
        case 'w':
            interval = atoi(optarg);
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
        case 'q':
            qflag = 1;
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
            if (!qflag) {
                printf("\n---> %d bytes to %s\n", len, ifname);
                print_hexdump(buf, len);
            }
            if (interval) {
                usleep(interval * 1000);
            }
        }
    } else {
        while ((len = fread(buf, 1, sizeof(buf), in)) > 0) {
            pkthandler.send(out, buf, len);
            if (!qflag) {
                printf("\n---> %d bytes to %s\n", len, ifname);
                print_hexdump(buf, len);
            }
            if (interval) {
                usleep(interval * 1000);
            }
        }
    }

    exit(EXIT_SUCCESS);
}
