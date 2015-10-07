#include <stdio.h>
#include <stdlib.h>
#ifndef USE_NETLIB
#include <netinet/in.h>
#endif

#include "defines.h"

#include "bpf.h"
#include "rawsock.h"
#include "libpcap.h"
#include "lib.h"

struct pkt_handler pkthandler = {
#ifdef USE_LIBPCAP
  libpcap_open_recv, libpcap_open_send, libpcap_recv, libpcap_send,
  libpcap_close,
#else
#ifdef __FreeBSD__
  bpf_open_recv, bpf_open_send, bpf_recv, bpf_send,
  bpf_close,
#endif
#ifdef __linux__
  rawsock_open_recv, rawsock_open_send, rawsock_recv, rawsock_send,
  rawsock_close,
#endif
#endif
};

int minval(int v0, int v1)
{
  return (v0 < v1) ? v0 : v1;
}

int maxval(int v0, int v1)
{
  return (v0 > v1) ? v0 : v1;
}

int ip_checksum(void *buffer, int size)
{
  union {
    char c[2];
    unsigned short s;
  } w;
  char *p;
  int sum = 0;

  for (p = buffer; size > 0; p += 2) {
    w.c[0] = p[0];
    w.c[1] = (size > 1) ? p[1] : 0;
    sum += w.s; /* Unneed ntohs() */
    size -= 2;
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return sum;
}

void *pkt_alloc_buffer(void *buffer, int *sizep, int size)
{
  if ((buffer == NULL) || (*sizep < size)) {
    if (buffer)
      free(buffer);
    buffer = malloc(size);
    if (buffer == NULL)
      error_exit("Out of memory.\n");
    *sizep = size;
  }
  return buffer;
}

void error_exit(char *message)
{
  fprintf(stderr, "%s", message);
  exit(1);
}
