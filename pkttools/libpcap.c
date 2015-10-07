#ifdef USE_LIBPCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

#include "defines.h"

#include "libpcap.h"
#include "lib.h"

struct pktif {
  unsigned long flags;
  pcap_t *pcap_handle;
  int bufsize;
  char errbuf[PCAP_ERRBUF_SIZE];
#ifdef USE_WINPCAP
  char *ifname;
#endif

  struct {
    int dummy;
  } recv;

  struct {
    int dummy;
  } send;
};

static pktif_t pktif_create()
{
  pktif_t pktif;

  pktif = malloc(sizeof(*pktif));
  if (pktif == NULL)
    error_exit("Cannot allocate memory.\n");
  memset(pktif, 0, sizeof(*pktif));

  pktif->flags = 0;
  pktif->bufsize = 65536;
#ifdef USE_WINPCAP
  pktif->ifname = NULL;
#endif

  return pktif;
}

static pktif_t pktif_destroy(pktif_t pktif)
{
  if (pktif) {
#ifdef USE_WINPCAP
    if (pktif->ifname) free(pktif->ifname);
#endif
    free(pktif);
  }
  return NULL;
}

#ifdef USE_WINPCAP
static char *interface_search(pktif_t pktif, char *ifname)
{
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i, n = -1;

  if (ifname) n = atoi(ifname);

  if (pcap_findalldevs(&alldevs, pktif->errbuf) < 0)
    error_exit("Cannot find devices.\n");

  fprintf(stderr, "Available interface list:\n");

  i = 0;
  for (d = alldevs; d; d = d->next) {
    if (n < 0) {
      fprintf(stderr, "\t%d\t%s\n\t\t%s\n", i,
	      d->description ? d->description : "No description",
	      d->name);
    } else {
      if (i == n) {
	pktif->ifname = strdup(d->name);
	break;
      }
    }
    i++;
  }

  pcap_freealldevs(alldevs);

  return pktif->ifname;
}
#endif

pktif_t libpcap_open_recv(char *ifname, unsigned long flags, int *bufsizep)
{
  pktif_t pktif;
  pcap_t *pcap_handle;

  pktif = pktif_create();

  pktif->flags = flags;

#ifdef USE_WINPCAP
  ifname = interface_search(pktif, ifname);
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
#endif

  pcap_handle = pcap_open_live(ifname, pktif->bufsize,
			       (flags & PKT_RECV_FLAG_PROMISC) ? 1 : 0,
			       50, pktif->errbuf);
  if (pcap_handle == NULL)
    error_exit("Cannot open libpcap.\n");

  pktif->pcap_handle = pcap_handle;

  if (flags & PKT_RECV_FLAG_RECVONLY) {
    if (pcap_setdirection(pcap_handle, PCAP_D_IN) < 0)
      error_exit("Fail to libpcap setdirection.\n");
  }

  if (bufsizep) *bufsizep = pktif->bufsize;

  return pktif;
}

pktif_t libpcap_open_send(char *ifname, unsigned long flags)
{
  pktif_t pktif;
  pcap_t *pcap_handle;

  pktif = pktif_create();

  pktif->flags = flags;

#ifdef USE_WINPCAP
  ifname = interface_search(pktif, ifname);
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
#endif

  pcap_handle = pcap_open_live(ifname, pktif->bufsize, 0, 0, pktif->errbuf);
  if (pcap_handle == NULL)
    error_exit("Cannot open libpcap.\n");

  pktif->pcap_handle = pcap_handle;

  if (flags & PKT_SEND_FLAG_COMPLETE) {
    error_exit("Unsupported -c option with libpcap.\n");
  }

  return pktif;
}

int libpcap_recv(pktif_t pktif, char *recvbuf, int recvsize,
		 struct timeval *tm)
{
  int r;
  const unsigned char *buffer;
  struct pcap_pkthdr header;

  do {
    buffer = pcap_next(pktif->pcap_handle, &header);
  } while (buffer == NULL);

  if (tm) {
    tm->tv_sec  = header.ts.tv_sec;
    tm->tv_usec = header.ts.tv_usec;
  }
  r = header.caplen;
  if (r > recvsize) r = recvsize;
  memcpy(recvbuf, buffer, r);

  return r;
}

int libpcap_send(pktif_t pktif, char *sendbuf, int sendsize)
{
  int r;
  r = pcap_sendpacket(pktif->pcap_handle, (unsigned char *)sendbuf, sendsize);
  r = (r < 0) ? -1 : sendsize;
  return r;
}

int libpcap_close(pktif_t pktif)
{
  pcap_close(pktif->pcap_handle);
  pktif_destroy(pktif);
  return 0;
}
#endif
