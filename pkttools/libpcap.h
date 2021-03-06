#ifdef USE_LIBPCAP
#ifndef _PKTTOOLS_LIBPCAP_H_INCLUDED_
#define _PKTTOOLS_LIBPCAP_H_INCLUDED_

struct timeval;
pktif_t libpcap_open_recv(char *ifname, unsigned long flags, int *bufsizep);
pktif_t libpcap_open_send(char *ifname, unsigned long flags);
int libpcap_recv(pktif_t pktif, char *recvbuf, int recvsize,
		 struct timeval *tm);
int libpcap_send(pktif_t pktif, char *sendbuf, int sendsize);
int libpcap_close(pktif_t pktif);

#endif
#endif
