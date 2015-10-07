#ifdef __linux__
#ifndef _PKTTOOLS_RAWSOCK_H_INCLUDED_
#define _PKTTOOLS_RAWSOCK_H_INCLUDED_

struct timeval;
pktif_t rawsock_open_recv(char *ifname, unsigned long flags, int *bufsizep);
pktif_t rawsock_open_send(char *ifname, unsigned long flags);
int rawsock_recv(pktif_t pktif, char *recvbuf, int recvsize,
		 struct timeval *tm);
int rawsock_send(pktif_t pktif, char *sendbuf, int sendsize);
int rawsock_close(pktif_t pktif);

#endif
#endif
