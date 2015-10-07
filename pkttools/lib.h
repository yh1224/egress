#ifndef _PKTTOOLS_LIB_H_INCLUDED_
#define _PKTTOOLS_LIB_H_INCLUDED_

#define PKT_BUFFER_SIZE_DEFAULT 0x14000 /* 80KB */

#define PKT_RECV_FLAG_PROMISC  (1<< 0)
#define PKT_RECV_FLAG_RECVONLY (1<< 1)
#define PKT_SEND_FLAG_COMPLETE (1<<16)
#define PKT_SEND_FLAG_INTERVAL (1<<17)

struct timeval;

struct pkt_handler {
  pktif_t (*open_recv)(char *ifname, unsigned long flags, int *bufsizep);
  pktif_t (*open_send)(char *ifname, unsigned long flags);
  int (*recv)(pktif_t pktif, char *recvbuf, int recvsize, struct timeval *tm);
  int (*send)(pktif_t pktif, char *sendbuf, int sendsize);
  int (*close)(pktif_t pktif);
};

extern struct pkt_handler pkthandler;

int minval(int v0, int v1);
int maxval(int v0, int v1);

int ip_checksum(void *buffer, int size);

void *pkt_alloc_buffer(void *buffer, int *sizep, int size);

void error_exit(char *message);

#endif
