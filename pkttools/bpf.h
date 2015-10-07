#ifdef __FreeBSD__
#ifndef _PKTTOOLS_BPF_H_INCLUDED_
#define _PKTTOOLS_BPF_H_INCLUDED_

struct timeval;
pktif_t bpf_open_recv(char *ifname, unsigned long flags, int *bufsizep);
pktif_t bpf_open_send(char *ifname, unsigned long flags);
int bpf_recv(pktif_t pktif, char *recvbuf, int recvsize, struct timeval *tm);
int bpf_send(pktif_t pktif, char *sendbuf, int sendsize);
int bpf_close(pktif_t pktif);

#endif
#endif
