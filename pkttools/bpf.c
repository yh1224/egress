#ifdef __FreeBSD__
#ifndef USE_NETLIB
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>

#include "defines.h"

#include "bpf.h"
#include "lib.h"

struct pktif {
  unsigned long flags;
  int fd;

  struct {
    int bufsize;
    int size;
    char *buffer;
    struct bpf_hdr *hdr;
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
  pktif->recv.buffer = NULL;
  pktif->recv.hdr = NULL;

  return pktif;
}

static pktif_t pktif_destroy(pktif_t pktif)
{
  if (pktif) {
    if (pktif->recv.buffer) free(pktif->recv.buffer);
    free(pktif);
  }
  return NULL;
}

static int open_free_bpf(int flags)
{
  int fd, i;
  char devfile[16];

#define BPF_DEVFILE "/dev/bpf"
  fd = open(BPF_DEVFILE, flags);
  if (fd < 0) {
    for (i = 0; i < 16; i++) {
      sprintf(devfile, "%s%d", BPF_DEVFILE, i);
      fd = open(devfile, flags);
      if (fd >= 0)
	break;
    }
  }
  if (fd < 0)
    error_exit("Cannot open bpf.\n");

  return fd;
}

pktif_t bpf_open_recv(char *ifname, unsigned long flags, int *bufsizep)
{
  pktif_t pktif;
  int fd;
  struct ifreq ifr;
  unsigned int one = 1;
  unsigned int val;

  pktif = pktif_create();

  pktif->flags = flags;

  fd = open_free_bpf(O_RDONLY);
  if (fd < 0)
    error_exit("Cannot open bpf.\n");

  pktif->fd = fd;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, BIOCSETIF, &ifr) < 0)
    error_exit("Fail to ioctl BIOCSETIF.\n");
  if (ioctl(fd, BIOCGBLEN, &val) < 0)
    error_exit("Fail to ioctl BIOCGBLEN.\n");
  pktif->recv.bufsize = val;
  if (flags & PKT_RECV_FLAG_PROMISC) {
    if (ioctl(fd, BIOCPROMISC, NULL) < 0)
      error_exit("Fail to ioctl BIOCPROMISC.\n");
  }
  if (ioctl(fd, BIOCIMMEDIATE, &one) < 0)
    error_exit("Fail to ioctl BIOCIMMEDIATE.\n");
  val = (flags & PKT_RECV_FLAG_RECVONLY) ? 0 : 1;
  if (ioctl(fd, BIOCSSEESENT, &val) < 0)
    error_exit("Fail to ioctl BIOCSSEESENT.\n");
  if (ioctl(fd, BIOCFLUSH, NULL) < 0)
    error_exit("Fail to ioctl BIOCFLUSH.\n");

  pktif->recv.buffer = malloc(pktif->recv.bufsize);
  if (pktif->recv.buffer == NULL)
    error_exit("Out of memory.\n");

  if (bufsizep) *bufsizep = pktif->recv.bufsize;

  return pktif;
}

pktif_t bpf_open_send(char *ifname, unsigned long flags)
{
  pktif_t pktif;
  int fd;
  struct ifreq ifr;
  unsigned int val;

  pktif = pktif_create();

  pktif->flags = flags;

  fd = open_free_bpf(O_RDWR);
  if (fd < 0)
    error_exit("Cannot open bpf.\n");

  pktif->fd = fd;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, BIOCSETIF, &ifr) < 0)
    error_exit("Fail to ioctl BIOCSETIF.\n");
  val = (flags & PKT_SEND_FLAG_COMPLETE) ? 0 : 1;
  if (ioctl(fd, BIOCSHDRCMPLT, &val) < 0)
    error_exit("Fail to ioctl BIOCSHDRCMPLT.\n");

  return pktif;
}

int bpf_recv(pktif_t pktif, char *recvbuf, int recvsize, struct timeval *tm)
{
  int r;

  if (pktif->recv.hdr == NULL) {
    pktif->recv.size = read(pktif->fd, pktif->recv.buffer,
			    pktif->recv.bufsize);
    /*
     * If interface is linkdown and down, block reading and can restart
     * when recovered.
     * If interface is destroyed, -1 is returned.
     * If set signal handler and signaled, but blocking is not canceled.
     */
    if (pktif->recv.size < 0)
      error_exit("Interface down.\n");
    if (pktif->recv.size == 0)
      error_exit("Interface is unknown status.\n");
    pktif->recv.hdr = (struct bpf_hdr *)pktif->recv.buffer;
  }

  if (tm) {
    tm->tv_sec  = pktif->recv.hdr->bh_tstamp.tv_sec;
    tm->tv_usec = pktif->recv.hdr->bh_tstamp.tv_usec;
  }
  r = pktif->recv.hdr->bh_caplen;
  if (r > recvsize) r = recvsize;
  memcpy(recvbuf, (char *)pktif->recv.hdr + pktif->recv.hdr->bh_hdrlen, r);

  pktif->recv.hdr = (struct bpf_hdr *)
    ((char *)pktif->recv.hdr +
     BPF_WORDALIGN(pktif->recv.hdr->bh_hdrlen + pktif->recv.hdr->bh_caplen));

  if ((char *)pktif->recv.hdr >= pktif->recv.buffer + pktif->recv.size)
    pktif->recv.hdr = NULL;

  return r;
}

int bpf_send(pktif_t pktif, char *sendbuf, int sendsize)
{
  return write(pktif->fd, sendbuf, sendsize);
}

int bpf_close(pktif_t pktif)
{
  close(pktif->fd);
  pktif_destroy(pktif);
  return 0;
}
#endif
#endif
