#ifndef _PKTTOOLS_CHECK_H_INCLUDED_
#define _PKTTOOLS_CHECK_H_INCLUDED_

#define PKT_CHECK_FLAG_CHECKSUM (1<< 0)

int pkt_check_ethernet(unsigned long flags, char *buffer, int size);

#endif
