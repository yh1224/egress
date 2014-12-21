TARGET_EGRESS = eg
TARGET_INJECT = eg_inject

TARGETS = $(TARGET_EGRESS)

SRCS = eg_cmd_inject.c eg_cmd_encode.c
OBJS = $(SRCS:%.c=%.o)
GENSRCS = eg_parse.tab.c eg_parse.tab.h eg_parse.yy.c
GENOBJS = $(GENSRCS:%.c=%.o)
LIBSRCS = $(GENSRCS) pcap.c pkttools/rawsock.c pkttools/bpf.c pkttools/pcap.c pkttools/lib.c
LIBSRCS += eg_enc.c eg_enc_buffer.c eg_enc_common.c eg_enc_ether.c eg_enc_vlan.c eg_enc_arp.c eg_enc_icmp.c eg_enc_tcp.c eg_enc_udp.c eg_enc_ipv4.c eg_enc_ipv6.c eg_enc_raw.c
LIBOBJS = $(LIBSRCS:%.c=%.o)
LIB = libeg.a

CC = gcc
AR = ar
YACC = bison
LEX = flex

GFLAGS  = -O -Wall
GFLAGS += -g
CFLAGS  =
LDFLAGS = -L. -leg

all : $(TARGETS)

.c.o :
	$(CC) $(GFLAGS) $(CFLAGS) -c $< -o $@

eg_parse.tab.c eg_parse.tab.h : eg_parse.y
	$(YACC) -d -l $<

eg_parse.yy.c : eg_parse.l eg_parse.tab.h
	$(LEX) -o $@ eg_parse.l

$(LIB) : $(LIBOBJS) $(GENOBJS)
	$(AR) ruc $(LIB) $(LIBOBJS)

$(TARGET_EGRESS) : $(TARGET_EGRESS).o $(OBJS) $(LIB)
	$(CC) $(GFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

doc : $(GENSRCS)
	doxygen

clean :
	rm -f $(TARGETS) $(OBJS) $(LIB) $(LIBOBJS) $(GENSRCS) $(GENOBJS)
	rm -fr html
	find . -type f -exec chmod -x {} \;
