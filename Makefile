TARGET_EGRESS = eg
TARGET_INJECT = eg_inject

TARGETS = $(TARGET_EGRESS)

SRCS = eg_cmd_inject.c eg_cmd_encode.c eg_cmd_decode.c
OBJS = $(SRCS:%.c=%.o)
GENSRCS = eg_parse.tab.c eg_parse.tab.h eg_parse.yy.c
GENOBJS = $(GENSRCS:%.c=%.o)
LIBSRCS = eg_enc.c eg_enc_buffer.c eg_enc_common.c eg_enc_ether.c eg_enc_vlan.c eg_enc_arp.c eg_enc_icmp.c eg_enc_tcp.c eg_enc_udp.c eg_enc_ipv4.c eg_enc_ipv6.c eg_enc_icmpv6.c eg_enc_raw.c $(GENSRCS)
LIBOBJS = $(LIBSRCS:%.c=%.o)
LIB = libeg.a
PKTTOOLSDIR = pkttools
LIBPKT = $(PKTTOOLSDIR)/libpkt.a

CC = gcc
AR = ar
YACC = bison
LEX = flex

GFLAGS  = -O -Wall
GFLAGS += -g
CFLAGS  =
LDFLAGS = -L. -leg -L$(PKTTOOLSDIR) -lpkt

all : $(TARGETS)

.c.o :
	$(CC) $(GFLAGS) $(CFLAGS) -c $< -o $@

eg_parse.tab.c eg_parse.tab.h : eg_parse.y
	$(YACC) -d -l -o eg_parse.tab.c eg_parse.y

eg_parse.yy.c : eg_parse.l eg_parse.tab.h
	$(LEX) -o$@ eg_parse.l

$(LIB) : $(LIBOBJS) $(GENOBJS)
	$(AR) ruc $(LIB) $(LIBOBJS)

$(LIBPKT) :
	cd $(PKTTOOLSDIR) && make

$(TARGET_EGRESS) : $(TARGET_EGRESS).o $(OBJS) $(LIB) $(LIBPKT)
	$(CC) $(GFLAGS) -o $@ $(TARGET_EGRESS).o  $(OBJS) $(LDFLAGS)

doc : $(GENSRCS)
	doxygen

clean :
	cd $(PKTTOOLSDIR) && make clean
	rm -f $(TARGETS) $(OBJS) $(LIB) $(LIBOBJS) $(GENSRCS) $(GENOBJS)
	rm -fr html
	find . -type f -exec chmod -x {} \;

