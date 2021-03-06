#USE_LIBPCAP = yes
#USE_WINPCAP = yes
#USE_NETLIB  = yes
#USE_MINGW   = yes

POSTFIX = $(USE_MINGW:yes=.exe)

TARGETS = pkt-recv pkt-send \
	pkt-txt2txt pkt-txt2pcap pkt-pcap2txt pkt-txt2bin pkt-bin2txt \
	pkt-analyze pkt-correct pkt-check pkt-filter pkt-change pkt-pingrep

OBJS := $(TARGETS:=.o)

TARGETS := $(TARGETS:=$(POSTFIX))

LIBOBJS = argument.o bpf.o rawsock.o libpcap.o lib.o text.o pcap.o \
	analyze.o correct.o check.o filter.o change.o pingrep.o \
	assemble.o disasm.o asm_val.o asm_field.o asm_entry.o asm_list.o

WINPCAPDIR = ./WpdPack
NETLIBDIR = ./netlib

LIB = libpkt.a

NETLIB = $(NETLIBDIR)/lib/libnet.a

LIBS = $(LIB) $(USE_NETLIB:yes=$(NETLIB))

SRCS = $(LIBOBJS:.o=.c)

INSTALLDIR = /usr/local
BINDIR = $(INSTALLDIR)/bin

PREFIX = $(USE_MINGW:yes=mingw32-)

CC = $(PREFIX)gcc
AR = $(PREFIX)ar

GFLAGS  = -O -Wall
GFLAGS += -g

CFLAGS  =
CFLAGS += $(USE_LIBPCAP:yes=-DUSE_LIBPCAP)
CFLAGS += $(USE_WINPCAP:yes=-DUSE_WINPCAP -I$(WINPCAPDIR)/Include)
CFLAGS += $(USE_NETLIB:yes=-DUSE_NETLIB -I$(NETLIBDIR)/include)
CFLAGS += $(USE_MINGW:yes=-DUSE_MINGW)

LFLAGS  = -L. -lpkt
LFLAGS += $(USE_WINPCAP:yes=-L$(WINPCAPDIR)/Lib)
LFLAGS += $(USE_LIBPCAP:yes=-l$(USE_WINPCAP:yes=w)pcap)
LFLAGS += $(USE_NETLIB:yes=-L$(NETLIBDIR)/lib -lnet)
#LFLAGS += $(USE_MINGW:yes=-lwsock32 -lws2_32)

.SUFFIXES:
.SUFFIXES: $(POSTFIX) .o .c

all :		$(TARGETS)

.c.o :
		$(CC) $(GFLAGS) $(CFLAGS) $< -c -o $@

$(LIB) :	$(LIBOBJS)
		$(AR) ruc $(LIB) $(LIBOBJS)

$(NETLIB) :
		cd $(NETLIBDIR) ; $(MAKE) USE_MINGW=$(USE_MINGW)

.o$(POSTFIX) :
		$(CC) $< $(GFLAGS) $(LFLAGS) -o $@

$(TARGETS) :	$(OBJS) $(LIBS)

install :	$(TARGETS)
		cp $(TARGETS) $(BINDIR)

uninstall :
		cd $(BINDIR) ; rm -f $(TARGETS)

clean :
		rm -f $(LIBOBJS) $(LIBS) $(OBJS) $(TARGETS)

clean-netlib :
		cd $(NETLIBDIR) ; $(MAKE) USE_MINGW=$(USE_MINGW) clean
