#CFLAGS=-g -O0 -Wno-implicit -fno-show-column -Wno-int-conversion
CFLAGS=-g -O0 -fno-show-column -Wall -Werror

#%.o:	%.c
#	$(CC) -c $(CFLAGS) -aux-info /tmp/foo.i $<
#	sed -n -e "/* $<:.*:NF */p" /tmp/foo.i >/tmp/foo.j
#	if [ ! -f $*-proto.h ] || ! cmp /tmp/foo.j $*-proto.h; then \
#	  mv /tmp/foo.j $*-proto.h; fi

dnssd-relay:	dnssd-relay.o asio.o dnsdump.o dnspacket.o mdns.o \
		pcmd.o tdns.o unixconn.o control.o

dnssd-relay.o:	dnssd-relay.c dnssd-relay.h
dnspacket.o:	dnspacket.c dnssd-relay.h
dnsdump.o:	dnsdump.c dnssd-relay.h
asio.o:		asio.c dnssd-relay.h
control.o:	control.c dnssd-relay.h
mdns.o:		mdns.c dnssd-relay.h
pcmd.o:		pcmd.c dnssd-relay.h
tdns.o:		tdns.c dnssd-relay.h
unixconn.o:	unixconn.c dnssd-relay.h
