CFLAGS=-g -O0 -fno-show-column -Wno-implicit -Wno-int-conversion -fno-diagnostics-fixit-info -fno-caret-diagnostics # -Wall -Werror

dnssd-relay:	dnssd-relay.o asio.o control.o dnsdump.o dnspacket.o mdns.o \
		pcmd.o tdns.o unixconn.o

dnssd-relay.o:	dnssd-relay.c dnssd-relay.h
dnspacket.o:	dnspacket.c dnssd-relay.h
dnsdump.o:	dnsdump.c dnssd-relay.h
asio.o:		asio.c dnssd-relay.h
control.o:	control.c dnssd-relay.h
mdns.o:		mdns.c dnssd-relay.h
pcmd.o:		pcmd.c dnssd-relay.h
tdns.o:		tdns.c dnssd-relay.h
unixconn.o:	unixconn.c dnssd-relay.h
