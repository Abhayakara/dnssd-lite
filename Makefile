CFLAGS=-g -O0 -Wall -Werror

ndp:	ndp neighbor.o dnspacket.o dnsdump.o 

ndp.o:	ndp.c ndp.h
dnspacket.o:	dnspacket.c ndp.h
dnsdump.o:	dnsdump.c ndp.h
