/* dnssd-relay.h
 *
 * Copyright (c) Nominum, Inc 2013, 2017
 */

/*
 * This file is part of dnssd-relay
 * 
 * dnssd-relay is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * dnssd-relay is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with dnssd-relay.  If not, see <http://www.gnu.org/licenses/>.
 */

typedef union {
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} address_t;

typedef struct interface {
  struct interface *next;

  // The name by which the O.S. calls the interface; not guaranteed stable 
  // across reboots
  char *name;

  // The interface index (RFC3542), also not guaranteed stable across reboots
  int index;

  // The port on which we listen for unicast mDNS queries that will be relayed
  // to this interface, and from which we send mDNS multicasts received on this
  // interface
  int port;

  // Complete list of IPv4 and IPv6 addresses bound to this interface.
  int numaddrs, maxaddrs;
  address_t **addresses;

  // If nonzero, interface is activated for mDNS relay
  int enabled;
} interface_t;

/* dnssd-relay.c */
extern interface_t *interfaces;
int response_read(query_t *query);
void query_read(int family, int sock);
int add_query(query_t *query);
query_t *query_allocate(const unsigned char *buf, ssize_t len);

/* dnspacket.c */
int query_parse(query_t *query, unsigned char *buf, ssize_t len);

int parse_name(char *namebuf, int max,
	       const unsigned char *buf, int offset, ssize_t len);

/* dnsdump.c */
const char *classname(int class);
int query_dump(unsigned char *buf, ssize_t len);
int dump_rrdata(int class, int type, int ttl, int offset, ssize_t len,
		const unsigned char *message, ssize_t max);

#define ID(buf) (((buf)[0] << 8) | ((buf)[1]))
#define QR(buf) ((buf)[2] >> 7)
#define OPCODE(buf) (((buf)[2] & 0x78) >> 3)
#define OPCODENAME(buf) (opcode_names[OPCODE(buf)])
#define AA(buf) (((buf)[2] & 4) >> 2)
#define TC(buf) (((buf)[2] & 2) >> 1)
#define RD(buf) ((buf)[2] & 1)
#define RA(buf) ((buf)[3] >> 7)
#define Z(buf)	(((buf)[3] & 0xE0) >> 4)
#define RCODE(buf) ((buf)[3] & 15)
#define SET_RCODE(buf, rcode) ((buf)[3] = ((buf)[3] & ~15) | ((rcode) & 15))
#define SET_QR(buf, val) ((buf)[2] = ((buf)[2] & 0x7f) | ((val) ? 0x80 : 0))
#define RCODENAME(buf) (rcode_names[RCODE(buf)])
#define QDCOUNT(buf) (((buf)[4] >> 8) | (buf)[5])
#define ANCOUNT(buf) (((buf)[6] >> 8) | (buf)[7])
#define NSCOUNT(buf) (((buf)[8] >> 8) | (buf)[9])
#define ARCOUNT(buf) (((buf)[10] >> 8) | (buf)[11])

// DNS RCODE values
#define FORMERR		1
#define SERVFAIL	2
#define NOTIMPL		4
#define REFUSED		5

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
