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

typedef struct unixconn {
  int slot;
  char buf[512];
  int buflen;
  char *path;
  char *remote;
  void (*listen_handler)(struct unixconn *uct);
  void (*read_handler)(struct unixconn *uct, char *data);
} unixconn_t;

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
  int mdns_listen;

  // Port to which to send DNS-over-TCP messages requesting mDNS queries
  // on this interface; value is zero if mdns isn't enabled on this interface.
  int dns_port;
} interface_t;

// // Structures required for pcmd.c, line-oriented command protocol parser

// Types of arguments supported on command lines.
typedef union arg {
  interface_t *interface;
  address_t addr;
  u_int16_t port;
} arg_t;
  
typedef enum {
  ARGTYPE_NONE, ARGTYPE_INTERFACE, ARGTYPE_IPADDR, ARGTYPE_PORT
} argtype_t;

// Maximum number of arguments supported per line.
#define MAX_CHUNKS	3

// Description of a command: its name, am integer code for that name,
// number of arguments expected, function to call to implement it,
// and an array containing the expected type of each argument.
typedef struct control_command control_command_t;
struct control_command {
  char *name;
  int code;
  int nargs;
  void (*implementation)(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args);
  argtype_t argtype[MAX_CHUNKS - 1];
};

typedef void (*asio_event_handler_t)(int slot, int events, void *thunk);

typedef struct {
  int fd;
  int events;
  void *thunk;
  void (*thunk_free)(void *);
  int refcount;
  asio_event_handler_t pollin, pollout, pollpri, pollerr, pollhup, pollnval;
} asio_state_t;

/* dnssd-relay.c */
extern interface_t *interfaces;

/* dnspacket.c */

/* dnsdump.c */

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

#include "asio-proto.h"
#include "control-proto.h"
#include "dnsdump-proto.h"
#include "dnspacket-proto.h"
#include "dnssd-relay-proto.h"
#include "mdns-proto.h"
#include "pcmd-proto.h"
#include "tdns-proto.h"
#include "unixconn-proto.h"

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
