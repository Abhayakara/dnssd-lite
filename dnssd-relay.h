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
  char inbuf[512];
  int inbuflen;
  char outbuf[512];
  int outbuflen;
  char *path;
  char *remote;
  void (*listen_handler)(struct unixconn *uct);
  void (*read_handler)(struct unixconn *uct, char *data);
} unixconn_t;

typedef struct {
  u_int8_t buf[4096];
  int len;
  int base;
  int dropped_frames;
} outbuf_t;

// A connection from a proxy
typedef struct tdns {
  struct tdns *next;
  struct tdns_listener *listener;
  address_t peer;
  int slot;
  u_int8_t inbuf[4096];
  int inbuflen;
  int awaiting;
  outbuf_t out;
} tdns_t;

// A listener for tdns connections (currently there's only one).
typedef struct tdns_listener {
  struct interface *interface;
  tdns_t *connections;
  int port;
  int slot;
} tdns_listener_t;

typedef struct mdns {
  struct interface *interface;
  address_t to;
  int slot;
  outbuf_t out;

  // Discovery Proxy connections subscribed to mdns traffic on this link
  // with this address family
  tdns_t *proxies;
  int num_proxies;
} mdns_t;

// State of a DNS Stateful Operation message
typedef struct tdns_dso_state_t {
  int have_op_tlv;
  int op_tlv_type;
  int op_tlv_len;
  u_int8_t *op_tlv_data;
  
  int have_l2_src;
  int l2_src_len;
  u_int8_t *l2_src_data;

  int have_ip_src;
  int have_ip_family;
  address_t ip_src;

  int have_ip_src_port;
  int src_port;

  int have_link_id;
  int link_id_len;
  u_int8_t *link_id_data;

  u_int8_t *invalid_link_data;
  int invalid_link_len;

  mdns_t **links;
  int num_links;
} tdns_dso_state_t;
  
typedef struct interface {
  struct interface *next;

  // The id of the link this interface is physically connected to, as
  // configured either in the configuration file, or using the control
  // interface
  u_int32_t link_id;
  
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

  // IPv4 and IPv6 multicast DNS sockets for this interface
  mdns_t mdns4;
  mdns_t mdns6;
} interface_t;

// // Structures required for pcmd.c, line-oriented command protocol parser

// Types of arguments supported on command lines.
typedef union arg {
  interface_t *interface;
  address_t addr;
  u_int16_t port;
  u_int32_t ifid;
} arg_t;
  
typedef enum {
  ARGTYPE_NONE, ARGTYPE_INTERFACE, ARGTYPE_IPADDR, ARGTYPE_PORT, ARGTYPE_IFNAME,
  ARGTYPE_IFID
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
#define NOERROR		0
#define FORMERR		1
#define SERVFAIL	2
#define NXDOMAIN	3
#define NOTIMP		4
#define REFUSED		5
#define NOTAUTH		9
#define DSONOTIMP	11

// DNS OPCODE values
#define QUERY 0
#define IQUERY	1
#define STATUS	2
#define NOTIFY	4
#define UPDATE	5
#define DSO	6

// DSO TLVs
#define RETRY_DELAY		0
#define KEEPALIVE		1
#define MDNS_LINK_REQUEST	0x7800
#define MDNS_LINK_INVALID	0x7801
#define MDNS_LINK_SUBSCRIBED	0x7802
#define MDNS_MESSAGE		0x7803
#define L2_SOURCE_ADDRESS	0x7804
#define IP_SOURCE_ADDRESS	0x7805
#define LINK_IDENTIFIERS	0x7806
#define MDNS_DISCONTINUE	0x7807

// IANA address families (that we support)
#define INET4	1
#define INET6	2

#include "asio-proto.h"
#include "control-proto.h"
#include "dnsdump-proto.h"
#include "dnspacket-proto.h"
#include "dnssd-relay-proto.h"
#include "mdns-proto.h"
#include "pcmd-proto.h"
#include "tdns-proto.h"
#include "unixconn-proto.h"

#define TAS(thing) &thing, sizeof thing

#define MDNS_PORT 5353
#define MDNS_MCAST6 "FF02::FB"
#define MDNS_MCAST4 "224.0.0.251"

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
