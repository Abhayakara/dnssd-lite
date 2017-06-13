/* mdns.c
 *
 * Copyright (c) Nominum, Inc 2017
 */

/*
 * This file is part of DNSSD-RELAY.
 * 
 * DNSSD-RELAY is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * DNSSD-RELAY is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with DNSSD-RELAY.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE 1
#define __APPLE_USE_RFC_3542 1

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <netinet/in.h>

#include "dnssd-relay.h"

const char *
mdns_addr_to_buf(int *addrlen, u_int8_t *buffer, int length, int max, address_t *from)
{
  int len;

  if (from->sa.sa_family == AF_INET)
    len = sizeof from->in.sin_addr;
  else
    len = sizeof from->in6.sin6_addr;
  len++;

  if (length + len + 2 > max)
    return "no space for address";
  
  buffer[length] = len >> 8;
  buffer[length + 1] = len & 255;
  buffer[length + 2] = from->sa.sa_family == AF_INET6;
  if (buffer[length + 2] == 0)
    memcpy(&buffer[length], &from->in6.sin6_addr, 16);
  else
    memcpy(&buffer[length], &from->in.sin_addr, 4);

  *addrlen = len + 2;
  return NULL;
}

// Handle incoming datagrams...
void
mdns_read_handler(int slot, int events, void *thunk)
{
  mdns_t *mdp = thunk;
  u_int8_t datagram[4096];
  int length, addrlen;
  const char *errstr;
  address_t from;
  
  errstr = asio_recvfrom(&length, slot,  datagram, sizeof datagram, 0, 
			 (struct sockaddr *)&from, sizeof from);
  if (errstr != NULL)
    {
    bad:
      syslog(LOG_ERR, "mdns_read_handler: %s", errstr);
      return;
    }
  
  // Copy out the source address at the end of the datagram buffer
  errstr = mdns_addr_to_buf(&addrlen, datagram, length, sizeof datagram, &from);
  if (errstr != NULL)
    goto bad;

  // Write the datagram plus the source address on the tcp socket
  errstr = tdns_write(mdp->tdns, datagram, length + addrlen + 2);
  if (errstr != NULL)
    goto bad;
}

void
mdns_finalize(void *thunk)
{
  mdns_t *mdp = thunk;
  mdp->slot = -1;
  memset(&mdp->out, 0, sizeof mdp->out);
}

// Multicast sockets don't seem to work as IPv4/IPv6 sockets, so in principle
// we need one of each.   It appears that we can have one socket per interface
// and only receive multicasts on that interface.   We could have a separate
// socket bound to INADDR_ANY that receives unicasts on any interface, but
// we'll leave that for later (could be useful for supporting a future
// anycast solution for non-multicast leaf networks).
// An artifact of the dual-socket model is that every question is going to be
// multicast twice, once for IPv4 and once for IPv6.   It would be nice to
// be able to tell whether this is necessary or not, and leave off IPv4
// multicasts if there are no IPv4 hosts on the wire.

const char *
mdns_listener_add(interface_t *ip)
{
  int sock, status;
  address_t addr;
  socklen_t slen;
  int one = 1;
  int zero = 0;
  struct ipv6_mreq mr6;
  struct ip_mreq mr4;
  const char *errstr;

  if (ip->mdns6.slot == -1)
    {
      sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      if (sock < 0)
	return strerror(errno);

      status = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, TAS(one));
      if (status < 0)
	{
	badsock:
	  errstr = strerror(errno);
	badsockerr:
	  close(sock);
	  return errstr;
	}

      status = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, TAS(one));
      if (status < 0)
	goto badsock;

      inet_pton(AF_INET6, MDNS_MCAST6, &ip->mdns6.to);
      ip->mdns6.to.in6.sin6_family = AF_INET6;
      ip->mdns6.to.in6.sin6_port = htons(MDNS_PORT);
      
      status = bind(sock, (struct sockaddr *)&ip->mdns6.to, sizeof ip->mdns6.to);
      if (status < 0)
	goto badsock;

      // Join the MDNS multicast group on this interface
      inet_pton(AF_INET6, MDNS_MCAST6, &mr6.ipv6mr_multiaddr);
      mr6.ipv6mr_interface = ip->index;
      status = setsockopt(sock, IPPROTO_IPV6, IP_ADD_MEMBERSHIP, TAS(mr6));
      if (status < 0)
	goto badsock;

      // Send packets on this socket out of this interface.
      status = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, TAS(ip->index));
      if (status < 0)
	goto badsock;

      // Disable looping back of packets (right?)
      // This will prevent services the local host is advertising from
      // being discovered, so have to figure out whether that's good or bad.
      status = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, TAS(zero));
      if (status < 0)
	goto badsock;
      
      errstr = asio_add(&ip->mdns6.slot, sock);
      if (errstr != NULL)
	goto badsockerr;

      ip->mdns6.interface = ip;
      errstr = asio_set_thunk(ip->mdns6.slot, &ip->mdns6, mdns_finalize);
      if (errstr != NULL)
	{
	badslot:
	  asio_deref(ip->mdns6.slot);
	  goto badsockerr;
	}

      errstr = asio_set_handler(ip->mdns6.slot, POLLIN, mdns_read_handler);
      if (errstr != NULL)
	goto badslot;
    }

  if (ip->mdns4.slot == -1)
    {
      int i;
      
      for (i = 0; i < ip->numaddrs; i++)
	{
	  if (ip->addresses[i]->sa.sa_family == AF_INET)
	    break;
	}
      if (i != ip->numaddrs)
	{
	  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	  if (sock < 0)
	    return strerror(errno);
	  
	  status = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, TAS(one));
	  if (status < 0)
	    goto badsock;
	  
	  status = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, TAS(one));
	  if (status < 0)
	    goto badsock;
	  
	  inet_pton(AF_INET, MDNS_MCAST4, &ip->mdns4.to);
	  ip->mdns4.to.in.sin_family = AF_INET;
	  ip->mdns4.to.in.sin_port = htons(MDNS_PORT);
	  
	  status = bind(sock, (struct sockaddr *)&ip->mdns4.to, sizeof ip->mdns4.to);
	  if (status < 0)
	    goto badsock;

	  // Join the MDNS multicast group on this interface
	  inet_pton(AF_INET, MDNS_MCAST4, &mr4.imr_multiaddr);
	  mr4.imr_interface.s_addr = ip->addresses[i]->in.sin_addr.s_addr;
	  status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, TAS(mr6));
	  if (status < 0)
	    goto badsock;

	  // Send packets on this socket out of this interface.
	  status = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, TAS(ip->addresses[i]));
	  if (status < 0)
	    goto badsock;

	  // Disable looping back of packets (right?)
	  // This will prevent services the local host is advertising from
	  // being discovered, so have to figure out whether that's good or bad.
	  status = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, TAS(zero));
	  if (status < 0)
	    goto badsock;
      
	  errstr = asio_add(&ip->mdns4.slot, sock);
	  if (errstr != NULL)
	    goto badsockerr;
	  
	  ip->mdns4.interface = ip;
	  errstr = asio_set_thunk(ip->mdns4.slot, &ip->mdns4, mdns_finalize);
	  if (errstr != NULL)
	    {
	    badslot4:
	      asio_deref(ip->mdns4.slot);
	      goto badsockerr;
	    }
	  
	  errstr = asio_set_handler(ip->mdns4.slot, POLLIN, mdns_read_handler);
	  if (errstr != NULL)
	    goto badslot4;
	}
    }
  return NULL;
}
      
void
mdns_write_handler(int slot, int events, void *thunk)
{
  mdns_t *mdp = thunk;
  int len;
  int buflen = mdp->out.len - mdp->out.base;
  int count;
  u_int8_t *outbuf = &mdp->out.buf[mdp->out.base];
  const char *errstr;
  
  // Programming error
  if (buflen < 2)
    {
      syslog(LOG_CRIT, "mdns_write_handler: unexpectedly short output buffer!");
      exit(1);
    }

  // Reconstitute the datagram length.
  len = (outbuf[0] << 8) + outbuf[1];

  // Programming error
  if (len + 2 > buflen)
    {
      syslog(LOG_CRIT, "mdns_write_handler: datagram length > buffer length!");
      exit(1);
    }
  
  errstr = asio_sendto(&count, mdp->slot, outbuf + 2, len, 0,
		       (struct sockaddr *)&mdp->to, sizeof mdp->to);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "mdns_write_handler: %s", errstr);
      return;
    }
  mdp->out.base += len + 2;

  // When the buffer is empty, get rid of the gap.
  if (mdp->out.base == mdp->out.len)
    {
      mdp->out.base = mdp->out.len = 0;
      // nothing left to write.
      asio_clear_handler(mdp->slot, POLLOUT);
    }
}

// Copy data from tcp buffer to mdns buffer, start transmission
//
// note: it may seem like an odd design choice to store the length
// and the data in a buffer given that this requires byte-ifying
// the length, but it's actually less bookkeeping than keeping
// a separate set of datagram lengths, and doesn't require us to
// guess the size of the average datagram.   That is, I think it's
// actually a smaller attack surface for Murphy.
void
mdns_write(mdns_t *mdp, u_int8_t *buf, int buflen)
{
  // Haven't set up an mdns socket?
  if (mdp->slot == -1)
    {
      mdp->out.dropped_frames++;
      return;
    }

  asio_queue_out(&mdp->out, buf, buflen);
  asio_set_handler(mdp->slot, POLLOUT, mdns_write_handler);
}

const char *
mdns_listener_drop(interface_t *interface)
{
  return "not implemented.";
}
      
/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
