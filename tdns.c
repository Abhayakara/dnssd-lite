/* tdns.c
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

// Copy data from tcp buffer to mdns buffer, start transmission
void
tdns_frame_to_mdns(tdns_t *tdp)
{
  tdns_listener_t *tlp = tdp->listener;

  // Should never happen.
  if (tlp == NULL || tlp->mdns == NULL)
    {
      syslog(LOG_CRIT, "tdp->mdns == NULL!");
      exit(1);
    }
  
  mdns_write(tlp->mdns, tdp->inbuf, tdp->inbuflen);
  tdp->inbuflen = 0;
}

	     
// Read available data from the socket.   Data is two bytes of length,
// followed by that many bytes of data.   We buffer in case of need.

void
tdns_read_handler(int slot, int events, void *thunk)
{
  tdns_t *tdp = thunk;
  int status, len;
  const char *errstr;

  // Programming error.
  if (tdp->listener == NULL)
    {
      syslog(LOG_CRIT, "tdns_read_handler: NULL listener");
      exit(1);
    }

  // read data from the socket.
  errstr = asio_read(&status, slot, &tdp->inbuf[tdp->inbuflen], tdp->awaiting);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "tdns_read_handler: %s", errstr);
      return;
    }
  tdp->inbuflen = tdp->inbuflen + status;

  // Remote connection close?
  if (status == 0)
    {
      char obuf[256];
      ntop(obuf, sizeof obuf, &tdp->peer);
      syslog(LOG_INFO, "dns disconnect on %s:%s from %s#%d\n", 
	     tdp->listener->interface->name, 
	     tdp->listener == &tdp->listener->interface->dns4 ? "ipv4" : "ipv6",
	     obuf, ntohs(tdp->peer.in6.sin6_port));
      asio_deref(slot);
      return;
    }

  // Do we have a length?
  if (tdp->inbuflen < 2)
    {
      tdp->awaiting = 2 - tdp->inbuflen;
      return;
    }
  
  len = (int)(tdp->inbuf[0]) * 256 + (int)(tdp->inbuf[1]);
  if (tdp->inbuflen < len + 2)
    {
      // If the data won't fit in the buffer, we're hosed, drop the
      // connection.
      if (len + 2 > sizeof tdp->inbuf)
	{
	  syslog(LOG_ERR, "tdns_read_handler: oversize request (%d)", len);
	  asio_deref(slot);
	  return;
	}
      tdp->awaiting = (len + 2) - tdp->inbuflen;
      return;
    }

  // Process the frame.
  tdns_frame_to_mdns(tdp);

  // Now we are waiting for the next frame.
  tdp->awaiting = 2;
  tdp->inbuflen = 0;
}

// Finalize a DNS TCP connection
void
tdns_connection_finalize(void *thunk)
{
  tdns_t *tdp = thunk;
  tdns_t **tp;

  for (tp = &tdp->listener->connections; *tp; tp = &(*tp)->next)
    {
      if (*tp == tdp)
	{
	  *tp = tdp->next;
	  break;
	}
    }
  free(tdp);
}

// Called when the listen socket is readable.
void
tdns_listen_handler(int slot, int events, void *thunk)
{
  int rslot;
  tdns_listener_t *tlp = thunk;
  address_t addr;
  socklen_t slen;
  const char *errstr;
  char obuf[256];
  tdns_t *tdp;

  slen = sizeof addr;
  errstr = asio_accept(&rslot, slot, (struct sockaddr *)&addr, &slen);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "tdns_listen_handler: asio_accept: %s", errstr);
      return;
    }

  tdp = malloc(sizeof *tdp);
  if (tdp == NULL)
    {
      syslog(LOG_ERR, "tdns_listen_handler: out of memory");
      asio_deref(rslot);
      return;
    }
  memset(tdp, 0, sizeof *tdp);
  tdp->peer = addr;
  tdp->awaiting = 2; // Length of first frame.
  tdp->listener = tlp;
  tdp->next = tlp->connections;
  tlp->connections = tdp;
  tdp->slot = rslot;

  errstr = asio_set_thunk(rslot, tdp, tdns_connection_finalize);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "tdns_listen_handler: asio_set_thunk: %s", errstr);
      return;
    }

  errstr = asio_set_handler(rslot, POLLIN, tdns_read_handler);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "tdns_listen_handler: asio_set_handler: %s", errstr);
      return;
    }

  ntop(obuf, sizeof obuf, &addr);
  syslog(LOG_INFO, "dns connection on %s:%s from %s#%d\n", 
	 tlp->interface->name, tlp == &tlp->interface->dns4 ? "ipv4" : "ipv6",
	 obuf, ntohs(addr.in6.sin6_port));
}

// Finalize a tcp listener
void
tdns_finalize_listener(void *thunk)
{
  tdns_listener_t *tlp = thunk;

  tlp->slot = -1;
  tlp->port = 0;
}

// Add a DNS listener for the specified interface.   Note that this is the
// port number for that interface, not a listener that only accepts packets
// on that interface.   DNS packets are accepted on all interfaces.

const char *
tdns_listener_add(tdns_listener_t *tlp)
{
  int sock, status;
  struct sockaddr_in6 sin6;
  socklen_t slen;
  const char *errstr;

  // If asked to set up a listener and there already is one, do nothing.
  if (tlp->slot == -1)
    {
      sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
      if (sock < 0)
	return strerror(errno);
  
      // Bind to INADDR_ANY, unspecified port.
      memset(&sin6, 0, sizeof sin6);
      sin6.sin6_family = AF_INET6;
      status = bind(sock, (struct sockaddr *)&sin6, sizeof sin6);
      if (status < 0)
	{
	badsock:
	  errstr = strerror(errno);
	badsockerr:
	  close(sock);
	  return errstr;
	}

      // Allow incoming connections.
      status = listen(sock, 5);
      if (status < 0)
	goto badsock;
  
      // Get the port
      slen = sizeof sin6;
      status = getsockname(sock, (struct sockaddr *)&sin6, &slen);
      if (status < 0)
	goto badsock;
      tlp->port = ntohs(sin6.sin6_port);

      // Set up the async event handler
      errstr = asio_add(&tlp->slot, sock);
      if (errstr != NULL)
	goto badsockerr;

      errstr = asio_set_thunk(tlp->slot, tlp, tdns_finalize_listener);
      if (errstr != NULL)
	goto badsockerr;

      errstr = asio_set_handler(tlp->slot, POLLIN, tdns_listen_handler);
      if (errstr != NULL)
	goto badsockerr;
    }
  return NULL;
}
      
const char *
tdns_listener_drop(interface_t *interface)
{
  return "not implemented.";
}

void
tdns_write_handler(int slot, int event, void *thunk)
{
  tdns_t *tdp = thunk;
  const char *errstr;
  int length;

  errstr = asio_write(&length, slot, &tdp->out.buf[tdp->out.base],
		      tdp->out.len - tdp->out.base);
  if (errstr != NULL)
    {
      char obuf[256];
      syslog(LOG_ERR, "tdns_write_handler: %s", errstr);
    noerr:
      ntop(obuf, sizeof obuf, &tdp->peer);
      syslog(LOG_INFO, "dropping connection on %s:%s with %s#%d\n", 
	     tdp->listener->interface->name, 
	     tdp->listener == &tdp->listener->interface->dns4 ? "ipv4" : "ipv6",
	     obuf, ntohs(tdp->peer.in6.sin6_port));
      asio_deref(slot);
      return;
    }
  if (length == 0)
    goto noerr;

  tdp->out.base += length;
  if (tdp->out.base == tdp->out.len)
    {
      tdp->out.base = tdp->out.len = 0;
      asio_clear_handler(tdp->slot, POLLOUT);
    }
}

const char *
tdns_write(tdns_listener_t *tlp, u_int8_t *buf, int length)
{
  tdns_t *tdp;

  for (tdp = tlp->connections; tdp; tdp = tdp -> next)
    {
      asio_queue_out(&tdp->out, buf, length);
      asio_set_handler(tdp->slot, POLLOUT, tdns_write_handler);
    }
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
