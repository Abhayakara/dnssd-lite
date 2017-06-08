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
	     
// deref
// write
// free_tlt
// make
// read_handler
// listen_handler
// listener_add
//    make a tcp46 socket
//    listen on it
//    get the port number
//    stash it on the interface, along with a pointer to the tcp listener
//    set up polling for the listen socket

// Read available data from the socket.   Data is two bytes of length,
// followed by that many bytes of data.   We buffer in case of need.

void
tdns_read_handler(int slot, int events, void *thunk)
{
  tdns_t *tdp = thunk;
  int status, len;
  const char *errstr;

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
      syslog(LOG_INFO, "dns disconnect on %s from %s#%d\n", 
	     tdp->interface->name, obuf, ntohs(tdp->peer.in6.sin6_port));
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

  query_dump((unsigned char *)&tdp->inbuf[2], len);

  // Process the frame.
  // tdns_frame(tdp);

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

  for (tp = &tdp->interface->dns_connections; *tp; tp = &(*tp)->next)
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
  interface_t *ip = thunk;
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
  tdp->interface = ip;
  tdp->next = ip->dns_connections;
  ip->dns_connections = tdp;
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
  syslog(LOG_INFO, "dns connection on %s from %s#%d\n", ip->name, obuf,
	 ntohs(addr.in6.sin6_port));
}

// Finalize a tcp listener
void
tdns_finalize_listener(void *thunk)
{
  interface_t *ip = thunk;

  ip->dns_slot = -1;
  ip->dns_port = 0;
}

// Add a DNS listener for the specified interface.   Note that this is the
// port number for that interface, not a listener that only accepts packets
// on that interface.   DNS packets are accepted on all interfaces.

const char *
tdns_listener_add(interface_t *ip)
{
  int sock, status;
  struct sockaddr_in6 sin6;
  socklen_t slen;
  const char *errstr;

  // If asked to set up a listener and there already is one, do nothing.
  if (ip->dns_slot == -1)
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
      ip->dns_port = ntohs(sin6.sin6_port);

      // Set up the async event handler
      errstr = asio_add(&ip->dns_slot, sock);
      if (errstr != NULL)
	goto badsockerr;

      errstr = asio_set_thunk(ip->dns_slot, ip, tdns_finalize_listener);
      if (errstr != NULL)
	goto badsockerr;

      errstr = asio_set_handler(ip->dns_slot, POLLIN, tdns_listen_handler);
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

#if 0
int
response_read(query_t *query)
{
  unsigned char buf[4096];	// XXX arbitrary limit
  ssize_t len;
  address_t src_addr;
  socklen_t srclen = sizeof src_addr;
  int sock;
  int result;
  query_t *response;
  
  len = recvfrom(query->socket, buf, sizeof buf, 0, &src_addr.sa, &srclen);
  if (len < 0)
    {
      syslog(LOG_ERR, "response socket (%d) read fail: %m", query->socket);
      return 0;
    }
  if (len < 12)
    {
      syslog(LOG_DEBUG, "short DNS packet: %ld", (long)len);
      return 0;
    }

  /* Allocate a query structure. */
  response = query_allocate(buf, len);
  if (!response)
    {
      syslog(LOG_ERR, "out of memory for response data structure.");
      return 0;
    }

  // If the result is bogus, just ignore it; if the query is never going
  // to succeed, it will time out.
  result = query_parse(response, buf, len);
  if (result < 0)
    {
      free(response);
      return 0;
    }

  // Get rid of the EDNS0 option coming back.
  result = drop_edns0(response, query->added_edns0);
  if (result < 0)
    {
      free(response);
      return 0;
    }

  if (query->src.sa.sa_family == AF_INET)
    sock = sock4;
  else if (query->src.sa.sa_family == AF_INET6)
    sock = sock6;
  else
    {
      syslog(LOG_ERR, "can't forward query response to family %d",
	      query->src.sa.sa_family);
      free(response);
      return -1;
    }

  sendto(sock, response->query, response->qlength, 0,
	 &query->src.sa, query->srclen);
  free(response);
  query->cur_nameserver->ncomplete[0]++;
  return -1;
}

void
query_read(int family, int sock)
{
  unsigned char buf[4096];	// XXX arbitrary limit
  unsigned char cmsg_buf[1024];
  ssize_t len;
  int result;
  address_t src_addr;
  socklen_t srclen = sizeof src_addr;
  query_t *query;
  nte_t *nte;
  int i;
  int added = 0;
  int ifindex, got_ifindex = 0;
  interface_t *ifp;
  struct cmsghdr *cmh;

  struct iovec iov;
  struct msghdr mh;

  /* Set up msgbuf. */
  memset(&iov, 0, sizeof iov);
  memset(&mh, 0, sizeof mh);

  /* This is equivalent to the from argument in recvfrom. */
  mh.msg_name = (caddr_t)&src_addr;
  mh.msg_namelen = sizeof src_addr;
                   
  /* This is equivalent to the buf argument in recvfrom. */
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  iov.iov_base = (caddr_t)&buf;
  iov.iov_len = sizeof buf;

  /* This is where additional headers get stuffed. */
  mh.msg_control = cmsg_buf;
  mh.msg_controllen = sizeof cmsg_buf;

  len = recvmsg(sock, &mh, 0);
  if (len < 0)
    {
      if (family == AF_INET)
	syslog(LOG_ERR, "INET socket read fail: %m");
      else
	syslog(LOG_ERR, "INET6 socket read fail: %m");
      return;
    }
  if (len < 12)
    {
      syslog(LOG_ERR, "short DNS packet: %ld", (long)len);
      return;
    }

  /* Loop through the control message headers looking for
   * the IPV6_PKTINFO or IP_PKTINFO data.
   */
  for (cmh = CMSG_FIRSTHDR(&mh); cmh; cmh = CMSG_NXTHDR(&mh, cmh))
    {
      if (cmh->cmsg_level == IPPROTO_IPV6 &&
	  cmh->cmsg_type == IPV6_PKTINFO)
	{
	  struct in6_pktinfo pktinfo;
	  
	  /* The sockaddr should be right after the cmsg_hdr. */
	  memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
	  ifindex = pktinfo.ipi6_ifindex;
	  got_ifindex = 1;
#ifdef IP_PKTINFO
	}
      else if (cmh->cmsg_level == IPPROTO_IP &&
	       cmh->cmsg_type == IP_PKTINFO)
	{
	  struct in_pktinfo pktinfo;
	  
	  /* The sockaddr should be right after the cmsg_hdr. */
	  memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
	  ifindex = pktinfo.ipi_ifindex;
	  got_ifindex = 1;
#endif
#ifdef IP_RECVIF
	}
      else if (cmh->cmsg_level == IPPROTO_IP &&
	       cmh->cmsg_type == IP_RECVIF)
	{
	  struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmh);
	  /* The sockaddr should be right after the cmsg_hdr. */
	  ifindex = sdl->sdl_index;
	  got_ifindex = 1;
#endif
	}
    }
  
  // If we didn't get an interface index, we probably shouldn't answer
  // the query.
  if (!got_ifindex)
    {
      syslog(LOG_ERR, "Unable to determine receive interface.");
      return;
    }

  for (ifp = interfaces; ifp; ifp = ifp->next)
    {
      if (ifp->index == ifindex)
	break;
    }
  if (!ifp)
    {
#if 0
      syslog(LOG_ERR, "Unknown interface index: %d", ifindex);
      return;
#endif
    }
  else
  // Don't answer queries on excluded interfaces.
  if (ifp->excluded)
    return;


  /* Allocate a query structure. */
  query = query_allocate(buf, len);
  if (query)
    {
      // See if there is another nameserver we can switch to.
      if (nameservers && nameservers != nameservers->next)
	{
	  nameserver_t *next = nameservers->next;
	  int qcur, qnext, dcur, dnext, ccur, cnext;
	  int i;

	  while (nameservers != next)
	    {
	      qcur = qnext = dcur = dnext = ccur = cnext = 0;
	      
	      for (i = 0; i < 5; i++)
		{
		  qcur += nameservers->nqueries[i];
		  qnext += next->nqueries[i];
		  dcur += nameservers->ndropped[i];
		  dnext += next->ndropped[i];
		  ccur += nameservers->ncomplete[i];
		  cnext += next->ncomplete[i];
		}
	  
	      // If either nameserver has no track record, switch.
	      if (!qcur)
		{
#ifdef DEBUG_CYCLE
		  printf("current has no track record.\n");
#endif
		  nameservers = next;
		  break;
		}
	      // ...
	      else if (!qnext)
		{
#ifdef DEBUG_CYCLE
		  printf("next has no track record.\n");
#endif
		  nameservers = next;
		  break;
		}
	      // If this name server is sucking a lot, switch.
	      else if (qcur && dcur && !ccur)
		{
#ifdef DEBUG_CYCLE
		  printf("current sucks.\n");
#endif
		  nameservers = next;
		  break;
		}
	      // If neither one is sucking, alternate.
	      else if (!dcur && !dnext)
		{
#ifdef DEBUG_CYCLE
		  printf("neither sucks.\n");
#endif
		  nameservers = next;
		  break;
		}
	      next = next->next;
	    }
	}
      
      // If there are no nameservers, we can't send the query.
      if (!nameservers)
	{
	  free(query);
	  return;
	}

      // Whichever name server we landed on, use.
      query->cur_nameserver = nameservers;

      query->src = src_addr;
      query->srclen = srclen;

      // Open a socket on which to forward the query.
      query->socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      if (query->socket < 0)
	{
	  syslog(LOG_ERR, "query socket: %m");
	  free(query);
	  return;
	}

      // Parse and validate the query.
      result = query_parse(query, buf, len);
      if (result < 0)
	{
	bogus:
	  SET_RCODE(buf, -result);
	  SET_QR(buf, 1);
	  sendto(sock, buf, len, 0, &src_addr.sa, srclen);
	  free(query);
	  return;
	}

      // Get a neighbor table entry for this IP address, and see if there
      // is a filter class attached to the host referenced by the nte.
      nte = fetch_nte(&src_addr);
      if (nte && nte->host >= 0)
	{
	  host_t *host = fetch_host(nte->host);
	  query->host = nte->host;
	  if (host->filter_class >= 0)
	    {
	      const char *filter_class =
		fetch_filter_class(host->filter_class);

	      // If there is a filter class, hack it in to the EDNS0 option
	      if (filter_class)
		result = add_opt_id(query, filter_class, strlen(filter_class));
	      if (result < 0)
		goto bogus;
	    }
	}
      else
	query->host = -1;

      // See if this query is a repeat.
      for (i = query_base; i < num_pollfds; i++)
	{
	  nameserver_t *ns;

	  // If the host and the transaction ID match, we assume it's the same
	  // query without checking the content.
	  // The expectation is that a repeated query is the result of a
	  // timeout, so we just drop the old query on the floor if the
	  // response comes in later.
	  if (queries[i]->host != -1 &&
	      queries[i]->xid == query->xid && queries[i]->host == query->host)
	    {
#ifdef DEBUG_DROPS
	      printf("matched query, xid=%d host=%d index=%d\n",
		     query->xid, query->host, i);
#endif
	      ns = queries[i]->cur_nameserver;
	      if (ns)
		{
		  ns->ndropped[0]++;

		  // cycle to the next name server in sequence.
		  if (ns->next && ns->next->address.sa.sa_family)
		    query->cur_nameserver = queries[i]->cur_nameserver->next;

		  // if this nameserver has gone stale, skip it.
		  else
		    query->cur_nameserver = nameservers;
		}
	      else
		query->cur_nameserver = 0;
	      close(queries[i]->socket);
	      pollfds[i].fd = query->socket;
	      pollfds[i].revents = 0;
	      free(queries[i]);
	      queries[i] = query;
	      added = 1;
	    }
	}

      // Forward the query to a name server
      if (query->cur_nameserver)
	{
	  query->cur_nameserver->nqueries[0]++;
	  len = sendto(query->socket, query->query, query->qlength, 0,
		       &query->cur_nameserver->address.sa,
		       sizeof query->cur_nameserver->address);
	  if (len < 0)
	    {
	      char obuf[128];
	      int port = ntop(obuf, sizeof obuf,
			      &query->cur_nameserver->address);

	      syslog(LOG_ERR, "sendto (%s#%d): %m", obuf, port);
	      close(query->socket);
	      if (added)
		query->socket = -1;
	      else
		free(query);
	    }
	  else if (!added && add_query(query) < 0)
	    {
	      close(query->socket);
	      free(query);
	    }
	}
      else
	{
	  close(query->socket);
	  if (added)
	    query->socket = -1;
	  else
	    free(query);
	}
    }
}

int
add_query(query_t *query)
{
  if (num_pollfds == pollfd_max)
    {
      int max = pollfd_max * 2;
      query_t **nq;
      struct pollfd *npfd;
      syslog(LOG_INFO, "allocating more slots: %d -> %d.\n", num_pollfds, max);
      nq = malloc(max * sizeof *nq);
      npfd = malloc(max * sizeof *npfd);
      if (!nq || !npfd)
	{
	  syslog(LOG_ERR, "No memory for pollfds!");
	  return -1;
	}
      memset(nq + pollfd_max, 0, pollfd_max * sizeof *nq);
      memcpy(nq, queries, pollfd_max * sizeof *nq);
      memcpy(npfd, pollfds, pollfd_max * sizeof *npfd);
      free(queries);
      free(pollfds);
      queries = nq;
      pollfds = npfd;
      pollfd_max = max;
    }
  pollfds[num_pollfds].fd = query->socket;
  pollfds[num_pollfds].events = POLLIN;
  queries[num_pollfds] = query;
#ifdef DEBUG_POLL
  printf("num_pollfds %d -> %d\n", num_pollfds, num_pollfds + 1);
#endif
  num_pollfds++;
  return 1;
}

query_t *
query_allocate(const unsigned char *buf, ssize_t len)
{
  ssize_t qmax = len + 64; // space for OPT RR and then some.
  query_t *query;
  query = malloc(qmax - 1 + sizeof *query);
  if (!query)
    {
      syslog(LOG_ERR, "out of memory on query");
      return 0;
    }
  memset(query, 0, (sizeof *query) - 1);
  memcpy(query->query, buf, len);
  query->qlength = len;
  query->qmax = qmax;
  query->cycle = cycle;
  return query;
}
#endif

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
