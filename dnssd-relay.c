/* dnssd-relay.c
 *
 * Copyright (c) Nominum, Inc 2013, 2017
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
	     
// dnssd-relay
//
//  * Get a list of interfaces
//  * Set up a control channel listener on a unix domain socket
//  * Start listening for messages on all open sockets (initially
//    just the unix domain socket)
//  * Accept updates on that socket as to which interfaces to listen
//    on for TCP connections from Query proxies
//      * primitive: add-dns <interface>
//          * starts up a DNS listener for <interface>
//        -> port
//      * primitive: drop-dns <interface>
//  * Accept updates on that socket as to which interfaces to listen
//    on for mDNS multicasts
//      * primitive: add-mdns <interface>
//      * primitive: drop-mdns <interface>
//  * Accept updates on that socket as to the IP addresses from which
//    to accept DNS queries
//      * primitive: add-accept <IP address> <source-port>
//      * primitive: drop-accept <IP address> <source-port>
//  * Accept command to print status on that socket
//      * primitive: dump-status
//        -> status
//  * TCP connections from hosts not matching whitelisted address/port
//    tuples are silently dropped
//  * DNS queries are forwarded unchanged on the interface
//    corresponding to the port on which the message was received.
//  * mDNS multicasts received on enabled interfaces are forwarded
//    unchanged to connected query proxies over the TCP connection for
//    that proxy corresponding to the interface on which the multicast
//    was received.

interface_t *interfaces;
tdns_listener_t tdns;

int
ntop(char *buf, size_t buflen, address_t *address)
{
  if (address->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &address->in.sin_addr, buf, buflen);
      return ntohs(address->in.sin_port);
    }
  else if (address->sa.sa_family == AF_INET6)
    {
      inet_ntop(AF_INET6, &address->in6.sin6_addr, buf, buflen);
      return ntohs(address->in6.sin6_port);
    }
  sprintf(buf, "unknown family: %d", address->sa.sa_family);
  return 0;	
}

int
main(int argc, char **argv)
{
  // enumerate interfaces
  struct ifaddrs *ifa, *ifp;
  interface_t *ip;
  int salen;
  int i;
  const char *errstr;

  openlog("dnssd-relay", LOG_NDELAY|LOG_PID|LOG_PERROR, LOG_DAEMON);

  // Get the interface address list.
  if (getifaddrs(&ifa) < 0)
    {
      syslog(LOG_CRIT, "getifaddrs: %m");
      exit(1);
    }

  // Go through the list; don't assume it's sorted by name.
  for (ifp = ifa; ifp; ifp = ifp->ifa_next)
    {
      /* Already seen this name? */
      for (ip = interfaces; ip; ip = ip->next)
	{
	  if (!strcmp(ip->name, ifp->ifa_name))
	    break;
	}
      /* No; make a new entry. */
      if (!ip)
	{
	  ip = malloc(sizeof *ip);
	  if (ip)
	    {
	      memset(ip, 0, sizeof *ip);
	      ip->name = strdup(ifp->ifa_name);
	    }
	  if (!ip || !ip->name)
	    {
	      syslog(LOG_CRIT, "Out of memory allocating interface %s",
		      ifp->ifa_name);
	      exit(1);
	    }
	  if (strlen(ip->name) >= IFNAMSIZ)
	    {
	      syslog(LOG_CRIT, "Interface name too long: %s", ip->name);
	      exit(0);
	    }
	  ip->index = -1;
	  ip->next = interfaces;
	  interfaces = ip;
	}
      if (ip->index == -1)
	{
	  ip->index = if_nametoindex(ip->name);
	  if (ip->index == 0)
	    {
	      syslog(LOG_CRIT, "SIOCGIFINDEX: %m");
	      exit(1);
	    }
	}
      // Does this entry have an address we care about?
      if (ifp->ifa_addr)
	{
	  if (ifp->ifa_addr->sa_family == AF_INET ||
	      ifp->ifa_addr->sa_family == AF_INET6)
	    {
	      if (ip->numaddrs == ip->maxaddrs)
		{
		  int newmax = ip->maxaddrs * 2;
		  address_t **na;
		  if (newmax == 0)
		    newmax = 5;
		  na = malloc(newmax * sizeof *na);
		  if (!na)
		    {
		      syslog(LOG_CRIT,
			      "Out of memory expanding address list for %s",
			      ip->name);
		      exit(1);
		    }
		  memset(&na[ip->maxaddrs], 0, newmax * sizeof *na);
		  if (ip->addresses)
		    {
		      memcpy(na, ip->addresses, ip->maxaddrs * sizeof *na);
		      free(ip->addresses);
		    }
		  ip->addresses = na;
		}
	      if (ifp->ifa_addr->sa_family == AF_INET)
		salen = sizeof (struct sockaddr_in);
	      else if (ifp->ifa_addr->sa_family == AF_INET6)
		salen = sizeof (struct sockaddr_in6);
	      else
		{
		  syslog(LOG_CRIT, "coding error in sa_len simulator.");
		  exit(1);
		}
	      // XXX why not just have the array of address pointers be an array
	      // XXX of addresses?
	      ip->addresses[ip->numaddrs] = malloc(salen);
	      if (!ip->addresses[ip->numaddrs])
		{
		  syslog(LOG_CRIT, "Out of memory adding address for %s",
			  ip->name);
		  exit(1);
		}
	      memcpy(ip->addresses[ip->numaddrs], ifp->ifa_addr, salen);
	      ip->numaddrs++;
	    }
	}
    }

#define IFLIST_DEBUG 1
#ifdef IFLIST_DEBUG
  for (ip = interfaces; ip; ip=ip->next)
    {
      syslog(LOG_INFO, "Interface %s index %d; %d addresses",
	     ip->name, ip->index, ip->numaddrs);
      for (i = 0; i < ip->numaddrs; i++)
	{
	  char obuf[256];
	  ntop(obuf, sizeof obuf, ip->addresses[i]);
	  syslog(LOG_INFO, "  address %d: %s", i, obuf);
	}
    }
#endif

  for (i = 1; i < argc; i++)
    {
      // Daemonize.
      if (!strcmp(argv[i], "-d"))
	{
	  closelog();
	  openlog("dnssd-relay", LOG_NDELAY|LOG_PID, LOG_DAEMON);
	}
      else if (!strcmp(argv[i], "-cf"))
	{
	  if (i + 1 == argc)
	    {
	      syslog(LOG_CRIT, "-cf must be followed by an argument.");
	      exit(1);
	    }
	  control_process_file(argv[++i]);
	}
    }

  // Listen for control messages on the unix socket.
  errstr = control_start("/tmp/dnssd-relay-sock");
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "control_start: %s", errstr);
      exit(1);
    }

  // Listen for DNS connections...
  
  errstr = tdns_listener_add(&tdns);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "tdns_listener_add: %s", errstr);
      exit(1);
    }
      
  // Process events...
  do {
    errstr = asio_poll_once(-1);
  } while (errstr == NULL);

  syslog(LOG_ERR, "asio_poll_once: %s", errstr);
  return 0;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
