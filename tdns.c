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

// Given a links TLV, find all of the actual corresponding links.   Returns 0
// if something goes wrong (servfail).
int
tdns_find_links(tdns_dso_state_t *dsos)
{
  dsos->invalid_link_data = malloc(dsos->link_id_len);
  if (!dsos->invalid_link_data)
    return 0;
  dsos->links = malloc((dsos->link_id_len / 5) * sizeof *dsos->links);
  if (!dsos->links)
    {
      free(dsos->invalid_link_data);
      dsos->invalid_link_data = 0;
      return 0;
    }
  dsos->num_links = 0;
  
  // Validate all the links that have been mentioned
  for (i = 0; i < dsos->link_id_len; i += 5)
    {
      mdns_t *link = 0;
      interface_t *ip;

      // Find the "link", which we represent as the mdns listener for a
      // particular family on the matching interface.
      for (ip = interfaces; ip; ip = ip->next)
	{
	  // Is this the link?
	  if (!memcmp(&ip->link_id, &dsos->link_id_data[i + 1], 4))
	    {
	      if (dsos->link_id_data[i] == INET4)
		link = ip->mdns4;
	      else if (dsos->link_id_data[i] == INET6)
		link = ip->mdns6;
	      break;
	    }
	}
      if (!link)
	{
	  memcpy(&dsos->invalid_link_data[dsos->invalid_link_len],
		 &dsos->link_id_data[i], 5);
	  dsos->invalid_link_len += 5;
	}
      else
	dsos->links[dsos->num_links++] = link;
    }
  return 1;
}

int
tdp_link_eliminate(link_t *dest, int dnl, link_t *src, int snl)
{
  int i, j;
  
  dsos.links, dsos.num_links, tdp->links, tdp->num_links;
	  
  for (i = 0; i < snl; i++)
    {
      for (j = 0; j < dnl;)
	{
	  if (src[i] == dest[j])
	    {
	      if (j + 1 < dnl)
		memmove(&dest[j], &dest[j + 1],
			(dnl - j - 1) * sizeof (link_t *));
	      --dnl;
	    }
	  else
	    j++;
	}
    }
  return dnl;
}

// Copy data from tcp buffer to mdns buffer, start transmission
void
tdns_frame_to_mdns(tdns_t *tdp)
{
  tdns_listener_t *tlp = tdp->listener;
  tdns_dso_state_t dsos;

  // Should never happen.
  if (tlp == NULL || tlp->mdns == NULL)
    {
      syslog(LOG_CRIT, "tdp->mdns == NULL!");
      exit(1);
    }
  
  // Parse the frame
  // We're expecting to see a DSO message (draft-ietf-dnsop-session-signal-04)
  // Opcode is 6; QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT are all zero, and this
  // is a query, because we never expect to get responses.
  // After that come the TLVs
  if (tdp->inbuflen < 12 || OPCODE(buf) != DSO || QDCOUNT(buf) != 0 || 
      ANCOUNT(buf) != 0 || NSCOUNT(buf) != 0 || ARCOUNT(buf) != 0 ||
      QR(buf) != 0)
    {
      tdns_respond(tdp, FORMERR);
      goto out;
    }

  memset(&dsos, 0, sizeof dsos);
  while (index < tdp->inbuflen)
    {
      int tlv_len;
      // Required TLV data is 4 bytes
      if (tdp->inbuflen - index < 4)
	{
	  tdns_respond(tdp, FORMERR);
	  goto out;
	}
      
      // Make sure that the length fits in the buffer.
      tlv_len = TLV_LEN(&tdp->inbuf[index]);
      if (index + tlv_len + 4 >= tdp->inbuflen)
	{
	  tdns_respond(tdp, FORMERR);
	  goto out;
	}

      tlv_type = TLV_TYPE(&tdp->inbuf[index]);
      switch(tlv_type)
	{
	  // Operation TLVs
	case RETRY_DELAY:
	case KEEPALIVE:
	case MDNS_LINK_REQUEST:
	case MDNS_DISCONTINUE:
	case MDNS_MESSAGE:
	case MDNS_LINK_INVALID:
	case MDNS_LINK_SUBSCRIBED:
	  if (dsos.have_op_tlv)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  dsos.have_op_tlv = 1;
	  dsos.op_tlv_type = tlv_type;
	  dsos.op_tlv_len = tlv_len;
	  dsos.op_tlv_data = TLV_DATA(&tdp->inbuf[index]);
	  break;

	case L2_SOURCE_ADDRESS: // modifier
	  if (have_l2_src)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  dsos.l2_src_data = TLV_DATA(&tdp->ibuf[index]);
	  dsos.l2_src_len = tlv_len;
	  break;
	    
	  // port(2) af(1) addr(4|16)
	case IP_SOURCE_ADDRESS: // modifier
	  if (have_ip_src)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  if (tlv_len > 3) {
	    int fam = TLV_DATA(&tdp->ibuf[index])[3]
	    if (fam == 1 && tlv_len == 7)
	      {
		dsos.ip_src.in.sin_family = AF_INET;
		memcpy(&dsos.ip_src.in.sin_port,
		       &TLV_DATA(&tdp->ibux[index])[1], 2);
		memcpy(&dsos.ip_src.in.sin_addr,
		       &TLV_DATA(&tdp->ibux[index])[3], 4);
	      }
	    else if (fam == 2 && tlv_len == 19)
	      {
		dsos.ip_src.in6.sin6_family = AF_INET6;
		memcpy(&dsos.ip_src.in6.sin6_port,
		       &TLV_DATA(&tdp->ibux[index])[1], 2);
		memcpy(&dsos.ip_src.in6.sin6_addr, 
		       &TLV_DATA(&tdp->ibux[index])[3], 16);
	      }
	    else
	      {
		tdns_respond(tdp, FORMERR);
		goto out;
	      }
	  have_ip_src = 1;
	  break;

	  // array(link-id(4), family(1))
	case LINK_IDENTIFIERS: // modifier
	  // We can have more than one link identifier.
	  // To do this, they are just clumped together in the same TLV.
	  if (have_link_id)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  // Should be a multiple of five bytes.
	  if (tlv_len % 5 != 0)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  have_link_id = 1;
	  dsos.link_id_data = TLV_DATA(&tdp->ibuf[index]);
	  dsos.link_id_len = tlv_len;
	  break;
	      
	default:
	  // Do not allow unknown operational TLVs (the first TLV is
	  // always an operational TLV).
	  if (dsos->have_op_tlv == 0)
	    {
	      tdns_respond(tdp, FORMERR); // XXX should send DSO response as above
	      goto out;
	    }
	  if (tlv_len != 1)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	}
      // Op TLV is required to come first.
      if (!dsos.have_op_tlv)
	{
	  tdns_respond(tdp, FORMERR);
	  goto out;
	}
      index = index + 4 + tlv_len;
    }

  switch(dsos.op_tlv_type)
    {
	case KEEPALIVE:
	  // Acknowledgement is required for keepalive.
	  if (!TLV_ACK(tdp->ibuf))
	    tdns_respond(tdp, FORMERR);
	  else
	    tdns_respond(tdp, NOERROR);
	  goto out;
	  
	case MDNS_LINK_REQUEST:
	  // Acknowledgement is required for link request.
	  // Link identifier is required.
	  if (!TLV_ACK(tdp->ibuf) || !dsos.have_link_id)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  if (!tdns_find_links(&dsos))
	    {
	      tdns_respond(tdp, SERVFAIL);
	      goto out;
	    }
	  // Were any of the links invalid?
	  if (tdns->invalid_links_len)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  free(dsos.invalid_links);
	  dsos.invalid_links = 0;
	  
	  for (i = 0; i < dsos.num_links; )
	    {
	      mdns_t *link = dsos.links[i];
	      for (j = 0; j < link->num_proxies; j++)
		{
		  if (link->proxies[j] == tdns)
		    {
		      if (i + 1 < dsos.link_count)
			memmove(&dsos.links[i], &dsos.links[i + 1],
				(dsos.num_links - i - 1) * sizeof (mdns_t *));
		  --dsos.num_links;
		}
	    }
	  if (!eliminated)
	    {
	    }
			    

	  	
	  // Send the response
	  tdns_link_response(tdp, &dsos);
	  free(dsos.links);
	  dsos.links = 0;
	  goto out;

	case MDNS_DISCONTINUE:
	  // Acknowledgement is required for link request
	  if (!TLV_ACK(tdp->ibuf) || !dsos.have_link_id)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  // Validate all of the listed links
	  if (!tdns_find_links(&dsos))
	    {
	      tdns_respond(tdp, SERVFAIL);
	      goto out;
	    }
	  // Were any of the links invalid?
	  if (tdns->invalid_links_len)
	    {
	      tdns_respond(tdp, FORMERR);
	      goto out;
	    }
	  free(dsos.invalid_links);
	  dsos.invalid_links = 0;

	  // Remove each of these links from the list of links to which this
	  // proxy is subscribed on this connection
	  if (tdp->num_links)
	    tdp->num_links = tdp_link_eliminate(tdp->links, tdp->num_links,
						dsos.links, dsos.num_links);
	  // Send the response
	  goto out;
	  
	case MDNS_MESSAGE:
	  // Acknowledgement is neither required nor desired, but if it's
	  // requested, we will ack.   Also, if the MDNS_MESSAGE doesn't
	  // come with any links, or comes with a link that isn't subscribed,
	  // we reject it.

	  // These are response operations that we send, but should
	  // never receive.
	case MDNS_LINK_INVALID:
	case MDNS_LINK_SUBSCRIBED:

	  // We are the server, so the client can't send us a RETRY_DELAY
	  // TLV 
	case RETRY_DELAY:
	  tdns_respond(tdp, DSONOTIMP);
	  goto out;
    }      

  mdns_write(tlp->mdns, tdp->inbuf, tdp->inbuflen);
 out:
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
  errstr = asio_read(&status, slot,
		     (char *)&tdp->inbuf[tdp->inbuflen], tdp->awaiting);
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
  tdp->peerlen = slen;
  tdp->awaiting = 2; // Length of first frame.
  tdp->listener = tlp;
  tdp->next = tlp->connections;
  tlp->connections = tdp;
  tdp->slot = rslot;

  // XXX why isn't tdp being freed here if there's an error?
  slen = sizeof addr;
  errstr = asio_getsockname(rslot, &addr, &slen);
  if (errstr != NULL)
    {
      syslog(LOG_ERR, "tdns_listen_handler: asio_getsockname: %s", errstr);
      return;
    }
  tdp->name = addr;
  tdp->namelen = slen;

  // XXX validate source address and destination address

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

// Add a DNS listener.
// We implement the restrictions on listen addresses using getsockname() to
// validate that the local address is allowed, rather than by binding to each
// allowed address.

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

  errstr = asio_write(&length, slot, (char *)&tdp->out.buf[tdp->out.base],
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
  return NULL;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
