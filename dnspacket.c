/* dnspacket.c
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

#include "dnssd-relay.h"
	     
int
query_parse(query_t *query, unsigned char *buf, ssize_t len)
{
  int count, i, j;
  int offset = 12;
  int type;

  // Validate the question section.
  count = QDCOUNT(buf);
  for (i = 0; i < count; i++)
    {
      offset = parse_name(0, 0, buf, offset, len);
      if (offset < 0)
	return offset;
      if (offset + 4 > len)
	{
	  syslog(LOG_DEBUG,
		  "malformed DNS packet in questions: too short: %d %ld\n",
		  offset, (long)len);
	  return -FORMERR; // Format error
	}
#if 0 // might need later.
      type = (buf[offset] << 8) | buf[offset + 1];
      class = (buf[offset + 2] << 8) | buf[offset + 3];
#endif
      offset += 4;
    }

  // Validate the other sections, and look for an OPT RR.
  for (j = 0; j < 3; j++)
    {
      const char *section;
      switch(j)
	{
	case 0:
	  count = ANCOUNT(buf);
	  section = "answer";
	  break;
	case 1:
	  count = NSCOUNT(buf);
	  section = "nameserver";
	  break;
	case 2:
	  count = ARCOUNT(buf);
	  section = "additional";
	  break;
	}
      for (i = 0; i < count; i++)
	{
	  int rdlength, np;
	  np = offset;
	  offset = parse_name(0, 0, buf, offset, len);
	  if (offset < 0)
	    return offset;
	  if (offset + 10 > len)
	    {
	      syslog(LOG_DEBUG,
		      "malformed DNS packet in %s: too short: %d %ld\n",
		     section, offset, (long)len);
	      return -FORMERR; // Format error
	    }
	  type = (buf[offset] << 8) | buf[offset + 1];
#if 0 // might need later
	  class = (buf[offset + 2] << 8) | buf[offset + 3];
	  ttl = ((buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
		 (buf[offset + 6] << 8) | buf[offset + 7]);
#endif
	  rdlength = (buf[offset + 8] << 8) | buf[offset + 9];
	  if (offset + 10 + rdlength > len)
	    {
	      syslog(LOG_DEBUG,
		      "bad DNS packet in %s: rdlength too short: %d %ld\n",
		     section, offset + 10 + rdlength, (long)len);
	      return -FORMERR; // Format error
	    }

	  if (type == 41)
	    {
	      // We should never see an OPT RR outside the additional section.
	      if (j != 2)
		{
	          syslog(LOG_DEBUG,
			 "bad DNS packet in %s: OPT in section %d\n",
			 section, j);
		  return -FORMERR;
		}
	      // Only one OPT RR is allowed.
	      if (query)
		{
		  if (query->optptr)
		    {
	              syslog(LOG_DEBUG,
			     "bad DNS packet in %s: duplicate OPT RR\n",
			     section);
		      return -FORMERR;
		    }
		  query->optptr = np;
		  query->optdata = offset;
		  query->optlen = 10 + rdlength + (offset - np);
		}
	    }
	  else
	    // We can't handle TSIG queries.
	    if (type == 250 && query)
	      {
		// If the TSIG RR isn't at the end of the additional
		// section, return FORMERR.
		if (j != 2 || offset + 10 + rdlength != query->qlength)
		  {
	            syslog(LOG_DEBUG,
			   "bad DNS packet in %s: duplicate OPT RR\n", section);
		    return -FORMERR;
		  }
		// Otherwise, hack the TSIG on the query to generate
		// the response; we have to set the length of the MAC
		// to 0 and set the response to BADKEY, and then return
		// NOTAUTH as the RCODE.
		// However, right now we're going to be lame and just
		// return REFUSED.
		return -REFUSED;
	      }
	    else
	      // We can't handle SIG(0) queries.
	      if (type == 24 && query)
		{
		  // RFC 2931 does not require SIG(0) to be at the end
		  // of the message, but is a bit vague about what it means
		  // for a SIG(0) to appear anywhere else.   We just refuse
		  // any message containing a SIG(0) for now.
		  return -REFUSED;
		}
	  offset += 10 + rdlength;
	}      
    }
  if (query)
    query->xid = ID(buf);
  return offset;
}

int
parse_name(char *namebuf, int max,
	   const unsigned char *buf, int offset, ssize_t len)
{
  int dp, sp;
  int status;
  int pointer;

  dp = 0;
  sp = offset;

  /* Naked root label. */ 
  if (buf[sp] == 0)
    {
      if (namebuf)
	{
	  namebuf[0] = '.';
	  namebuf[1] = 0;
	}
      return sp + 1;
    }

  while (!namebuf || dp < max)
    {
      switch(buf[sp] & 0xc0)
	{
	  // normal label
	case 0:
	  if (sp + buf[sp] > len)
	    {
	      syslog(LOG_DEBUG, "parse_name: label longer than message.\n");
	      return -FORMERR; // Format error
	    }
	  if (namebuf && dp + buf[sp] + 1 > max)
	    {
	      syslog(LOG_DEBUG, "parse_name: buffer full in normal label.\n");
	      return -FORMERR; // Format error
	    }
	  if (buf[sp] && namebuf)
	    {
	      memcpy(&namebuf[dp], &buf[sp + 1], buf[sp]);
	      dp += buf[sp];
	    }
	  if (!buf[sp])
	    {
	      if (namebuf)
		namebuf[dp++] = 0;
	      return sp + 1;
	    }
	  if (namebuf)
	    namebuf[dp++] = '.';
	  sp = sp + buf[sp] + 1;
	  break;

	  // compressed label
	case 0xc0:
	  pointer = ((buf[sp] & 63) << 8) | buf[sp + 1];
	  if (pointer > len)
	    {
	      syslog(LOG_DEBUG, "parse_name: pointer outside of message.\n");
	      return -FORMERR; // Format error
	    }
	  if (namebuf)
	    status = parse_name(&namebuf[dp], max - dp, buf, pointer, len);
	  else
	    status = parse_name(0, 0, buf, pointer, len);
	  if (status < 0)
	    return status;
	  return sp + 2;

	  // extended label
	case 0x40:
	  syslog(LOG_DEBUG, "parse_name: unsupported label type 01 seen.\n");
	  return -NOTIMPL; // Not implemented

	  // unassigned
	case 0x80:
	  syslog(LOG_DEBUG, "parse_name: unsupported label type 10 seen.\n");
	  return -NOTIMPL; // Not implemented
	}
    }
  syslog(LOG_DEBUG, "parse_name: full buffer suggests malicious packet.\n");
  return -FORMERR; // Format error
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
