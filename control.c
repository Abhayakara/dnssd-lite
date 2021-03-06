/* control.c
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
	     
address_t *whitelist;
int whitelist_len, whitelist_max;

typedef enum {
  NONE, ADD_DNS, DROP_DNS, ADD_MDNS, DROP_MDNS, ADD_ACCEPT, DROP_ACCEPT,
  SET_IFID, DUMP_STATUS, END
} code_t;

control_command_t control_commands[] = {
  { "add-dns",     ADD_DNS,     1, control_add_dns,     {ARGTYPE_INTERFACE} },
  { "drop-dns",    DROP_DNS,    1, control_drop_dns,    {ARGTYPE_INTERFACE} },
  { "add-mdns",    ADD_MDNS,    1, control_add_mdns,    {ARGTYPE_INTERFACE} },
  { "drop-mdns",   DROP_MDNS,   1, control_drop_mdns,   {ARGTYPE_INTERFACE} },
  { "add-accept",  ADD_ACCEPT,  2, control_add_accept,  {ARGTYPE_IPADDR, 
							 ARGTYPE_PORT} },
  { "drop-accept", DROP_ACCEPT, 2, control_drop_accept, {ARGTYPE_IPADDR,
							 ARGTYPE_PORT} },
  { "set-ifid",    SET_IFID     2, control_set_ifid,	{ARGTYPE_IFNAME,
							 ARGTYPE_IFID} },
  { "dump-status", DUMP_STATUS, 0, control_dump_status, {} },
  { "end",         END,         0, control_end,         {} },
  { NULL,          NONE,        0, (void *)0, {} } };

// Read commands out of a file...
void
control_process_file(const char *filename)
{
  char buf[2048];
  
  FILE *inf = fopen(filename, "r");
  if (inf == NULL)
    {
      syslog(LOG_CRIT, "Unable to load commands from %s: %m", filename);
      exit(1);
    }
  while (fgets(buf, sizeof buf, inf) != NULL)
    {
      const char *errstr;
      char *nl;

      nl = strchr(buf, '\r');
      if (nl == NULL)
	{
	  nl = strchr(buf, '\n');
	  if (nl == NULL)
	    {
	      syslog(LOG_ERR, "Line too long in %s: %s", filename, buf);
	      exit(1);
	    }
	}
      *nl = 0;
	      
      // This is a bit chatty, but pcmd_dispatch can log an error, so
      // we want to know what caused it.
      syslog(LOG_INFO, "Dispatch: %s", buf);
      errstr = pcmd_dispatch(0, buf, control_commands);
      if (errstr != NULL)
	{
	  syslog(LOG_CRIT, errstr);
	  exit(1);
	}
    }
  fclose(inf);
}

// Write a response to the client
void
control_write_status(unixconn_t *uct, int code, const char *message, const char *more)
{
  if (uct)
    {
      char buf[256];
      snprintf(buf, sizeof buf, 
	       "%03d %s%s%s\n", code, message, more[0] == 0 ? "" : ": ", more);
      unixconn_write(uct, buf);
    }
  else
    {
      if (code > 500)
	syslog(LOG_ERR, "%03d %s%s%s\n", code, message, more[0] == 0 ? "" : ": ", more);
      return;
    }
}

// Called when a line of text comes in from the client
void
control_read(unixconn_t *uct, char *line)
{
  const char *errstr;
  errstr = pcmd_dispatch(uct, line, control_commands);
  if (errstr != NULL)
    unixconn_write(uct, errstr);
}
      
// Called when a new client connects.

void
control_listen(unixconn_t *uct)
{
  unixconn_write(uct, "220 dnssd-relay\n");
  unixconn_set_read_handler(uct, control_read);
}

// This file contains the unix connection protocol engine.

const char *
control_start(const char *path)
{
  unixconn_t *uct;
  const char *errstr;

  errstr = unixconn_socket_create(&uct, path);
  if (errstr != NULL)
    return errstr;

  errstr = unixconn_set_listen_handler(uct, control_listen);
  if (errstr != NULL)
    return errstr;

  return NULL;
}

// add-dns <interface>
// Add a DNS listener for <interface>

void
control_add_dns(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  const char *errstr;
  char portbuf[64];
  errstr = tdns_listener_add(&args[0].interface->dns4);
  if (errstr != NULL)
    {
      control_write_status(uct, 512, errstr, "");
      return;
    }
  errstr = tdns_listener_add(&args[0].interface->dns6);
  if (errstr != NULL)
    {
      control_write_status(uct, 512, errstr, "");
      return;
    }
  if (args[0].interface->dns4.port == -1)
    snprintf(portbuf, sizeof portbuf, "%d", args[0].interface->dns6.port);
  else
    snprintf(portbuf, sizeof portbuf, "%d %d",
	     args[0].interface->dns6.port, args[0].interface->dns4.port);
  control_write_status(uct, 250, portbuf, "");
}

// drop-dns <interface>
// Drop the DNS listener for <interface>

void
control_drop_dns(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  const char *errstr = tdns_listener_drop(args[0].interface);
  if (errstr != NULL)
    control_write_status(uct, 512, errstr, "");
  else
    control_write_status(uct, 250, "Ok.", "");
}

// add-mdns <interface>
// Add an mDNS listener for <interface>

void
control_add_mdns(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  const char *errstr = mdns_listener_add(args[0].interface);
  if (errstr != NULL)
    control_write_status(uct, 512, errstr, "");
  else
    control_write_status(uct, 250, "Ok.", "");
}

// drop-mdns <interface>
// Drop the mDNS listener for <interface>

void
control_drop_mdns(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  const char *errstr = mdns_listener_drop(args[0].interface);
  if (errstr != NULL)
    control_write_status(uct, 512, errstr, "");
  else
    control_write_status(uct, 250, "Ok.", "");
}

int
control_digest_addr(address_t *addr, arg_t *args)
{
  int ix;

  memset(addr, 0, sizeof *addr);
  if (args[0].addr.sa.sa_family == AF_INET)
    {
      addr->in.sin_addr = args[0].addr.in.sin_addr;
      addr->in.sin_port = htons(args[1].port);
      addr->in.sin_family = AF_INET;
    }
  else // we can assume AF_INET6
    {
      addr->in6.sin6_addr = args[0].addr.in6.sin6_addr;
      addr->in6.sin6_port = htons(args[1].port);
      addr->in.sin_family = AF_INET6;
    }
  for (ix = 0; ix < whitelist_len; ix++)
    {
      if (!memcmp(addr, &whitelist[ix], sizeof *addr))
	return ix;
    }
  return -1;
}
  
// add-accept <addr> <port>
// Whitelist connections from address/port tuple

void
control_add_accept(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  address_t addr;
  int ix;

  ix = control_digest_addr(&addr, args);
  if (ix != -1)
    return control_write_status(uct, 500, "ok", "");

  if (whitelist_len == whitelist_max)
    {
      int new_whitelist_max = whitelist_max + 10;
      address_t *new_whitelist;

      new_whitelist = malloc(new_whitelist_max * sizeof *whitelist);
      if (new_whitelist == NULL)
	return control_write_status(uct, 522, "no more room in whitelist", "");
      if (whitelist != NULL)
	{
	  memcpy(new_whitelist, whitelist, whitelist_len * sizeof *whitelist);
	  free(whitelist);
	}
      whitelist = new_whitelist;
      whitelist_max = new_whitelist_max;
    }
  memcpy(&whitelist[whitelist_len], &addr, sizeof addr);
  whitelist_len++;
  control_write_status(uct, 500, "ok", "");
}

// drop-accept <addr> <port>
// Remove address/port tuple from whitelist

void
control_drop_accept(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  address_t addr;
  int ix;

  ix = control_digest_addr(&addr, args);
  if (ix != -1)
    {
      if (ix + 1 < whitelist_len)
	{
	  memmove(&whitelist[ix], &whitelist[ix + 1],
		  (whitelist_len - ix - 1) * sizeof *whitelist);
	}
      --whitelist_len;
    }
  control_write_status(uct, 200, "ok", "");
  return;
}

void
control_set_ifid(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  arguments[0].interface->ifid_valid = 1;
  arguments[0].interface->ifid = arguments[1].ifid;
  control_write_status(uct, 200, "ok", "");
}

// dump-status
// Return a human-readable status dump

void
control_dump_status(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  interface_t *ip;
  int ix;
  if (!uct)
    return;
  for (ip = interfaces; ip; ip = ip->next)
    {
      unixconn_write(uct, "200-");
      unixconn_write(uct, ip->name);
      if (ip->mdns4.slot)
	unixconn_write(uct, " +mdns4");
      if (ip->mdns6.slot)
	unixconn_write(uct, " +mdns6");
      if (ip->dns4.slot)
	unixconn_write(uct, " +dns4");
      if (ip->dns6.slot)
	unixconn_write(uct, " +dns6");
      unixconn_write(uct, "\n");
    }
  for (ix = 0; ix < whitelist_len; ix++)
    {
      char nbuf[64];
      ntop(nbuf, sizeof nbuf, &whitelist[ix]);
      if (ix + 1 == whitelist_len)
	unixconn_write(uct, "200 ");
      else
	unixconn_write(uct, "200-");
      unixconn_write(uct, nbuf);
      unixconn_write(uct, "\n");
    }
  if (whitelist_len == 0)
    unixconn_write(uct, "200 no whitelist entries\n");
}

// quit
// Terminate the connection.

void
control_end(unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args)
{
  unixconn_write(uct, "200 goodbye!\n");
  unixconn_deref(uct);
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
