/* pcmd.c
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
	     
// parser/dispatcher for line-oriented protocols with a restricted set
// of possible arguments on the command line.

const char *
pcmd_dispatch (void *thunk, char *line, control_command_t *control_commands)
{
  const char *argv[MAX_CHUNKS];
  arg_t args[MAX_CHUNKS];
  int argc, i;
  const char *start;
  control_command_t *command = NULL;
  unixconn_t *uct = thunk;
  char *cp;
  u_int32_t ifid;

  start = line;
  argc = 0;
  
  if (line[0] != ' ' && line[0] != '\t')
    argv[argc++] = &line[0];
      
  // tokenize
  for (i = 0; line[i]; i++)
    {
      if (line[i] == ' ' || line[i] == '\t')
	{
	  line[i] = 0;
	  for (i++; line[i]; i++)
	    {
	      if (line[i] != ' ' && line[i] != '\t')
		{
		  // Too many chunks?
		  if (argc == MAX_CHUNKS)
		    return "500 bad request\n";
		  argv[argc++] = &line[i];
		  break;
		}
	    }
	}
    }

  // identify the command
  for (i = 0; control_commands[i].name != NULL; i++)
    {
      if (!strcmp(control_commands[i].name, argv[0]))
	{
	  command = &control_commands[i];
	  break;
	}
    }

  // Not found
  if (command == NULL)
    return "502 no such command\n";

  // Validate and parse the arguments
  for (i = 0; i < command->nargs; i++)
    {
      const char *arg = argv[i + 1];
      interface_t *ip;
      char *endptr;
      unsigned long port;
      
      switch (command->argtype[i])
	{
	case ARGTYPE_IFNAME:
	  args[i].interface = NULL;
	  for (ip = interfaces; ip; ip = ip->next)
	    {
	      if (ip->name != NULL && !strcmp(ip->name, arg))
		{
		  args[i].interface = ip;
		  break;
		}
	    }
	  if (args[i].interface == NULL)
	    return "512 unknown interface\n";
	  break;

	case ARGTYPE_INTERFACE:
	  args[i].interface = NULL;
	  ifid = strtoul(arg, &cp, 16);
	  // Make sure that the whole string was consumed.
	  if (cp == arg || *cp != '\0')
	    {
	      return "Invalid interface ID (must be a hexadecimal integer\n";
	    }
	  for (ip = interfaces; ip; ip = ip->next)
	    {
	      if (ip->ifid_valid && ip->ifid == ifid)
		{
		  args[i].interface = ip;
		  break;
		}
	    }
	  if (args[i].interface == NULL)
	    return "512 unknown interface\n";
	  break;

	case ARGTYPE_IFID:
	  args[i].ifid = strtoul(arg, &cp, 16);
	  // Make sure that the whole string was consumed.
	  if (cp == arg || *cp != '\0')
	    {
	      return "Invalid interface ID (must be a hexadecimal integer\n";
	    }
	  break;
	  
	case ARGTYPE_IPADDR:
	  memset(&args[i], sizeof args[i], 0);

	  // IPv6 address?
	  if (strchr(arg, ':') != NULL)
	    {
	      if (inet_pton(AF_INET6, arg, &args[i].addr.in6.sin6_addr) != 1)
		return "501 bad IPv6 (?) address\n";
	      args[i].addr.sa.sa_family = AF_INET6;
	    }
	  else
	    {
	      if (inet_pton(AF_INET, arg, &args[i].addr.in.sin_addr) != 1)
		return "501 bad IPv4 (?) address\n";
	      args[i].addr.sa.sa_family = AF_INET;
	    }
	  break;

	case ARGTYPE_PORT:
	  port = strtoul(arg, &endptr, 10);
	  if ((port >= 1 << 16) || *endptr != '\0')
	    return "501 bad port number\n";
	  args[i].port = (u_int16_t)port;
	  break;

	default:
	  return "500 unrecognized command\n";
	}
    }

  command->implementation(uct, command, argc, args);
  return NULL;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
