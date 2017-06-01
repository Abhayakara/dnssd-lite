/* asio.c
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

// This file contains routines for managing asynchronous I/O on sockets.

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
	     
struct pollfd *pollfds;
asio_state_t *pollers;
int *pollmap;
int num_pollers;
int max_pollers;
int next_open_slot;

#define POLLFD_INC 10

// Register a poller for a particular file descriptor
const char *
asio_add(int *rv, void *thunk, int sock, void (*thunk_free)(void *))
{
  if (rv == NULL)
    return "add_poller: no return value store.";

  // If there is an open slot, fill it; otherwise if there is room in
  // the array, use that; otherwise allocate more space.
  if (next_open_slot == num_pollers)
    {
      if (num_pollers == max_pollers)
	{
	  struct pollfd *new_pollfds;
	  asio_state_t *new_pollers;
	  int *new_pollmap;
	  int new_max_pollers = max_pollers + POLLFD_INC;

	  new_pollfds = malloc(new_max_pollers * sizeof *new_pollfds);
	  if (new_pollfds == NULL)
	    {
	      *rv = -1;
	      return "No memory for pollfds!";
	    }
	  new_pollers = malloc(new_max_pollers * sizeof *new_pollers);
	  if (new_pollers == NULL)
	    {
	      free(new_pollfds);
	      *rv = -1;
	      return "No memory for pollers!";
	    }
	  new_pollmap = malloc(new_max_pollers * sizeof *new_pollmap);
	  if (new_pollmap == NULL)
	    {
	      free(new_pollfds);
	      free(new_pollers);
	      *rv = -1;
	      return "No memory for pollmap!";
	    }
      
	  if (pollers != NULL)
	    {
	      memcpy(new_pollers, pollers, max_pollers * sizeof *new_pollers);
	      free(pollers);
	      memset(new_pollers + max_pollers * sizeof *pollers,
		     POLLFD_INC * sizeof *new_pollers, 0);
	    }
	  else
	    {
	      memset(new_pollers, new_max_pollers * sizeof *new_pollers, 0);
	    }

	  max_pollers = new_max_pollers;
	  pollfds = new_pollfds;
	  pollers = new_pollers;
	}      
      next_open_slot = num_pollers;
    }

  pollers[next_open_slot].fd = sock;
  pollers[next_open_slot].events = 0;
  pollers[next_open_slot].thunk = thunk;
  pollers[next_open_slot].thunk_free = thunk_free;
  pollers[next_open_slot].refcount = 1;
  if (next_open_slot != num_pollers)
    {
      next_open_slot++;
      while (next_open_slot < num_pollers)
	{
	  if (pollers[next_open_slot].fd != -1 ||
	      pollers[next_open_slot].refcount != 0)
	    break;
	  next_open_slot++;
	}
    }
  else
    {
      next_open_slot++;
      num_pollers++;
    }
  
  *rv = num_pollers - 1;
  return NULL;
}

// Remvoe a poller froma a slot
void
asio_deref(int slot)
{
  // No way to signal an error here.   Fix?
  if (slot < 0 || slot >= num_pollers || 
      pollers[slot].fd == -1 || pollers[slot].refcount < 1)
    {
      syslog(LOG_ERR, "bogus call to asio_deref: slot %d fd %d refcount %d",
	     slot, pollers[slot].fd, pollers[slot].refcount);
      return;
    }

  if (pollers[slot].refcount > 1)
    pollers[slot].refcount--;

  if (pollers[slot].refcount == 1)
    {
      if (pollers[slot].thunk != NULL && pollers[slot].thunk_free != NULL)
	pollers[slot].thunk_free(pollers[slot].thunk);
      memset(&pollers[slot], 0, sizeof pollers[slot]);
      pollers[slot].fd = -1;
    }
}

// Provide an event handler for all of the event types in the specified mask
char *
asio_set_handler(int slot, int events, asio_event_handler_t handler)
{
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "set_event_handler: invalid slot";
  if (!(events & (POLLERR | POLLHUP | POLLIN | POLLNVAL | POLLOUT | POLLPRI)))
    return "set_event_handler: invalid event flag";
  if (events & POLLERR)
    pollers[slot].pollerr = handler;
  if (events & POLLHUP)
    pollers[slot].pollhup = handler;
  if (events & POLLIN)
    pollers[slot].pollin = handler;
  if (events & POLLNVAL)
    pollers[slot].pollnval = handler;
  if (events & POLLOUT)
    pollers[slot].pollout = handler;
  if (events & POLLPRI)
    pollers[slot].pollpri = handler;
  pollers[slot].events |= events;
  return NULL;
}

// Clear an event handler for all the event types in the specified mask
// E.g., we are only interested in whether a socket is writable if we have
// something to write.
char *
asio_clear_handler(int slot, int events, asio_event_handler_t handler)
{
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "clear_event_handler: invalid slot";
  if (!(events & (POLLERR | POLLHUP | POLLIN | POLLNVAL | POLLOUT | POLLPRI)))
    return "clear_event_handler: invalid event flag";

  if (events & POLLERR)
    pollers[slot].pollerr = 0;
  if (events & POLLHUP)
    pollers[slot].pollhup = 0;
  if (events & POLLIN)
    pollers[slot].pollin = 0;
  if (events & POLLNVAL)
    pollers[slot].pollnval = 0;
  if (events & POLLOUT)
    pollers[slot].pollout = 0;
  if (events & POLLPRI)
    pollers[slot].pollpri = 0;
  pollers[slot].events &= ~events;
  return NULL;
}

// Do a single poll and event dispatch cycle.
char *
asio_poll_once(int timeout)
{
  int nfds = 0;
  int i;
  int count;

  for (i = 0; i < num_pollers; i++)
    {
      if (pollers[i].fd != -1)
	{
	  pollmap[nfds] = i;
	  pollfds[nfds].fd = pollers[i].fd;
	  pollfds[nfds].events = pollers[i].events;
	  pollfds[nfds].revents = 0;
	  nfds++;
	}
    }

  // If there aren't any descriptors to wait on, fail.
  if (nfds == 0)
    return "asio_poll_once: done";

  count = poll(pollfds, nfds, timeout);

  if (count < 0)
    {
      // It's okay if the poll was interrupted.
      if (errno == EINTR)
	return NULL;
      return strerror(errno);
    }

  for (i = 0; i < nfds && count > 0; i++)
    {
      int slot = pollmap[i];
      int revents = pollfds[i].revents;
      int fd = pollfds[i].fd;
      if (revents)
	{
	  if ((revents & POLLERR) && pollers[slot].pollerr != NULL)
	    pollers[slot].pollerr(slot, revents & POLLERR, pollers[slot].thunk);
	  if ((revents & POLLHUP) && pollers[slot].pollhup != NULL)
	    pollers[slot].pollhup(slot, revents & POLLHUP, pollers[slot].thunk);
	  if ((revents & POLLIN) && pollers[slot].pollin != NULL)
	    pollers[slot].pollin(slot, revents & POLLIN, pollers[slot].thunk);
	  if ((revents & POLLNVAL) && pollers[slot].pollnval != NULL)
	    pollers[slot].pollnval(slot, revents & POLLNVAL,
				    pollers[slot].thunk);
	  if ((revents & POLLOUT) && pollers[slot].pollout != NULL)
	    pollers[slot].pollout(slot, revents & POLLOUT, pollers[slot].thunk);
	  if ((revents & POLLPRI) && pollers[slot].pollpri != NULL)
	    pollers[slot].pollpri(slot, revents & POLLPRI, pollers[slot].thunk);
	  --count;
	}
    }
 return NULL;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
