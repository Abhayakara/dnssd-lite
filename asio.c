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

const char *
asio_set_thunk(int slot, void *thunk, void (*thunk_free)(void *))
{
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "set_thunk: invalid slot";
  
  pollers[slot].thunk = thunk;
  pollers[slot].thunk_free = thunk_free;
  return NULL;
}

// Register a poller for a particular file descriptor
const char *
asio_add(int *rv, int sock)
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
		     0, POLLFD_INC * sizeof *new_pollers);
	    }
	  else
	    {
	      memset(new_pollers, 0, new_max_pollers * sizeof *new_pollers);
	    }

	  max_pollers = new_max_pollers;
	  pollfds = new_pollfds;
	  pollers = new_pollers;
	  pollmap = new_pollmap;
	}      
    }

  memset(&pollers[next_open_slot], 0, sizeof pollers[next_open_slot]);
  pollers[next_open_slot].fd = sock;
  pollers[next_open_slot].events = 0;
  pollers[next_open_slot].refcount = 1;
  if (next_open_slot != num_pollers)
    {
      next_open_slot++;
      while (next_open_slot < num_pollers)
	{
	  if (pollers[next_open_slot].fd == -1 &&
	      pollers[next_open_slot].refcount == 0)
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

// Disable polling on this slot
void
asio_disable(int slot)
{
  if (slot < 0 || slot >= num_pollers || 
      pollers[slot].fd == -1 || pollers[slot].refcount < 1)
    {
      syslog(LOG_ERR, "bogus call to asio_disable: slot %d fd %d refcount %d",
	     slot, pollers[slot].fd, pollers[slot].refcount);
      return;
    }

  // This clears all the event handlers and disables polling for all events.
  asio_clear_handler(slot, pollers[slot].events);
}

// Remove a poller from a slot
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
      close(pollers[slot].fd);
      memset(&pollers[slot], 0, sizeof pollers[slot]);
      pollers[slot].fd = -1;
    }
}

// Provide an event handler for all of the event types in the specified mask
const char *
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
const char *
asio_clear_handler(int slot, int events)
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
const char *
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
      if (revents)
	{
	  if ((revents & POLLERR) && pollers[slot].pollerr != NULL)
	    pollers[slot].pollerr(slot, revents & POLLERR, pollers[slot].thunk);
	  if (pollers[slot].fd != -1 &&
	      (revents & POLLHUP) && pollers[slot].pollhup != NULL)
	    pollers[slot].pollhup(slot, revents & POLLHUP, pollers[slot].thunk);
	  if (pollers[slot].fd != -1 &&
	      (revents & POLLIN) && pollers[slot].pollin != NULL)
	    pollers[slot].pollin(slot, revents & POLLIN, pollers[slot].thunk);
	  if (pollers[slot].fd != -1 &&
	      (revents & POLLNVAL) && pollers[slot].pollnval != NULL)
	    pollers[slot].pollnval(slot, revents & POLLNVAL,
				    pollers[slot].thunk);
	  if (pollers[slot].fd != -1 &&
	      (revents & POLLOUT) && pollers[slot].pollout != NULL)
	    pollers[slot].pollout(slot, revents & POLLOUT, pollers[slot].thunk);
	  if (pollers[slot].fd != -1 &&
	      (revents & POLLPRI) && pollers[slot].pollpri != NULL)
	    pollers[slot].pollpri(slot, revents & POLLPRI, pollers[slot].thunk);
	  --count;
	}
    }
 return NULL;
}

// Read from a slot
const char *
asio_read(int *len, int slot, char *buf, int max)
{
  int status;
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "asio_read: invalid slot";

  status = read(pollers[slot].fd, buf, max);
  if (status < 0)
    return strerror(errno);
  *len = status;
  return NULL;
}

// Write to a slot
const char *
asio_write(int *len, int slot, char *buf, int max)
{
  int status;
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "asio_write: invalid slot";

  status = write(pollers[slot].fd, buf, max);
  if (status < 0)
    return strerror(errno);
  *len = status;
  return NULL;
}

// Read from a slot
const char *
asio_recvfrom(int *count, int slot, char *buf, int max, int flags,
	      struct sockaddr *sa, socklen_t *len)
{
  int status;
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "asio_read: invalid slot";

  status = recvfrom(pollers[slot].fd, buf, max, flags, sa, len);
  if (status < 0)
    return strerror(errno);
  *count = status;
  return NULL;
}

// Write to a slot
const char *
asio_sendto(int *count, int slot, char *buf, int max, int flags,
	    struct sockaddr *sa, socklen_t len)
{
  int status;
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "asio_write: invalid slot";

  status = sendto(pollers[slot].fd, buf, max, flags, sa, len);
  if (status < 0)
    return strerror(errno);
  *count = status;
  return NULL;
}

// Accept a connection, make a slot for it
const char *
asio_accept(int *rv, int slot, struct sockaddr *remote, socklen_t *remote_len)
{
  int status;
  int new_slot;
  const char *errstr;
  if (slot < 0 || slot >= num_pollers || pollers[slot].fd == -1)
    return "asio_read: invalid slot";

  status = accept(pollers[slot].fd, remote, remote_len);
  if (status < 0)
    return strerror(errno);
  
  errstr = asio_add(&new_slot, status);
  if (errstr != NULL)
    return errstr;
  *rv = new_slot;
  return NULL;
}

// Lossy output buffer.   If there's room, put the data there, preceded by
// a two-byte length.   If there's not room, increment the dropped frame
// count and silently discard the data.    If we really cared we could buffer
// the data, but if we are getting behind, buffering is likely to make
// things worse: the assumption is that the protocol is tolerant of
// datagram drops.
void
asio_queue_out(outbuf_t *out, u_int8_t *buf, int buflen)
{
  int need = buflen + 2; // datagram plus length

  // No space in buffer...
  if (out->len + need >= sizeof out->buf)
    {
      if (out->len + need - out->base < sizeof out->buf)
	{
	  out->len -= out->base;
	  memmove(&out->buf[0], &out->buf[out->base], out->len);
	  out->base = 0;
	}
      else
	{
	  out->dropped_frames++;
	  return;
	}
    }

  // Copy the datagram length and the data into the buffer and enable writing
  out->buf[out->len] = buflen >> 8;
  out->buf[out->len + 1] = buflen & 255;
  memcpy(&out->buf[out->len + 2], buf, buflen);
  out->len += need;
}

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
