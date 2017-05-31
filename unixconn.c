/* unixconn.c
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

// This file contains routines for creating unix domain sockets, listening
// on them, and sending and receiving data on them.

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
	     
// Create a unix-domain stream socket, bind it to the specified path,
// listen on it, and add it to the polling set.
// On error, return value is non-NULL, and contains a string that
// explains what went wrong.
// On success, return value is NULL, and a unixconn_t is stored
// through the rv pointer.

const char *
unixconn_socket_create(unixconn_t *rv, const char *path)
{
  struct sockaddr_un sockname;
  int len;
  int sock;
  int result;
  const char *errstr;

  if (path == NULL)
    return "no name given";
  len = strnlen(path, 1 + sizeof sockname.sun_path);
  if (len > sizeof sockname.sun_path)
    return "name too long";
  if (rv == NULL)
    return "no return destination";

  socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    return strerror(errno);

  strcpy(sockname.sun_path, path);
  sockname.sun_len = len + (sizeof sockname) - (sizeof sockname.path);
  sockname.sun_family = AF_UNIX;
  result = bind(sock, (sockaddr_t *)&sockname, sockname.sun_len);
  if (result < 0)
    {
      close(sock);
      return strerror(err);
    }
  
  result = listen(sock, 5);
  if (result < 0)
    {
      close(sock);
      return strerror(err);
    }

  return unixconn_make(rv, sock, path, "listener", unixconn_listen_handler, listen_callback);
}

// Provide a function to call when a listen completes.
const char *
unixconn_set_listen_handler(unixconn_t *uct,
			    char *(*listen_handler)(unixconn_t *))
{
  if (uct == NULL)
    return "unixconn_set_listen_handler: invalid unixconn_t";
  uct->listen_handler = listen_handler;
  return NULL;
}  

// Provide a function to call when a listen completes.
const char *
unixconn_set_read_handler(unixconn_t *uct,
			  char *(*read_handler)(unixconn_t *))
{
  if (uct == NULL)
    return "unixconn_set_read_handler: invalid unixconn_t";
  uct->read_handler = read_handler;
  return NULL;
}  

// Free function for the unixconn_t that we pass to the async i/o package
void
unixconn_free_uct(unixconn_t *uct)
{
  if (!uct)
    return;

  if (uct->path)
    {
      free(uct->path);
      uct->path = 0;
    }

  if (uct->remote)
    {
      free(uct->remote);
      uct->remote = 0;
    }
  free(uct);
}
      

// Helper function to finish setting up the unixconn_t and register the
// async I/O handler.

const char *
unixconn_make(unixconn_t *rv, int sock, const char *path, const char *remote, 
	      asio_event_handler_t handler)
{
  unixconn_t *uct = malloc(sizeof unixconn_t);
  if (uct == NULL)
    {
      errstr = "insufficient memory for unixconn_t";
      goto have_socket_err;
    }
  memset(uct, 0, sizeof *uct);

  uct->path = malloc(len + 1);
  if (uct->path == NULL)
    {
      errstr = "Insufficient memory for name in unixconn_t";
      goto have_uct_err;
    }
  strcpy(uct->path, name);

  uct->remote = malloc(strlen(remote) + 1);
  if (uct->remote == NULL)
    {
      errstr = "Insufficient memory for remote name in unixconn_t";
      goto have_path_err;
    }
  strcpy(uct->remote, remote);

  uct->socket = sock;

  errstr = asio_add(&slot, uct, sock, unixconn_free_uct);
  if (errstr != NULL)
    goto have_remote_err;

  errstr = asio_set_handler(POLLIN, handler);
  if (errorstr != NULL)
    goto have_asio_err;
      
  *rv = uct;
  return NULL;

 have_asio_err:
  asio_deref(slot);
 have_remote_err:
  free(uct->remote);
 have_path_err:
  free(uct->path);
 have_uct_err:
  free(uct);
  close(sock);

  return errstr;
}

// Called when the listen socket is readable.
void
unixconn_listen_handler(int slot, int events, void *thunk)
{
  unixconn_t *uct = thunk;
  unixconn_t *rv;
  int sock;
  struct sockaddr junk;
  const char *errstr;

  errstr = asio_accept(&sock, slot, &junk, sizeof junk);
  if (errstr != NULL)
    {
      syslog(LOG_CRIT, "unixconn_listen_handler: %s", errstr);
      return;
    }

  errstr = unixconn_make(&rv, sock, uct->path, "connected", unixconn_read_handler);
  if (errstr != NULL)
    {
      syslog(LOG_CRIT, "unixconn_listen_handler: %s", errstr);
      return;
    }
  uct->listen_handler(rv);
}
  
// Read available data from the socket.   Data is in the form of lines
// of text separated by '\n' or '\r\n'.  Call the line-of-text handler
// once for each line of  text.  Text is NUL-terminated before passing
// to line-of-text handler.
//
// If the attacker^H^H^H^H^H^H^H^Hclient sends text with a NUL in the
// middle, whatever comes after the NUL in that line is safely
// ignored.  Possibly we should do pointer/length strings instead, but
// it's added complexity without added value for this application.
//
// This should really be a separate layer that can work with with
// unixconns and tcpconns (and anything similar), but objects are hard
// in C and this isn't needed for TCP connections yet, so we can
// generalize later if needed.

void
unixconn_read_handler(int slot, int events, void *thunk)
{
  unixconn_t *uct = thunk;
  int status, len;
  char *eol;
  char ibuf[256];

  // read text from the socket; complete an unfinished line if there
  // is one hanging from a previous read.  later: generalize this into
  // its own module so we can use it for tcp connections, etc?
  status = asio_read(sock, ibuf, sizeof ibuf);
  if (status < 0)
    {
      syslog(LOG_ERR, "unixconn_read_handler: %m");
      return;
    }
  
  { // invalidate resid after while loop exits.
    char * resid = &ibuf[0];

    while (resid - &ibuf[0] < status)
      {
	eol = memchr(resid, '\n', status);
	if (eol == NULL)
	  {
	    if (status + uct->buflen > sizeof uct->buf)
	      goto buffer_overflow;
	    memcpy(uct->buf + uct->buflen, resid, status);
	    uct->buflen += status;
	    return;
	  }

	len = eol - resid;
	resid = eol + 1;
	if (len > 0 && eol[-1] == '\r')
	  len--;
	if (uct->buflen != 0)
	  {
	    // The line could still be too long.
	    if (len + uct->buflen + 1 > sizeof uct->buf)
	      {
	      buffer_overflow:
		syslog(LOG_ERR, "unixconn_read_handler: buffer overflow from %s:%s",
		       uct->path, uct->remote);
		asio_disable(slot);
		asio_deref(slot);
		return;
	      }
	    memcpy(uct->buf + uct->buflen, resid);
	    uct->buflen += len;
	    uct->buf[uct->buflen] = 0;

	    if (uct->read_handler != NULL)
	      uct->read_handler(uct, uct->buf);

	    uct->buflen = 0;
	  }
	else
	  {
	    if (uct->read_handler != NULL)
	      {
		*eol = 0;
		uct->read_handler(uct, resid);
	      }
	  }

	resid = eol + 1;
      }
  }
}
      
/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
