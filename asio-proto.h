/* asio.c:60:NF */ extern const char *asio_set_thunk (int slot, void *thunk, void (*thunk_free) (void *)); /* (slot, thunk, thunk_free) int slot; void *thunk; void (*thunk_free)(); */
/* asio.c:72:NF */ extern const char *asio_add (int *rv, int sock); /* (rv, sock) int *rv; int sock; */
/* asio.c:156:NF */ extern void asio_disable (int slot); /* (slot) int slot; */
/* asio.c:172:NF */ extern void asio_deref (int slot); /* (slot) int slot; */
/* asio.c:198:NF */ extern const char *asio_set_handler (int slot, int events, asio_event_handler_t handler); /* (slot, events, handler) int slot; int events; asio_event_handler_t handler; */
/* asio.c:224:NF */ extern const char *asio_clear_handler (int slot, int events); /* (slot, events) int slot; int events; */
/* asio.c:249:NF */ extern const char *asio_poll_once (int timeout); /* (timeout) int timeout; */
/* asio.c:313:NF */ extern const char *asio_read (int *len, int slot, char *buf, int max); /* (len, slot, buf, max) int *len; int slot; char *buf; int max; */
/* asio.c:328:NF */ extern const char *asio_write (int *len, int slot, char *buf, int max); /* (len, slot, buf, max) int *len; int slot; char *buf; int max; */
/* asio.c:343:NF */ extern const char *asio_recvfrom (int *count, int slot, char *buf, int max, int flags, struct sockaddr *sa, socklen_t *len); /* (count, slot, buf, max, flags, sa, len) int *count; int slot; char *buf; int max; int flags; struct sockaddr *sa; socklen_t *len; */
/* asio.c:359:NF */ extern const char *asio_sendto (int *count, int slot, char *buf, int max, int flags, struct sockaddr *sa, socklen_t len); /* (count, slot, buf, max, flags, sa, len) int *count; int slot; char *buf; int max; int flags; struct sockaddr *sa; socklen_t len; */
/* asio.c:375:NF */ extern const char *asio_accept (int *rv, int slot, struct sockaddr *remote, socklen_t *remote_len); /* (rv, slot, remote, remote_len) int *rv; int slot; struct sockaddr *remote; socklen_t *remote_len; */
/* asio.c:401:NF */ extern void asio_queue_out (outbuf_t *out, u_int8_t *buf, int buflen); /* (out, buf, buflen) outbuf_t *out; u_int8_t *buf; int buflen; */
