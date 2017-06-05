/* asio.c:61:NF */ extern const char *asio_add (int *rv, int sock); /* (rv, thunk, sock, thunk_free) int *rv; void *thunk; int sock; void (*thunk_free)(); */
/* asio.c:146:NF */ extern void asio_deref (int slot); /* (slot) int slot; */
/* asio.c:171:NF */ extern char *asio_set_handler (int slot, int events, asio_event_handler_t handler); /* (slot, events, handler) int slot; int events; asio_event_handler_t handler; */
/* asio.c:197:NF */ extern char *asio_clear_handler (int slot, int events, asio_event_handler_t handler); /* (slot, events, handler) int slot; int events; asio_event_handler_t handler; */
/* asio.c:222:NF */ extern char *asio_poll_once (int timeout); /* (timeout) int timeout; */
const char *
asio_set_thunk(int slot, void *thunk, void (*thunk_free)(void *));
const char *asio_read(int *len, int slot, char *buf, int buflen);
void asio_disable(int slot);
const char *asio_accept(int *slot, struct sockaddr *, size_t);
