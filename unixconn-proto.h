/* unixconn.c:46:NF */ extern void unixconn_free_uct (unixconn_t *uct); /* (uct) unixconn_t *uct; */
/* unixconn.c:69:NF */ extern const char *unixconn_make (unixconn_t **rv, int slot, const char *path, const char *remote, asio_event_handler_t handler); /* (rv, slot, path, remote, handler) unixconn_t **rv; int slot; const char *path; const char *remote; asio_event_handler_t handler; */
/* unixconn.c:133:NF */ extern void unixconn_read_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* unixconn.c:206:NF */ extern void unixconn_listen_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* unixconn.c:238:NF */ extern const char *unixconn_socket_create (unixconn_t **rv, const char *path); /* (rv, path) unixconn_t **rv; const char *path; */
/* unixconn.c:295:NF */ extern const char *unixconn_set_listen_handler (unixconn_t *uct, void (*listen_handler) (unixconn_t *)); /* (uct, listen_handler) unixconn_t *uct; void (*listen_handler)(); */
/* unixconn.c:306:NF */ extern const char *unixconn_set_read_handler (unixconn_t *uct, void (*read_handler) (unixconn_t *, char *)); /* (uct, read_handler) unixconn_t *uct; void (*read_handler)(); */
