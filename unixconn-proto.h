/* unixconn.c:48:NF */ extern void unixconn_deref (unixconn_t *uct); /* (uct) unixconn_t *uct; */
/* unixconn.c:56:NF */ extern const char *unixconn_write (unixconn_t *uct, const char *str); /* (uct, str) unixconn_t *uct; const char *str; */
/* unixconn.c:92:NF */ extern void unixconn_finalize (unixconn_t *uct); /* (uct) unixconn_t *uct; */
/* unixconn.c:115:NF */ extern void unixconn_finalize_listener (unixconn_t *uct); /* (uct) unixconn_t *uct; */
/* unixconn.c:127:NF */ extern const char *unixconn_make (unixconn_t **rv, int slot, const char *path, const char *remote, asio_event_handler_t handler, void (*finalize) (void *)); /* (rv, slot, path, remote, handler, finalize) unixconn_t **rv; int slot; const char *path; const char *remote; asio_event_handler_t handler; void (*finalize)(); */
/* unixconn.c:191:NF */ extern void unixconn_read_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* unixconn.c:267:NF */ extern void unixconn_listen_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* unixconn.c:303:NF */ extern const char *unixconn_socket_create (unixconn_t **rv, const char *path); /* (rv, path) unixconn_t **rv; const char *path; */
/* unixconn.c:362:NF */ extern const char *unixconn_set_listen_handler (unixconn_t *uct, void (*listen_handler) (unixconn_t *)); /* (uct, listen_handler) unixconn_t *uct; void (*listen_handler)(); */
/* unixconn.c:373:NF */ extern const char *unixconn_set_read_handler (unixconn_t *uct, void (*read_handler) (unixconn_t *, char *)); /* (uct, read_handler) unixconn_t *uct; void (*read_handler)(); */
