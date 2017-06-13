/* tdns.c:50:NF */ extern void tdns_frame_to_mdns (tdns_t *tdp); /* (tdp) tdns_t *tdp; */
/* tdns.c:70:NF */ extern void tdns_read_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* tdns.c:137:NF */ extern void tdns_connection_finalize (void *thunk); /* (thunk) void *thunk; */
/* tdns.c:155:NF */ extern void tdns_listen_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* tdns.c:210:NF */ extern void tdns_finalize_listener (void *thunk); /* (thunk) void *thunk; */
/* tdns.c:223:NF */ extern const char *tdns_listener_add (tdns_listener_t *tlp); /* (tlp) tdns_listener_t *tlp; */
/* tdns.c:279:NF */ extern const char *tdns_listener_drop (interface_t *interface); /* (interface) interface_t *interface; */
/* tdns.c:285:NF */ extern void tdns_write_handler (int slot, int event, void *thunk); /* (slot, event, thunk) int slot; int event; void *thunk; */
/* tdns.c:318:NF */ extern const char *tdns_write (tdns_listener_t *tlp, u_int8_t *buf, int length); /* (tlp, buf, length) tdns_listener_t *tlp; u_int8_t *buf; int length; */
