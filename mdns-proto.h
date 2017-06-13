/* mdns.c:49:NF */ extern const char *mdns_addr_to_buf (int *addrlen, u_int8_t *buffer, int length, int max, address_t *from); /* (addrlen, buffer, length, max, from) int *addrlen; u_int8_t *buffer; int length; int max; address_t *from; */
/* mdns.c:76:NF */ extern void mdns_read_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* mdns.c:105:NF */ extern void mdns_finalize (void *thunk); /* (thunk) void *thunk; */
/* mdns.c:124:NF */ extern const char *mdns_listener_add (interface_t *ip); /* (ip) interface_t *ip; */
/* mdns.c:272:NF */ extern void mdns_write_handler (int slot, int events, void *thunk); /* (slot, events, thunk) int slot; int events; void *thunk; */
/* mdns.c:325:NF */ extern void mdns_write (mdns_t *mdp, u_int8_t *buf, int buflen); /* (mdp, buf, buflen) mdns_t *mdp; u_int8_t *buf; int buflen; */
/* mdns.c:339:NF */ extern const char *mdns_listener_drop (interface_t *interface); /* (interface) interface_t *interface; */
