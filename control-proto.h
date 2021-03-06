/* control.c:71:NF */ extern void control_write_status (unixconn_t *uct, int code, const char *message, const char *more); /* (uct, code, message, more) unixconn_t *uct; int code; const char *message; const char *more; */
/* control.c:81:NF */ extern void control_read (unixconn_t *uct, char *line); /* (uct, line) unixconn_t *uct; char *line; */
/* control.c:92:NF */ extern void control_listen (unixconn_t *uct); /* (uct) unixconn_t *uct; */
/* control.c:101:NF */ extern const char *control_start (const char *path); /* (path) const char *path; */
/* control.c:124:NF */ extern void control_add_dns (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:152:NF */ extern void control_drop_dns (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:163:NF */ extern void control_add_mdns (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:174:NF */ extern void control_drop_mdns (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:182:NF */ extern int control_digest_addr (address_t *addr, arg_t *args); /* (addr, args) address_t *addr; arg_t *args; */
/* control.c:211:NF */ extern void control_add_accept (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:245:NF */ extern void control_drop_accept (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:268:NF */ extern void control_dump_status (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
/* control.c:305:NF */ extern void control_end (unixconn_t *uct, control_command_t *cmd, int argc, arg_t *args); /* (uct, cmd, argc, args) unixconn_t *uct; control_command_t *cmd; int argc; arg_t *args; */
