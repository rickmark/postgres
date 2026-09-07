/*-------------------------------------------------------------------------
 *
 * xpc_postmaster.c
 *	  macOS XPC service support for PostgreSQL postmaster.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/xpc_postmaster.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "miscadmin.h"
#include "libpq/libpq-be.h"
#include "libpq/pqcomm.h"
#include "postmaster/postmaster.h"
#include "postmaster/xpc_postmaster.h"

/* GUC variables */
bool		enable_xpc = false;
char	   *xpc_service_name = NULL;
char	   *xpc_client_teamid = NULL;
char	   *xpc_client_bundleid = NULL;
char	   *xpc_client_requirement = NULL;

#ifdef USE_XPC

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <pwd.h>
#include <unistd.h>

#define Size MacTypes_Size
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#undef Size

extern void xpc_connection_get_audit_token(xpc_connection_t connection, audit_token_t *token);

#ifdef USE_DARWIN_CODESIGN
#include "libpq/be-codesign.h"
#endif

static int	pm_xpc_pipe[2] = {-1, -1};
static xpc_connection_t xpc_listener = NULL;
static dispatch_queue_t xpc_queue = NULL;

/*
 * Send a file descriptor across a Unix domain stream socket using SCM_RIGHTS.
 */
static int
send_fd(int sock, int fd_to_send)
{
	struct msghdr msg;
	struct iovec iov;
	char		dummy = 'C';
	union
	{
		struct cmsghdr cm;
		char		control[CMSG_SPACE(sizeof(int))];
	}			control_un;
	struct cmsghdr *cmptr;
	int			res;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len = CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	*((int *) CMSG_DATA(cmptr)) = fd_to_send;

	do
	{
		res = sendmsg(sock, &msg, 0);
	} while (res < 0 && errno == EINTR);

	return res;
}

/*
 * Receive a file descriptor across a Unix domain stream socket.
 */
static int
recv_fd(int sock)
{
	struct msghdr msg;
	struct iovec iov;
	char		dummy;
	union
	{
		struct cmsghdr cm;
		char		control[CMSG_SPACE(sizeof(int))];
	}			control_un;
	struct cmsghdr *cmptr;
	int			received_fd = -1;
	ssize_t		res;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	do
	{
		res = recvmsg(sock, &msg, 0);
	} while (res < 0 && errno == EINTR);

	if (res <= 0)
		return -1;

	cmptr = CMSG_FIRSTHDR(&msg);
	if (cmptr != NULL && cmptr->cmsg_len == CMSG_LEN(sizeof(int)) &&
		cmptr->cmsg_level == SOL_SOCKET && cmptr->cmsg_type == SCM_RIGHTS)
	{
		received_fd = *((int *) CMSG_DATA(cmptr));
	}
	return received_fd;
}

/*
 * Validate an XPC peer process using its audit token.
 */
static bool
validate_xpc_peer(audit_token_t token, const char *req_teamid, const char *req_bundleid,
				  const char *req_expr, char *errbuf, size_t errlen)
{
	CFDataRef	tokdata;
	const void *key;
	const void *value;
	CFDictionaryRef attrs;
	SecCodeRef	code = NULL;
	OSStatus	status;

	tokdata = CFDataCreate(NULL, (const UInt8 *) &token, sizeof(token));
	if (!tokdata)
	{
		snprintf(errbuf, errlen, "out of memory");
		return false;
	}

	key = kSecGuestAttributeAudit;
	value = tokdata;
	attrs = CFDictionaryCreate(NULL, &key, &value, 1,
							   &kCFTypeDictionaryKeyCallBacks,
							   &kCFTypeDictionaryValueCallBacks);
	CFRelease(tokdata);
	if (!attrs)
	{
		snprintf(errbuf, errlen, "out of memory");
		return false;
	}

	status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	if (status != errSecSuccess || !code)
	{
		snprintf(errbuf, errlen, "could not retrieve peer SecCode (OSStatus %d)", (int) status);
		return false;
	}

	/* Validate custom code signing requirement string if provided */
	if (req_expr && req_expr[0])
	{
		CFStringRef reqstr = CFStringCreateWithCString(NULL, req_expr, kCFStringEncodingUTF8);
		if (reqstr)
		{
			SecRequirementRef req = NULL;
			CFErrorRef	err = NULL;

			status = SecRequirementCreateWithStringAndErrors(reqstr, kSecCSDefaultFlags, &err, &req);
			CFRelease(reqstr);
			if (status == errSecSuccess && req)
			{
				status = SecCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, req, &err);
				CFRelease(req);
				if (status != errSecSuccess)
				{
					snprintf(errbuf, errlen, "peer failed code signing requirement (OSStatus %d)", (int) status);
					if (err)
						CFRelease(err);
					CFRelease(code);
					return false;
				}
			}
			else
			{
				snprintf(errbuf, errlen, "invalid code signing requirement expression (OSStatus %d)", (int) status);
				if (err)
					CFRelease(err);
				CFRelease(code);
				return false;
			}
		}
	}

	/* Validate Bundle ID and/or Team ID */
	if ((req_teamid && req_teamid[0]) || (req_bundleid && req_bundleid[0]))
	{
		CFDictionaryRef info = NULL;

		status = SecCodeCopySigningInformation((SecStaticCodeRef) code, kSecCSSigningInformation, &info);
		if (status != errSecSuccess || !info)
		{
			snprintf(errbuf, errlen, "could not read peer signing info (OSStatus %d)", (int) status);
			CFRelease(code);
			return false;
		}

		if (req_bundleid && req_bundleid[0])
		{
			CFStringRef bundle_id = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
			char		bundle_buf[256];

			if (!bundle_id || !CFStringGetCString(bundle_id, bundle_buf, sizeof(bundle_buf), kCFStringEncodingUTF8) ||
				strcmp(bundle_buf, req_bundleid) != 0)
			{
				snprintf(errbuf, errlen, "peer bundle id does not match required \"%s\"", req_bundleid);
				CFRelease(info);
				CFRelease(code);
				return false;
			}
		}

		if (req_teamid && req_teamid[0])
		{
			CFStringRef team_id = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
			char		team_buf[256];

			if (strcmp(req_teamid, "same") == 0)
			{
#ifdef USE_DARWIN_CODESIGN
				char	own_teamid[256];
				char	own_err[256];

				if (pg_codesign_get_own_teamid(own_teamid, sizeof(own_teamid), own_err, sizeof(own_err)) != 0 ||
					!team_id || !CFStringGetCString(team_id, team_buf, sizeof(team_buf), kCFStringEncodingUTF8) ||
					strcmp(team_buf, own_teamid) != 0)
				{
					snprintf(errbuf, errlen, "peer team id does not match server team id");
					CFRelease(info);
					CFRelease(code);
					return false;
				}
#else
				snprintf(errbuf, errlen, "server code signature verification not supported");
				CFRelease(info);
				CFRelease(code);
				return false;
#endif
			}
			else
			{
				if (!team_id || !CFStringGetCString(team_id, team_buf, sizeof(team_buf), kCFStringEncodingUTF8) ||
					strcmp(team_buf, req_teamid) != 0)
				{
					snprintf(errbuf, errlen, "peer team id does not match required \"%s\"", req_teamid);
					CFRelease(info);
					CFRelease(code);
					return false;
				}
			}
		}
		CFRelease(info);
	}

	CFRelease(code);
	return true;
}

/*
 * Socket helper routines for direct query execution.
 */
static bool
write_all(int fd, const void *buf, size_t len)
{
	const char *p = (const char *) buf;

	while (len > 0)
	{
		ssize_t		res = write(fd, p, len);

		if (res < 0)
		{
			if (errno == EINTR)
				continue;
			return false;
		}
		p += res;
		len -= res;
	}
	return true;
}

static bool
read_all(int fd, void *buf, size_t len)
{
	char	   *p = (char *) buf;

	while (len > 0)
	{
		ssize_t		res = read(fd, p, len);

		if (res < 0)
		{
			if (errno == EINTR)
				continue;
			return false;
		}
		if (res == 0)
			return false;		/* EOF */
		p += res;
		len -= res;
	}
	return true;
}

static bool
read_int32(int fd, int32 *val)
{
	uint32		netval;

	if (!read_all(fd, &netval, 4))
		return false;
	*val = (int32) ntohl(netval);
	return true;
}

static bool
read_int16(int fd, int16 *val)
{
	uint16		netval;

	if (!read_all(fd, &netval, 2))
		return false;
	*val = (int16) ntohs(netval);
	return true;
}

static bool
read_cstring(int fd, char *buf, size_t maxlen)
{
	size_t		i = 0;

	while (i < maxlen)
	{
		char		c;

		if (!read_all(fd, &c, 1))
			return false;
		buf[i] = c;
		if (c == '\0')
			return true;
		i++;
	}
	buf[maxlen - 1] = '\0';
	return true;
}

/*
 * Execute a SQL query directly via backend protocol over a socketpair,
 * returning columns and rows in an XPC dictionary.
 */
static void
execute_xpc_query(const char *query_str, const char *dbname, const char *username, xpc_object_t reply)
{
	int			fds[2];
	char		buf[4096];
	size_t		offset;
	uint32		net_len, net_proto;
	const char *user;
	const char *db;
	int			len;
	char		msg_type;
	int32		msg_len;
	xpc_object_t cols_array = NULL;
	xpc_object_t rows_array = NULL;
	char		command_tag[128] = "";
	char		err_msg[512] = "";
	bool		query_failed = false;
	bool		got_ready = false;
	char		default_user[128];

	if (!query_str || query_str[0] == '\0')
	{
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", "empty query string");
		return;
	}

	if (username && username[0])
		user = username;
	else
	{
		struct passwd pw;
		struct passwd *pwp = NULL;
		char		pwbuf[512];

		if (getpwuid_r(geteuid(), &pw, pwbuf, sizeof(pwbuf), &pwp) == 0 && pwp && pwp->pw_name)
			strlcpy(default_user, pwp->pw_name, sizeof(default_user));
		else if (getenv("USER"))
			strlcpy(default_user, getenv("USER"), sizeof(default_user));
		else
			strlcpy(default_user, "postgres", sizeof(default_user));
		user = default_user;
	}
	db = (dbname && dbname[0]) ? dbname : "postgres";

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
	{
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", "socketpair failed");
		return;
	}

	/* Dispatch backend socket to postmaster */
	if (send_fd(pm_xpc_pipe[1], fds[0]) < 0)
	{
		close(fds[0]);
		close(fds[1]);
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", "failed to launch backend process");
		return;
	}
	close(fds[0]);

	/* Build and send StartupMessage */
	offset = 4;					/* reserve 4 bytes for total length */
	net_proto = htonl(0x00030000);	/* Protocol 3.0 */
	memcpy(buf + offset, &net_proto, 4);
	offset += 4;

	strcpy(buf + offset, "user");
	offset += strlen("user") + 1;
	strcpy(buf + offset, user);
	offset += strlen(user) + 1;

	strcpy(buf + offset, "database");
	offset += strlen("database") + 1;
	strcpy(buf + offset, db);
	offset += strlen(db) + 1;

	buf[offset++] = '\0';		/* final null terminator */

	net_len = htonl((uint32) offset);
	memcpy(buf, &net_len, 4);

	if (!write_all(fds[1], buf, offset))
	{
		close(fds[1]);
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", "failed to write startup message");
		return;
	}

	/* Read authentication / startup handshake until ReadyForQuery */
	for (;;)
	{
		if (!read_all(fds[1], &msg_type, 1))
			break;
		if (!read_int32(fds[1], &msg_len))
			break;

		if (msg_type == 'Z')	/* ReadyForQuery */
		{
			char		status_byte;

			read_all(fds[1], &status_byte, 1);
			got_ready = true;
			break;
		}
		else if (msg_type == 'E')	/* ErrorResponse */
		{
			int			rem = msg_len - 4;

			while (rem > 0)
			{
				char		field_type;
				char		field_val[256];

				if (!read_all(fds[1], &field_type, 1))
					break;
				rem--;
				if (field_type == '\0')
					break;

				read_cstring(fds[1], field_val, sizeof(field_val));
				rem -= (strlen(field_val) + 1);
				if (field_type == 'M' && err_msg[0] == '\0')
					strlcpy(err_msg, field_val, sizeof(err_msg));
			}
			query_failed = true;
		}
		else
		{
			/* Skip other handshake messages (Auth, BackendKeyData, ParameterStatus) */
			int			rem = msg_len - 4;

			while (rem > 0)
			{
				char		skip_buf[256];
				int			chunk = rem > sizeof(skip_buf) ? sizeof(skip_buf) : rem;

				if (!read_all(fds[1], skip_buf, chunk))
					break;
				rem -= chunk;
			}
		}
	}

	if (query_failed || !got_ready)
	{
		close(fds[1]);
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", err_msg[0] ? err_msg : "backend connection closed during startup");
		return;
	}

	/* Send Simple Query Message ('Q') */
	len = strlen(query_str);
	buf[0] = 'Q';
	net_len = htonl((uint32) (len + 1 + 4));
	memcpy(buf + 1, &net_len, 4);
	memcpy(buf + 5, query_str, len + 1);

	if (!write_all(fds[1], buf, len + 6))
	{
		char		errbuf[128];
		snprintf(errbuf, sizeof(errbuf), "failed to send query: errno=%d (%s)", errno, strerror(errno));
		close(fds[1]);
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", errbuf);
		return;
	}

	cols_array = xpc_array_create(NULL, 0);
	rows_array = xpc_array_create(NULL, 0);

	/* Read query response */
	for (;;)
	{
		if (!read_all(fds[1], &msg_type, 1))
			break;
		if (!read_int32(fds[1], &msg_len))
			break;

		if (msg_type == 'T')	/* RowDescription */
		{
			int16		num_fields;

			read_int16(fds[1], &num_fields);
			for (int i = 0; i < num_fields; i++)
			{
				char		field_name[256];
				int32		table_oid;
				int16		col_attr;
				int32		type_oid;
				int16		type_size;
				int32		type_mod;
				int16		format_code;

				read_cstring(fds[1], field_name, sizeof(field_name));
				read_int32(fds[1], &table_oid);
				read_int16(fds[1], &col_attr);
				read_int32(fds[1], &type_oid);
				read_int16(fds[1], &type_size);
				read_int32(fds[1], &type_mod);
				read_int16(fds[1], &format_code);

				xpc_array_set_string(cols_array, XPC_ARRAY_APPEND, field_name);
			}
		}
		else if (msg_type == 'D')	/* DataRow */
		{
			int16		num_cols;
			xpc_object_t row_array = xpc_array_create(NULL, 0);

			read_int16(fds[1], &num_cols);
			for (int i = 0; i < num_cols; i++)
			{
				int32		col_len;

				read_int32(fds[1], &col_len);
				if (col_len == -1)
				{
					xpc_array_set_value(row_array, XPC_ARRAY_APPEND, xpc_null_create());
				}
				else
				{
					char	   *val_buf = malloc(col_len + 1);

					if (val_buf)
					{
						read_all(fds[1], val_buf, col_len);
						val_buf[col_len] = '\0';
						xpc_array_set_string(row_array, XPC_ARRAY_APPEND, val_buf);
						free(val_buf);
					}
					else
					{
						/* skip bytes if allocation failed */
						for (int b = 0; b < col_len; b++)
						{
							char dummy;

							read_all(fds[1], &dummy, 1);
						}
					}
				}
			}
			xpc_array_set_value(rows_array, XPC_ARRAY_APPEND, row_array);
			xpc_release(row_array);
		}
		else if (msg_type == 'C')	/* CommandComplete */
		{
			read_cstring(fds[1], command_tag, sizeof(command_tag));
		}
		else if (msg_type == 'E')	/* ErrorResponse */
		{
			int			rem = msg_len - 4;

			while (rem > 0)
			{
				char		field_type;
				char		field_val[256];

				if (!read_all(fds[1], &field_type, 1))
					break;
				rem--;
				if (field_type == '\0')
					break;

				read_cstring(fds[1], field_val, sizeof(field_val));
				rem -= (strlen(field_val) + 1);
				if (field_type == 'M' && err_msg[0] == '\0')
					strlcpy(err_msg, field_val, sizeof(err_msg));
			}
			query_failed = true;
		}
		else if (msg_type == 'Z')	/* ReadyForQuery */
		{
			char		status_byte;

			read_all(fds[1], &status_byte, 1);
			break;
		}
		else
		{
			/* Skip unknown message */
			int			rem = msg_len - 4;

			while (rem > 0)
			{
				char		skip_buf[256];
				int			chunk = rem > sizeof(skip_buf) ? sizeof(skip_buf) : rem;

				if (!read_all(fds[1], skip_buf, chunk))
					break;
				rem -= chunk;
			}
		}
	}

	/* Send Terminate ('X') */
	buf[0] = 'X';
	net_len = htonl(4);
	memcpy(buf + 1, &net_len, 4);
	write_all(fds[1], buf, 5);

	close(fds[1]);

	if (query_failed)
	{
		xpc_dictionary_set_string(reply, "status", "ERROR");
		xpc_dictionary_set_string(reply, "error_message", err_msg[0] ? err_msg : "query failed");
	}
	else
	{
		xpc_dictionary_set_string(reply, "status", "OK");
		xpc_dictionary_set_string(reply, "command_tag", command_tag);
		xpc_dictionary_set_value(reply, "columns", cols_array);
		xpc_dictionary_set_value(reply, "rows", rows_array);
	}

	if (cols_array)
		xpc_release(cols_array);
	if (rows_array)
		xpc_release(rows_array);
}

/*
 * Handle an incoming XPC connection from a peer.
 */
static void
handle_xpc_peer_connection(xpc_connection_t peer)
{
	xpc_connection_set_target_queue(peer, xpc_queue);

	xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
		xpc_type_t	type = xpc_get_type(event);
		const char *action;

		if (type == XPC_TYPE_ERROR)
			return;

		if (type != XPC_TYPE_DICTIONARY)
			return;

		/* Peer code signing validation if configured */
		if ((xpc_client_teamid && xpc_client_teamid[0]) ||
			(xpc_client_bundleid && xpc_client_bundleid[0]) ||
			(xpc_client_requirement && xpc_client_requirement[0]))
		{
			audit_token_t audit_token;
			char		errbuf[256];

			xpc_connection_get_audit_token(peer, &audit_token);
			if (!validate_xpc_peer(audit_token, xpc_client_teamid, xpc_client_bundleid,
								   xpc_client_requirement, errbuf, sizeof(errbuf)))
			{
				xpc_object_t reply = xpc_dictionary_create_reply(event);

				if (reply)
				{
					xpc_dictionary_set_string(reply, "status", "ERROR");
					xpc_dictionary_set_string(reply, "error_message", errbuf);
					xpc_connection_send_message(peer, reply);
					xpc_release(reply);
				}
				return;
			}
		}

		action = xpc_dictionary_get_string(event, "action");

		if (!action)
			action = "connect";

		if (strcmp(action, "ping") == 0)
		{
			xpc_object_t reply = xpc_dictionary_create_reply(event);

			if (reply)
			{
				xpc_dictionary_set_string(reply, "status", "OK");
				xpc_dictionary_set_int64(reply, "postmaster_pid", getpid());
				xpc_dictionary_set_string(reply, "version", PG_VERSION);
				xpc_connection_send_message(peer, reply);
				xpc_release(reply);
			}
		}
		else if (strcmp(action, "connect") == 0)
		{
			int			fds[2];
			xpc_object_t reply;

			if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
			{
				reply = xpc_dictionary_create_reply(event);
				if (reply)
				{
					xpc_dictionary_set_string(reply, "status", "ERROR");
					xpc_dictionary_set_string(reply, "error_message", "socketpair failed");
					xpc_connection_send_message(peer, reply);
					xpc_release(reply);
				}
				return;
			}

			if (send_fd(pm_xpc_pipe[1], fds[0]) < 0)
			{
				close(fds[0]);
				close(fds[1]);
				reply = xpc_dictionary_create_reply(event);
				if (reply)
				{
					xpc_dictionary_set_string(reply, "status", "ERROR");
					xpc_dictionary_set_string(reply, "error_message", "failed to launch backend process");
					xpc_connection_send_message(peer, reply);
					xpc_release(reply);
				}
				return;
			}
			close(fds[0]);

			reply = xpc_dictionary_create_reply(event);
			if (reply)
			{
				xpc_dictionary_set_string(reply, "status", "OK");
				xpc_dictionary_set_fd(reply, "fd", fds[1]);
				xpc_connection_send_message(peer, reply);
				xpc_release(reply);
			}
			close(fds[1]);
		}
		else if (strcmp(action, "query") == 0)
		{
			const char *query = xpc_dictionary_get_string(event, "query");
			const char *database = xpc_dictionary_get_string(event, "database");
			const char *user = xpc_dictionary_get_string(event, "user");
			xpc_object_t reply = xpc_dictionary_create_reply(event);

			if (reply)
			{
				execute_xpc_query(query, database, user, reply);
				xpc_connection_send_message(peer, reply);
				xpc_release(reply);
			}
		}
		else
		{
			xpc_object_t reply = xpc_dictionary_create_reply(event);

			if (reply)
			{
				xpc_dictionary_set_string(reply, "status", "ERROR");
				xpc_dictionary_set_string(reply, "error_message", "unknown action requested");
				xpc_connection_send_message(peer, reply);
				xpc_release(reply);
			}
		}
	});

	xpc_connection_resume(peer);
}

/*
 * Initialize the macOS XPC service listener and postmaster IPC pipe.
 */
void
InitializeXPCService(void)
{
	if (!enable_xpc)
		return;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pm_xpc_pipe) != 0)
	{
		ereport(FATAL,
				(errmsg("could not create socketpair for XPC communication: %m")));
	}

	xpc_queue = dispatch_queue_create("org.postgresql.xpc.listener", DISPATCH_QUEUE_SERIAL);
	xpc_listener = xpc_connection_create(NULL, xpc_queue);

	if (!xpc_listener)
	{
		ereport(FATAL,
				(errmsg("could not create XPC service listener")));
	}

	xpc_connection_set_event_handler(xpc_listener, ^(xpc_object_t peer) {
		xpc_type_t type = xpc_get_type(peer);

		if (type == XPC_TYPE_CONNECTION)
		{
			handle_xpc_peer_connection((xpc_connection_t) peer);
		}
	});

	xpc_connection_resume(xpc_listener);

	if (xpc_service_name && xpc_service_name[0] != '\0')
	{
		xpc_endpoint_t ep = xpc_endpoint_create(xpc_listener);
		mach_port_t ep_port = (ep != NULL) ? *((mach_port_t *) ((char *) ep + 0x18)) : MACH_PORT_NULL;
		mach_port_t bp;
		kern_return_t kr;

		task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		kr = bootstrap_register(bp, xpc_service_name, ep_port);
#pragma clang diagnostic pop
		if (kr != KERN_SUCCESS)
		{
			ereport(WARNING,
					(errmsg("could not register XPC Mach service \"%s\" in bootstrap namespace: %d",
							xpc_service_name, kr)));
		}

		ereport(LOG,
				(errmsg("starting macOS XPC service \"%s\" (port=%u, kr=%d)", xpc_service_name, ep_port, kr)));
	}
	else
	{
		ereport(LOG,
				(errmsg("starting macOS XPC anonymous service")));
	}
}

/*
 * Return the postmaster-side read FD for XPC connections.
 */
pgsocket
GetXPCListenSocket(void)
{
	if (!enable_xpc || pm_xpc_pipe[0] < 0)
		return PGINVALID_SOCKET;
	return (pgsocket) pm_xpc_pipe[0];
}

/*
 * Accept an incoming connection from the XPC pipe and populate ClientSocket.
 */
int
AcceptXPCConnection(ClientSocket *client_sock)
{
	int			fd;

	client_sock->sock = PGINVALID_SOCKET;

	if (pm_xpc_pipe[0] < 0)
		return STATUS_ERROR;

	fd = recv_fd(pm_xpc_pipe[0]);
	if (fd < 0)
		return STATUS_ERROR;

	client_sock->sock = (pgsocket) fd;
	memset(&client_sock->raddr, 0, sizeof(client_sock->raddr));
	client_sock->raddr.salen = sizeof(struct sockaddr_un);
	client_sock->raddr.addr.ss_family = AF_UNIX;

	return STATUS_OK;
}

/*
 * Close XPC descriptors in forked child processes.
 */
void
CloseXPCServiceInChild(void)
{
	if (pm_xpc_pipe[0] >= 0)
	{
		close(pm_xpc_pipe[0]);
		pm_xpc_pipe[0] = -1;
	}
	if (pm_xpc_pipe[1] >= 0)
	{
		close(pm_xpc_pipe[1]);
		pm_xpc_pipe[1] = -1;
	}
}

/*
 * Shut down the XPC service in postmaster.
 */
void
CloseXPCService(void)
{
	if (xpc_service_name && xpc_service_name[0] != '\0')
	{
		mach_port_t bp;

		task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		(void) bootstrap_register(bp, xpc_service_name, MACH_PORT_NULL);
#pragma clang diagnostic pop
	}

	if (xpc_listener)
	{
		xpc_connection_cancel(xpc_listener);
		xpc_release(xpc_listener);
		xpc_listener = NULL;
	}
	if (xpc_queue)
	{
		dispatch_release(xpc_queue);
		xpc_queue = NULL;
	}
	CloseXPCServiceInChild();
}

#endif							/* USE_XPC */
