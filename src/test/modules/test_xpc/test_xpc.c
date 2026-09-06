/*-------------------------------------------------------------------------
 *
 * test_xpc.c
 *	  Unit test client for macOS XPC PostgreSQL service and libpq support.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/test/modules/test_xpc/test_xpc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include "libpq-fe.h"

static int
test_ping(const char *service_name)
{
	dispatch_queue_t queue;
	xpc_connection_t conn;
	xpc_object_t msg;
	xpc_object_t reply;
	const char *status;
	int64_t pid;
	const char *version;

	queue = dispatch_queue_create("org.postgresql.test.xpc.ping", DISPATCH_QUEUE_SERIAL);
	conn = xpc_connection_create_mach_service(service_name, queue, 0);
	if (!conn)
	{
		fprintf(stderr, "Failed to create XPC connection to %s\n", service_name);
		dispatch_release(queue);
		return 1;
	}

	xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {});
	xpc_connection_resume(conn);

	msg = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(msg, "action", "ping");

	reply = xpc_connection_send_message_with_reply_sync(conn, msg);
	xpc_release(msg);

	if (!reply || xpc_get_type(reply) == XPC_TYPE_ERROR)
	{
		const char *desc = reply ? xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION) : "null reply";

		fprintf(stderr, "XPC ping error: %s\n", desc ? desc : "unknown");
		if (reply)
			xpc_release(reply);
		xpc_connection_cancel(conn);
		xpc_release(conn);
		dispatch_release(queue);
		return 1;
	}

	status = xpc_dictionary_get_string(reply, "status");
	pid = xpc_dictionary_get_int64(reply, "postmaster_pid");
	version = xpc_dictionary_get_string(reply, "version");

	printf("STATUS: %s\n", status ? status : "null");
	printf("POSTMASTER_PID: %lld\n", (long long) pid);
	printf("VERSION: %s\n", version ? version : "null");

	xpc_release(reply);
	xpc_connection_cancel(conn);
	xpc_release(conn);
	dispatch_release(queue);

	return (status && strcmp(status, "OK") == 0) ? 0 : 1;
}

static int
test_query(const char *service_name, const char *sql_query)
{
	dispatch_queue_t queue;
	xpc_connection_t conn;
	xpc_object_t msg;
	xpc_object_t reply;
	const char *status;
	const char *tag;
	xpc_object_t cols;
	xpc_object_t rows;
	size_t ncols;
	size_t nrows;

	queue = dispatch_queue_create("org.postgresql.test.xpc.query", DISPATCH_QUEUE_SERIAL);
	conn = xpc_connection_create_mach_service(service_name, queue, 0);
	if (!conn)
	{
		fprintf(stderr, "Failed to create XPC connection to %s\n", service_name);
		dispatch_release(queue);
		return 1;
	}

	xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {});
	xpc_connection_resume(conn);

	msg = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(msg, "action", "query");
	xpc_dictionary_set_string(msg, "query", sql_query);
	xpc_dictionary_set_string(msg, "database", "postgres");

	reply = xpc_connection_send_message_with_reply_sync(conn, msg);
	xpc_release(msg);

	if (!reply || xpc_get_type(reply) == XPC_TYPE_ERROR)
	{
		const char *desc = reply ? xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION) : "null reply";

		fprintf(stderr, "XPC query error: %s\n", desc ? desc : "unknown");
		if (reply)
			xpc_release(reply);
		xpc_connection_cancel(conn);
		xpc_release(conn);
		dispatch_release(queue);
		return 1;
	}

	status = xpc_dictionary_get_string(reply, "status");
	printf("STATUS: %s\n", status ? status : "null");

	if (!status || strcmp(status, "OK") != 0)
	{
		const char *err_msg = xpc_dictionary_get_string(reply, "error_message");

		printf("ERROR_MESSAGE: %s\n", err_msg ? err_msg : "null");
		xpc_release(reply);
		xpc_connection_cancel(conn);
		xpc_release(conn);
		dispatch_release(queue);
		return 1;
	}

	tag = xpc_dictionary_get_string(reply, "command_tag");
	printf("COMMAND_TAG: %s\n", tag ? tag : "null");

	cols = xpc_dictionary_get_value(reply, "columns");
	if (cols && xpc_get_type(cols) == XPC_TYPE_ARRAY)
	{
		ncols = xpc_array_get_count(cols);
		printf("COLUMNS:");
		for (size_t i = 0; i < ncols; i++)
		{
			const char *col_name = xpc_array_get_string(cols, i);

			printf(" %s", col_name ? col_name : "(null)");
		}
		printf("\n");
	}

	rows = xpc_dictionary_get_value(reply, "rows");
	if (rows && xpc_get_type(rows) == XPC_TYPE_ARRAY)
	{
		nrows = xpc_array_get_count(rows);
		for (size_t r = 0; r < nrows; r++)
		{
			xpc_object_t row = xpc_array_get_value(rows, r);

			if (row && xpc_get_type(row) == XPC_TYPE_ARRAY)
			{
				size_t rcols = xpc_array_get_count(row);

				printf("ROW:");
				for (size_t c = 0; c < rcols; c++)
				{
					xpc_object_t val = xpc_array_get_value(row, c);

					if (xpc_get_type(val) == XPC_TYPE_NULL)
						printf(" (null)");
					else
					{
						const char *s = xpc_array_get_string(row, c);

						printf(" %s", s ? s : "(null)");
					}
				}
				printf("\n");
			}
		}
	}

	xpc_release(reply);
	xpc_connection_cancel(conn);
	xpc_release(conn);
	dispatch_release(queue);

	return 0;
}

static int
test_libpq(const char *service_name, const char *sql_query)
{
	char conninfo[512];
	PGconn *conn;
	PGresult *res;
	int nrows;
	int ncols;

	snprintf(conninfo, sizeof(conninfo), "xpc_service=%s dbname=postgres", service_name);
	conn = PQconnectdb(conninfo);

	if (PQstatus(conn) != CONNECTION_OK)
	{
		fprintf(stderr, "libpq connection failed: %s\n", PQerrorMessage(conn));
		PQfinish(conn);
		return 1;
	}

	printf("LIBPQ_STATUS: OK\n");
	printf("LIBPQ_XPC_SERVICE: %s\n", PQxpcService(conn) ? PQxpcService(conn) : "null");

	res = PQexec(conn, sql_query);
	if (!res)
	{
		fprintf(stderr, "libpq query failed: %s\n", PQerrorMessage(conn));
		PQfinish(conn);
		return 1;
	}

	printf("LIBPQ_RESULT_STATUS: %s\n", PQresStatus(PQresultStatus(res)));
	printf("LIBPQ_COMMAND_TAG: %s\n", PQcmdStatus(res));

	ncols = PQnfields(res);
	nrows = PQntuples(res);

	printf("LIBPQ_COLUMNS:");
	for (int i = 0; i < ncols; i++)
		printf(" %s", PQfname(res, i));
	printf("\n");

	for (int r = 0; r < nrows; r++)
	{
		printf("LIBPQ_ROW:");
		for (int c = 0; c < ncols; c++)
		{
			if (PQgetisnull(res, r, c))
				printf(" (null)");
			else
				printf(" %s", PQgetvalue(res, r, c));
		}
		printf("\n");
	}

	PQclear(res);
	PQfinish(conn);
	return 0;
}

int
main(int argc, char *argv[])
{
	const char *mode;
	const char *service;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <ping|query|libpq> <service_name> [query_string]\n", argv[0]);
		return 1;
	}

	mode = argv[1];
	service = argv[2];

	if (strcmp(mode, "ping") == 0)
		return test_ping(service);
	else if (strcmp(mode, "query") == 0)
	{
		const char *query = (argc >= 4) ? argv[3] : "SELECT 1;";

		return test_query(service, query);
	}
	else if (strcmp(mode, "libpq") == 0)
	{
		const char *query = (argc >= 4) ? argv[3] : "SELECT 1;";

		return test_libpq(service, query);
	}
	else
	{
		fprintf(stderr, "Unknown mode: %s\n", mode);
		return 1;
	}
}
