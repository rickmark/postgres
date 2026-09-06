/*-------------------------------------------------------------------------
 *
 * xpc_postmaster.h
 *	  macOS XPC service support for postmaster.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * src/include/postmaster/xpc_postmaster.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef XPC_POSTMASTER_H
#define XPC_POSTMASTER_H

#include "libpq/libpq-be.h"
#include "libpq/pqcomm.h"

#ifdef USE_XPC

extern void InitializeXPCService(void);
extern pgsocket GetXPCListenSocket(void);
extern int AcceptXPCConnection(ClientSocket *client_sock);
extern void CloseXPCServiceInChild(void);
extern void CloseXPCService(void);

#else

static inline void InitializeXPCService(void) {}
static inline pgsocket GetXPCListenSocket(void) { return PGINVALID_SOCKET; }
static inline int AcceptXPCConnection(ClientSocket *client_sock) { return -1; }
static inline void CloseXPCServiceInChild(void) {}
static inline void CloseXPCService(void) {}

#endif /* USE_XPC */

#endif /* XPC_POSTMASTER_H */
