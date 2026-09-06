/*-------------------------------------------------------------------------
 *
 * be-codesign.h
 *	  Interface to platform code-signature validation for peers of
 *	  Unix-domain socket connections.
 *
 * The implementation (currently only be-codesign-darwin.c) has to include
 * platform headers that are not compatible with postgres.h: Apple's
 * <MacTypes.h>, reached via <Security/Security.h>, defines "Size" as "long",
 * while c.h defines it as "size_t".  This header therefore deliberately
 * exposes a plain C interface using only standard types, so that it can be
 * included both by the platform-specific implementation, which must not
 * include postgres.h, and by its callers, which must.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/libpq/be-codesign.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef BE_CODESIGN_H
#define BE_CODESIGN_H

#include <stddef.h>

/*
 * Maximum length, including the terminating NUL, of the individual components
 * of a peer's code signing identity.  Signing identifiers are conventionally
 * reverse-DNS names and team identifiers are ten characters, so this is
 * generous; longer values are rejected rather than silently truncated.
 */
#define PG_CODESIGN_ID_MAXLEN	256

/* Maximum length, including the terminating NUL, of an error message */
#define PG_CODESIGN_ERR_MAXLEN	256

/*
 * A peer's validated code signing identity.
 */
typedef struct pg_codesign_peer
{
	/* Signing identifier, e.g. "com.example.app".  Never empty on success. */
	char		identifier[PG_CODESIGN_ID_MAXLEN];

	/*
	 * Team identifier, e.g. "ABCDE12345".  Empty if the peer has none, which
	 * is the case for Apple platform binaries and ad-hoc signed code.
	 */
	char		teamid[PG_CODESIGN_ID_MAXLEN];
} pg_codesign_peer;

/*
 * Check that "reqtext" is a syntactically valid code signing requirement,
 * without evaluating it against anything.
 *
 * Returns 0 on success.  On failure, returns -1 and writes a message
 * describing the problem into errbuf, which must be at least errlen bytes.
 */
extern int	pg_codesign_check_requirement(const char *reqtext,
										  char *errbuf, size_t errlen);

/*
 * Validate the code signature of the process on the far end of "sock", which
 * must be a connected Unix-domain socket, against the code signing
 * requirement "reqtext".
 *
 * On success, returns 0 and stores the peer's signing identity in *peer.  On
 * failure, returns -1 and writes a message describing the problem into
 * errbuf, which must be at least errlen bytes; *peer is then undefined.
 */
extern int	pg_codesign_verify_peer(int sock, const char *reqtext,
									pg_codesign_peer *peer,
									char *errbuf, size_t errlen);

#endif							/* BE_CODESIGN_H */
