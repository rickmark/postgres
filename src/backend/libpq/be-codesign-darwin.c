/*-------------------------------------------------------------------------
 *
 * be-codesign-darwin.c
 *	  macOS code-signature validation for peers of Unix-domain connections.
 *
 * This file must not include postgres.h, and nothing here may be called from
 * the postmaster before it forks a backend; see be-codesign.h and the notes
 * on pg_codesign_verify_peer() below for the reasons.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/libpq/be-codesign-darwin.c
 *
 *-------------------------------------------------------------------------
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/audit.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "libpq/be-codesign.h"


/*
 * Copy a CFString into a fixed-size C buffer as UTF-8.
 *
 * Returns true on success.  Returns false if s is NULL or does not fit, so
 * that an over-long identity is reported as an error rather than silently
 * truncated into something that might match a user map it shouldn't.
 */
static bool
cfstring_to_buf(CFStringRef s, char *buf, size_t buflen)
{
	if (s == NULL || CFGetTypeID(s) != CFStringGetTypeID())
		return false;

	if (!CFStringGetCString(s, buf, (CFIndex) buflen, kCFStringEncodingUTF8))
		return false;

	return true;
}

/*
 * Write a description of an OSStatus failure into errbuf.
 *
 * "err", if not NULL, is a CFError from one of the *WithErrors() variants; its
 * description is usually much more specific than the OSStatus alone (for
 * example naming the clause of a requirement that failed), so prefer it.
 */
static void
report_osstatus(char *errbuf, size_t errlen, const char *context,
				OSStatus status, CFErrorRef err)
{
	char		detail[PG_CODESIGN_ERR_MAXLEN];
	CFStringRef msg = NULL;

	detail[0] = '\0';

	if (err != NULL)
		msg = CFErrorCopyDescription(err);
	if (msg == NULL)
		msg = SecCopyErrorMessageString(status, NULL);

	if (msg != NULL)
	{
		if (!cfstring_to_buf(msg, detail, sizeof(detail)))
			detail[0] = '\0';
		CFRelease(msg);
	}

	if (detail[0] != '\0')
		snprintf(errbuf, errlen, "%s: %s (OSStatus %d)",
				 context, detail, (int) status);
	else
		snprintf(errbuf, errlen, "%s: OSStatus %d", context, (int) status);
}

/*
 * Compile a requirement string, reporting failures into errbuf.
 *
 * Returns NULL on failure, otherwise a requirement the caller must release.
 */
static SecRequirementRef
compile_requirement(const char *reqtext, char *errbuf, size_t errlen)
{
	CFStringRef reqstr;
	SecRequirementRef req = NULL;
	CFErrorRef	err = NULL;
	OSStatus	status;

	reqstr = CFStringCreateWithCString(NULL, reqtext, kCFStringEncodingUTF8);
	if (reqstr == NULL)
	{
		snprintf(errbuf, errlen,
				 "code signing requirement is not valid UTF-8");
		return NULL;
	}

	status = SecRequirementCreateWithStringAndErrors(reqstr,
													kSecCSDefaultFlags,
													&err, &req);
	CFRelease(reqstr);

	if (status != errSecSuccess)
	{
		report_osstatus(errbuf, errlen,
						"could not parse code signing requirement",
						status, err);
		if (err != NULL)
			CFRelease(err);
		return NULL;
	}

	if (err != NULL)
		CFRelease(err);

	return req;
}

/*
 * Check that "reqtext" is a syntactically valid code signing requirement.
 *
 * This only compiles the requirement, which is done entirely in-process by
 * libsecurity; it establishes no XPC connection and so is safe to call before
 * the postmaster forks.
 */
int
pg_codesign_check_requirement(const char *reqtext, char *errbuf, size_t errlen)
{
	SecRequirementRef req;

	req = compile_requirement(reqtext, errbuf, errlen);
	if (req == NULL)
		return -1;

	CFRelease(req);
	return 0;
}

/*
 * Validate the code signature of sock's peer against "reqtext".
 *
 * The peer is identified by its audit token rather than its pid: a pid can be
 * recycled between the time the kernel reports it and the time we ask the
 * system about it, which would let an untrusted process inherit a trusted
 * process's verdict.  An audit token names one specific process for the
 * lifetime of that process, so no such race exists.
 *
 * Must be called from a backend, never from the postmaster: obtaining a
 * SecCodeRef and checking its validity talk to system daemons over XPC, which
 * is not supported in a process that has forked without exec'ing if the
 * connection was established before the fork.
 */
int
pg_codesign_verify_peer(int sock, const char *reqtext,
						pg_codesign_peer *peer, char *errbuf, size_t errlen)
{
	audit_token_t token;
	socklen_t	toklen = sizeof(token);
	CFDataRef	tokdata;
	CFDictionaryRef attrs;
	const void *key = kSecGuestAttributeAudit;
	const void *value;
	SecCodeRef	code = NULL;
	SecRequirementRef req;
	CFDictionaryRef info = NULL;
	CFErrorRef	err = NULL;
	OSStatus	status;
	int			result = -1;

	/*
	 * Compile the requirement before touching the peer, so that a
	 * misconfigured requirement is reported as such.
	 */
	req = compile_requirement(reqtext, errbuf, errlen);
	if (req == NULL)
		return -1;

	if (getsockopt(sock, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &toklen) != 0)
	{
		snprintf(errbuf, errlen,
				 "could not get peer audit token: %s", strerror(errno));
		CFRelease(req);
		return -1;
	}
	if (toklen != sizeof(token))
	{
		snprintf(errbuf, errlen,
				 "peer audit token has unexpected length %d",
				 (int) toklen);
		CFRelease(req);
		return -1;
	}

	tokdata = CFDataCreate(NULL, (const UInt8 *) &token, sizeof(token));
	if (tokdata == NULL)
	{
		snprintf(errbuf, errlen, "out of memory");
		CFRelease(req);
		return -1;
	}
	value = tokdata;

	attrs = CFDictionaryCreate(NULL, &key, &value, 1,
							   &kCFTypeDictionaryKeyCallBacks,
							   &kCFTypeDictionaryValueCallBacks);
	if (attrs == NULL)
	{
		snprintf(errbuf, errlen, "out of memory");
		CFRelease(tokdata);
		CFRelease(req);
		return -1;
	}

	status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags,
											&code);
	if (status != errSecSuccess)
	{
		report_osstatus(errbuf, errlen, "could not identify peer code",
						status, NULL);
		goto done;
	}

	/*
	 * Check the signature before reading any of the peer's identity, so that
	 * we never report an identity we have not validated.
	 *
	 * kSecCSDefaultFlags deliberately does not include
	 * kSecCSEnforceRevocationChecks: that would perform an online revocation
	 * check, putting a network round trip, and a possible hang, in the middle
	 * of authenticating a connection.
	 */
	status = SecCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, req,
											&err);
	if (status != errSecSuccess)
	{
		report_osstatus(errbuf, errlen,
						"peer does not satisfy code signing requirement",
						status, err);
		goto done;
	}

	status = SecCodeCopySigningInformation((SecStaticCodeRef) code,
										   kSecCSSigningInformation, &info);
	if (status != errSecSuccess)
	{
		report_osstatus(errbuf, errlen,
						"could not read peer code signing information",
						status, NULL);
		goto done;
	}

	memset(peer, 0, sizeof(*peer));

	if (!cfstring_to_buf(CFDictionaryGetValue(info, kSecCodeInfoIdentifier),
						 peer->identifier, sizeof(peer->identifier)))
	{
		snprintf(errbuf, errlen,
				 "peer has a missing or over-long code signing identifier");
		goto done;
	}

	/*
	 * A team identifier is absent for Apple platform binaries and for ad-hoc
	 * signed code; that is not an error here.  Callers decide whether an
	 * identity can be formed without one.
	 */
	if (CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier) != NULL &&
		!cfstring_to_buf(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier),
						 peer->teamid, sizeof(peer->teamid)))
	{
		snprintf(errbuf, errlen, "peer has an over-long team identifier");
		goto done;
	}

	result = 0;

done:
	if (info != NULL)
		CFRelease(info);
	if (err != NULL)
		CFRelease(err);
	if (code != NULL)
		CFRelease(code);
	CFRelease(attrs);
	CFRelease(tokdata);
	CFRelease(req);

	return result;
}
