/*
 * File: auth.h
 *
 * SMTP client for Tavi network
 *
 * Authorisation type codes and table.
 *
 * Bob Eager   December 2004
 *
 */

/* Internal authorisation mechanism codes. Note that the numeric order is
   significant; if the server offers more than one mechanism that is supported
   by this client, then the lowest numbered one is chosen. */

#define	AUTH_NONE	0
#define	AUTH_LOGIN	1
#define	AUTH_PLAIN	2

/* Mechanism type table */

typedef	struct	_AUTHTYPE {
	PUCHAR	authname;		/* Authorisation mechanism name */
	INT	authcode;		/* Authorisation mechanism code */
} AUTHTYPE, *PAUTHTYPE;

static AUTHTYPE authtab[] = {
	{ "LOGIN", AUTH_LOGIN },
	{ "PLAIN", AUTH_PLAIN },
	{ "",      AUTH_NONE }			/* End of table marker */
};

/*
 * End of file: auth.h
 *
 */

