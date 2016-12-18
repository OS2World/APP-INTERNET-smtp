/*
 * File: client.c
 *
 * SMTP client for Tavi network
 *
 * Protocol handler for client
 *
 * Bob Eager   December 2004
 *
 */

#pragma	strings(readonly)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <io.h>

#define	INCL_DOSERRORS
#define	INCL_DOSFILEMGR
#include <os2.h>

#include "smtp.h"
#include "netio.h"
#include "auth.h"

#define	RBUFSIZE	1000		/* Size of read buffer */
#define	WBUFSIZE	1000		/* Size of write buffer */
#define	RTIMEOUT	30		/* Read timeout (secs) */
#define	WTIMEOUT	30		/* Write timeout (secs) */

#define	MAXLINE		2002		/* Maximum length of line */
#define	MAXMES		100		/* Maximum message length */
#define	MAXAUTH		10		/* Maximum number of auth types */

/* Type definitions */

typedef	enum	{ ST_MAIL, ST_RCPT, ST_RCPT_OR_DATA, ST_DATA,
		  ST_DATASTART, ST_TEXT }
	STATE;

/* Forward references */

static	PUCHAR	cmdname(STATE);
static	BOOL	directory_not_empty(PUCHAR);
static	BOOL	do_auth_login(INT, PUCHAR, PUCHAR);
static	BOOL	do_auth_plain(INT, PUCHAR, PUCHAR);
static	BOOL	do_etrn(INT, PUCHAR, BOOL);
static	PUCHAR	enbase64(PUCHAR, INT, PUCHAR);
static	BOOL	get_reply(INT, PUCHAR);
static	BOOL	process_directory(INT, PUCHAR, BOOL);
static	BOOL	process_extensions(INT);
static	VOID	process_extension_auth(PUCHAR);
static	BOOL	process_file(INT, PUCHAR, BOOL);

/* Local storage */

static	INT	authmech;		/* Auth mechanism chosen for use */
static	INT	authsupp;		/* Bitmap of supported auth types */
static	BOOL	extensions;		/* True if EHLO accepted */
static	INT	msgcount;
static	UCHAR	rbuf[RBUFSIZE+1];
static	UCHAR	wbuf[WBUFSIZE+1];

/*
 * Do the conversation between the client and the server.
 *
 * Returns:
 *	TRUE		client ran and terminated
 *	FALSE		client failed
 *
 */

BOOL client(INT sockno, PFL filelist, PUCHAR clientname, BOOL verbose,
		PUCHAR username, PUCHAR password, PUCHAR domain)
{	BOOL rc;
	BOOL etrn_rc;
	PFL temp;

	extensions = FALSE;
	authmech = AUTH_NONE;		/* No authorisation by default */

	if(netio_init() == FALSE) {
		error("network initialisation failure");
		return(FALSE);
	}

	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);

	msgcount = 0;

	/* Handle the reply to the connect; first, absorb all but the
	   last line of any multiline reply */

	while(rbuf[3] == '-') {
		rc = get_reply(sockno, rbuf);
		if(rc == FALSE) return(FALSE);
	}

	if(rbuf[0] != '2') {		/* Some kind of failure */
		error("connect failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}

	/* Try EHLO to open conversation */

	sprintf(wbuf, "EHLO %s\n", clientname);
#ifdef	DEBUG
	trace(wbuf);
#endif
	sock_puts(wbuf, sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);

	/* Handle the reply to EHLO.
	   250 => EHLO recognised and implemented, so process reply
	   500 => EHLO not recognised, so try HELO
	   502 => EHLO recognised but not implemented, so try HELO
	*/

	rc = (rbuf[0] - '0')*100 + (rbuf[1] - '0')*10 + (rbuf[2] - '0');

	switch(rc) {
		case 500:
		case 502:		/* OK, try HELO */
			sprintf(wbuf, "HELO %s\n", clientname);
#ifdef	DEBUG
			trace(wbuf);
#endif
			sock_puts(wbuf, sockno, WTIMEOUT);
			rc = get_reply(sockno, rbuf);
			if(rc == FALSE) return(FALSE);
			if(rbuf[0] != '2') {	/* Some kind of failure */
				error("HELO failed: %s", rbuf);
				dolog(LOG_ERR, rbuf);
				return(FALSE);
			}
			break;

		case 250:
			if(rbuf[3] != '-') break;	/* No extensions */
			extensions = TRUE;
			if(process_extensions(sockno) == FALSE)
				return(FALSE);
			break;

		default:
			error("EHLO failed: %s", rbuf);
			dolog(LOG_ERR, rbuf);
			return(FALSE);
	}

	/* We are now talking to the server. See if authorisation is needed. */

	if(username[0] == '\0') authmech = AUTH_NONE;

	switch(authmech) {
		case AUTH_NONE:
			break;

		case AUTH_LOGIN:
			rc = do_auth_login(sockno, username, password);
			if(rc == FALSE) return(FALSE);
			break;

		case AUTH_PLAIN:
			rc = do_auth_plain(sockno, username, password);
			if(rc == FALSE) return(FALSE);
			break;

		default:
			error("internal error (bad authmech");
			return(FALSE);
	}

	if(domain[0] != '\0') {
		etrn_rc = do_etrn(sockno, domain, verbose);
	} else {
		while(filelist != (PFL) NULL) {
			if(filelist->isdir == TRUE) {
				process_directory(
					sockno, filelist->name, verbose);
			} else {
				process_file(
					sockno, filelist->name, verbose);
			}
			temp = filelist->next;
			free(filelist);
			filelist = temp;
		}

		if(verbose == TRUE) {
			fprintf(
				stdout,
				"%50s\r%d message%s transmitted\n",
				"",
				msgcount,
				msgcount == 1 ? "" : "s");
			fflush(stdout);
		}
	}

	/* Send QUIT to close the conversation */

#ifdef	DEBUG
	trace("QUIT");
#endif
	sock_puts("QUIT\n", sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);

	/* Handle the reply to QUIT */

	if(rbuf[0] != '2') {		/* Some kind of failure */
		error("QUIT failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}
	dolog(LOG_INFO, rbuf);

	if(domain[0] == '\0') {		/* Not ETRN case */
		sprintf(
			rbuf,
			"[%d message%s sent]",
			msgcount,
			msgcount == 1 ? "" : "s");
		dolog(LOG_INFO, rbuf);
	} else {
		if(etrn_rc == TRUE) {
			sprintf(
				rbuf,
				"[ETRN sent for %s]",
				domain);
			dolog(LOG_INFO, rbuf);
		}
	}

	return(TRUE);
}


/*
 * Process SMTP extensions, ignoring ones we do not support.
 * The extension lines start with 250, with '-' in the fourth column
 * for all but the last line.
 *
 */

static BOOL process_extensions(INT sockno)
{	BOOL rc;
	BOOL going = TRUE;
	PUCHAR p;

	while(going) {
		rc = get_reply(sockno, rbuf);
		if(rc == FALSE) return(FALSE);

		/* Valid responses are a 250 reply code, with a 250-
		   indicating more to come. */

		if(strnicmp(rbuf, "250", 3) != 0) return(FALSE);
		if(rbuf[3] != '-') going = FALSE;	/* Last one */

		p = &rbuf[4];
		while((*p == ' ') || (*p == '\t')) p++;

		if(strnicmp(p, "AUTH", 4) == 0) {
			process_extension_auth(p);
			if(authmech == -1) {
				p[strlen(p)-1] = '\0';/* Lose newline */
				p += 4;	/* Lose leading AUTH */
				error("authorisation mechanisms not supported");
				error("server said it supports: %s", p);
				return(FALSE);
			}
		}

		/* Ignore other extensions */
	}

	return(TRUE);
}


/*
 * Process the AUTH extension. Read and store the possible authorisation
 * mechanisms that the server specifies and that we support. Then choose
 * a mechanism; the lowest numbered one is the preferred one.
 *
 */

static VOID process_extension_auth(PUCHAR s)
{	PUCHAR item;
	PAUTHTYPE q;
	INT code;
	UCHAR buf[RBUFSIZE+1];

	strcpy(buf, s);			/* Work on copy */
	authsupp = 0;			/* Clear bitmap */

	buf[strlen(buf)-1] = '\0';	/* Lose newline at end */
	(VOID) strtok(buf, " \t");	/* Prime strtok and lose AUTH part */

	for(;;) {	/* Loop to handle one mechanism spec per iteration */
		item = strtok((PUCHAR) NULL, " \t");
			/* Get mechanism name from server */
		if(item == (PUCHAR) NULL) break;	/* No more */

#ifdef	DEBUG
		trace("Mechanism %s named by server", item);
#endif
		q = &authtab[0];
		for(;;) {	/* Loop to try and match mechanism name */
			if(strlen(q->authname) == 0) {
				code = -1;	/* Not found */
				break;
			}
			if(stricmp(item, q->authname) == 0) {
				code = q->authcode;
					/* Get our internal code for it */
				break;
			}
			q++;		/* Move to next table entry */
		}
		if(code != -1) {	/* If code was valid */
#ifdef	DEBUG
			trace("Code %d supported", code);
#endif
			authsupp = authsupp | (1 << code);
		}
	}
#ifdef	DEBUG
	trace("Auth bitmap = %08x", authsupp);
#endif

	code = 0;
	while(authsupp != 0) {
		if((authsupp & 1) != 0) {
			authmech = code;
			break;
		}
		code++;
		authsupp = authsupp >> 1;
	}
#ifdef	DEBUG
	trace("Auth mechanism chosen = %d", authmech);
#endif
}


/*
 * Perform LOGIN style authorisation.
 *
 */

static BOOL do_auth_login(INT sockno, PUCHAR username, PUCHAR password)
{	INT rc;
	UCHAR temp[WBUFSIZE];

	strcpy(wbuf, "AUTH LOGIN\n");
#ifdef	DEBUG
	trace(wbuf);
#endif
	sock_puts(wbuf, sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);
	if((rbuf[0] != '3') && (rbuf[1] != '3') && (rbuf[2] != '4')) {
			/* Unexpected response */
		error("AUTH LOGIN failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}

	sprintf(wbuf, "%s\n", enbase64(username, strlen(username), temp));
#ifdef	DEBUG
	trace(wbuf);
#endif
	sock_puts(wbuf, sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);
	if((rbuf[0] != '3') && (rbuf[1] != '3') && (rbuf[2] != '4')) {
			/* Unexpected response */
		error("AUTH LOGIN response 1 failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}

	sprintf(wbuf, "%s\n", enbase64(password, strlen(password), temp));
#ifdef	DEBUG
	trace(wbuf);
#endif
	sock_puts(wbuf, sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);
	if((rbuf[0] != '2') && (rbuf[1] != '3') && (rbuf[2] != '5')) {
			/* Unexpected response */
		error("AUTH LOGIN response 2 failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}

	return(TRUE);
}


/*
 * Perform PLAIN style authorisation.
 *
 */

static BOOL do_auth_plain(INT sockno, PUCHAR username, PUCHAR password)
{	INT rc, authlen;
	UCHAR temp[WBUFSIZE];
	UCHAR authstr[WBUFSIZE];
	PUCHAR p = &authstr[0];

	*p++ = '\0';			/* No authentication name */
	strcpy(p, username);
	p += strlen(username);		/* To null terminator */
	p++;				/* Beyond null terminator */
	strcpy(p, password);
	p += strlen(password);		/* To null terminator */
	p++;				/* Beyond null terminator */
	authlen = p - &authstr[0];

	sprintf(wbuf, "AUTH PLAIN %s\n", enbase64(authstr, authlen, temp));
#ifdef	DEBUG
	trace(wbuf);
#endif
	sock_puts(wbuf, sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);
	if((rbuf[0] != '2') && (rbuf[1] != '3') && (rbuf[2] != '5')) {
			/* Unexpected response */
		error("AUTH PLAIN failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}

	return(TRUE);
}


/*
 * Process a single directory. Iterate over the files in the directory,
 * passing them down to 'process_file'.
 *
 * Returns:
 *	TRUE		directory processed OK
 *	FALSE		failed
 *
 */

static BOOL process_directory(INT sockno, PUCHAR dirname, BOOL verbose)
{	APIRET rc;
	HDIR hdir = HDIR_CREATE;
	ULONG count;
	FILEFINDBUF3 entry;
	UCHAR fullname[CCHMAXPATH+1];
	UCHAR mask[CCHMAXPATH+3];

#ifdef	DEBUG
	trace("process_dir : %s\n", dirname);
#endif

	strcpy(mask, dirname);
	strcat(mask, "\\*");		/* Form search mask */

	count = 1;
	rc = DosFindFirst(
		mask,
		&hdir,
		FILE_NORMAL,
		&entry,
		sizeof(entry),
		&count,
		FIL_STANDARD);
	if(rc == ERROR_NO_MORE_FILES) return(TRUE);
	if(rc == ERROR_PATH_NOT_FOUND) {
		error("directory '%s' does not exist", dirname);
		return(FALSE);
	}
	if(rc != NO_ERROR) {
		error("DosFindFirst failed, rc = %d", rc);
		return(FALSE);
	}

	while(count != 0) {
		strcpy(fullname, dirname);
		strcat(fullname, "\\");
		strcat(fullname, entry.achName);
		(VOID) process_file(sockno, fullname, verbose);

		count = 1;
		rc = DosFindNext(
			hdir,
			&entry,
			sizeof(entry),
			&count);

		if(rc == ERROR_NO_MORE_FILES) break;
		if(rc != NO_ERROR) {
			error("DosFindNext failed, rc = %d", rc);
			return(FALSE);
		}
	}

	(VOID) DosFindClose(hdir);

	return(TRUE);
}


/*
 * Process a single file.
 *
 * Returns:
 *	TRUE		file processed OK
 *	FALSE		failed
 *
 */

static BOOL process_file(INT sockno, PUCHAR name, BOOL verbose)
{	FILE *fp;
	UCHAR mes[MAXMES+1];
	STATE state = ST_MAIL;
	UCHAR buf[MAXLINE+1];
	INT file_error = FALSE;
	INT line = 0;
	BOOL rc;

#ifdef	DEBUG
	trace("process_file : %s\n", name);
#endif

	fp = fopen(name, "r");
	if(fp == (FILE *) NULL) {
		sprintf(mes, "cannot open mail file %s", name);
		error(mes);
		dolog(LOG_ERR, mes);
		return(FALSE);
	}

	if(verbose == TRUE) {
		fprintf(stdout, "Transmitting message %d\r", msgcount + 1);
		fflush(stdout);
	}

	while(fgets(buf, MAXLINE, fp) != (PUCHAR) NULL) {
		line++;
		if(buf[strlen(buf)-1] != '\n') {
			sprintf(mes, "line %d too long in mail file %s",
				line, name);
			error(mes);
			dolog(LOG_WARNING, mes);
			file_error = TRUE;
			break;
		}

		switch(state) {
			case ST_MAIL:		/* Expecting MAIL command */
				if(strnicmp(buf, "MAIL", 4) != 0) {
					sprintf(
						mes,
						"MAIL line error in mail file"
						" %s",
						name);
					error(mes);
					dolog(LOG_ERR, mes);
					file_error = TRUE;
				} else state = ST_RCPT;
				break;

			case ST_RCPT:
				if(strnicmp(buf, "RCPT", 4) != 0) {
					sprintf(
						mes,
						"RCPT line error in mail file"
						" %s",
						name);
					error(mes);
					dolog(LOG_ERR, mes);
					file_error = TRUE;
				} else state = ST_RCPT_OR_DATA;
				break;

			case ST_RCPT_OR_DATA:
				if(strnicmp(buf, "RCPT", 4) == 0) break;
				state = ST_DATA;
				/* drop through */

			case ST_DATA:
				if(strnicmp(buf, "DATA", 4) != 0) {
					sprintf(
						mes,
						"DATA line error in mail file"
						" %s",
						name);
					error(mes);
					dolog(LOG_ERR, mes);
					file_error = TRUE;
				} else state = ST_DATASTART;
				break;

			case ST_DATASTART:
				state = ST_TEXT;
				/* drop through */

			case ST_TEXT:		/* Just pass text through, but
						   dot-stuff if necessary */
				break;
		}
		if(file_error == TRUE) break;

		/* A valid line has been read from the mail file, in context.
		   Send it to the server. */

#ifdef	DEBUG
		trace(buf);
#endif
		if(state == ST_TEXT && buf[0] == '.') {	/* Dot-stuff */
			memmove(&buf[1], &buf[0], strlen(buf)+1);
			buf[0] = '.';
		}
		sock_puts(buf, sockno, WTIMEOUT);
		if(state == ST_TEXT) continue;	/* No response expected */
		rc = get_reply(sockno, rbuf);
		if(rc == FALSE) return(FALSE);
		if(rbuf[0] != '2' && rbuf[0] != '3') {	/* Some kind of failure */
			error("%s failed: %s", cmdname(state), rbuf);
			dolog(LOG_ERR, rbuf);
			return(FALSE);
		}
	}

	if(!feof(fp)) {			/* Not end of file, but read error */
		if(file_error == FALSE) {
			sprintf(mes, "read error on mail file %s", name);
			error(mes);
			dolog(LOG_ERR, mes);
		}
		(VOID) fclose(fp);
	} else {
		strcpy(buf, ".\n");
#ifdef	DEBUG
		trace(buf);
#endif
		sock_puts(buf, sockno, WTIMEOUT);
		rc = get_reply(sockno, rbuf);
		if(rc == FALSE) return(FALSE);
		if(rbuf[0] != '2') {		/* Some kind of failure */
			error("text terminate failed: %s", rbuf);
			dolog(LOG_ERR, rbuf);
			return(FALSE);
		}
		(VOID) fclose(fp);
		remove(name);
	}

	msgcount++;
	return(TRUE);
}


/*
 * See if there is anything to send.
 *
 * Returns TRUE if there is at least one message; otherwise returns FALSE.
 *
 */

BOOL something(PFL filelist)
{	while(filelist != (PFL) NULL) {
		if(filelist->isdir == TRUE) {
			if(directory_not_empty(filelist->name) == TRUE)
				return(TRUE);
		} else {
			if(access(filelist->name, 0) == 0) return(TRUE);
		}
		filelist = filelist->next;
	}

	return(FALSE);
}


/*
 * See if a directory has at least one file in it.
 *
 * Returns TRUE if directory is not empty, otherwise returns FALSE.
 *
 */

static BOOL directory_not_empty(PUCHAR dirname)
{	APIRET rc;
	HDIR hdir = HDIR_CREATE;
	ULONG count;
	FILEFINDBUF3 entry;
	UCHAR mask[CCHMAXPATH+3];

	strcpy(mask, dirname);
	strcat(mask, "\\*");		/* Form search mask */

	count = 1;
	rc = DosFindFirst(
		mask,
		&hdir,
		FILE_NORMAL,
		&entry,
		sizeof(entry),
		&count,
		FIL_STANDARD);

	(VOID) DosFindClose(hdir);

	return(rc == NO_ERROR ? TRUE : FALSE);
}


/*
 * Send an ETRN for a domain.
 *
 * Returns:
 *	TRUE if sent OK.
 *	FALSE if not sent OK.
 *
 */

static BOOL do_etrn(INT sockno, PUCHAR domain, BOOL verbose)
{	BOOL rc;

	sprintf(wbuf, "ETRN %s\n", domain);
#ifdef	DEBUG
	trace(wbuf);
#endif
	sock_puts(wbuf, sockno, WTIMEOUT);
	rc = get_reply(sockno, rbuf);
	if(rc == FALSE) return(FALSE);
	if(rbuf[0] != '2' && rbuf[0] != '3') {	/* Some kind of failure */
		error("ETRN failed: %s", rbuf);
		dolog(LOG_ERR, rbuf);
		return(FALSE);
	}

	if(verbose == TRUE) {
		fprintf(stdout, "ETRN sent for %s\n", domain);
	}

	return(TRUE);
}


/*
 * Read a reply from the server.
 *
 * Returns:
 *	TRUE if reply read OK.
 *	FALSE if network read error.
 *
 */

static BOOL get_reply(INT sockno, PUCHAR buf)
{	INT rc;

	rc = sock_gets(buf, RBUFSIZE, sockno, RTIMEOUT);
	if(rc < 0) {
		if(rc == SOCKIO_ERR) {
			error("network read error");
			return(FALSE);
		}
		if(rc == SOCKIO_TIMEOUT) {
			error("network read timeout");
			return(FALSE);
		}
		if(rc == SOCKIO_TOOLONG) {
			error("network input line too long");
			return(FALSE);
		}
	}
#ifdef	DEBUG
	trace("%s", buf);
#endif
	return(TRUE);
}


/*
 * Return the command name corresponding to a particular state.
 *
 */

static PUCHAR cmdname(STATE state)
{	switch(state) {
		case ST_MAIL:		return("MAIL command");
		case ST_RCPT:
		case ST_RCPT_OR_DATA:	return("RCPT command");
		case ST_DATASTART:
		case ST_TEXT:		return("mail text send");

		default:		return("????");
	}
}

/*
 * Notes on BASE64 encoding
 * ------------------------
 *
 * Strings are encoded as follows.
 * The input string is split into triples, each 24 bits in size (3 octets);
 * The earliest octet is stored as the most significant one.
 * To encode the triple, the 24 bit value is taken as four 6 bit values,
 * starting again at the most significant end. Each 6 bit value is encoded
 * by using an array of encoding characters, and simply indexing that.
 * Any terminating, incomplete triple is encoded with enough characters
 * to describe all of the actual characters in the partial triple.
 * The output string is always padded to a multiple of four characters using
 * the '=' character.
 *
 */

static	const	UCHAR charset[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode a string in BASE64. Note that the string to be encoded is NOT
 * null terminated, since it may contain nulls; the length is passed
 * explicitly.
 *
 * For convenience, returns a pointer to the converted string.
 *
 */

static PUCHAR enbase64(PUCHAR in, INT size, PUCHAR out)
{	PUCHAR op = out;
	INT triple = 0;
	INT noctets = 0;
	INT i, j;

	for(i = 0; i < size; i++) {
		triple = (triple << 8) | in[i];
		noctets++;
		if(noctets == 3) {
			for(j = 3; j >= 0; j--)
				*op++ = charset[(triple >> (j*6)) & 0x3f];
			triple = noctets = 0;
		}
	}
	if(noctets == 1) {
		*op++ = charset[triple >> 2];
		*op++ = charset[(triple << 4) & 0x3f];
		*op++ = '=';
		*op++ = '=';
	} else {
		if(noctets == 2) {
			*op++ = charset[triple >> 10];
			*op++ = charset[(triple >> 4) & 0x3f];
			*op++ = charset[(triple << 2) & 0x3f];
			*op++ = '=';
		}
	}
	*op++ = '\0';

	return(out);
}

/*
 * End of file: client.c
 *
 */
