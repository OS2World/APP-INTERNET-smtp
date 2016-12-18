/*
 * File: netio.c
 *
 * General network I/O and timeout routines.
 *
 * Bob Eager   December 2004
 *
 */

#pragma	strings(readonly)

#pragma	alloc_text(a_init_seg, netio_init)

#define	OS2
#include <os2.h>

#include <stdlib.h>
#include <string.h>
#include <types.h>
#include <sys\socket.h>
#include <nerrno.h>

#include "netio.h"

#define	BUFSIZE		1024		/* Size of network input buffer */

/* Forward references */

static	INT	fill_buffer(INT, INT);
static	INT	sock_send(INT, PUCHAR, INT, INT);

/* Local storage */

static	INT	count;			/* Bytes remaining in input buffer */
static	INT	next;			/* Offset of next byte in input buffer */
static	UCHAR	buf[BUFSIZE];		/* Network input buffer */


/*
 * Initialise buffering, etc.
 * Returns:
 *	TRUE		success
 *	FALSE		failure
 *
 */

BOOL netio_init(VOID)
{	/* Initialise count of bytes in network input buffer */

	count = 0;

	return(TRUE);
}


/*
 * Get a line from a socket. Carriage return, linefeed sequence is replaced
 * by a linefeed.
 *
 * Returns:
 *	>= 0			length of line read
 *	SOCKIO_TOOLONG		line too long for buffer; rest of line absorbed
 *	SOCKIO_TIMEOUT		input timed out
 *	SOCKIO_ERR		nonspecific network read error
 *
 */

INT sock_gets(PUCHAR line, INT size, INT sockno, INT timeout)
{	INT len = 0;
	UCHAR c;
	BOOL full = FALSE;

	for(;;) {
		if(count == 0) count = fill_buffer(sockno, timeout);
		if(count == 0) return(SOCKIO_ERR);
		if(count < 0) return(SOCKIO_TIMEOUT);

		c = buf[next++];
		count--;
		if(c == '\r') {
			if(count == 0) count = fill_buffer(sockno, timeout);
			if(count == 0) return(SOCKIO_ERR);
			if(count < 0) return(SOCKIO_TIMEOUT);

			if(buf[next] == '\n') {
				next++;
				count--;
				if(full == FALSE) line[len++] = '\n';
				break;
			}
		}
		if(full == FALSE) line[len++] = c;
		if(len == size - 1) full = TRUE;
		if(c == '\n') break;
	}
	
	line[len] = '\0';

	return(full ? SOCKIO_TOOLONG : len);
}


/*
 * Send a line to a socket. Massages a terminating linefeed (\n)
 * into carriage return followed by linefeed.
 *
 */

VOID sock_puts(PUCHAR line, INT sockno, INT timeout)
{	static const UCHAR crlf[] = "\r\n";
	INT len = strlen(line);

	if(line[len-1] == '\n') {
		len--;
		sock_send(sockno, line, len, timeout);
		len = strlen(crlf);
		line = (PUCHAR) &crlf[0];
	}
	sock_send(sockno, line, len, timeout);
}


/*
 * Refill the network input buffer.
 *
 * Returns:
 *	>0		number of bytes in buffer
 *	0		nonspecific network read error
 *	<0		timeout
 *
 */

static INT fill_buffer(INT sockno, INT timeout)
{	INT rc;
	INT len;
	INT sockset[2];

	next = 0;			/* Reset buffer pointer */

	/* Set up and perform select call */

	sockset[0] = sockno;		/* Read waiting */
	sockset[1] = sockno;		/* Exception */

	rc = select(
		sockset,		/* List of sockets */
		1,			/* Sockets for read check */
		0,			/* Sockets for write check */
		1,			/* Sockets for exception check */
		timeout*1000);		/* Timeout period */

	if(rc == 0) return(-1);		/* Timeout expired */
	if(rc < 0) return(0);		/* Error */

	if(sockset[1] != -1)		/* Exception on socket */
		return(0);

	if(sockset[0] != -1) {	/* Read ready */
		len = recv(sockno, buf, BUFSIZE, 0);
		return(len);
	}

	return(0);			/* Some other problem */
}


/*
 * Write a buffer to a socket.
 *
 * Returns:
 *	same as for 'send'
 *
 */

static INT sock_send(INT sockno, PUCHAR buf, INT len, INT timeout)
{	return(send(sockno, buf, len, 0));
}

/*
 * End of file: netio.c
 *
 */
