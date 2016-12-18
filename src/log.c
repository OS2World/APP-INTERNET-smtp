/*
 * File: log.c
 *
 * General logging and tracing routines
 *
 * Bob Eager   December 2004
 *
 */

#pragma	strings(readonly)

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <os2.h>

#include "log.h"

#pragma	alloc_text(a_init_seg, open_logfile)
#pragma	alloc_text(a_init_seg, close_logfile)

#ifdef	DEBUG
#define	MAXTRACE	200		/* Maximum length of trace line */
#endif

#define	SYSLOGSERVICE	"syslog"	/* Name of syslog service */
#define	UDP		"udp"		/* UDP protocol */

/* Type definitions */

typedef	struct servent		SERV, *PSERV;		/* Service structure */
typedef struct sockaddr         SOCKG, *PSOCKG;         /* Generic structure */
typedef struct sockaddr_in      SOCK, *PSOCK;           /* Internet structure */

/* Forward references */

static	VOID	dolog_file(UINT, PUCHAR);
static	VOID	dolog_syslog(UINT, PUCHAR);
static	INT	open_logfile(PUCHAR, PUCHAR);
static	INT	open_syslog(PUCHAR, PUCHAR);

/* Local storage */

static	FILE	*logfp = (FILE *) NULL;
static	UINT	logging_type = LOGGING_UNSET;
static	INT	logsock = -1;
static	UCHAR	procname[100];
static	UCHAR	hostname[100];
static	SOCK	syslog;

/*
 * Open the logging system. The 'type' parameter specified how the logging
 * is to be done - to a file, or to the syslog deamon on the local machine.
 *
 * If logging to a file, this is in the directory specified by the
 * environment variable given by 'direnv'; open fails if that
 * environment variable is not found. The actual name of the logfile
 * is given by 'file'.
 *
 * Returns:
 *	LOGERR_OK		log successfully opened
 *	LOGERR_NOENV		environment variable not set for log directory
 *	LOGERR_OPENFAIL		failed to open log
 *
 */

INT open_log(UINT log_type, PUCHAR direnv, PUCHAR file, PUCHAR myname,
		PUCHAR myprocname)
{	logging_type = log_type;

	switch(log_type) {
		case LOGGING_FILE:
			return(open_logfile(direnv, file));

		case LOGGING_SYSLOG:
			return(open_syslog(myname, myprocname));

		default:
			logging_type = LOGGING_UNSET;
			return(LOGERR_LOGTYPE);
	}
}


/*
 * Open the logfile. This is in the directory specified by the
 * environment variable given by 'direnv'; open fails if that
 * environment variable is not found. The actual name of the logfile
 * is given by 'file'.
 *
 * Returns:
 *	LOGERR_OK		log successfully opened
 *	LOGERR_NOENV		environment variable not set for log directory
 *	LOGERR_OPENFAIL		failed to open log
 *
 */

static INT open_logfile(PUCHAR direnv, PUCHAR file)
{	PUCHAR etc = getenv(direnv);
	UCHAR logname[CCHMAXPATH+1];

	if(etc == NULL) return(LOGERR_NOENV);

	sprintf(logname, "%s\\%s", etc, file);
	logfp = fopen(logname, "a");
	if(logfp == (FILE *) NULL) {
		fprintf(stderr, "logfile failure: %d\n", errno);
		return(LOGERR_OPENFAIL);
	}

#ifdef	DEBUG
	_set_crt_msg_handle(fileno(logfp));
#endif

	return(LOGERR_OK);
}


/*
 * Open the syslog.
 *
 * Returns:
 *	LOGERR_OK		log successfully opened
 *	LOGERR_NOENV		environment variable not set for log directory
 *	LOGERR_OPENFAIL		failed to open log
 *
 */

static INT open_syslog(PUCHAR myname, PUCHAR myprocname)
{	INT rc;
	PSERV logserv;
	PUCHAR p, q;

	if(logsock != -1) return(LOGERR_OK);

	/* Save host and process name for later use */

	if(myname[0] == '[') {	/* IP address - strip brackets */
		p = myname;
		q = hostname;

		while(*p != '\0') {
			if((*p != '[') && (*p != ']')) {
				*q++ = *p;
			}
			*p++;
		}
		*q = '\0';
	} else {		/* Lose domain part */
		strcpy(hostname, myname);
		p = strchr(hostname, '.');
		if(p != (PUCHAR) NULL) *p = '\0';
	}
	strcpy(procname, myprocname);

	logserv = getservbyname(SYSLOGSERVICE, UDP);
	endservent();
	if(logserv == (PSERV) NULL) {
		fprintf(
			stderr,
			"cannot get port for %s/%s service",
			SYSLOGSERVICE,
			UDP);
		return(LOGERR_OPENFAIL);
	}

	logsock = socket(PF_INET, SOCK_DGRAM, 0);
	if(logsock == -1) {
		fprintf(stderr, "cannot create socket for logging");
		return(LOGERR_OPENFAIL);

	}

	memset(&syslog, 0, sizeof(syslog));
	syslog.sin_family = AF_INET;
	syslog.sin_addr.s_addr = htonl(gethostid());
	syslog.sin_port = logserv->s_port;
	rc = connect(logsock, (PSOCKG) &syslog, sizeof(SOCK));
	if(rc == -1) {
		fprintf(stderr, "cannot connect to syslog daemon");
		return(LOGERR_OPENFAIL);
	}

	return(LOGERR_OK);
}


/*
 * Close the log.
 *
 */

VOID close_log(VOID)
{	switch(logging_type) {
		case LOGGING_FILE:
			if(logfp != (FILE *) NULL) fclose(logfp);
			break;

		case LOGGING_SYSLOG:
			if(logsock != -1) {
				soclose(logsock);
				logsock = -1;
			}
			break;
	}

	logging_type = LOGGING_UNSET;
}


/*
 * Write a string to the log, wherever it is.
 *
 */

VOID dolog(UINT type, PUCHAR s)
{	switch(logging_type) {
		case LOGGING_FILE:
			dolog_file(type, s);
			break;

		case LOGGING_SYSLOG:
			dolog_syslog(type, s);
			break;
	}
}


/*
 * Write a string to the logfile. The string is timestamped, and a newline
 * appended to the end unless there is one there already.
 *
 * This routine is thread-safe; it writes only ONE string to the logfile,
 * ensuring that the file does not become garbled.
 *
 */

static VOID dolog_file(UINT type, PUCHAR s)
{	time_t tod;
	UCHAR timeinfo[35];
	UCHAR buf[MAXLOG+1];

	if(logfp == (FILE *) NULL) return;

	(VOID) time(&tod);
	(VOID) strftime(
			timeinfo,
			sizeof(timeinfo),
			"%d/%m/%y %X>",
			localtime(&tod));
	sprintf(buf, "%s %s", timeinfo, s);
	if(s[strlen(s)-1] != '\n') strcat(buf, "\n");

	fputs(buf, logfp);
	fflush(logfp);
}


static VOID dolog_syslog(UINT severity, PUCHAR s)
{	UCHAR buf[MAXLOG+1];
	UCHAR temp[MAXLOG+1];
	time_t tod;

	/* Construct the Priority field */

	sprintf(buf, "<%d>", (LOGF_MAIL*8) + severity);

	/* Now add date and time */

	(VOID) time(&tod);
	(VOID) strftime(temp, MAXLOG, "%b %Oe %T ", localtime(&tod));
	strcat(buf, temp);

	/* Now the host name and process name */

	sprintf(temp, "%s %s: ", hostname, procname);
	strcat(buf, temp);

	/* Now the message */

	strcat(buf, s);

	/* Clean trailing newline */

	if(buf[strlen(buf)-1] == '\n')
		buf[strlen(buf)-1] = '\0';

	/* Send the message */

	(VOID) send(logsock, &buf[0], strlen(buf), 0);
}


#ifdef	DEBUG
/*
 * Output trace message, in printf style, to the logfile.
 *
 */

VOID trace(PUCHAR mes, ...)
{	va_list ap;
	UCHAR buf[MAXTRACE+1];

	strcpy(buf, "trace: ");

	va_start(ap, mes);
	vsprintf(buf+strlen(buf), mes, ap);
	va_end(ap);

	dolog(LOG_DEBUG, buf);
}
#endif

/*
 * End of file: log.c
 *
 */
