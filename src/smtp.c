/*
 * File: smtp.c
 *
 * SMTP client for Tavi network
 *
 * Main program
 *
 * Bob Eager   December 2004
 *
 */

/*
 * History:
 *
 *	1.0	Initial version.
 *	1.1	Use new thread-safe logging module.
 *		Use OS/2 type definitions.
 *		Added -v option to display progress of mail transmission.
 *	1.2	New, simplified network interface module.
 *	1.3	Does not make connection at all if there are no messages
 *		to send.
 *	1.4	Corrected failure to dot-stuff on sending.
 *	1.5	Modified to use NETLIB DLL.
 *	2.0	Added BLDLEVEL string.
 *		Diagnostics for occasional logfile open failures.
 *		Additional error checking in logging module.
 *		Grouped initialisation code together.
 *	3.0	Recompiled using 32-bit TCP/IP toolkit, in 16-bit mode.
 *	3.1	Added support for ESMTP function AUTH (LOGIN, PLAIN).
 *	4.0	Added support for logging to 'syslog' instead of to file,
 *		selectable by '-z' option. This has the advantage of
 *		avoiding clashing logfile usage.
 *	4.1	Fixed error in handling an EHLO response where there are
 *		no SMTP extensions reported.
 *	4.2	Added -q flag for quiet operation.
 *	4.3	Corrected exit code inversion (0 for failure!).
 *	4.4	Added support for sending ETRN to server.
 *	4.5	Fixed problem where multiline replies to the initial connect
 *		were not being handled properly.
 *		Fixed problem when an unsupported authorisation method could be
 *		mistaken as supported.
 *
 */

#pragma	strings(readonly)

#pragma	alloc_text(a_init_seg, main)
#pragma	alloc_text(a_init_seg, add_file)
#pragma	alloc_text(a_init_seg, add_directory)
#pragma	alloc_text(a_init_seg, fix_domain)
#pragma	alloc_text(a_init_seg, error)
#pragma	alloc_text(a_init_seg, log_connection)
#pragma	alloc_text(a_init_seg, putusage)

#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <types.h>

#define	OS2
#include <sys\socket.h>
#include <netinet\in.h>
#include <netdb.h>
#include <arpa\nameser.h>
#include <resolv.h>

#include "smtp.h"

#define	LOGFILE		"SMTP.Log"	/* Name of log file */
#define	LOGENV		"ETC"		/* Environment variable for log dir */
#define	SMTPDIR		"SMTP"		/* Environment variable for spool dir */
#define	SMTPSERVICE	"smtp"		/* Name of SMTP service */
#define	TCP		"tcp"		/* TCP protocol */

/* Type definitions */

typedef	struct hostent		HOST, *PHOST;		/* Host entry structure */
typedef struct in_addr		INADDR, *PINADDR;	/* Internet address */
typedef	struct sockaddr		SOCKG, *PSOCKG;		/* Generic structure */
typedef	struct sockaddr_in	SOCK, *PSOCK;		/* Internet structure */
typedef	struct servent		SERV, *PSERV;		/* Service structure */

/* Forward references */

static	VOID	add_directory(PUCHAR);
static	VOID	add_file(PUCHAR);
static	VOID	fix_domain(PUCHAR);
static	VOID	log_connection(PUCHAR, BOOL);
static	VOID	process_logging(PUCHAR);
static	VOID	putusage(VOID);

/* Local storage */

static	LOGTYPE	log_type = LOGGING_UNSET;
static	PFL	head = (PFL) NULL;	/* Head of file list */
static	PFL	tail;
static	PUCHAR	progname;		/* Name of program, as a string */

/* Help text */

static	const	PUCHAR helpinfo[] = {
"%s: SMTP client",
"Synopsis: %s [options] [file...]",
" Options:",
"    -ddirectory  specify directory containing mail; all files are sent",
"    -edomain     send ETRN for domain",
"    -h           display this help",
"    -ppass       specify password for authentication",
"    -q           operate quietly",
"    -sserver     specify address of SMTP server",
"    -uuser       specify username for authentication",
"    -v           verbose; display progress",
"    -zf          log to file (default)",
"    -zs          log to SYSLOG",
" ",
"Any specified file is treated as a single mail message.",
" ",
"If no files or directories are specified, the directory described",
"by the environment variable "SMTPDIR" is used.",
"There is no default for the address of the SMTP server.",
"Sending mail and sending ETRN are mutually exclusive.",
""
};


/*
 * Parse arguments and handle options.
 *
 */

INT main(INT argc, PUCHAR argv[])
{	INT sockno, rc;
	INT i;
	BOOL verbose = FALSE;
	BOOL quiet = FALSE;
	PUCHAR argp, p;
	UCHAR servername[MAXDNAME+1];
	UCHAR clientname[MAXDNAME+1];
	UCHAR username[MAXUNAME+1];
	UCHAR password[MAXPASS+1];
	UCHAR domain[MAXDNAME+1];
	ULONG server_addr;
	SOCK server;
	PHOST smtphost;
	PSERV smtpserv;

	progname = strrchr(argv[0], '\\');
	if(progname != (PUCHAR) NULL)
		progname++;
	else
		progname = argv[0];
	p = strchr(progname, '.');
	if(p != (PUCHAR) NULL) *p = '\0';
	strlwr(progname);

	tzset();			/* Set time zone */
	res_init();			/* Initialise resolver */
	servername[0] = '\0';
	username[0] = '\0';
	password[0] = '\0';
	domain[0] = '\0';

	/* Process input options */

	for(i = 1; i < argc; i++) {
		argp = argv[i];
		if(argp[0] == '-') {		/* Option */
			switch(argp[1]) {
				case 'd':	/* Specified directory */
					if(argp[2] != '\0') {
						add_directory(&argp[2]);
					} else {
						if(i == argc - 1) {
							error("no arg for -d");
							exit(EXIT_FAILURE);
						} else {
							add_directory(
								argv[++i]);
						}
					}
					break;

				case 'e':	/* Send ETRN for domain */
					if(domain[0] != '\0') {
						error(
							"ETRN domain specified"
							" more than once");
						exit(EXIT_FAILURE);
					}
					if(argp[2] != '\0') {
						strcpy(domain, &argp[2]);
					} else {
						if(i == argc - 1) {
							error("no arg for -e");
							exit(EXIT_FAILURE);
						} else {
							strcpy(
								domain,
								argv[++i]);
						}
					}
					break;

				case 'h':	/* Display help */
					putusage();
					exit(EXIT_SUCCESS);

				case 'p':	/* Specified password */
					if(password[0] != '\0') {
						error(
							"password specified"
							" more than once");
						exit(EXIT_FAILURE);
					}
					if(argp[2] != '\0') {
						strcpy(password, &argp[2]);
					} else {
						if(i == argc - 1) {
							error("no arg for -p");
							exit(EXIT_FAILURE);
						} else {
							strcpy(
								password,
								argv[++i]);
						}
					}
					break;

				case 'q':	/* Quiet mode */
					quiet = TRUE;
					break;

				case 's':	/* Specified server */
					if(servername[0] != '\0') {
						error(
							"server specified more"
							" than once");
						exit(EXIT_FAILURE);
					}
					if(argp[2] != '\0') {
						strcpy(servername, &argp[2]);
					} else {
						if(i == argc - 1) {
							error("no arg for -s");
							exit(EXIT_FAILURE);
						} else {
							strcpy(
								servername,
								argv[++i]);
						}
					}
					break;

				case 'u':	/* Specified username */
					if(username[0] != '\0') {
						error(
							"username specified"
							" more than once");
						exit(EXIT_FAILURE);
					}
					if(argp[2] != '\0') {
						strcpy(username, &argp[2]);
					} else {
						if(i == argc - 1) {
							error("no arg for -u");
							exit(EXIT_FAILURE);
						} else {
							strcpy(
								username,
								argv[++i]);
						}
					}
					break;

				case 'v':	/* Verbose - display progress */
					verbose = TRUE;
					break;

				case 'z':	/* Logging */
					if(log_type != LOGGING_UNSET) {
						error(
							"Logging option "
							"specified more than "
							"once");
						exit(EXIT_FAILURE);
					}
					if(argp[2] != '\0') {
						process_logging(&argp[2]);
					} else {
						if(i == argc - 1) {
							error ("no arg for -z");
							exit(EXIT_FAILURE);
						} else {
							i++;
							process_logging(argv[i]);
						}
					}
					break;

				case '\0':
					error("missing flag after '-'");
					exit(EXIT_FAILURE);

				default:
					error("invalid flag '%c'", argp[1]);
					exit(EXIT_FAILURE);
			}
		} else {
			add_file(argp);
		}
	}

	if(servername[0] == '\0') {
		error("server must be specified using -s");
		exit(EXIT_FAILURE);
	}

	if(domain[0] != '\0') {		/* ETRN wanted */
		if(head != (PFL) NULL) {
			error("cannot send mail at same time as ETRN");
			exit(EXIT_FAILURE);
		}
	}

	if((username[0] != '\0') && (password[0] == '\0') ||
	   (username[0] == '\0') && (password[0] != '\0')) {
		error("neither or both of username and password must be"
		      " specified");
		exit(EXIT_FAILURE);
	}

	fix_domain(servername);

	if(domain[0] == 0) {		/* Not ETRN */
		if(head == (PFL) NULL) {
			PUCHAR dir = getenv(SMTPDIR);
			PUCHAR temp;

			if(dir == (PUCHAR) NULL) {
				error(
					"no files specified,"
					" and environment variable "
					SMTPDIR" not set");
				exit(EXIT_FAILURE);
			}

			temp = xmalloc(strlen(dir)+1);
			strcpy(temp, dir);
			add_directory(temp);
		}

		/* Exit if nothing to do */

		if(something(head) == FALSE) {
			if(verbose == TRUE)
				fprintf(stdout, "No mail to send\n");
			exit(EXIT_SUCCESS);
		}
	}

	/* Set default logging type if not specified */

	if(log_type == LOGGING_UNSET) log_type = LOGGING_FILE;

	/* Get the host name of this client; if not possible, set it to the
	   dotted address. */

	rc = gethostname(clientname, sizeof(clientname));
	if(rc != 0) {
		INADDR myaddr;

		myaddr.s_addr = htonl(gethostid());
		sprintf(clientname, "[%s]", inet_ntoa(myaddr));
	} else {
		fix_domain(clientname);
	}

	rc = sock_init();		/* Initialise socket library */
	if(rc != 0) {
		error("INET.SYS not running");
		exit(EXIT_FAILURE);
	}

	sockno = socket(PF_INET, SOCK_STREAM, 0);
	if(sockno == -1) {
		error("cannot create socket");
		exit(EXIT_FAILURE);
	}

	smtphost = gethostbyname(servername);
	if(smtphost == (PHOST) NULL) {
		if(isdigit(servername[0])) {
			server_addr = inet_addr(servername);
		} else {
			error(
				"cannot get address for SMTP server '%s'",
				servername);
			exit(EXIT_FAILURE);
		}
	} else {
		server_addr = *((u_long *) smtphost->h_addr);
	}

	smtpserv = getservbyname(SMTPSERVICE, TCP);
	if(smtpserv == (PSERV) NULL) {
		error("cannot get port for %s/%s service", SMTPSERVICE, TCP);
		exit(EXIT_FAILURE);
	}
	endservent();

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = server_addr;
	server.sin_port = smtpserv->s_port;
	rc = connect(sockno, (PSOCKG) &server, sizeof(SOCK));
	if(rc == -1) {
		error("cannot connect to SMTP server '%s'", servername);
		exit(EXIT_FAILURE);
	}

	/* Start logging */

	rc = open_log(log_type, LOGENV, LOGFILE, clientname, progname);
	if(rc != LOGERR_OK) {
		error(
		"logging initialisation failed - %s",
		rc == LOGERR_NOENV    ? "environment variable "LOGENV" not set" :
		rc == LOGERR_OPENFAIL ? "file open failed" :
					"internal log type failure");
		exit(EXIT_FAILURE);
	}

	log_connection(servername, quiet);

	/* Do the work */

	rc = client(
			sockno, head, clientname, verbose,
			username, password, domain);

	(VOID) soclose(sockno);
	close_log();

	return(rc == TRUE ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
 * Process the value of the '-z' option (logging).
 *
 */

static VOID process_logging(PUCHAR s)
{	if(strlen(s) == 1) {
		switch(toupper(s[0])) {
			case 'F':	/* Log to file */
				log_type = LOGGING_FILE;
				return;

			case 'S':	/* Log to SYSLOG */
				log_type = LOGGING_SYSLOG;
				return;
		}
	}
	error("invalid value for -z option");
	exit(EXIT_FAILURE);
}


/*
 * Add a filename to the file list.
 *
 */

static VOID add_file(char *name)
{	PFL temp = (PFL) xmalloc(sizeof(FL));

	temp->next = (PFL) NULL;
	temp->name = name;
	temp->isdir = FALSE;
	strcpy(temp->name, name);
	if(head == (PFL) NULL) {
		head = temp;
		tail = temp;
	} else {
		tail->next = temp;
		tail = temp;
	}
}


/*
 * Add a directory to the file list.
 *
 */

static VOID add_directory(char *name)
{	PFL temp = (PFL) xmalloc(sizeof(FL));

	temp->next = (PFL) NULL;
	temp->name = name;
	temp->isdir = TRUE;
	strcpy(temp->name, name);
	if(head == (PFL) NULL) {
		head = temp;
		tail = temp;
	} else {
		tail->next = temp;
		tail = temp;
	}
}


/*
 * Check for a full domain name; if not present, add default domain name.
 *
 */

static VOID fix_domain(PUCHAR name)
{	if(strchr(name, '.') == (PUCHAR) NULL && _res.defdname[0] != '\0') {
		strcat(name, ".");
		strcat(name, _res.defdname);
	}
}


/*
 * Print message on standard error in printf style,
 * accompanied by program name.
 *
 */

VOID error(PUCHAR mes, ...)
{	va_list ap;

	fprintf(stderr, "%s: ", progname);

	va_start(ap, mes);
	vfprintf(stderr, mes, ap);
	va_end(ap);

	fputc('\n', stderr);
}


/*
 * Log details of the connection to standard output (if not quiet mode)
 * and to the logfile.
 *
 */

static VOID log_connection(PUCHAR servername, BOOL quiet)
{	time_t tod;
	UCHAR timeinfo[35];
	UCHAR buf[100];

	if(quiet == FALSE) {
		(VOID) time(&tod);
		(VOID) strftime(timeinfo, sizeof(timeinfo),
			"on %a %d %b %Y at %X %Z", localtime(&tod));
		sprintf(buf, "%s: connection to %s, %s",
			progname, servername, timeinfo);
			fprintf(stdout, "%s\n", buf);
	}

	sprintf(buf, "connection to %s", servername);
	dolog(LOG_INFO, buf);
}


/*
 * Output program usage information.
 *
 */

static VOID putusage(VOID)
{	PUCHAR *p = (PUCHAR *) helpinfo;
	PUCHAR q;

	for(;;) {
		q = *p++;
		if(*q == '\0') break;

		fprintf(stderr, q, progname);
		fputc('\n', stderr);
	}
	fprintf(stderr, "\nThis is version %d.%d\n", VERSION, EDIT);
}


/*
 * Allocate memory using 'malloc'; terminate with a message
 * if allocation failed.
 *
 */

PVOID xmalloc(size_t size)
{	PVOID res;

	res = malloc(size);

	if(res == (PVOID) NULL)
		error("cannot allocate memory");

	return(res);
}

/*
 * End of file: smtp.c
 *
 */
