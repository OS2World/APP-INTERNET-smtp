/*
 * File: log.h
 *
 * General logging and tracing routines; header file.
 *
 * Bob Eager   December 2004
 *
 */

/* Tunable constants */

#define	MAXLOG			200	/* Maximum length of a logfile line */

/* Error codes */

#define	LOGERR_OK		0	/* Log successfully opened */
#define	LOGERR_NOENV		1	/* Env variable not set for log dir */
#define	LOGERR_OPENFAIL		2	/* Failed to open log */
#define	LOGERR_LOGTYPE		3	/* Unrecognised logging type */

/* Log facility codes */

#define	LOGF_MAIL		2	/* Mail system */

/* Log entry types */

#define	LOG_EMERG		0	/* System is unusable */
#define	LOG_ALERT		1	/* Action must be taken immediately */
#define	LOG_CRIT		2	/* Critical conditions */
#define	LOG_ERR			3	/* Error conditions */
#define	LOG_WARNING		4	/* Warning conditions */
#define	LOG_NOTICE		5	/* Normal but significant condition */
#define	LOG_INFO		6	/* Informational */
#define	LOG_DEBUG		7	/* Debug-level messages */

/* Type definitions */

typedef	enum	{ LOGGING_UNSET, LOGGING_FILE, LOGGING_SYSLOG }
				LOGTYPE;

/* External references */

extern	VOID	close_log(VOID);
extern	VOID	dolog(UINT, PUCHAR);
extern	INT	open_log(UINT, PUCHAR, PUCHAR, PUCHAR, PUCHAR);
#ifdef	DEBUG
extern	VOID	trace(PUCHAR, ...);
#endif

/*
 * End of file: log.h
 *
 */

