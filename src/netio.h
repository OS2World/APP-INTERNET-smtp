/*
 * File: netio.h
 *
 * General network I/O and timeout routines; header file.
 *
 * Bob Eager   December 2004
 *
 */

#define	FALSE			0
#define	TRUE			1

/* Error codes */

#define	SOCKIO_TOOLONG		-1	/* Line too long from sock_gets() */
#define	SOCKIO_TIMEOUT		-2	/* Timeout on sock_gets()/sock_puts() */
#define	SOCKIO_ERR		-3	/* Nonspecific socket I/O error */

/* Network I/O functions */

extern	BOOL	netio_init(VOID);
extern	INT	sock_gets(PUCHAR, INT, INT, INT);
extern	VOID	sock_puts(PUCHAR, INT, INT);

/*
 * End of file: netio.h
 *
 */

