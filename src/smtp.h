/*
 * File: smtp.h
 *
 * SMTP client for Tavi network
 *
 * Header file
 *
 * Bob Eager   December 2004
 *
 */

#include <os2.h>

#include "log.h"

#define	VERSION			4	/* Major version number */
#define	EDIT			5	/* Edit number within major version */

#define	FALSE			0
#define	TRUE			1

#define	MAXUNAME		50	/* Maximum length of username */
#define	MAXPASS			50	/* Maximum length of password */

/* Structure definitions */

typedef struct _FL {			/* Filename list cell */
struct	_FL	*next;
INT		isdir;
PUCHAR		name;
} FL, *PFL;

/* External references */

extern	VOID	error(PUCHAR mes, ...);
extern	BOOL	client(INT, PFL, PUCHAR, BOOL, PUCHAR, PUCHAR, PUCHAR);
extern	BOOL	something(PFL);
extern	PVOID	xmalloc(size_t);

/*
 * End of file: smtp.h
 *
 */

