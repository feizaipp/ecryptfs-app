#include "helper.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <termios.h>
#include <signal.h>
#include <stdio.h>

/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */
#define	STDERR_FILENO	2	/* Standard error output.  */

#define PAM_MAX_MSG_SIZE      512
#define INPUTSIZE PAM_MAX_MSG_SIZE

/* Copy whatever the last rule matched to the standard output. */
#ifndef ECHO
/* This used to be an fputs(), but since the string might contain NUL's,
 * we now use fwrite().
 */
#define ECHO fwrite( yytext, yyleng, 1, yyout )
#endif

#define  x_strdup(s)  ( (s) ? strdup(s):NULL )

/* Good policy to strike out passwords with some characters not just
   free the memory */

#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)

#define _pam_delete(xx)		\
{				\
	_pam_overwrite(xx);	\
	_pam_drop(xx);		\
}

int read_usbkey_pin_password(int echo, const char *prompt, char **retstr)
{
    struct termios term_before, term_tmp;
    char line[INPUTSIZE];
    int nc = -1, have_term = 0;
    sigset_t oset, nset;

    //printf("called with echo='%s', prompt='%s'.\n", echo ? "ON":"OFF" , prompt);

    if (isatty(STDIN_FILENO)) {                      /* terminal state */

        /* is a terminal so record settings and flush it */
        if ( tcgetattr(STDIN_FILENO, &term_before) != 0 ) {
            printf("<error: failed to get terminal settings>\n");
            *retstr = NULL;
            return -1;
        }
        memcpy(&term_tmp, &term_before, sizeof(term_tmp));
        if (!echo) {
            term_tmp.c_lflag &= ~(ECHO);
        }
        have_term = 1;

        /*
        * We make a simple attempt to block TTY signals from suspending
        * the conversation without giving PAM a chance to clean up.
        */

        sigemptyset(&nset);
        sigaddset(&nset, SIGTSTP);
        (void) sigprocmask(SIG_BLOCK, &nset, &oset);
    } else if (!echo) {
	    printf("<warning: cannot turn echo off>\n");
    }

    /* reading the line */
	/* this may, or may not set echo off -- drop pending input */
	if (have_term)
	    (void) tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_tmp);

	fprintf(stderr, "%s", prompt);

    if (have_term)
        nc = read(STDIN_FILENO, line, INPUTSIZE-1);
    else                             /* we must read one line only */
        for (nc = 0; nc < INPUTSIZE-1 && (nc?line[nc-1]:0) != '\n';
                nc++) {
            int rv;
            if ((rv=read(STDIN_FILENO, line+nc, 1)) != 1) {
            if (rv < 0)
                nc = rv;
            break;
            }
        }
    if (have_term) {
        (void) tcsetattr(STDIN_FILENO, TCSADRAIN, &term_before);
        if (!echo)             /* do we need a newline? */
            fprintf(stderr,"\n");
    }

    if (nc > 0) {                 /* we got some user input */
        //printf("we got some user input\n");

        if (nc > 0 && line[nc-1] == '\n') {     /* <NUL> terminate */
            line[--nc] = '\0';
        } else {
            if (echo) {
                fprintf(stderr, "\n");
            }
            line[nc] = '\0';
        }
        *retstr = x_strdup(line);
        _pam_overwrite(line);

        goto cleanexit;                /* return malloc()ed string */

    } else if (nc == 0) {                                /* Ctrl-D */
        printf("user did not want to type anything\n");

        *retstr = NULL;
        if (echo) {
            fprintf(stderr, "\n");
        }
        goto cleanexit;                /* return malloc()ed "" */
    } else if (nc == -1) {
        /* Don't loop forever if read() returns -1. */
        printf("error reading input from the user: %m\n");
        if (echo) {
            fprintf(stderr, "\n");
        }
        *retstr = NULL;
        goto cleanexit;                /* return NULL */
    }

    *retstr = NULL;
    _pam_overwrite(line);

 cleanexit:

    if (have_term) {
        (void) sigprocmask(SIG_SETMASK, &oset, NULL);
        (void) tcsetattr(STDIN_FILENO, TCSADRAIN, &term_before);
    }

    return nc;
}