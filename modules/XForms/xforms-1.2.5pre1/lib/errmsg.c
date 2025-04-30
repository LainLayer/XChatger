/*
 *  This file is part of the XForms library package.
 *
 *  XForms is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1, or
 *  (at your option) any later version.
 *
 *  XForms is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file errmsg.c
 *
 *   Copyright(c) 1993,1994 by T.C. Zhao
 *   All rights reserved.
 *
 *  Error handling routines.
 *
 *  Messages are divided into graphics and non-graphics types.
 *  For graphical error messages, a user input may be demanded,
 *  while for non-graphical messages, a string is printed and
 *  does nothing else.
 *
 *  The graphical output routine must have the following form:
 *    void (*gmout)(const char *, const char *, const char *, int);
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>
#include "local.h"  /* up stairs */

#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"
#include "ulib.h"

extern int errno;       /* system error no            */

#ifndef HAVE_STRERROR
extern char *sys_errlist[ ];
#endif


/**********************************************************************
 * msg_threshold controls amount of message to print
 * 0: only error      1: error and warning
 * 2: info            3: more info
 * 4: debugging       5: trace
 **********************************************************************/

/************ Local variables ****************************************/

static FILE *errlog;           /* where the msg is going       */
static int threshold;          /* current threshold            */
static int level;              /* requested message level      */
static const char *file;       /* source file name             */
static int lineno = 0;         /* line no. in that file        */


FL_ERROR_FUNC efp_;                  /* global pointer to shut up lint */
FL_ERROR_FUNC user_error_function_;  /* hook for application error handler */


/***************************************
 * set up where err is gonna go 
 ***************************************/

void
fl_set_err_logfp( FILE * fp )
{
    if ( fp )
        errlog = fp;
}


/***************************************
 ***************************************/

void
fl_set_error_handler( FL_ERROR_FUNC user_func)
{
    user_error_function_ = user_func;
}


/***************************************
 ***************************************/

const char *
fli_get_syserror_msg( void )
{
    const char  *pp;

#ifdef HAVE_STRERROR
    pp = errno ? strerror( errno ) : "";
#else
    pp = errno ? sys_errlist[ errno ] : "";
#endif

    return pp;
}


/***************************************
 * Message levels
 ***************************************/

void
fli_set_msg_threshold( int mlevel )
{
    threshold = mlevel;
}


/********************************************************************
 * Generate two strings that contain where and why an error occured
 *********************************************************************/

static void
P_errmsg( const char * func,
          const char * fmt,
          ... )
{
    char line[ ( int ) log10( INT_MAX ) + 3 ],
         *why;

    /* Return if there is nothing to do */

    if ( level >= threshold )
        return;

    if ( ! errlog )
        errlog = stderr;

    EXPAND_FORMAT_STRING( why, fmt );

    if ( lineno > 0 )
        sprintf( line, "%d", lineno );
    else
        strcpy( line, "?" );

    if ( func && *func )
        fprintf( errlog, "In %s() [%s:%s]: %s\n", func, file, line,
                 why ? why : "" );
    else
        fprintf( errlog, "In [%s:%s]: %s\n", file, line, why ? why : "" );

    fli_safe_free( why );
}


/*********************************************************************
 * Set the level, line number and file where error occurred, return
 * the function to use for outputting the error message
 ********************************************************************/

FL_ERROR_FUNC
fli_error_setup( int          lev,
                 const char * f,
                 int          l )
{
    file   = f;
    lineno = l;
    level  = lev;

    return user_error_function_ ? user_error_function_ : P_errmsg;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
