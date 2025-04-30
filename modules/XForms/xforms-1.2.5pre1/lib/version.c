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
 * \file version.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Version info
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"
#include "flinternal.h"
#include "private/flsnprintf.h"


static const char *version =
    "(Compiled " __DATE__ ")\n"
#ifdef FL_WIN32
    "Copyright (c) 1996-2002 by T.C. Zhao, Gang Li and Mark Overmars\n"
#else
    "Copyright (c) 1996-2002 by T.C. Zhao and Mark Overmars\n"
#endif
    "Parts Copyright(c) 1999-2002 by T.C. Zhao and Steve Lamont\n"
    "GNU Lesser General Public License since 2002";


static const char *fli_fix_level = FL_FIXLEVEL;


/***************************************
 ***************************************/

int
fl_library_version( int * ver,
                    int * rev )
{
    if ( ver )
        *ver = FL_VERSION;
    if ( rev )
        *rev = FL_REVISION;

    return FL_VERSION * 1000 + FL_REVISION;
}


/***************************************
 ***************************************/

long
fl_library_full_version( int         * version,
                         int         * revision,
                         int         * fix_level,
                         const char ** extra )
{
    long flv;
    char *x;

    if ( version )
        *version = FL_VERSION;
    if ( revision )
        *revision = FL_REVISION;

    flv = strtol( fli_fix_level, &x, 10 );
    if ( fix_level )
        *fix_level = flv;
    if ( extra )
        *extra = x;

    return FL_VERSION * 1000000 + FL_REVISION * 1000  + flv;
}


/***************************************
 ***************************************/

void
fli_print_version( int in_window )
{
    char *msg = fl_malloc(   strlen( version ) + sizeof "FORMS Library Version "
                           + 30 );

    sprintf( msg, "FORMS Library Version %d.%d.%s\n%s",
             FL_VERSION, FL_REVISION, FL_FIXLEVEL, version );

    if ( in_window )
        fl_show_messages( msg );
    else
        fprintf( stderr, "%s\n", msg );

    fl_free( msg );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
