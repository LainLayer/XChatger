/*
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file version.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 * version information
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fd2ps.h"


#define S( a )  #a
#define LIBVERSION( a, b ) S( a ) "." S( b )

static char *version[ ] =
{
    "fd2ps " LIBVERSION( FL_VERSION, FL_REVISION ) "." FL_FIXLEVEL,
    "Copyright (c) 1997-2002 by T.C. Zhao",
    "GNU Lesser General Public License since 2002",
    NULL
};


/***************************************
 ***************************************/

void
print_version( int die )
{
    char **q = version;

    for ( ; *q; q++ )
        fprintf( stderr, "%s\n", *q );

    if ( die )
        exit( 0 );
}


/***************************************
 ***************************************/

const char *
get_version( void )
{
    static char buf[ 256 ];
    char **q = version;

    for ( *buf = '\0'; *q; q++ )
        strcat( buf, *q );

    return buf;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
