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
 * \file sys.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd2ps.h"
#include <string.h>
#include <time.h>
#include <ctype.h>


/***************************************
 ***************************************/

const char *
ascii_date( void )
{
    time_t t = time( 0 );
    static char buf[ 64 ];

    strcpy( buf, asctime( localtime( &t ) ) );
    buf[ strlen( buf ) - 1 ] = '\0';
    return buf;
}


#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>


/***************************************
 ***************************************/

const char *
whoami( void )
{
#ifndef __VMS
    struct passwd *passwd = getpwuid( getuid( ) );
    const char *name = passwd ? passwd->pw_name : "Unknown";
    endpwent( );
#else
    const char *name = getenv( "USER" );
#endif
    return name ? name : "unknown";
}


/***************************************
 ***************************************/

char *
fl_strdup( const char * s )
{
    char *p = malloc( strlen( s ) + 1 );
    return p ? strcpy( p, s ) : NULL;
}


/***************************************
 ***************************************/

#ifndef HAVE_STRCASECMP
int
strcasecmp( const char * s1,
            const char * s2 )
{
    int c1, c2;

    while ( *s1 && *s2 )
    {
        c1 = tolower( *s1 );
        c2 = tolower( *s2 );
        if ( c1 != c2 )
            return c1 - c2;
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
