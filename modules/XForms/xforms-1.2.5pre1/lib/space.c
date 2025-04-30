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


/*
 * \file space.c
 *
 *   Copyright(c) 1993,1994 by T.C. Zhao
 *   All rights reserved.
 *
 *   Remove unescaped leadingi/trailing spaces from a string.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "include/forms.h"
#include "flinternal.h"
#include "ulib.h"


/***************************************
 * Remove leading space
 ***************************************/

char *
fli_de_space( char * s )
{
    char *p;

    /* Not all isspace considers '\t' a white space */

    for ( p = s; p && ( isspace( ( unsigned char ) *p ) || *p == '\t' ); p++ )
        /* empty */ ;

    return p == s ? s : memmove( s, p, strlen( p ) + 1 );
}


/***************************************
 * remove trailing space
 ***************************************/

char *
fli_space_de( char * s )
{
    char *p,
         *q;

    if ( ! s || ! *s )
        return s;

    q = p = s + strlen( s ) - 1;

    /* maybe replace \ with space ? */

    for ( q--;
          p >= s && isspace( ( unsigned char ) *p ) && ( q < s || *q != '\\' );
          p--,q-- )
        /* empty */ ;

    *++p = '\0';
    return s;
}


/***************************************
 * Remove space from both ends
 ***************************************/

char *
fli_de_space_de( char * p )
{
    return fli_space_de( fli_de_space( p ) );
}


/***************************************
 * remove non-alphanumericals from string
 ***************************************/

char *
fli_nuke_all_non_alnum( char * s )
{
    char *p = s,
         *q = s + strlen( s ),
         *b;
    char buf[ 1024 ];

    for ( b = buf; p < q; p++ )
        if ( isalnum( ( unsigned char ) *p ) )
            *b++ = *p;
    *b = '\0';

    return strcpy( s, buf );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
