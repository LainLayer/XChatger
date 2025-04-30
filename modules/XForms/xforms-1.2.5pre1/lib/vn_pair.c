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
 * \file vn_pair.c
 *
 * Name value pair stuff
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "ulib.h"
#include <stdlib.h>
#include <limits.h>


/***************************************
 ***************************************/

int
fli_get_vn_value( FLI_VN_PAIR * vn_pair,
                  const char  * name )
{
    long val;
    char *ep;

    for ( ; vn_pair->name; vn_pair++ )
        if ( ! strcmp( vn_pair->name, name ) )
            return vn_pair->val;

    val = strtol( name, &ep, 10 );

    if ( ep != name && ! *ep && val >= INT_MIN && val <= INT_MAX )
        return val;

    return -1;
}


/***************************************
 ***************************************/

const char *
fli_get_vn_name( FLI_VN_PAIR * vn_pair,
                 int           val )
{
    static char buf[ 5 ][ 16 ];
    static int k;

    k = ( k + 1 ) % 5;

    for ( ; vn_pair->name; vn_pair++ )
        if ( vn_pair->val == val )
            return vn_pair->name;

    sprintf( buf[ k ], "%d", val );
    return buf[ k ];
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
