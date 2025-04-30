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
 *  along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/*
 *  This file is part of the XForms library package.
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 ***************************************/

void *
fl_get_matrix( int          nrows,
               int          ncols,
               unsigned int esize )
{
    char **mat;
    int i;

    if ( ! ( mat = fl_malloc( ( nrows + 1 ) * sizeof *mat ) ) )
        return NULL;

    mat[ 0 ] = ( void * ) FL_GET_MATRIX;

    if ( ! ( mat[ 1 ] = fl_calloc( nrows * ncols, esize ) ) )
    {
        fl_free( mat );
        return NULL;
    }

    for ( i = 2; i <= nrows; i++ )
        mat[ i ] = mat[ i - 1 ] + ncols * esize;

    return mat + 1;
}


/***************************************
 * Given a piece of memory, make a matrix out of it
 ***************************************/

void *
fl_make_matrix( int            nrows,
                int            ncols,
                unsigned int   esize,
                void         * mem )
{
    char **mat = fl_malloc( ( nrows + 1 ) * sizeof *mat );
    int i;

    if ( ! mat )
        return NULL;

    mat[ 0 ] = ( char * ) FL_MAKE_MATRIX;

    for ( mat[ 1 ] = mem, i = 2; i <= nrows; i++ )
        mat[ i ] = mat[ i - 1 ] + ncols * esize;

    return mat + 1;
}


/***************************************
 ***************************************/

void
fl_free_matrix( void *p )
{
    char **matrix = p;

    if ( ! p )
        return;

    if ( matrix[ -1 ] && matrix[ 0 ] )
    {
        if ( matrix[ -1 ] == ( char * ) FL_GET_MATRIX )
            fl_free( matrix[ 0 ] );
        fl_free( matrix - 1 );
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
