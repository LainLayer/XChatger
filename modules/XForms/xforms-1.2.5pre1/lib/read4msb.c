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
 * \file read4msb.c
 *
 *   Copyright(c) 1993,1994 by T.C. Zhao
 *   All rights reserved.
 *
 *   Read 4bytes MSB first
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"
#include "flinternal.h"
#include "ulib.h"


/***************************************
 ***************************************/

int
fli_fget4MSBF( FILE * fp )
{
    int ret = getc(fp);

    ret = ( ret << 8 ) | getc( fp );
    ret = ( ret << 8 ) | getc( fp );
    ret = ( ret << 8 ) | getc( fp );
    return ret;
}


/***************************************
 ***************************************/

int
fli_fput4MSBF( int    n,
               FILE * fp )
{
     putc( ( n >> 24 ) & 0xff, fp );
     putc( ( n >> 16 ) & 0xff, fp );
     putc( ( n >>  8 ) & 0xff, fp );
     putc( n           & 0xff, fp );
     return n;
}



/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
