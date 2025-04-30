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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 ***************************************/

static int
IRIS_identify( FILE * fp )
{
    char buf[ 2 ];

    if ( fread( buf, 1, 2, fp ) != 2 )
        return 0;

    return    ( buf[ 0 ] == '\001' && buf[ 1 ] == '\332' )
           || ( buf[ 0 ] == '\332' && buf[ 1 ] == '\001' );
}


/***************************************
 ***************************************/

static int
IRIS_description( FL_IMAGE * im )
{
    static char *cmds[ ] = { "sgitopnm %s > %s", NULL };

    return flimage_description_via_filter( im, cmds, "reading iris ...", 0 );
}


/***************************************
 ***************************************/

static int
IRIS_load( FL_IMAGE * im  FL_UNUSED_ARG )
{
    fprintf( stderr, "should never been here\n" );
    return -1;
}


/***************************************
 ***************************************/

static int
IRIS_dump( FL_IMAGE * im )
{
    static char *cmds[ ] = { "pnmtosgi %s > %s", NULL };
    static char *formats[ ] = { "ppm", "pgm", "pbm", NULL };

    return flimage_write_via_filter( im, cmds, formats, 0 );
}


/***************************************
 ***************************************/

void
flimage_enable_sgi( void )
{
    flimage_add_format( "SGI Iris", "iris", "rgb",
                        FL_IMAGE_RGB | FL_IMAGE_GRAY | FL_IMAGE_MONO,
                        IRIS_identify,
                        IRIS_description,
                        IRIS_load,
                        IRIS_dump);
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
