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
 *  Copyright (c) 1993, 1998-2002  By T.C. Zhao
 *  All rights reserved.
 *
 *  TODO: png should be implemented in real code
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
PNG_identify( FILE * fp )
{
    char buf[ 8 ];

    if ( fread( buf, 1, 8, fp ) != 8 )
        return 0;
    rewind( fp );
    return  ! strncmp( buf, "\x89PNG\x0d\x0a\x1a\x0a", 8 );
}


/***************************************
 ***************************************/

static int
PNG_description( FL_IMAGE * im )
{
    int status;

    static char *cmds[] = { "pngtopnm %s > %s", NULL };

    status = flimage_description_via_filter( im, cmds, "reading png ...", 1 );
    return status;
}


/***************************************
 ***************************************/

static int
PNG_load( FL_IMAGE * im  FL_UNUSED_ARG )
{
    fprintf( stderr, "should never been here\n" );
    return -1;
}


/***************************************
 ***************************************/

static int
PNG_dump( FL_IMAGE * im )
{
    char *cmds[ ] = { "pnmtopng %s  > %s", NULL };
    char *formats[ ] = { "ppm", "pgm", "pbm", NULL };

    return flimage_write_via_filter( im, cmds, formats, 1 );
}


/***************************************
 ***************************************/

void
flimage_enable_png( void )
{
    flimage_add_format( "Portable Network Graphics", "png", "png",
                        FL_IMAGE_RGB | FL_IMAGE_GRAY,
                        PNG_identify,
                        PNG_description,
                        PNG_load,
                        PNG_dump);
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
