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
 * \file xpmtops.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 *  Turn an xpm file into PostScript.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "include/forms.h"
#include "fd2ps.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     /* unlink */
#include <signal.h>


/***************************************
 * Get the dimension of the xpm file for alignment
 ***************************************/

static int
get_xpm_size( const char * file,
              int        * w,
              int        *h )
{
    FILE *fp = fopen( file, "r" );
    int c, j;

    if ( ! fp )
    {
        fprintf( stderr, "Can't open xpm file '%s'\n", file );
        return -1;
    }

    while ( ( c = getc( fp ) ) != '"' && c != EOF )
        /* empty */ ;

    if ( c == EOF )
    {
        fprintf( stderr, "Error reading xpm file '%s'\n", file );
        fclose( fp );
        return -1;
    }

    if ( fscanf( fp, "%d %d %d %d", w, h, &j, &j ) != 4 )
    {
        fprintf( stderr, "Failed to get the size of xpm file '%s'\n", file );
        fclose( fp );
        return -1;
    }

    fclose( fp );
    return 0;
}


/***************************************
 ***************************************/

void
draw_xpm( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;
    int xx, yy, w, h;

    if ( get_xpm_size( sp->file, &w, &h ) != -1 )
    {
        fl_get_align_xy( sp->align, ob->x, ob->y, ob->w, ob->h, w, h,
                         FL_abs( ob->bw ) + sp->dx, FL_abs( ob->bw ) + sp->dy,
                         &xx, &yy );

        xpmtops_direct( sp->file, xx, yy, ob->col1 );
    }

}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
