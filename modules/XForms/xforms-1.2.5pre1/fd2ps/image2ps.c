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
 * \file image2ps.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 * Turn a colormapped image into PostScript
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "fd2ps.h"

static const char *hexdigits = "0123456789abcdef";
#define LINELENGTH  37


/***************************************
 ***************************************/

int
image2colorps( short      * pixels,
               int          w,
               int          h,
               fd2psCMAP *  map,
               int          ncol  FL_UNUSED_ARG,
               const char * cmt)
{
    int x,
        y,
        k,
        r,
        g,
        b;
    int *rb,
        *gb,
        *bb;
    char pscmd[ 128 ];
    short *p;

    strcpy( pscmd, ps_literal( ( cmt && *cmt ) ? cmt : "startColorImage" ) );
    ps_output( "/redstring %d string def\n", w );
    ps_output( "/grnstring %d string def\n", w );
    ps_output( "/blustring %d string def\n", w );

    ps_output( "/%s\n", pscmd );
    ps_output( "{%d %d 8 [ %d 0 0 -%d 0 %d]\n", w, h, w, h, h );
    ps_output( " {currentfile redstring readhexstring pop}\n" );
    ps_output( " {currentfile grnstring readhexstring pop}\n" );
    ps_output( " {currentfile blustring readhexstring pop}\n" );
    ps_output( " true 3 colorimage\n } bind def\n");

    /* Start */

    ps_output( "%d %d scale\n", w, h );

    ps_verbatim( "%s\n", pscmd );

    rb = malloc( w * sizeof *rb );
    gb = malloc( w * sizeof *gb );
    bb = malloc( w * sizeof *bb );

    for ( p = pixels, k = y = 0; y < h; y++ )
    {
        for ( x = 0; x < w; x++, p++ )
        {
            rb[ x ] = map[ *p ].red;
            gb[ x ] = map[ *p ].green;
            bb[ x ] = map[ *p ].blue;
        }

        for ( x = 0; x < w; x++ )
        {
            r = rb[ x ];
            ps_output( "%c%c", hexdigits[ ( r >> 4 ) & 15 ],
                       hexdigits[ r & 15 ] );
            if ( ++k % LINELENGTH == 0 )
                ps_output( "\n" );
        }

        for ( x = 0; x < w; x++ )
        {
            g = gb[ x ];
            ps_output( "%c%c", hexdigits[ ( g >> 4 ) & 15 ],
                       hexdigits[ g & 15 ] );
            if ( ++k % LINELENGTH == 0 )
                ps_output( "\n" );
        }

        for ( x = 0; x < w; x++ )
        {
            b = bb[ x ];
            ps_output( "%c%c", hexdigits[ ( b >> 4 ) & 15 ],
                       hexdigits[ b & 15 ] );
            if ( ++k % LINELENGTH == 0 )
                ps_output( "\n" );
        }
    }

    free( rb );
    free( gb );
    free( bb );

    return 0;
}


/***************************************
 ***************************************/

int
image2grayps( short      * pixels,
              int          w,
              int          h,
              fd2psCMAP  * map,
              int          ncol,
              const char * cmt)
{
    int x,
        y,
        k,
        r;
    char pscmd[ 128 ];
    short *p;

    strcpy( pscmd, ps_literal( ( cmt && *cmt ) ? cmt : "startGrayImage" ) );
    ps_output( "/graystring %d string def\n", w );

    ps_output( "/%s\n", pscmd );
    ps_output( "{%d %d 8 [ %d 0 0 -%d 0 %d]\n", w, h, w, h, h );
    ps_output( " {currentfile graystring readhexstring pop}\n" );
    ps_output( " image \n} bind def\n" );
    ps_output( "%d %d scale\n", w, h );
    ps_verbatim( "%s\n", pscmd );

    /* convert colormap to grayscale */

    for ( x = 0; x < ncol; x++ )
        map[ x ].red = rgb2gray( map[ x ].red, map[ x ].green, map[ x ].blue );

    for ( p = pixels, k = y = 0; y < h; y++ )
    {
        for ( x = 0; x < w; x++, p++ )
        {
            r = map[ *p ].red;
            ps_output( "%c%c", hexdigits[ ( r >> 4 ) & 15 ],
                       hexdigits[ r & 15 ] );
            if ( ++k % LINELENGTH == 0 )
                ps_output( "\n" );
        }
    }

    return 0;
}


/***************************************
 ***************************************/

char *
ps_literal( const char * s )
{
    static char buf[ 1024 ];
    char *p = buf;

    for ( *p = '\0'; s && *s; s++ )
        *p++ = ( PS_SPECIAL( *s ) ) ? '$' : *s;

    *p = '\0';
    return buf;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
