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
 * \file xbmtops.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 *  Turn an xbm file into PostScript
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd2ps.h"
#include <ctype.h>
#include <stdlib.h>

static int
gethexint( FILE * fp )
{
    char buf[ 20 ], *p;
    int c;

    while ( ( c = getc( fp ) ) == ',' || isspace( ( unsigned char ) c ) )
        /* empty */ ;

    if (c == EOF)
        return -1;

    for ( p = buf; c != EOF && c != ',' && !isspace( ( unsigned char ) c );
          c = getc( fp ) )
        *p++ = c;
    *p = '\0';

    return strtol(buf, 0, 16);
}


#define MAXH  500
static int bit_w, bit_h;
static char *bit_buf[ MAXH ];

static int
read_xbm( const char * f )
{
    char buf[ 256 ];
    int nosize, c, i, j, ct, err;
    FILE *fp;
    char *bits;

    if ( ! ( fp = fopen( f, "r" ) ) )
    {
        fprintf( stderr, "Can't open xbm '%s'\n", f );
        return -1;
    }

    bit_w = bit_h = 0;

    for ( nosize = 1; nosize && fgets( buf, sizeof buf - 1, fp ); )
    {
        if ( sscanf( buf, "#define %*s %d", &c ) == 1 )
        {
            if ( strstr( buf, "_width" ) )
                bit_w = c;
            else if ( strstr( buf, "_height" ) )
                bit_h = c;
            nosize = bit_w < 1 || bit_h < 1;
        }
    }

    if ( bit_h > MAXH )
    {
        fprintf( stderr, "bitmap too large. truncated\n" );
        bit_h = MAXH;
    }

    for ( i = 0; i < bit_h; i++ )
    {
        if ( bit_buf[ i ] )
            free( bit_buf[ i ] );
        bit_buf[ i ] = calloc( bit_w, sizeof *bit_buf[ i ] );
    }

    /* skip until getting a brace */

    while ( ( c = getc( fp ) ) != EOF && c != '{' )
        /* empty */ ;

    if ( feof( fp ) || ferror( fp ) )
    {
        fprintf( stderr, "error reading xb, file '%s'\n", f );

        bit_w = 0;
        return -1;
    }

    /* read the data */

    for ( j = err = c = 0; j < bit_h && ! err; j++ )
    {
        bits = bit_buf[ bit_h - 1 - j ];
        for ( i = ct = 0; i < bit_w && ! err; i++, ct = ( ct + 1 ) & 7 )
        {
            if ( ct == 0 )
                err = ( c = gethexint( fp ) ) < 0;
            *bits++ = c & 1;
            c = c >> 1;
        }
    }

    if ( err )
        fprintf( stderr, "Junk in bitmap file '%s' hex stream\n", f );

    return j > bit_h / 2 ? 0 : -1;
}


void
draw_bitmap( const char * f,
             float        x,
             float        y,
             float        w,
             float        h,
             long         fcol,
             long         bcol )
{
    int i, j, r, g, b;
    char *bits;
    float xx, yy;
    fd2psCMAP cmap[ 2 ];
    short *pixels, *pix;

    read_xbm( f );

    if ( bit_w < 1 )
        return;

    xx = x + ( w - bit_w ) / 2;
    yy = y + ( h - bit_h ) / 2;

    /* in xforms, bitmap is really an image with two colors, not *
       neccessarily black and white */

    fl_query_imap( bcol, &r, &g, &b );
    cmap[ 0 ].red   = r;
    cmap[ 0 ].green = g;
    cmap[ 0 ].blue  = b;

    fl_query_imap( fcol, &r, &g, &b );
    cmap[ 1 ].red = r;
    cmap[ 1 ].green = g;
    cmap[ 1 ].blue = b;

    pix = pixels = malloc( bit_w * bit_h * sizeof *pixels );

    for ( j = 0; j < bit_h; j++ )
    {
        bits = bit_buf[ bit_h - 1 - j ];
        for ( i = 0; i < bit_w; i++, bits++, pix++ )
            *pix = ( *bits != 0 );
    }

    ps_verbatim( "\n%% Start of XBM file %s %%{\n", f );
    ps_output( "gsave " );
    ps_output( "%.1f %.1f translate\n", xx, yy );

    if ( flps->colorps )
        image2colorps( pixels, bit_w, bit_h, cmap, 2, 0 );
    else
        image2grayps( pixels, bit_w, bit_h, cmap, 2, 0 );

    ps_verbatim( "\ngrestore%%}\n" );

    free( pixels );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
