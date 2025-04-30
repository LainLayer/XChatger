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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include <ctype.h>


/***************************************
 ***************************************/

static int
XBM_identify( FILE * fp )
{
    int n = 3;
    char buf[ 128 ];

    while ( --n >= 0 && fgets( buf, sizeof buf - 1, fp ) )
    {
        if ( strstr( buf, "#define" ) && strstr( buf, "_width " ) )
        {
            rewind( fp );
            return 1;
        }
    }

    return -1;
}


/***************************************
 ***************************************/

static int
XBM_description( FL_IMAGE * im )
{
    char tmpstr[ 256 ];
    int w = -1,
        h = -1,
        no_size = 1,
        c;

    while ( no_size && fgets( tmpstr, sizeof tmpstr, im->fpin ) )
    {
        if ( sscanf( tmpstr, "#define %*s %d", &c ) == 1 )
        {
            if ( strstr( tmpstr, "_width" ) )
                w = c;
            else if ( strstr( tmpstr, "_height" ) )
                h = c;
            no_size = w < 1 || h < 1;
        }
    }

    if ( no_size )
    {
        im->error_message( im, "can't get xbm size" );
        return -1;
    }

    im->w = w;
    im->h = h;

    im->map_len = 2;

    /* skip until we get brace */

    while ( ( h = getc( im->fpin ) ) != EOF && h != '{' )     /* } VI */
        /* empty */ ;

    return h == EOF ? EOF : 0;
}


/***************************************
 ***************************************/

static int
XBM_load( FL_IMAGE * im )
{
    int c,
        ct,
        i,
        j,
        err;
    unsigned short *bits;

    /* populate the colormap */

    im->red_lut[ 0 ] = im->green_lut[ 0 ] = im->blue_lut[ 0 ] = FL_PCMAX;
    im->red_lut[ 1 ] = im->green_lut[ 1 ] = im->blue_lut[ 1 ] = 0;

    for ( j = err = c = 0; j < im->h && !err; j++ )
    {
        bits = im->ci[ j ];
        im->completed = j + 1;

        for (i  = ct = 0; i < im->w && !err; i++, ct = ( ct + 1 ) & 7, c >>= 1 )
        {
            if ( ! ct )
                err = ( c = fli_readhexint( im->fpin ) ) < 0;
            *bits++ = c & 1;
        }
    }

    if ( err )
    {
        im->error_message( im, "Junk in hex stream" );
    }

    return j > im->h / 2 ? j : -1;
}


/***************************************
 ***************************************/

static int
XBM_write( FL_IMAGE * im )
{
    char tmpstr[ 256 ],
         *p;
    unsigned short *bits;
    int nbits,
        k,
        len,
        i,
        j;
    FILE *fp = im->fpout;

    strncpy( tmpstr, im->outfile, sizeof tmpstr - 25 );
    tmpstr[ sizeof tmpstr - 25 ] = '\0';
    if ( ( p = strchr( tmpstr, '.' ) ))
        *p = '\0';

    if ( isdigit( ( int ) tmpstr[ 0 ] ) )
        tmpstr[ 0 ] = 'a';

    fprintf( fp, "#define %s_width %d\n#define %s_height %d\n",
             tmpstr, im->w, tmpstr, im->h );
    fprintf( fp, "static char %s_bits[] = {\n ", tmpstr );

    for ( j = 0, len = 1; j < im->h; j++ )
    {
        bits = im->ci[ j];
        im->completed = j;

        for ( i = nbits = k = 0; i < im->w; i++, bits++ )
        {
            k = k >> 1;
            if ( *bits )
                k |= 0x80;

            if ( ++nbits == 8 )
            {
                fprintf( fp, "0x%02x", k &= 0xf );

                if ( j != im->h - 1 || i != im->w - 1 )
                    putc( ',', fp );

                if ( ( len += 5 ) > 70 )
                {
                    fprintf( fp, "\n " );
                    len = 1;
                }

                nbits = k = 0;
            }
        }

        /* check for possible padding */

        if ( nbits )
        {
            k >>= 8 - nbits;
            fprintf( fp, "0x%02x", k &= 0xff );

            if ( j != im->h - 1 )
                putc( ',', fp );

            if ( ( len += 5 ) > 70 )
            {
                fprintf( fp, "\n " );
                len = 1;
            }
        }
    }

    fputs( "};\n", fp );

    return fflush( fp );
}


/***************************************
 ***************************************/

void
flimage_enable_xbm( void )
{
    flimage_add_format( "X11 Bitmap", "xbm", "xbm", FL_IMAGE_MONO,
                        XBM_identify,
                        XBM_description,
                        XBM_load,
                        XBM_write );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
