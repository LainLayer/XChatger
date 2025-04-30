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
 *  This file is part of the XForms library package.
 *  Copyright (c) 1993,1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *   MS Windows/OS2  bmp file support
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define BMPDEBUG   0


typedef struct
{
    long fsize;         /* total file size              */
    long offset;
    int infosize;       /* supposedly 40 bytes          */
    int bpp;            /* bits per pixel               */
    int w, h;           /* width & height in pixels     */
    int col_used;       /* actual colors used           */
    int col_important;
    int planes;
    int encode;         /* compression method           */
    long isize;         /* (compressed) image size      */
    int xres, yres;     /* pix per meter                */
    int bpl;            /* bytes per line               */
    int pad;            /* line pad                     */
}
SPEC;

static int load_24bit_bmp( FL_IMAGE *,
                           SPEC     * );
static int load_8bit_bmp( FL_IMAGE *,
                          SPEC     * );
static int load_4bit_bmp( FL_IMAGE *,
                          SPEC     * );
static int load_1bit_bmp( FL_IMAGE *,
                          SPEC     * );


/***************************************
 ***************************************/

static int
BMP_identify( FILE * fp )
{
    char buf[ 2 ];

    if ( fread( buf, 1, 2, fp ) != 2 )
        return 0;
    rewind( fp );
    return ! strncmp( buf, "BM", 2 );
}


/***************************************
 ***************************************/

#if BMPDEBUG
static void
dump_header( const char * where,
             SPEC       * sp )
{
    fprintf( stderr, "%s\noffset=%ld infosize=%d\n", where,
             sp->offset, sp->infosize );
    fprintf( stderr, "bpl=%d ", sp->bpl );
    fprintf( stderr, "w=%d h=%d bpp=%d col_used=%d important=%d\n",
             sp->w, sp->h, sp->bpp, sp->col_used, sp->col_important );
}
#endif

enum
{
    E_RGB,
    E_RLE8,
    E_RLE4
};

#define bad_bpp( b ) ( b != 1 && b != 4 && b != 8 && b != 24 )


/***************************************
 ***************************************/

static void
generate_header_info( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;
    static const char *encoding[ ] = { "RGB", "RLE8", "RLE4" };
    char buf[ 128 ];

    if ( ! ( im->info = fl_malloc( 512 ) ) )
        return;

    sprintf( im->info,"Size=(%d x %d)\n", im->w, im->h );
    sprintf( buf, "BitsPerPixel=%d\nBytesPerLine=%d\n", sp->bpp, sp->bpl );
    strcat( im->info,buf );

    if ( sp->bpp != 24 )
    {
        sprintf( buf,"ColorUsed=%d\n", sp->col_used );
        strcat( im->info,buf );
    }

    sprintf( buf,"Encoding=%s", encoding[ sp->encode ] );
    strcat( im->info,buf );
}


/***************************************
 ***************************************/

static int
BMP_description( FL_IMAGE * im )
{
    SPEC *sp = fl_calloc( 1, sizeof *sp );
    char buf[ 40 ];

    if ( fread( buf, 1, 2, im->fpin ) != 2 )
    {
        im->error_message( im, "error while readin bmp file" );
        fl_free( sp );
        return -1;
    }

    sp->fsize = fli_fget4LSBF( im->fpin );

    if ( fread( buf, 1, 4, im->fpin ) != 4 )
    {
        im->error_message( im, "error while reading bmp file" );
        fl_free( sp );
        return -1;
    }

    sp->offset = fli_fget4LSBF( im->fpin );
    sp->infosize = fli_fget4LSBF( im->fpin );

    if ( sp->infosize != 40 && sp->infosize != 64 )
    {
        im->error_message( im, "unsupported old obsolete bmp file" );
        fl_free( sp );
        return -1;
    }

    im->io_spec = sp;
    sp->w = fli_fget4LSBF( im->fpin );
    sp->h = fli_fget4LSBF( im->fpin );
    sp->planes = fli_fget2LSBF( im->fpin );
    sp->bpp = fli_fget2LSBF( im->fpin );
    sp->encode = fli_fget4LSBF( im->fpin );
    sp->isize = fli_fget4LSBF( im->fpin );
    sp->xres = fli_fget4LSBF( im->fpin );
    sp->yres = fli_fget4LSBF(im->fpin);
    sp->col_used = fli_fget4LSBF( im->fpin );
    sp->col_important = fli_fget4LSBF( im->fpin );

    if ( bad_bpp( sp->bpp ) )
    {
        flimage_error( im, "%s: bad bpp (%d)", im->infile, sp->bpp );
        fl_free( im->io_spec );
        im->io_spec = 0;
        return -1;
    }

    if ( sp->infosize != 40 )
    {
        int skip = sp->infosize - 40;

        if (    skip < 0
             || fread( buf, 1, skip, im->fpin ) != ( size_t ) skip )
        {
            flimage_error( im, "%s: error while reading bmp file",
                           im->infile );
            fl_free( im->io_spec );
            im->io_spec = 0;
            return -1;
        }
    }

    im->w = sp->w;
    im->h = sp->h;

    /* read colormap */

    if ( sp->bpp != 24 )
    {
        int i;

        if ( ( im->map_len = sp->col_used ) <= 0 )
            im->map_len = 1 << sp->bpp;
        flimage_getcolormap( im );
        for ( i = 0; i < im->map_len; i++ )
        {
            im->blue_lut[ i ]  = getc( im->fpin );
            im->green_lut[ i ] = getc( im->fpin );
            im->red_lut[ i ]   = getc( im->fpin );
            im->alpha_lut[ i ] = getc( im->fpin );
        }
    }

    sp->bpl = ( sp->w * sp->bpp + 7 ) / 8;
    sp->pad = ( ( sp->bpl + 3 ) / 4 ) * 4 - sp->bpl;    /* pad to 4 bytes */

    if ( sp->bpp == 24 )
        im->type = FL_IMAGE_RGB;
    else if ( sp->bpp == 1 )
        im->type = FL_IMAGE_MONO;
    else
        im->type = FL_IMAGE_CI;

#if BMPDEBUG
    dump_header( "after read", sp );
#endif

    if ( im->setup->header_info )
        generate_header_info( im );

    return 1;
}


/***************************************
 ***************************************/

static int
BMP_read_pixels( FL_IMAGE * im )
{
    int status;
    SPEC *sp = im->io_spec;

    fseek( im->fpin, sp->offset, SEEK_SET );

    im->completed = 0;

    if ( sp->bpp == 24 )
        status = load_24bit_bmp( im, sp );
    else if ( sp->bpp == 8 )
        status = load_8bit_bmp( im, sp );
    else if ( sp->bpp == 4 )
        status = load_4bit_bmp( im, sp );
    else
        status = load_1bit_bmp( im, sp );

    return status;
}


/***************************************
 ***************************************/

static int
load_24bit_bmp( FL_IMAGE * im,
                SPEC     * sp )
{
    FILE *fp = im->fpin;
    int i,
        j;
    unsigned char *red,
                  *green,
                  *blue;

    for ( i = im->h - 1; ! feof( fp ) && i >= 0; i--, im->completed++ )
    {
        red   = im->red[ i ];
        green = im->green[ i ];
        blue  = im->blue[ i ];

        for ( j = 0; j < im->w; j++ )
        {
            blue[ j ]  = getc( fp );
            green[ j ] = getc( fp );
            red[ j ]   = getc( fp );
        }

        for ( j = 0; j < sp->pad; j++ )
            getc( fp );

        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, "Reading 24bit BMP" );
    }

    return ( i < im->h / 2 ) ? 1 : -1;
}


/***************************************
 ***************************************/

static int
load_8bit_bmp( FL_IMAGE * im,
               SPEC     * sp )
{
    FILE *fp = im->fpin;
    int i,
        pix;
    unsigned short *ci;

    if ( sp->encode == E_RGB )
    {
        for ( i = im->h - 1; i >= 0 && ! feof( fp ); i--, im->completed++ )
        {
            int j;

            ci = im->ci[ i ];

            for ( j = 0; j < im->w + sp->pad; j++ )
            {
                /* check for EOF so we can display partial files */

                if ( ( pix = getc( fp ) ) != EOF && j < im->w )
                    *ci++ = pix;
            }

            if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
                im->visual_cue( im, "Reading 8bit BMP" );
        }
    }
    else
    {
        ci = im->ci[ im->h - 1 ];

        for ( i = im->h - 1; i >= 0 && ! feof( fp ); )
        {
            int len = getc( fp );
            pix = getc( fp );

            if ( len )
            {
                while ( --len >= 0 )
                    *ci++ = pix;
            }
            else
            {
                if ( pix == 0 )
                    ci = im->ci[ --i ];
                else if ( pix == 1 )
                    goto done;
                else if ( pix == 2 )
                {
                    /* the document is unclear. don't know what does down
                       mean */
                    ci += getc( fp );
                    i += ( pix = getc( fp ) );
                    ci -= pix * im->w;
                }
                else
                {
                    int k;

                    for ( k = 0; k < pix; k++ )
                        *ci++ = getc( fp );
                    if ( k & 1 )
                        getc( fp );
                }
            }

            if ( ! ( ( im->completed = im->h - i - 1 ) & FLIMAGE_REPFREQ ) )
                im->visual_cue( im, "Reading 8bit encoded BMP" );
        }
    }

 done:
    return i < ( 2 * im->h / 3 ) ? 1 : -1;
}


/***************************************
 ***************************************/

static int
load_4bit_bmp( FL_IMAGE * im,
               SPEC     * sp )
{
    FILE *fp = im->fpin;
    int i = -1;
    unsigned short *ci,
                   *cis = 0;

    if ( sp->encode == E_RGB )
    {
        for ( i = im->h - 1; i >= 0 && ! feof( fp ); i--, im->completed++ )
        {
            int j;

            ci = im->ci[ i ];
            cis = ci + im->w;

            for ( j = 0; j < sp->bpl; j++ )
            {
                int c = getc( fp );

                *ci++ = ( c >> 4 ) & 0x0f;
                if ( ci < cis )
                    *ci++ = c & 0x0f;
            }
            for ( ; j < sp->bpl + sp->pad; j++ )
                getc( fp );

            if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
                im->visual_cue( im, "Reading 4bit BMP" );
        }
    }
    else
    {
        for ( i = im->h - 1; i >= 0 && ! feof( fp ); )
        {
            int len = getc( fp );
            int pix = getc( fp );

            ci = im->ci[ i ];
            if ( len )
            {
                int k;

                /* len is the number of pixels, not bytes */

                for ( k = 0; k < len; k++ )
                    *ci++ = ( ( k & 1 ) ? pix : ( pix >> 4 ) ) & 0x0f;
            }
            else
            {
                if ( pix == 0 )
                    ci = im->ci[ --i] ;
                else if ( pix == 1 )
                    goto done;
                else if ( pix == 2 )
                {
                    ci += getc( fp );
                    i += ( pix = getc( fp ) );
                    ci -= pix * im->w;
                }
                else
                {
                    int k;

                    for ( k = 0, len = pix; k < len; k++ )
                    {
                        if ( ( k & 1 ) == 0 )
                            pix = getc( fp );
                        *ci++ = ( ( k & 1 ) ? pix : ( pix >> 4 ) ) & 0x0f;
                    }

                    /* take care of padding, 2bytes boundary */

                    pix = len % 4;
                    if ( pix && pix != 3 )
                        getc( fp );
                }
            }

            if ( ! ( ( im->completed = im->h - 1 - i ) & FLIMAGE_REPFREQ ) )
                im->visual_cue( im, "Reading 4bit encoded BMP" );
        }
    }

 done:
    return ( i < ( 2 * im->h / 3 ) ) ? 1 : -1;
}


/***************************************
 ***************************************/

static int
load_1bit_bmp( FL_IMAGE * im,
               SPEC     * sp )
{
    int i,
        totalbpl = sp->bpl + sp->pad;
    unsigned char *buf = fl_malloc( totalbpl );

    if( ! buf )
    {
        im->error_message( im, "malloc() failed" );
        return -1;
    }

    for ( i = im->h; --i >= 0 && ! feof( im->fpin ); )
    {
        if ( fread( buf, 1, totalbpl, im->fpin ) != ( size_t ) totalbpl )
        {
            fl_free( buf );
            im->error_message( im, "malloc() failed" );
            return -1;
        }

        unpack_bits( im->ci[ i ], buf, im->w );
    }

    fl_free( buf );

    return i < im->h / 2 ? 1 : -1;
}


/* write routine */

#define IS_RGB( im )  ( im->type == FL_IMAGE_RGB )
#define IS_BW( im )   ( im->type == FL_IMAGE_MONO )
#define IS_8bit( im ) ( im->map_len > 16 )


/***************************************
 ***************************************/

static int
write_bmp_header( FL_IMAGE * im,
                  SPEC     * sp )
{
    FILE *fp = im->fpout;
    int mapsize;

    sp->w = im->w;
    sp->h = im->h;

    sp->bpp = ( IS_RGB( im ) ? 24 : ( IS_BW( im ) ? 1 : 8 ) );

    /* make exception for 16 colors or less */

    if ( im->type == FL_IMAGE_CI && im->map_len <= 16 )
        sp->bpp = im->map_len <= 2 ? 1 : 4;

    /* if grayscale, we can make it into a CI */

    if ( im->type == FL_IMAGE_GRAY )
        sp->bpp = 8;

    /* bytes per line */

    sp->bpl = ( im->w * sp->bpp + 7 ) / 8;
    sp->pad = ( ( sp->bpl + 3 ) / 4 ) * 4 - sp->bpl;
    sp->infosize = 40;
    mapsize = 4 * ( sp->bpp != 24 ? ( 1 << sp->bpp ) : 0 );
    sp->fsize = 14 + sp->infosize + mapsize + im->h * ( im->w + sp->pad );
    sp->offset = 14 + sp->infosize + mapsize;

    sp->col_used = sp->col_important = sp->bpp != 24 ? im->map_len : 0;
    if ( sp->bpp == 1 )
        sp->col_used = sp->col_important = 2;

#if BMPDEBUG
    dump_header( "before write", sp );
#endif

    /* start writing */

    fputc( 'B', fp );
    fputc( 'M', fp );
    fli_fput4LSBF( sp->fsize, fp );
    fli_fput4LSBF( 0, fp );
    fli_fput4LSBF( sp->offset, fp );
    fli_fput4LSBF( sp->infosize, fp );
    fli_fput4LSBF( sp->w, fp );
    fli_fput4LSBF( sp->h, fp );
    fli_fput2LSBF( 1, fp );
    fli_fput2LSBF( sp->bpp, fp );
    fli_fput4LSBF( E_RGB, fp );
    fli_fput4LSBF( 0, fp );                  /* encoded size */
    fli_fput4LSBF( 96 * 36, fp );
    fli_fput4LSBF( 96 * 36, fp );
    fli_fput4LSBF( sp->col_used, fp );       /* actual colors   */
    fli_fput4LSBF( sp->col_important, fp );  /* important colors */

    if ( sp->bpp != 24 )
    {
        char junk[ ] = { 0, 0, 0, 0 };
        int i;

        for ( i = 0; i < im->map_len; i++ )
        {
            putc( im->blue_lut[ i ], fp );
            putc( im->green_lut[ i ], fp );
            putc( im->red_lut[ i ], fp );
            putc( 0, fp );
    }

        for ( ; i < 1 << sp->bpp; i++ )
            fwrite( junk, 1, 4, fp );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
BMP_write_image( FL_IMAGE * im )
{
    SPEC *sp = fl_calloc( 1, sizeof *sp );
    FILE *fp = im->fpout;
    int i, j;

    write_bmp_header( im, sp );

    if ( sp->bpp == 24 )
    {
        unsigned char *r,
                      *g,
                      *b;

        for ( i = im->h; --i >= 0 ; )
        {
            r = im->red[ i ];
            g = im->green[ i ];
            b = im->blue[ i ];

            for ( j = 0; j < im->w; j++, r++, g++, b++ )
            {
                putc( *b, fp );
                putc( *g, fp );
                putc( *r, fp );
            }

            for ( j = 0; j < sp->pad; j++ )
                putc( 0, fp );
        }
    }
    else if ( sp->bpp == 8 )
    {
        unsigned short *p8,
                       **ras = FL_IMAGE_CI ? im->ci:im->gray;

        for ( i = im->h; --i >= 0; )
        {
            p8 = ras[ i ];

            for ( j = 0; j < im->w; j++, p8++ )
                putc( *p8, fp );

            for ( j = 0; j < sp->pad; j++ )
                putc( 0, fp );
        }
    }
    else if ( sp->bpp == 4 )
    {
        unsigned short *ci,
                       *cis;
        unsigned char uc;

        for ( i = im->h; --i >= 0; )
        {
            cis = ( ci = im->ci[ i ] ) + im->w;

            for ( j = 0; j < sp->bpl; j++ )
            {
                uc = *ci++;
                uc <<= 4;
                if ( ci < cis )
                    uc |= *ci++;
                putc( uc, fp );
            }

            for ( j = 0; j < sp->pad; j++ )
                putc( 0, fp );
        }
    }
    else if ( sp->bpp == 1 )
    {
        int totalbpl = sp->bpl + sp->pad;
        unsigned char *tmpbuf = fl_malloc( totalbpl );

        if ( ! tmpbuf )
        {
            im->error_message( im, "malloc() failed" );
            return -1;
        }

        for ( i = im->h; --i >= 0; )
        {
            pack_bits( tmpbuf, im->ci[ i ], im->w );
            fwrite( tmpbuf, 1, totalbpl, fp );
        }

        fl_free( tmpbuf );
    }

    fl_free( sp );

    return 0;
}


/***************************************
 ***************************************/

void
flimage_enable_bmp( void )
{
    flimage_add_format( "Windows/OS2 BMP file", "bmp", "bmp",
                        FL_IMAGE_FLEX & ~FL_IMAGE_GRAY16,
                        BMP_identify,
                        BMP_description,
                        BMP_read_pixels,
                        BMP_write_image );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
