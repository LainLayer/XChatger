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
 *  XWD format support. Probably buggy as hell
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "ulib.h"
#include "flimage.h"
#include "flimage_int.h"
#include <ctype.h>
#include <X11/XWDFile.h>

typedef struct
{
    XWDFileHeader header;
    char name[256];
    int swap;
    unsigned int rbits, rshifts;
    unsigned int gbits, gshifts;
    unsigned int bbits, bshifts;
}
SPEC;


#define XWDDEBUG  0


static unsigned int value_to_bits( unsigned int val );


/***************************************
 ***************************************/

#if XWDDEBUG==1
static void
dumpheader( const char    * where,
            XWDFileHeader * h )
{
    fprintf( stderr, "%s\n", where );
    fprintf( stderr, "file_version = %ld\n", ( long ) h->file_version );
    fprintf( stderr, "header_size = %ld\n", ( long ) h->header_size );
    fprintf( stderr, "visual_class = %ld\n", ( long ) h->visual_class );
    fprintf( stderr, "pixmap_depth = %ld\n", ( long ) h->pixmap_depth );
    fprintf( stderr, "bits_per_pixel = %ld\n", ( long ) h->bits_per_pixel );
    fprintf( stderr, "pixmap_width = %ld\n", ( long ) h->pixmap_width );
    fprintf( stderr, "pixmap_height = %ld\n", ( long ) h->pixmap_height );
    fprintf( stderr, "ncolors = %ld\n", ( long ) h->ncolors );
    fprintf( stderr, "red_mask = 0x%lx\n", ( long ) h->red_mask );
    fprintf( stderr, "green_mask = 0x%lx\n", ( long ) h->green_mask );
    fprintf( stderr, "blue_mask = 0x%lx\n", ( long ) h->blue_mask );
}
#endif

typedef union
{
    CARD32 l;
    CARD16 s;
    CARD8 c[ sizeof( CARD32 ) ];
} tLong;


/***************************************
 ***************************************/

static CARD32
swap32( CARD32 in )
{
    tLong t;
    CARD8 c;

    t.l = in;
    c = t.c[ 0 ];
    t.c[ 0 ] = t.c[ 3 ];
    t.c[ 3 ] = c;
    c = t.c[ 1 ];
    t.c[ 1 ] = t.c[ 2 ];
    t.c[ 2 ] = c;

    return t.l;
}


#define swap16( a )  ( ( ( ( a ) &0xff ) <<8 ) | ( ( ( a ) >> 8 ) & 0xff ) )


/***************************************
 ***************************************/

static void
swap_header( XWDFileHeader * h )
{
    h->file_version = swap32( h->file_version );
    h->header_size = swap32( h->header_size );
    h->visual_class = swap32( h->visual_class );
    h->pixmap_depth = swap32( h->pixmap_depth );
    h->pixmap_format = swap32( h->pixmap_format );
    h->bits_per_pixel = swap32( h->bits_per_pixel );
    h->pixmap_width = swap32( h->pixmap_width );
    h->pixmap_height = swap32( h->pixmap_height );
    h->bytes_per_line = swap32( h->bytes_per_line );
    h->byte_order = swap32( h->byte_order );
    h->ncolors = swap32( h->ncolors );
    h->red_mask = swap32( h->red_mask );
    h->green_mask = swap32( h->green_mask );
    h->blue_mask = swap32( h->blue_mask );
    h->bitmap_unit = swap32( h->bitmap_unit );
    h->bitmap_pad = swap32( h->bitmap_pad );
}


static int need_swap;


/***************************************
 * XWD does not have a signature, we'll have to guess
 ***************************************/

static int
XWD_identify( FILE * fp )
{
    XWDFileHeader h;

    if ( fread( &h, 1, sizeof h, fp ) != sizeof h )
        return 0;
    rewind( fp );

    need_swap = ( h.file_version != XWD_FILE_VERSION );

    if ( need_swap )
        swap_header( &h );

    if ( h.file_version != XWD_FILE_VERSION )
        return -1;

#if XWDDEBUG==1
    dumpheader( "Identify", &h );
#endif

    return    h.file_version == XWD_FILE_VERSION
           && h.visual_class <= 5
           && h.pixmap_depth > 0
           && h.pixmap_depth <= 32
           && h.pixmap_format <= ZPixmap;
}


/***************************************
 ***************************************/

static void
generate_header_info( FL_IMAGE      * im,
                      XWDFileHeader * h )
{
    char buf[ 128 ];

    if ( ! ( im->info = fl_malloc( 1024 ) ) )
        return;

    sprintf( im->info, "file_version=%ld\nheader_size=%ld\n",
             ( long ) h->file_version, ( long ) h->header_size );
    sprintf( buf, "visual_class=%d\nbits_per_pixel=%d\nncolors=%d",
             ( int ) h->visual_class, ( int ) h->bits_per_pixel,
             ( int ) h->ncolors );
    strcat( im->info, buf );
    sprintf( buf, "PixmapDepth=%d\nPixmapWidth=%d\nPixmapHeight=%d",
             ( int ) h->bits_per_pixel, ( int ) h->pixmap_width,
             ( int ) h->pixmap_height );
    strcat( im->info, buf );
    sprintf( buf, "red_mask=0x%x\n green_mask=0x%x\n blue_mask=0x%x\n",
             ( int ) h->red_mask, ( int ) h->green_mask, ( int ) h->blue_mask );
    strcat( im->info, buf );
}


/***************************************
 ***************************************/

static int
XWD_description( FL_IMAGE * im )
{
    SPEC *sp = fl_malloc(sizeof *sp );
    XWDFileHeader *header = &sp->header;
    FILE *fp = im->fpin;
    int k;

    im->io_spec = sp;
    im->spec_size = sizeof *sp;

    if ( fread( header, 1, sizeof *header, fp ) != sizeof *header )
        M_err( "ImageXWD", "failure to read from file" );

    if ( ( sp->swap = need_swap ) )
        swap_header( header );

    fli_rgbmask_to_shifts( header->red_mask,   &sp->rshifts, &sp->rbits );
    fli_rgbmask_to_shifts( header->green_mask, &sp->gshifts, &sp->gbits );
    fli_rgbmask_to_shifts( header->blue_mask,  &sp->bshifts, &sp->bbits );

    if ( sp->gbits > ( unsigned int ) FL_PCBITS )
    {
        sp->rshifts += sp->rbits - FL_PCBITS;
        sp->gshifts += sp->gbits - FL_PCBITS;
        sp->bshifts += sp->bbits - FL_PCBITS;
    }

    /* print header info */

    if ( im->setup->header_info )
        generate_header_info( im, header );

#if XWDDEBUG
    dumpheader( "Description", header );
#endif

    if ( ( k = header->header_size - sizeof *header ) > 0 )
        k = fread( sp->name, 1, k, fp );
    if ( k >= 0 )
        sp->name[ k ] = '\0';

    /* image type */

    if (    header->visual_class == StaticGray
         || header->visual_class == GrayScale )
    {
        im->type = header->pixmap_depth == 1 ? FL_IMAGE_MONO : FL_IMAGE_GRAY;
        if ( header->bits_per_pixel > 8 )
        {
            im->type = FL_IMAGE_GRAY16;
            im->gray_maxval = ( 1 << header->bits_per_pixel ) - 1;
        }
    }
    else if (    header->visual_class == TrueColor
              || header->visual_class == DirectColor )
        im->type = FL_IMAGE_RGB;
    else
    {
        im->type = FL_IMAGE_CI;
        if ( header->ncolors == 0 )
            M_err( "ImageXWD", "no colormap ?" );
    }

    im->w = header->pixmap_width;
    im->h = header->pixmap_height;
    im->map_len = header->ncolors;

    return 0;
}


/***************************************
 ***************************************/

static int
XWD_read_pixels( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;
    XWDFileHeader *h = &sp->header;
    FILE *fp = im->fpin;
    unsigned short us;
    unsigned int u32,
                 n,
                 r,
                 g,
                 b,
                 rn,
                 gn,
                 bn;
    unsigned char *uc;
    int x,
        y,
        i,
        err;
    int ( * get32 )( FILE * ),
        ( * get16 )( FILE * );

    fseek( fp, sp->header.header_size, SEEK_SET );
    im->completed = 0;
    im->visual_cue( im, "Loading XWD" );

    if ( sp->gbits < FL_PCBITS )
    {
        rn = FL_PCBITS - sp->rbits;
        gn = FL_PCBITS - sp->gbits;
        bn = FL_PCBITS - sp->bbits;
    }
    else
        rn = gn = bn = 0;

    if ( h->byte_order == MSBFirst )
    {
        get32 = fli_fget4MSBF;
        get16 = fli_fget2MSBF;
    }
    else
    {
        get32 = fli_fget4LSBF;
        get16 = fli_fget2LSBF;
    }

    /* read the colormap */

    if ( h->ncolors > 0 )
    {
        XWDColor *xwdcolor = fl_malloc( h->ncolors * sizeof *xwdcolor );

        if (    fread( xwdcolor, sizeof *xwdcolor, h->ncolors, fp )
                                                                 == h->ncolors
             && h->visual_class != TrueColor && h->visual_class != DirectColor )
        {
            for ( i = 0; i < ( int ) h->ncolors; i++ )
            {
                if ( sp->swap )
                {
                    im->red_lut[   i ] = swap16( xwdcolor[ i ].red   ) >> 8;
                    im->green_lut[ i ] = swap16( xwdcolor[ i ].green ) >> 8;
                    im->blue_lut[  i ] = swap16( xwdcolor[ i ].blue  ) >> 8;
                }
                else
                {
                    im->red_lut[   i ] = ( xwdcolor[ i ].red   ) >> 8;
                    im->green_lut[ i ] = ( xwdcolor[ i ].green ) >> 8;
                    im->blue_lut[  i ] = ( xwdcolor[ i ].blue  ) >> 8;
                }
            }
        }

        fl_free( xwdcolor );
    }

    if ( feof( fp ) || ferror( fp ) )
    {
        im->error_message( im, "premature EOF ?" );
        return -1;
    }

    /* reading the pixels */

    y = err = 0;

    switch ( h->bits_per_pixel )
    {
        case 32 :
            for ( y = 0; !err && y < im->h; y++ )
            {
                for ( x = 0; x < im->w; x++ )
                {
                    u32 = get32( fp );
                    im->red[   y ][ x ] =
                                         ( u32 & h->red_mask   ) >> sp->rshifts;
                    im->green[ y ][ x ] =
                                         ( u32 & h->green_mask ) >> sp->gshifts;
                    im->blue[  y ][ x ] =
                                         ( u32 & h->blue_mask  ) >> sp->bshifts;
                }

                for ( n = im->w * 4; n < h->bytes_per_line; n++ )
                    getc( fp );

                err = feof( fp ) || ferror( fp );
            }
            break;

        case 8 :
            if (    h->visual_class == TrueColor
                 || h->visual_class == DirectColor )
            {
                for ( err = 0, y = 0; !err && y < im->h; y++ )
                {
                    for ( x = 0; x < im->w; x++ )
                    {
                        us = getc( fp );
                        r = ( us & h->red_mask   ) >> sp->rshifts;
                        g = ( us & h->green_mask ) >> sp->gshifts;
                        b = ( us & h->blue_mask  ) >> sp->bshifts;

                        /* normalize. */

                        im->red[   y ][ x ] = ( ( r + 1 ) << rn ) - 1;
                        im->green[ y ][ x ] = ( ( g + 1 ) << gn ) - 1;
                        im->blue[  y ][ x ] = ( ( b + 1 ) << bn ) - 1;
                    }

                    for ( ; x < ( int ) h->bytes_per_line; x++ )
                        getc( fp );

                    err = feof( fp ) || ferror( fp );
                }
            }
            else
            {
                for ( y = 0; !err && y < im->h; y++ )
                {
                    for ( x = 0; x < im->w; x++ )
                        im->ci[ y ][ x ] = getc( fp );

                    for ( ; x < (int)h->bytes_per_line; x++ )
                        getc( fp );

                    err = feof( fp ) || ferror( fp );
                }
            }
            break;

        case 16 :
            if (    h->visual_class == TrueColor
                 || h->visual_class == DirectColor )
            {
                for ( err = 0, y = 0; ! err && y < im->h; y++ )
                {
                    for ( x = 0; x < im->w; x++ )
                    {
                        us = get16( fp );
                        r = ( us & h->red_mask   ) >> sp->rshifts;
                        g = ( us & h->green_mask ) >> sp->gshifts;
                        b = ( us & h->blue_mask  ) >> sp->bshifts;

                        /* normalize. */

                        im->red[   y ][ x ] = ( ( r + 1 ) << rn ) - 1;
                        im->green[ y ][ x ] = ( ( g + 1 ) << gn ) - 1;
                        im->blue[  y ][ x ] = ( ( b + 1 ) << bn ) - 1;
                    }

                    for ( x = im->w * 2; x < ( int ) h->bytes_per_line; x++ )
                        getc( fp );

                    err = feof( fp ) || ferror( fp );
                }
            }
            else
            {
                for ( y = 0; !err && y < im->h; y++ )
                {
                    for ( x = 0; x < im->w; x++ )
                        im->ci[ y ][ x ] = get16( fp );

                    for ( ; x < ( int ) h->bytes_per_line; x++ )
                        getc( fp );

                    err = feof( fp ) || ferror( fp );
                }
            }
            break;

        case 1 :
            uc = fl_malloc( h->bytes_per_line );
            for ( y = 0; y < im->h; y++ )
            {
                if ( fread( uc, 1, h->bytes_per_line, fp )
                                                         != h->bytes_per_line )
                {
                    M_err( "LoadXWD", "failure to read from file" );
                    err = 1;
                    break;
                }

                unpack_bits( im->ci[y], uc, h->bytes_per_line );
            }

            fl_free( uc );
            break;

        default:
            M_err( "LoadXWD", "%d bpp not implemented\n", h->bits_per_pixel );
            err = 1;
            break;
    }

    if ( ! err )
    {
        im->completed = im->total;
        im->visual_cue( im, "Done Loading XWD" );
    }

    return err ? ( y < im->h / 2 ? -1 : y ) : 0;
}

/*********** output routines ************************************/

/***************************************
 ***************************************/

static int
detect_endian( void )
{
    short a = 0x1234;
    unsigned char *uc = ( unsigned char * ) &a;

    return ( uc[ 0 ] == 0x12 && uc[ 1 ] == 0x34 ) ? MSBFirst : LSBFirst;
}


/***************************************
 ***************************************/

static int
XWD_write_image( FL_IMAGE * im )
{
    XWDFileHeader header,
                  *h;
    FILE *fp = im->fpout;
    int x,
        y,
        n;
    CARD32 *c32;
    int ( * write32 )( int, FILE * ),
        ( * write16 )( int, FILE * );
    unsigned char *uc;
    static int machine_endian = -1;

    if ( machine_endian < 0 )
        machine_endian = detect_endian( );

    /* some programs expect MSBF always. Force it */

    machine_endian = MSBFirst;

    /* make the header */

    h = &header;
    memset( h, 0, sizeof *h );

    h->header_size = sizeof *h + strlen( im->outfile ) + 1;
    h->file_version = XWD_FILE_VERSION;
    h->pixmap_format = im->type == FL_IMAGE_MONO ? XYBitmap : ZPixmap;
    h->pixmap_width = im->w;
    h->pixmap_height = im->h;

    h->byte_order = machine_endian;
    h->bitmap_bit_order = h->byte_order;

    h->red_mask = FL_RMASK;
    h->green_mask = FL_GMASK;
    h->blue_mask = FL_BMASK;
    h->colormap_entries = h->ncolors = im->map_len;

    h->window_width = h->pixmap_width;
    h->window_height = h->pixmap_height;
    h->window_x = h->window_y = h->window_bdrwidth = 0;

    /* type specific stuff */

    if ( FL_IsRGB( im ) )
    {
        h->pixmap_depth = 24;
        h->bits_per_pixel = 32;
        h->bitmap_unit = 32;
        h->bitmap_pad = 32;
        h->visual_class = TrueColor;
    }
    else if ( im->type == FL_IMAGE_CI || im->type == FL_IMAGE_GRAY )
    {
        h->pixmap_depth = 8;
        h->bits_per_pixel = 8;
        h->bitmap_unit = 8;
        h->bitmap_pad = 8;
        h->visual_class = FL_IsGray( im->type ) ? GrayScale : PseudoColor;
    }
    else if ( im->type == FL_IMAGE_GRAY16 )
    {
        h->pixmap_depth = value_to_bits( im->gray_maxval + 1 );
        h->bits_per_pixel = 16;
        h->bitmap_unit = 16;
        h->bitmap_pad = 16;
        h->visual_class = GrayScale;
    }
    else if ( im->type == FL_IMAGE_MONO )
    {
        h->pixmap_depth = 1;
        h->bits_per_pixel = 1;
        h->bitmap_unit = 8;
        h->bitmap_pad = 8;
        h->visual_class = StaticGray;
    }

    h->bits_per_rgb = h->pixmap_depth;
    h->bytes_per_line = ( im->w * h->bits_per_pixel + 7 ) / 8;

    if ( h->byte_order == MSBFirst )
    {
        write32 = fli_fput4MSBF;
        write16 = fli_fput2MSBF;
    }
    else
    {
        write32 = fli_fput4LSBF;
        write16 = fli_fput2LSBF;
    }

    /* write the header */

    c32 = ( CARD32 * ) h;

    for ( n = 0; ( size_t ) n < sizeof *h / sizeof h->file_version; n++, c32++ )
        write32( *c32, fp );

    fwrite( im->outfile, 1, strlen( im->outfile ) + 1, fp );

    if ( h->ncolors )
    {
        XWDColor xwdcolor;

        xwdcolor.flags = DoRed | DoGreen | DoBlue;

        for ( n = 0; n < ( int ) h->ncolors; n++ )
        {
            int pad;

            xwdcolor.red   = ( im->red_lut[   n ] << 8 ) | 0xff;
            xwdcolor.green = ( im->green_lut[ n ] << 8 ) | 0xff;
            xwdcolor.blue  = ( im->blue_lut[  n ] << 8 ) | 0xff;

            xwdcolor.pixel = n;
            write32( xwdcolor.pixel, fp );
            write16( xwdcolor.red, fp );
            write16( xwdcolor.green, fp );
            write16( xwdcolor.blue, fp );
            putc( xwdcolor.flags, fp );

            /* pad */

            pad = sizeof xwdcolor - 11;
            for ( ; --pad >= 0; )
                putc( 0, fp );
        }
    }

    if ( im->type == FL_IMAGE_RGB )
    {
        for ( y = 0; y < im->h; y++ )
        {
            for ( x = 0; x < im->w; x++ )
                write32( FL_PACK( im->red[   y ][ x ],
                                  im->green[ y ][ x ],
                                  im->blue[  y ][ x ] ),
                         fp );
        }
    }
    else if ( im->type == FL_IMAGE_CI || im->type == FL_IMAGE_GRAY )
    {
        uc = fl_malloc( h->bytes_per_line );

        for ( y = 0; y < im->h; y++ )
        {
            for ( x = 0; x < im->w; x++ )
                uc[ x ] = im->ci[ y ][ x ];
            fwrite( uc, 1, h->bytes_per_line, fp );
        }

        fl_free( uc );
    }
    else if ( im->type == FL_IMAGE_GRAY16 )
    {
        for ( y = 0; y < im->h; y++ )
            for ( x = 0; x < im->w; x++ )
                write16( im->gray[ y ][ x ], fp );
    }
    else if ( im->type == FL_IMAGE_MONO )
    {
        uc = fl_malloc( h->bytes_per_line );

        for ( y = 0; y < im->h; y++ )
        {
            pack_bits( uc, im->ci[ y ], im->w );
            fwrite( uc, 1, h->bytes_per_line, fp );
        }

        fl_free( uc );
    }
    else
    {
        im->error_message( im, "Unknown type" );
        return -1;
    }

    return 0;
}


/***************************************
 ***************************************/

void
flimage_enable_xwd( void )
{
    flimage_add_format( "X Window Dump", "xwd", "xwd",
                        FL_IMAGE_FLEX & ~FL_IMAGE_PACKED,
                        XWD_identify, XWD_description,
                        XWD_read_pixels, XWD_write_image );
}


/***************************************
 ***************************************/

static unsigned int
value_to_bits( unsigned int val )
{
    unsigned int i;

    for ( i = 1; ( 1u << i ) < val; i++ )
        /* empty */ ;

    return i;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
