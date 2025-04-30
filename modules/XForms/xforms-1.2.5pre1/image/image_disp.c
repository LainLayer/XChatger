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
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 * Image display.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "flimage.h"
#include "flimage_int.h"

#define IMAGEDEBUG  0
#define TRACE       0

static int count_repeats_and_shared( unsigned long *,
                                     int );
static int fl_display_ci( FL_IMAGE * im,
                          Window     win );
static int fl_display_gray( FL_IMAGE * im,
                            Window     win );
static int fl_display_rgb( FL_IMAGE * im,
                           Window     win );
static int fl_display_packed( FL_IMAGE * im,
                              Window     win );
static int do_quantization( FL_IMAGE *,
                            Colormap,
                            int,
                            unsigned short ** );



/***************************************
 * Try to allocate all colors
 ***************************************/

static unsigned long *
get_colors( Colormap   colormap,
            int      * red_lut,
            int      * green_lut,
            int      * blue_lut,
            int        map_len,
            int      * allocated )
{
    XColor xc;
    unsigned long *newpixels = 0;
    int npixels,
        i;

    *allocated = 0;

    if ( map_len <= 0 )
    {
        M_err( "get_colors", "bad map length %d\n", map_len );
        return 0;
    }

    if ( ! ( newpixels = fl_malloc( map_len * sizeof *newpixels ) ) )
    {
        M_err( "get_colors", "malloc failed while getting colors" );
        return 0;
    }

    xc.flags = DoRed | DoGreen | DoBlue;

    for ( npixels = i = 0; i < map_len; i++ )
    {
        xc.red   = ( red_lut[   i ] << 8 ) | 0xff;
        xc.green = ( green_lut[ i ] << 8 ) | 0xff;
        xc.blue  = ( blue_lut[  i ] << 8 ) | 0xff;
        if ( XAllocColor( fl_display, colormap, &xc ) )
            newpixels[ npixels++ ] = xc.pixel;
    }

    *allocated = npixels;
    return newpixels;
}


/***************************************
 * Allocate colors. If not enough color, use substitutions
 ***************************************/

static void
get_all_colors( FL_IMAGE      * im,
                unsigned long   newpix[ ],
                int           * npix,
                XColor          xc[ ] )
{
    int i,
        max_colors = 1 << im->depth,
        n;

    for ( i = n = *npix = 0; i < im->map_len; i++ )
    {
        xc[ i ].flags = DoRed | DoGreen | DoBlue;
        xc[ i ].red   = ( im->red_lut[   i ] << 8 ) | 0xff;
        xc[ i ].green = ( im->green_lut[ i ] << 8 ) | 0xff;
        xc[ i ].blue  = ( im->blue_lut[  i ] << 8 ) | 0xff;

        if ( XAllocColor( im->xdisplay, im->xcolormap, xc + i ) )
            newpix[ n++ ] = xc[ i ].pixel;
        else
            xc[ i ].pixel = FL_NoColor;     /* bad pixel marker */
    }

    *npix = n;

    if ( n < im->map_len )
    {
        XColor *mapentry = fl_malloc( max_colors * sizeof *mapentry );

        if ( ! mapentry )
        {
            M_err( "get_all_colors", "malloc failure(%d entries)", max_colors );
            return;
        }

        for ( i = 0; i < max_colors; i++ )
            mapentry[ i ].pixel = i;

        XQueryColors( im->xdisplay, im->xcolormap, mapentry, max_colors );

        for ( i = 0; i < im->map_len; i++ )
            if ( xc[ i ].pixel == FL_NoColor )
                fli_find_closest_color( xc[ i ].red   >> 8,
                                        xc[ i ].green >> 8,
                                        xc[ i ].blue  >> 8,
                                        mapentry, max_colors,
                                        &xc[ i ].pixel );

        fl_free( mapentry );
    }
}


#define RGB2PIXEL_8_OR_LESS( im, r, g, b, s, out )            \
    do  {                                                     \
        unsigned int trr, tgg, tbb;                           \
        trr = ( r ) >> ( 8 - ( s )->rbits );                  \
        tgg = ( g ) >> ( 8 - ( s )->gbits );                  \
        tbb = ( b ) >> ( 8 - ( s )->bbits );                  \
        out =   ( ( trr << ( s )->rshift ) & ( s )->rmask )   \
              | ( ( tgg << ( s )->gshift ) & ( s )->gmask )   \
              | ( ( tbb << ( s )->bshift ) & ( s )->bmask );  \
        if ( im->sdepth == 32 && im->depth == 24 )            \
            out |= 0xff000000;                                \
    } while ( 0 )


/***************************************
 ***************************************/

static unsigned int
rgb2pixel_8bits_or_less( FL_IMAGE     * im,
                         unsigned int   r,
                         unsigned int   g,
                         unsigned int   b,
                         FL_RGB2PIXEL * s )
{
    unsigned int ret;

    RGB2PIXEL_8_OR_LESS( im, r, g, b, s, ret );
    return ret;
}


#define RGB2PIXEL_8_OR_MORE( im, r, g, b, s, out)              \
    do {                                                       \
        unsigned int trr, tgg, tbb;                            \
        trr = ( r ) << ( ( s )->rbits - 8 );                   \
        tgg = ( g ) << ( ( s )->gbits - 8 );                   \
        tbb=  ( b ) << ( ( s )->bbits - 8 );                   \
        out =   ( ( trr << ( s )->rshift ) & ( s )->rmask )    \
              | ( ( tgg << ( s )->gshift ) & ( s )->gmask )    \
              | ( ( tbb << ( s )->bshift ) & ( s )->bmask );   \
        if ( im->sdepth == 32 && im->depth == 24 )             \
            out |= 0xff000000;                                 \
    } while ( 0 )


/***************************************
 ***************************************/

static unsigned int
rgb2pixel_more_than_8bits( FL_IMAGE     * im,
                           unsigned int   r,
                           unsigned int   g,
                           unsigned int   b,
                           FL_RGB2PIXEL * s )
{
    unsigned int ret;

    RGB2PIXEL_8_OR_MORE( im, r, g, b, s, ret );
    return ret;
}


static unsigned int ( * rgb2pixel )( FL_IMAGE *,
                                     unsigned int,
                                     unsigned int,
                                     unsigned int,
                                     FL_RGB2PIXEL * ) = rgb2pixel_8bits_or_less;



/***************************************
 ***************************************/

static int
machine_endian( void )
{
    static unsigned short a = 0x1234;
    static unsigned char *c = ( unsigned char * ) &a;

    return c[ 0 ] == 0x12 ? MSBFirst : LSBFirst;
}


#define SWAP_CHAR( a, b )               \
    do {                                \
        unsigned char tmp_char = a;     \
        a = b;                          \
        b = tmp_char;                   \
    } while ( 0 )


/***************************************
 * display colormapped image: always 8bit color LUT.
 * ASSUMPTIONS: sizeof(int) == 32bits
 ***************************************/

static int
fl_display_ci( FL_IMAGE * im,
               Window     win  FL_UNUSED_ARG )
{
    Colormap xcolormap;
    unsigned long *xmapped = NULL;
    unsigned char *xpixels = NULL,
                  *xpixtmp;
    unsigned short **ci,
                   *ipixels;
    unsigned long newpixels[ FLIMAGE_MAXLUT ];
    XColor xc[ FLIMAGE_MAXLUT ];
    int npixels = 0;
    int i,
        j,
        pad,
        total = im->w * im->h;
    XImage *ximage = 0;

    ci = im->pixels ? im->pixels : im->ci;
    ipixels = ci[ 0 ];

    xcolormap = im->xcolormap;

    pad = im->depth <= 8 ? 8 : ( im->depth <= 16 ? 16 : 32 );

    ximage = XCreateImage( im->xdisplay, im->visual, im->sdepth,
                           ZPixmap, 0, 0, im->w, im->h, pad, 0 );

    if ( ximage )
    {
        xpixels = fl_malloc( im->h * ximage->bytes_per_line * sizeof *xpixels );

        if ( ! xpixels )
            XFree( ximage );
    }

    if ( ! ximage || ! xpixels )
    {
        im->error_message( im, "fl_display_ci: Can't allocate memory" );
        return -1;
    }

    ximage->data = ( char * ) xpixels;

#if IMAGEDEBUG
    M_err( "fl_display_ci", "w=%d bytes_per_line=%d bits_per_pixel=%d",
           im->w, ximage->bytes_per_line, ximage->bits_per_pixel );
#endif

    if ( im->vclass == DirectColor || im->vclass == TrueColor )
    {
        if ( ! ( xmapped = fl_malloc( im->map_len * sizeof *xmapped ) ) )
        {
            XFree( ximage );
            fl_free( xpixels );
            M_err("fl_display_ci", "malloc failed");
            return -1;
        }

#if IMAGEDEBUG
        fprintf( stderr, "rbits: %d gbits: %d bbits: %d\n",
                 im->rgb2p.rbits, im->rgb2p.gbits, im->rgb2p.bbits );
        fprintf( stderr, "rshift: %d gshift: %d bshift: %d\n"a,
                 im->rgb2p.rshift, im->rgb2p.gshift, im->rgb2p.bshift );
#endif

        for ( i = 0; i < im->map_len; i++ )
        {
            xmapped[ i ] = rgb2pixel( im, im->red_lut[ i ],
                                      im->green_lut[ i ],
                                      im->blue_lut[ i ], &im->rgb2p );
            if ( i == im->tran_index && im->depth == 24 && im->sdepth == 32 )
                xmapped[ i ] &= ~ 0xff000000;
        }

        if ( machine_endian( ) != ximage->byte_order )
        {
            unsigned char *rgba = ( unsigned char * ) xmapped;

            if ( ximage->bits_per_pixel == 32 )
            {
                for ( i = 0; i < im->map_len; i++, rgba += 4 )
                {
                    SWAP_CHAR( rgba[ 0 ], rgba[ 3 ] );
                    SWAP_CHAR( rgba[ 1 ], rgba[ 2 ] );
                }
            }
            else if ( ximage->bits_per_pixel == 16 )
                for ( i = 0; i < im->map_len; i++, rgba += 2 )
                    SWAP_CHAR( rgba[ 0 ], rgba[ 1 ] );
        }

        if ( ximage->bits_per_pixel == 32 )
        {
            unsigned int *ltmp = ( unsigned int * ) xpixels;

            for ( i = 0; i < total; i++ )
                *ltmp++ = xmapped[ ipixels[ i ] ];
        }
        else if ( ximage->bits_per_pixel == 16)
        {
            unsigned short *stmp = ( unsigned short * ) xpixels;

            for ( i = 0; i < total; i++ )
                *stmp++ = ( unsigned short ) xmapped[ ipixels[ i ] ];
        }
        else if ( ximage->bits_per_pixel == 8 )
        {
            unsigned char *ctmp = xpixels;

            for ( i = 0; i < total; i++ )
                *ctmp++ = ( unsigned char ) xmapped[ ipixels[ i ] ];

        }
        else if ( ximage->bits_per_pixel == 24 )
        {
            unsigned char *tt = xpixels,
                          *tmp3;
            unsigned int xcol;

            for ( j = 0; j < im->h; j++, tt += ximage->bytes_per_line )
                for ( i = 0, tmp3 = tt; i < im->w; i++ )
                {
                    xcol = xmapped[ci[ j ][ i ] ];
                    if ( ximage->byte_order == MSBFirst )
                    {
                        *tmp3++ = ( xcol >> 16 ) & 0xff;
                        *tmp3++ = ( xcol >>  8 ) & 0xff;
                        *tmp3++ = ( xcol       ) & 0xff;
                    }
                    else
                    {
                        *tmp3++ = ( xcol       ) & 0xff;
                        *tmp3++ = ( xcol >>  8 ) & 0xff;
                        *tmp3++ = ( xcol >> 16 ) & 0xff;
                    }
                }
        }
        else
        {
            im->error_message( im, "fl_display_ci: unhandled non-byte-aligned "
                               "pixel" );
            return -1;
        }
    }
    else if ( im->vclass == GrayScale || im->vclass == StaticGray )
    {
        int gray;

        npixels = 0;

#if IMAGEDEBUG
        M_err( "fl_display_ci", "Grayscale: maplen=%d", im->map_len );
#endif

        for ( i = 0; i < im->map_len; i++ )
        {
            xc[ i ].flags = DoRed | DoGreen | DoBlue;
            gray = FL_RGB2GRAY( im->red_lut[   i ],
                                im->green_lut[ i ],
                                im->blue_lut[  i ]);
            xc[ i ].red = xc[ i ].green = xc[ i ].blue = ( gray << 8 ) | 0xff;
        }

        get_all_colors( im, newpixels, &npixels, xc );
        im->colors = npixels;

#if TRACE
        M_err( "fl_display_ci", "Done colormap" );
#endif

        if ( ximage->bits_per_pixel == 1 )
        {
            int bit, k;

            for ( i = 0; i < im->h; i++ )
            {
                xpixtmp = xpixels + ( i * ximage->bytes_per_line );

                for ( k = bit = j = 0; j < im->w; j++ )
                {
                    k = ( k << 1 ) | xc[ ci[ i ][ j ] ].pixel;
                    if ( ++bit == 8 )
                    {
                        *xpixtmp++ = k;
                        k = bit = 0;
                    }
                }

                if ( bit )
                {
                    k <<= ( 8 - bit );
                    *xpixtmp++ = k;
                }
            }
        }
        else if ( ximage->bits_per_pixel == 8 )
        {
#if TRACE
            M_err( "fl_display_ci", "Converting %d pixels", im->w * im->h );
#endif

            for ( i = 0, total = im->w * im->h; i < total; i++ )
                xpixels[ i ] = ( unsigned char ) xc[ ipixels[ i ] ].pixel;
        }
        else
            M_err( "fl_display_ci", "unhandled bits_per_pixel=%d depth=%d",
                   ximage->bits_per_pixel, im->depth );
    }
    else if ( im->vclass == StaticColor || im->vclass == PseudoColor )
    {
        /* Get all needed colors, use substituion if necessary */

        get_all_colors( im, newpixels, &npixels, xc );
        im->colors = npixels;

        if ( ximage->bits_per_pixel == 8 )
            for ( i = 0; i < total; i++ )
                xpixels[ i ] = ( unsigned char ) xc[ ipixels[ i ] ].pixel;
        else
            M_err( "fl_display_ci", "unhandled bits_per_pixel=%d depth=%d",
                   ximage->bits_per_pixel, im->depth );
    }
    else
        M_err( "fl_display_ci", "unhandled visual class" );

#if TRACE
    M_err( "fl_display_ci", "about to XPutImage" );
#endif

    if ( ximage && ximage->data )
        im->ximage = ximage;
    else
        fprintf( stderr, "no image\n" );

    if ( npixels )
        XFreeColors( im->xdisplay, xcolormap, newpixels, npixels, 0 );

    if ( xmapped )
        fl_free( xmapped );

#if TRACE
    M_err( "fl_display_ci", "Leaving" );
#endif

    return 0;
}


/***************************************
 * do window levelling
 ***************************************/

static void
window_levelling( FL_IMAGE * im )
{
    int upper,
        lower,
        tmp,
        i;
    int npix = im->w * im->h;
    unsigned short *pix = im->pixels[ 0 ];  /* display image  */
    unsigned short *ci = im->gray[ 0 ]; /* original image */
    unsigned short *wlut = im->wlut;
    float fact;

    lower = im->level - im->wwidth / 2;
    upper = im->level + im->wwidth / 2;

    if ( im->wwidth <= 0 )
    {
        lower = 0;
        upper = im->gray_maxval;
    }

    if ( lower < 0 )
        lower = 0;

    fact = ( im->map_len - 0.999f ) / ( upper - lower );

    for ( i = 0; i <= im->gray_maxval; i++ )
    {
        tmp = i < lower ? lower : ( i > upper ? upper : i );
        wlut[ i ] = ( unsigned short ) ( ( tmp - lower ) * fact );
    }

    for ( i = 0; i < npix; i++ )
        pix[ i ] = wlut[ ci[ i ] ];
}


/***************************************
 ***************************************/

static int
fl_display_gray( FL_IMAGE * im,
                 Window     win )
{
    int i,
        npix = im->w * im->h;
    float fact,
        scale;
    float graymax;      /* what the display can display */
    unsigned short *pix;
    unsigned short *ci = im->gray[ 0 ];

#if TRACE
    M_err( "DisplayGray", "Entering" );
#endif

    /* To avoid scaling of the original data, we create display type */

    if ( ! ( im->pixels = fl_get_matrix( im->h, im->w, sizeof **im->pixels ) ) )
    {
        M_err( "DisplayGray", "can't get memory" );
        return -1;
    }

    pix = im->pixels[ 0 ];
    im->display_type = FL_IMAGE_CI;

    /* graymax takes care of 12bit gray displays */

    if ( im->vclass == DirectColor || im->vclass == TrueColor )
    {
        if ( im->rgb2p.bbits > FL_PCBITS )
            im->map_len = 1 << im->rgb2p.bbits;
        else
            im->map_len = 1 << FL_PCBITS;
    }
    else
    {
        im->map_len = 1 << im->depth;
        if ( im->map_len > 250 )
            im->map_len -= 20;
        else if ( im->map_len == 0 )
            im->map_len = FLIMAGE_MAXLUT;
    }

    flimage_getcolormap( im );

    if ( im->rgb2p.bbits > FL_PCBITS )
        graymax = ( float )( ( 1 << im->rgb2p.bbits ) - 1 );
    else
        graymax = 255.0;    /* (1 << FL_PCBITS) - 1; */

    fact = ( graymax + 0.001 ) / ( im->map_len - 1 );
    scale = ( im->map_len - 1 ) / ( graymax - 0.001 );

    for ( i = 0; i < im->map_len; i++ )
        im->red_lut[ i ] = im->green_lut[ i ] = im->blue_lut[ i ] =
            ( int )( i * fact );

    if ( im->type == FL_IMAGE_GRAY16 )
        window_levelling( im );
    else
    {
        /* 8bit grayscale */

        if ( im->map_len != 256 )
        {
            unsigned short *wlut = im->wlut;

            for ( i = 0; i < 256; i++ )
                wlut[ i ] = ( unsigned short ) ( i * scale );

            for ( i = 0; i < npix; i++ )
                pix[i] = wlut[ ci[ i ] ];
        }
        else
            memcpy( pix, ci, npix * sizeof *ci );
    }

    fl_display_ci( im, win );

#if TRACE
    M_err( "DisplayGray", "Leaving" );
#endif

    return 0;
}


#define RGBTOPIXEL( type )                                               \
    do {                                                                 \
        type *ltmp = ( type * ) xpixels;                                 \
        if ( im->rgb2p.rbits > 8 )                                       \
            for ( i = 0; i < total; ltmp++, i++ )                        \
            {                                                            \
                RGB2PIXEL_8_OR_MORE( im, red[ i ],green[ i ],blue[ i ],  \
                                     &im->rgb2p, *ltmp );                \
                if (    im->depth == 24 && im->sdepth == 32              \
                     && i == im->tran_index )                            \
                    *ltmp &= ~ 0xff000000;                               \
            }                                                            \
        else                                                             \
            for ( i = 0; i < total; ltmp++, i++ )                        \
            {                                                            \
                RGB2PIXEL_8_OR_LESS( im, red[ i ],green[ i ],blue[ i ],  \
                                     &im->rgb2p, *ltmp );                \
                if (    im->depth == 24 && im->sdepth == 32              \
                     && i == im->tran_index )                            \
                    *ltmp &= ~ 0xff000000;                               \
            }                                                            \
    } while ( 0 )


/***************************************
 ***************************************/

static int
fl_display_rgb( FL_IMAGE * im,
                Window     win  FL_UNUSED_ARG )
{
    unsigned char *xpixels;
    int total = im->w * im->h;
    XImage *ximage = 0;
    unsigned char *red   = im->red[   0 ],
                  *green = im->green[ 0 ],
                  *blue  = im->blue[  0 ];
    int w = im->w,
        h = im->h;

    if ( im->vclass == DirectColor || im->vclass == TrueColor )
    {
        int i;

        /* Use minimum possible padding */

        int pad = im->depth <= 8 ? 8 : ( im->depth <= 16 ? 16 : 32 );
        ximage = XCreateImage( im->xdisplay, im->visual, im->sdepth,
                               ZPixmap, 0, 0, w, h, pad, 0 );

        if ( ximage->bits_per_pixel % 8 )
        {
            im->error_message( im, "can't handle non-byte aligned pixel" );
            return -1;
        }

#if IMAGEDEBUG
        fprintf( stderr, "XBytesPerLine: %d BitsPerPixel=%d\n",
                 ximage->bytes_per_line, ximage->bits_per_pixel );
#endif

        xpixels = fl_malloc( h * ximage->bytes_per_line * sizeof *xpixels );

        if ( ! xpixels )
        {
            flimage_error( im, "malloc() failed" );
            return -1;
        }

        ximage->data = ( char * ) xpixels;

        if ( ximage->bits_per_pixel == 32 )
        {
            RGBTOPIXEL( unsigned int );

            if ( machine_endian( ) != ximage->byte_order )
            {
                unsigned char *rgba = ( unsigned char * ) ximage->data;

                for ( i = 0; i < total; i++, rgba += 4 )
                {
                    SWAP_CHAR(rgba[ 0 ], rgba[ 3 ]);
                    SWAP_CHAR(rgba[ 1 ], rgba[ 2 ]);
                }
            }
        }
        else if ( ximage->bits_per_pixel == 16 )
        {
            RGBTOPIXEL( unsigned short );

            if ( machine_endian( ) != ximage->byte_order )
            {
                unsigned char *rgba = ( unsigned char * ) ximage->data;
                int i;

                for ( i = 0; i < total; i++, rgba += 2 )
                    SWAP_CHAR( rgba[ 0 ], rgba[ 1 ] );
            }
        }
        else if ( ximage->bits_per_pixel == 8 )
        {
            RGBTOPIXEL( unsigned char );
        }
        else if ( ximage->bits_per_pixel == 24 )
        {
            unsigned char *tt = ( unsigned char * ) xpixels,
                          *tmp3;
            unsigned int xcol;
            int j;

            for ( j = 0; j < im->h; j++, tt += ximage->bytes_per_line )
            {
                int i;

                if ( ximage->byte_order == MSBFirst )
                    for ( i = 0, tmp3 = tt; i < im->w; i++ )
                    {
                        xcol = rgb2pixel( im, red[ i ], green[ i ], blue[ i ],
                                          &im->rgb2p );
                        *tmp3++ = ( xcol >> 16 ) & 0xff;
                        *tmp3++ = ( xcol >>  8 ) & 0xff;
                        *tmp3++ = ( xcol       ) & 0xff;
                    }
                else
                    for ( i = 0, tmp3 = tt; i < im->w; i++ )
                    {
                        xcol = rgb2pixel( im, red[ i ], green[ i ], blue[ i ],
                                          &im->rgb2p );
                        *tmp3++ = ( xcol       ) & 0xff;
                        *tmp3++ = ( xcol >>  8 ) & 0xff;
                        *tmp3++ = ( xcol >> 16 ) & 0xff;
                    }
            }
        }

        im->ximage = ximage;
    }
    else if ( im->vclass == GrayScale || im->vclass == StaticGray )
    {
        M_err( "fl_display_rgb", "RGB with grayscale display" );
        return -1;
    }
    else if ( im->vclass == PseudoColor || im->vclass == StaticColor )
    {
        M_err( "fl_display_rgb", "Internal error" );
        return -1;
    }
    else
    {
        fprintf( stderr, "ImageDisp: internal color\n" );
        return -1;
    }

    return 0;
}


/***************************************
 ***************************************/

static int
fl_display_packed( FL_IMAGE * im,
                   Window     win )
{
    flimage_convert( im, FL_IMAGE_RGB, 0 );
    return fl_display_rgb( im, win );
}


/***************************************
 * Here we already got the proper XImage. Actually it would be
 * much faster if we create a Pixmap from the XImage. TODO
 ***************************************/

static void
displayXImage( FL_IMAGE * im )
{
    XImage *ximage = im->ximage;
    Colormap xcolormap = im->xcolormap;
    unsigned long newpixels[ FLIMAGE_MAXLUT ];
    XColor xc[ FLIMAGE_MAXLUT ];
    int npix = 0;

    if ( im->vclass != TrueColor && im->vclass != DirectColor )
        get_all_colors( im, newpixels, &npix, xc );

    XPutImage( im->xdisplay, im->win, im->gc, ximage, im->sxd, im->syd,
               im->wxd, im->wyd, im->swd, im->shd );

    if ( npix )
        XFreeColors( im->xdisplay, xcolormap, newpixels, npix, 0 );
}


/***************************************
 * Convert an RGB triple to a pixel
 ***************************************/

unsigned long
flimage_color_to_pixel( FL_IMAGE * im,
                        int        r,
                        int        g,
                        int        b,
                        int      * newpix )
{
    XColor xc;
    static Colormap lastcolormap;
    static XColor *xcolor;
    unsigned long pixel = 0;

    *newpix = 0;

    if ( im->vclass == TrueColor || im->vclass == DirectColor )
        return rgb2pixel( im, r, g, b, &im->rgb2p );
    else
    {
        int max_col;

        xc.flags = DoRed | DoGreen | DoBlue;
        xc.red   = ( r << 8 ) | 0xff;
        xc.green = ( g << 8 ) | 0xff;
        xc.blue  = ( b << 8 ) | 0xff;
        if ( ( *newpix = XAllocColor( im->xdisplay, im->xcolormap, &xc ) ) )
            return xc.pixel;

        /* Search for a closest match */

        max_col = FL_min( 256, 1 << im->depth );
        if ( ! xcolor )
            xcolor = fl_malloc( 256 * sizeof *xcolor );

        /* Not theoretically correct as colormap may have changed
         * since the last time we asked for colors. Take a chance for
         * performace. */

        if ( lastcolormap != im->xcolormap )
        {
            int i;

            for ( i = 0; i < max_col; i++ )
                xcolor[ i ].pixel = i;
            XQueryColors( im->xdisplay, im->xcolormap, xcolor, max_col );
            lastcolormap = im->xcolormap;
        }

        fli_find_closest_color( r, g, b, xcolor, max_col, &pixel );
    }

    return pixel;
}


/***************************************
 ***************************************/

int
flimage_swapbuffer( FL_IMAGE * im )
{
    int sw = im->sw ? im->sw : im->w,
        sh = im->sh ? im->sh : im->h;

    XCopyArea(im->xdisplay, im->pixmap, im->win, im->gc,
              im->sx, im->sy, sw, sh, im->wx, im->wy);
    return 0;
}


/***************************************
 ***************************************/

static void
create_backbuffer( FL_IMAGE  * im,
                   FL_WINDOW   win,
                   int         depth )
{
    if (    depth != im->pixmap_depth
         || im->w > im->pixmap_w || im->pixmap_w > 1200
         || im->h > im->pixmap_h || im->pixmap_h > 1200 )
    {
        if ( im->pixmap )
            XFreePixmap( im->xdisplay, im->pixmap );
        im->pixmap = XCreatePixmap( im->xdisplay, win, im->w, im->h, depth );
        im->pixmap_w = im->w;
        im->pixmap_h = im->h;
        im->pixmap_depth = depth;
        im->modified = 1;
    }
}


/***************************************
 * This function handles display caused by Expose event. If we
 * somehow can get hold of the Expose event, we may only need
 * to re-display part of the image
 ***************************************/

static void
handle_redraw( FL_IMAGE  * im,
               FL_WINDOW   win )
{
    if ( im->double_buffer && im->pixmap )
    {
        im->win = im->pixmap;
        im->display_markers( im );
        im->display_text( im );
        im->win = win;
        flimage_swapbuffer( im );
    }
    else
    {
        im->win = win;
        displayXImage( im );
        im->display_markers( im );
        im->display_text( im );
    }
}


/***************************************
 ***************************************/

static void
adapt_image_to_window( FL_IMAGE          * im,
                       XWindowAttributes * xwa )
{
    FL_RGB2PIXEL *rgb2p = &im->rgb2p;

    rgb2p->bits_per_rgb = xwa->visual->bits_per_rgb;
    rgb2p->colormap_size = xwa->visual->map_entries;

#if IMAGEDEBUG
    fprintf( stderr, "bits_per_rgb=%d mapsize=%d\n",
             im->rgb2p.bits_per_rgb, im->rgb2p.colormap_size );
#endif

    rgb2p->rmask = xwa->visual->red_mask;
    rgb2p->gmask = xwa->visual->green_mask;
    rgb2p->bmask = xwa->visual->blue_mask;
    im->depth  = im->sdepth = xwa->depth;
    im->vclass = xwa->visual->class;
    im->visual = xwa->visual;
    im->xcolormap = xwa->colormap;
    fli_rgbmask_to_shifts( rgb2p->rmask, &rgb2p->rshift, &rgb2p->rbits );
    fli_rgbmask_to_shifts( rgb2p->gmask, &rgb2p->gshift, &rgb2p->gbits );
    fli_rgbmask_to_shifts( rgb2p->bmask, &rgb2p->bshift, &rgb2p->bbits );
}


#define Compatible( x, im )                             \
    (    ( x ).depth == im->depth                       \
      && ( x ).visual->class == im->vclass              \
      && ( x ).visual->red_mask == im->rgb2p.rmask      \
      && ( x ).visual->green_mask == im->rgb2p.gmask )


/***************************************
 * Convert an FL_IMAGE into an XImage. The converted ximage is
 * im->ximage if successful
 ***************************************/

int
flimage_to_ximage( FL_IMAGE *          im,
                   FL_WINDOW           win,
                   XWindowAttributes * xwa )
{
    unsigned long bk = 0;
    int type,
        ret = 0;

    if ( im->display_type != FL_IMAGE_NONE && im->modified )
    {
        if ( im->pixels )
        {
            fl_free_matrix( im->pixels );
            im->pixels = 0;
        }

        im->display_type = FL_IMAGE_NONE;
    }

    if ( ! xwa )
    {
        static XWindowAttributes tmpxwa;

        XGetWindowAttributes( im->xdisplay, win, &tmpxwa );
        xwa = &tmpxwa;
    }

    /* Handle transparency */

    if ( im->tran_rgb >= 0 && im->app_background >= 0 )
    {
        if ( im->app_background >= 0 )
            bk = im->app_background;

        if (    FL_IsCI( im->type )
             && im->tran_index >= 0
             && im->tran_index < im->map_len )
        {
            int ar,
                ag,
                ab,
                tc = im->tran_index;

            FL_UNPACK3( bk, ar, ag, ab );
            im->red_lut[   tc ] = ar;
            im->green_lut[ tc ] = ag;
            im->blue_lut[  tc ] = ab;
        }
        else
            flimage_replace_pixel( im, im->tran_rgb, bk );
    }

    if ( ! ( im->win == win || Compatible( * xwa, im ) ) )
    {
        adapt_image_to_window( im, xwa );

        if ( im->rgb2p.rbits > 8 || im->rgb2p.gbits > 8 )
            rgb2pixel = rgb2pixel_more_than_8bits;
        else
            rgb2pixel = rgb2pixel_8bits_or_less;
    }

    im->win = win;

    if (    im->depth == 32
         && im->rgb2p.rbits + im->rgb2p.gbits + im->rgb2p.bbits < 32 )
        im->depth = im->rgb2p.rbits + im->rgb2p.gbits + im->rgb2p.bbits;

    /* Prepare the display image */

    if ( im->depth == 1 && im->type != FL_IMAGE_MONO )
    {
        unsigned short **ci;
        int otype = im->type;

        if ( im->type != FL_IMAGE_CI )
        {
            flimage_convert( im, FL_IMAGE_MONO, 2 );
            im->pixels = im->ci;
            im->ci = 0;
        }
        else
        {
            im->pixels = fl_get_matrix( im->h, im->w, sizeof **im->pixels );
            memcpy( im->pixels[ 0 ], im->ci[ 0 ],
                    sizeof **im->ci * im->w * im->h );
            flimage_convert( im, FL_IMAGE_MONO, 2 );
            ci = im->pixels;
            im->pixels = im->ci;
            im->ci = ci;
        }

        im->available_type &= ~ FL_IMAGE_MONO;
        im->type = otype;
        im->display_type = FL_IMAGE_MONO;
        im->available_type |= otype;
    }
    else if (    ( im->vclass == StaticGray || im->vclass == GrayScale )
              && im->depth != 1 && ! FL_IsGray( im->type ) )
    {
        int otype = im->type;

        flimage_convert( im, FL_IMAGE_GRAY, 2 );
        im->type = otype;

        /* this gets reset by fl_display_gray */

        im->display_type = FL_IMAGE_GRAY;
    }
    else if (    ( im->vclass == PseudoColor || im->vclass == StaticColor )
              && im->type == FL_IMAGE_RGB )
    {
        int max_colors = 1 << im->depth;
        unsigned short **ci = fl_get_matrix( im->h, im->w, sizeof **ci );

        if ( max_colors > 250 )
            max_colors -= 20;

        im->map_len = max_colors;
        flimage_getcolormap( im );
        do_quantization( im, im->xcolormap, im->map_len, ci );
        im->pixels = ci;
        im->display_type = FL_IMAGE_CI;
    }

    if ( ( type = im->display_type ) == FL_IMAGE_NONE )
        type = im->type;

    switch ( type )
    {
        case FL_IMAGE_GRAY:
        case FL_IMAGE_GRAY16:
            ret = fl_display_gray( im, win );
            break;

        case FL_IMAGE_CI:
        case FL_IMAGE_MONO:
            ret = fl_display_ci( im, win );
            break;

        case FL_IMAGE_RGB:
            ret = fl_display_rgb( im, win );
            break;

        case FL_IMAGE_PACKED:
            ret = fl_display_packed( im, win );
            break;

        default:
            ret = -1;
    }

    return ret;
}


/***************************************
 * We always keep hi-res image whenever possible. For this reason,
 * the displayed image and the image in memory are not necessarily the
 * same type. When we quantize for display, we do not overwrite the
 * the image, rather we create a displayable image
 ***************************************/

int
flimage_sdisplay( FL_IMAGE * im,
                  Window     win )
{
    XWindowAttributes xwa;
    int ret = 0;

    if ( win <= 0 || !im || im->w <= 0 || im->type == FL_IMAGE_NONE )
        return -1;

    if ( sizeof( int ) != 4 )
    {
        fprintf( stderr, "FatalError: Assumed sizeof(int)==4\n" );
        exit( 1 );
    }

    /* Check for consistent subimage */

    im->sx = FL_clamp( im->sx, 0, im->w );
    im->sy = FL_clamp( im->sy, 0, im->h );
    im->sw = FL_clamp( im->sw, 0, im->w );
    im->sh = FL_clamp( im->sh, 0, im->h );

    if ( im->sx + im->sw > im->w )
        im->sx = im->sw = 0;
    if ( im->sy + im->sh > im->h )
        im->sy = im->sh = 0;

    if ( im->double_buffer )
    {
        im->sxd = im->syd = 0;
        im->swd = im->w;
        im->shd = im->h;
        im->wxd = im->wyd = 0;
    }
    else
    {
        im->sxd = im->sx;
        im->syd = im->sy;
        im->wxd = im->wx;
        im->wyd = im->wy;
        im->swd = im->sw ? im->sw : im->w;
        im->shd = im->sh ? im->sh : im->h;
    }

    XGetWindowAttributes( im->xdisplay, win, &xwa );

    if ( ! im->setup->do_not_clear )
    {
        /* Only clear the minimum region we have to */

        int sw = im->sw ? im->sw : im->w;
        int sh = im->sh ? im->sh : im->h;

        if ( im->wx > 0 )
            XClearArea( im->xdisplay, win, 0, 0, im->wx, 0, 0 );
        if ( im->wy > 0 )
            XClearArea( im->xdisplay, win, 0, 0, 0, im->wy, 0 );

        XClearArea( im->xdisplay, win, im->wx + sw, 0, 0, 0, 0 );
        XClearArea( im->xdisplay, win, 0, im->wy + sh, 0, 0, 0 );
    }

    if ( im->double_buffer )
        create_backbuffer( im, win, xwa.depth );

    /* Check if redraw. Possible optimization: obtain the dirty region  and
       do subimage stuff */

    if (    im->ximage
         && !im->modified
         && (  im->win == win || Compatible( xwa, im ) ) )
    {
        handle_redraw( im, win );
        return 0;
    }

    /* If we got here, we need to re-generate ximage */

    if ( im->ximage )
    {
        XDestroyImage( ( XImage * ) im->ximage );
        im->ximage = None;
    }

    if ( ! Compatible( xwa, im ) )
    {
        if ( im->gc )
            XFreeGC( im->xdisplay, im->gc );

        if ( im->textgc )
            XFreeGC( im->xdisplay, im->textgc );

        im->gc = im->textgc = None;
    }

    if ( ! im->gc )
        im->gc = XCreateGC( im->xdisplay, win, 0, 0 );

    ret = flimage_to_ximage( im, win, &xwa );

    if ( ret >= 0 )
    {
        im->win = im->double_buffer ? im->pixmap : win;

        XPutImage( im->xdisplay, im->win, im->gc, im->ximage,
                   im->sxd, im->syd, im->wxd, im->wyd, im->swd, im->shd );
        im->display_markers( im );
        im->display_text( im );
        im->win = win;

        if ( im->double_buffer )
            flimage_swapbuffer( im );
        im->modified = 0;
    }

    return ret;
}


/***************************************
 * quantize a full color image
 ***************************************/

static int
do_quantization( FL_IMAGE        * im,
                 Colormap          colormap,
                 int               maxcol,
                 unsigned short ** ci )
{
    int empty_slots,
        done,
        repeats;
    unsigned long *newpixels;
    int request = FL_max( maxcol - 4, 1 );

    do
    {
        if ( im->type == FL_IMAGE_RGB )
            flimage_quantize_rgb( im->red, im->green, im->blue, im->w, im->h,
                                  request, ci, &im->map_len, im->red_lut,
                                  im->green_lut, im->blue_lut, im );
        else
            flimage_quantize_packed( im->packed, im->w, im->h, request, ci,
                                     &im->map_len, im->red_lut, im->green_lut,
                                     im->blue_lut, im);

        newpixels = get_colors( colormap,
                                im->red_lut, im->green_lut, im->blue_lut,
                                im->map_len, &empty_slots );

        /* It's better to take a chance of finding similar colors in the
           colormap than reducing the number of colors too much */

        done =    empty_slots == im->map_len
               || empty_slots < 12
               || empty_slots < maxcol / 4;

        if ( ! done )
        {
            repeats = count_repeats_and_shared( newpixels, empty_slots );
            XFreeColors( im->xdisplay, colormap, newpixels, empty_slots, 0 );
            fl_free( newpixels );
            im->map_len = 1;
            request = empty_slots - repeats;
        }
    } while ( ! done );

    if ( empty_slots )
        XFreeColors( im->xdisplay, colormap, newpixels, empty_slots, 0 );
    fl_free( newpixels );

    return newpixels ? 0 : -1;
}


/*****************************************************************
 * local functions
 ***************************************************************/

#define SSS 8

/***************************************
 ***************************************/

static int
count_repeats_and_shared( unsigned long * array,
                          int             len )
{
    int i,
        j,
        n;

    if ( len < 10 )
        return 0;

    /* This does not really count the shared colors, but < 5 is a good guess */

    for ( i = n = 0; i < len - 1; i++ )
        for ( j = i + 1; j < len; j++ )
            if ( array[ i ] == array[ j ] || array[ i ] < SSS )
                n++;

    n += array[ len - 1 ] < SSS;

    return n > 4 ? 4 : n;
}



/***************************************
 ***************************************/

int
flimage_display( FL_IMAGE * in_image,
                 Window     win )
{
    int err = 0;
    FL_IMAGE *im = in_image;

    if ( ! im || im->w <= 0 || win == 0 )
        return -1;

    for ( err = 0; err >= 0 && im; im = im->next )
    {
        im->app_background = in_image->app_background;
        err = flimage_sdisplay( im, win );
        XSync( in_image->xdisplay, 0 );
        if ( in_image->setup->delay )
            fl_msleep( in_image->setup->delay );
    }

    return err;
}


/***************************************
 * convert an XImage into flimage
 ***************************************/

static int
convert_ximage( FL_IMAGE * im,
                XImage   * ximage )
{
    unsigned int rshift,
                 gshift,
                 bshift,
                 delta;
    unsigned int rbits,
                 gbits,
                 bbits;
    unsigned int *ui;
    unsigned short *us;
    unsigned char *uc;
    unsigned int rnorm,
                 gnorm,
                 bnorm,
                 r,
                 g,
                 b;
    int x,
        y;

#if 0
    /* For some reason, red_mask is not always set on some systems.
       This problem makes this conversion unsafe as we're blindingly
       using the red_mask of some arbirary window!
    */

    fli_rgbmask_to_shifts( ximage->red_mask, &rshift, &rbits );
    fli_rgbmask_to_shifts( ximage->green_mask, &gshift, &gbits );
    fli_rgbmask_to_shifts( ximage->blue_mask, &bshift, &bbits );
#else
    ximage->red_mask = im->rgb2p.rmask;
    ximage->green_mask = im->rgb2p.gmask;
    ximage->blue_mask = im->rgb2p.bmask;
    rshift = im->rgb2p.rshift;
    gshift = im->rgb2p.gshift;
    bshift = im->rgb2p.bshift;
    rbits = im->rgb2p.rbits;
    gbits = im->rgb2p.gbits;
    bbits = im->rgb2p.bbits;
#endif
    rnorm = FL_PCBITS - rbits;
    gnorm = FL_PCBITS - gbits;
    bnorm = FL_PCBITS - bbits;

    if ( im->rgb2p.gbits > FL_PCBITS )
    {
        rshift += rbits - FL_PCBITS;
        gshift += gbits - FL_PCBITS;
        bshift += gbits - FL_PCBITS;
        rnorm = gnorm = bnorm = 0;
    }

    if ( ximage->bits_per_pixel != 1 && ximage->bits_per_pixel % 8 )
    {
        M_err( "ConvertImage", "unsupported bpp=%d",
               ximage->bits_per_pixel );
        return -1;
    }

    if ( im->vclass == TrueColor || im->vclass == DirectColor )
        im->type = FL_IMAGE_RGB;
    else
    {
        im->type = im->depth == 1 ? FL_IMAGE_MONO : FL_IMAGE_CI;
        im->map_len = 1 << im->depth;
    }

    im->w = ximage->width;
    im->h = ximage->height;
    flimage_invalidate_pixels( im );

    if ( flimage_getmem( im ) < 0 )
    {
        flimage_error( im, "ConvertXImage(%dX%d): out of memory",
                       im->w, im->h );
        return -1;
    }

    im->modified = 1;

    switch ( ximage->bits_per_pixel )
    {
        case 32:
            ui = ( unsigned int * ) ximage->data;
            delta = ximage->bytes_per_line / 4;
            for ( y = 0; y < im->h; y++ )
            {
                for ( x = 0; x < im->w; x++ )
                {
                    im->red[ y][ x ] =
                                    ( ui[ x ] & ximage->red_mask   ) >> rshift;
                    im->green[ y][ x ] =
                                    ( ui[ x ] & ximage->green_mask ) >> gshift;
                    im->blue[ y][ x ] =
                                    ( ui[ x ] & ximage->blue_mask  ) >> bshift;
                }
                ui += delta;
            }
            im->modified = 1;
            break;

        case 16:
            if ( im->vclass == GrayScale || im->vclass == StaticGray )
            {
                /* Probably very rare */

                M_err( "ConvertXImage", "16bpp grayscale not handled" );
                return -1;
            }

            us = ( unsigned short * ) ximage->data;
            delta = ximage->bytes_per_line / 2;
            for ( y = 0; y < im->h; y++ )
            {
                for ( x = 0; x < im->w; x++ )
                {
                    r = ( us[ x ] & ximage->red_mask   ) >> rshift;
                    g = ( us[ x ] & ximage->green_mask ) >> gshift;
                    b = ( us[ x ] & ximage->blue_mask  ) >> bshift;

                    /* Normalize */

                    im->red[   y ][ x ] = ( ( r + 1 ) << rnorm ) - 1;
                    im->green[ y ][ x ] = ( ( g + 1 ) << gnorm ) - 1;
                    im->blue[  y ][ x ] = ( ( b + 1 ) << bnorm ) - 1;
                }

                us += delta;
            }
            im->modified = 1;
            break;

        case 8:
            uc = ( unsigned char * ) ximage->data;
            if ( im->type == FL_IMAGE_RGB )
            {
                for ( y = 0; y < im->h; y++ )
                {
                    for ( x = 0; x < im->w; x++ )
                    {
                        r = ( uc[ x ] & ximage->red_mask   ) >> rshift;
                        g = ( uc[ x ] & ximage->green_mask ) >> gshift;
                        b = ( uc[ x ] & ximage->blue_mask  ) >> bshift;
                        /* normalize */
                        im->red[   y ][ x ] = ( ( r + 1 ) << rnorm ) - 1;
                        im->green[ y ][ x ] = ( ( g + 1 ) << gnorm ) - 1;
                        im->blue[  y ][ x ] = ( ( b + 1 ) << bnorm ) - 1;
                    }

                    uc += ximage->bytes_per_line;
                }
            }
            else
            {
                XColor xcolor[ 256 ],
                       *xc,
                       *xce;
                int max_colors = 1 << im->depth,
                    pixel;

                for ( x = 0; x < max_colors; x++ )
                    xcolor[ x ].pixel = x;

                XQueryColors( im->xdisplay, im->xcolormap, xcolor, max_colors );

                for ( xc = xcolor, xce = xc + max_colors; xc < xce; xc++ )
                {
                    pixel = xc->pixel;
                    im->red_lut[   pixel ] = xc->red   >> 8;
                    im->green_lut[ pixel ] = xc->green >> 8;
                    im->blue_lut[  pixel ] = xc->blue  >> 8;
                }

                for ( y = 0; y < im->h; y++ )
                {
                    for ( x = 0; x < im->w; x++ )
                        im->ci[ y ][ x ] = uc[ x ];
                    uc += ximage->bytes_per_line;
                }
            }
            break;

        case 1:
            uc = ( unsigned char * ) ximage->data;
            for ( y = 0; y < im->h; y++ )
            {
                unpack_bits( im->ci[ y ], uc, ximage->bytes_per_line );
                uc += ximage->bytes_per_line;
            }
            break;

        default:
            M_err( "XImageConvert", "unsupported bpp %d", ximage->depth );
            im->modified = 0;
            return -1;
    }

    return 0;
}


/***************************************
 * Setup the pixel conversion using the window attributes
 ***************************************/

static int
flimage_from_pixmap_( FL_IMAGE * im,
                      Pixmap     pixmap,
                      int        w,
                      int        h )
{
    XImage *ximage;
    int status;

    if ( w == 0 || h == 0 )
    {
        unsigned int ww,
                     hh,
                     bjunk,
                     djunk;
        int xx,
            yy;
        Window root;

        XGetGeometry( im->xdisplay, pixmap, &root, &xx, &yy, &ww, &hh,
                      &bjunk, &djunk );
        w = ww;
        h = hh;
    }

    /* Turn pixmap into an X image */

    ximage = XGetImage( im->xdisplay, pixmap, 0, 0, w, h, AllPlanes, ZPixmap );
    if ( ! ximage )
    {
        flimage_error( im, "XGetImage() failed" );
        return -1;
    }

    /* It's possible that im may contain nothing if w == h == 0 on input */

    if ( im->rgb2p.rbits == 0 )
    {
        XWindowAttributes xwa;

        XGetWindowAttributes( im->xdisplay, fl_root, &xwa );
        adapt_image_to_window( im, &xwa );
     }

    status = convert_ximage( im, ximage );

    /* The old Ximage is now out of date */

    if ( im->ximage )
        XDestroyImage((XImage *) im->ximage);

    im->ximage = ximage;

    return status;
}


/***************************************
 ***************************************/

int flimage_from_pixmap( FL_IMAGE * im,
                         Pixmap     pixmap )
{
    if ( ! im || !pixmap )
        return -1;

    return flimage_from_pixmap_( im, pixmap, 0, 0 );
}


/***************************************
 ***************************************/

Pixmap flimage_to_pixmap( FL_IMAGE  * im,
                          FL_WINDOW   win )
{
    Pixmap pixmap;
    XWindowAttributes xwa;

    if ( ! im || im->type == FLIMAGE_NONE || win == 0 )
        return 0;

    XGetWindowAttributes( im->xdisplay, win, &xwa );

    if ( ! im->gc )
        im->gc = XCreateGC( im->xdisplay, win, 0, 0 );

    pixmap = XCreatePixmap( im->xdisplay, win, im->w, im->h, xwa.depth );

    if ( flimage_to_ximage( im, win, &xwa ) >= 0 )
        XPutImage( im->xdisplay, pixmap, im->gc, im->ximage,
                   0, 0, 0, 0, im->w, im->h );

    return pixmap;
}


/***************************************
 * Render possible annotations into the the image
 ***************************************/

int
flimage_render_annotation( FL_IMAGE  * im,
                           FL_WINDOW   win )
{
    int status;
    XWindowAttributes xwa;

    if ( ! im || ! win )
        return -1;

    if ( ! im->ntext && ! im->nmarkers )
        return 0;

    XGetWindowAttributes( im->xdisplay, win, &xwa );

    /* Create an offscreen pixmap to hold the image */

    create_backbuffer(im, win, xwa.depth);

    if ( flimage_to_ximage( im, win, &xwa ) < 0 )
        return -1;

    XPutImage( im->xdisplay, im->pixmap, im->gc, im->ximage, 0, 0, 0, 0,
               im->w, im->h );

    im->win = im->pixmap;
    im->display_markers( im );
    im->display_text( im );
    im->win = win;

    status = flimage_from_pixmap_( im, im->pixmap, im->w, im->h );

    im->free_text( im );
    im->free_markers( im );

    return status;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
