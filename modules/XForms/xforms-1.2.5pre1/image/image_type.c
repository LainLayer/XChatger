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
 *  Copyright (c) 1998-2002  By T.C. Zhao
 *  All rights reserved.
 *
 *  image type conversions
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 * Specialized for image processing
 ***************************************/

static int
spline_int_interpolate( const int * wx,
                        const int * wy,
                        int         nin,
                        int         grid,
                        int       * y )
{
    int i,
        j,
        k,
        jo,
        ih,
        im,
        nout;
    double sig,
           p,
           h,
           a,
           b,
           x;
    static int nwork = 0;
    static double *y2 = NULL,
                  *u = NULL;

    if ( nin <= 3 )
    {
        M_warn( "fl_spline_int_interpolate",
                "too few points (less than 4) for interpolation" );
        return -1;
    }

    if ( nwork < nin )
    {
        y2 = fl_realloc( y2, nin * sizeof *y2 );
        u = fl_realloc( u, nin * sizeof *u );
        nwork = nin;
    }

    y2[ 0 ] = u[ 0 ] = 0.0;

    for ( i = 1; i < nin - 1; i++ )
    {
        sig = ( double ) ( wx[ i ] - wx[ i - 1 ] ) /
              ( wx[ i + 1 ] - wx[ i - 1 ] );
        p = sig * y2[ i - 1 ] + 2.0;
        y2[ i ] = ( sig - 1.0 ) / p;
        u[ i ] =   ( double ) ( wy[ i + 1 ] - wy[ i ] ) /
                              ( wx[ i + 1 ] - wx[ i ] )
                 - ( double ) ( wy[ i ] - wy[ i - 1 ] ) /
                              ( wx[ i ] - wx[ i - 1 ] );
        u[ i ] = (   6.0 * u[ i ] / ( wx[ i + 1 ] - wx[ i - 1 ] )
                   - sig * u[ i - 1 ] ) / p;
    }

    y2[ nin - 1 ] = 0.0;
    for ( k = nin - 2; k >= 0; k-- )
        y2[ k ] = y2[ k ] * y2[ k + 1 ] + u[ k ];

    /* Outputs */

    nout = ( int ) ( ( wx[ nin - 1 ] - wx[ 0 ] ) / grid + 1.01 );

    y[ 0 ] = wy[ 0 ];

    /* Start the main loop */

    for ( jo = 0, i = 1; i < nout; i++ )
    {
        x = wx[ 0 ] + i * grid;

        /* Center */

        j = jo;
        ih = nin - 1;
        while ( ih - j > 1 )
        {
            im = ( ih + j ) / 2;
            if ( x > wx[ im ] )
                j = im;
            else
                ih = im;
        }

        jo = j;

        /* Interpolate */

        h = wx[ ih ] - wx[ j ];
        a = ( wx[ ih ] - x ) / h;
        b = ( x - wx[ j ] ) / h;

        y[i] = ( a * wy[ j ] + b * wy[ ih ]
                 + ( ( a * a * a - a ) * y2[ j ]
                     + ( b * b * b - b ) * y2[ ih ] )
                 * ( h * h ) / 6.0 ) + 0.1;

        /* Clamp */

        if ( y[ i ] < 0 )
            y[ i ] = 0;
        else if ( y[ i ] > FL_PCMAX )
            y[ i ] = FL_PCMAX;
    }

    y[ nout - 1 ] = wy[ nin - 1 ];
    return nout;
}


/***********************************************************************
 * convert image types
 ***********************************************************************/

/***********************************************************************
 * to rgba image
 *********************************************************************{*/

/***************************************
 ***************************************/

static int
packed_to_rgba( FL_IMAGE * im )
{
    FL_PACKED *packed = im->packed[ 0 ];
    unsigned char *r,
                  *g,
                  *b,
                  *a;
    int i,
        npix;

    r = im->red[   0 ];
    g = im->green[ 0 ];
    b = im->blue[  0 ];
    a = im->alpha[ 0 ];

    for ( i = 0, npix = im->w * im->h; i < npix; i++ )
        FL_UNPACK4( packed[ i ], r[ i ], g[ i ], b[ i ], a[ i ] );

    return 0;
}


/***************************************
 ***************************************/

static int
gray_to_rgba( FL_IMAGE * im )
{
    unsigned short *gray = im->gray[ 0 ];
    unsigned char *r,
                  *g,
                  *b;
    int i,
        npix;

    r = im->red[   0 ];
    g = im->green[ 0 ];
    b = im->blue[  0 ];

    for ( i = 0, npix = im->w * im->h; i < npix; i++ )
        r[ i ] = g[ i ] = b[ i ] = gray[ i ];

    return 0;
}


/***************************************
 ***************************************/

static int
gray16_to_rgba( FL_IMAGE * im )
{
    unsigned short *gray = im->gray[ 0 ];
    unsigned char *r,
                  *g,
                  *b;
    float scale = ( FL_PCMAX + 0.001 ) / im->gray_maxval;
    int i,
        npix;

    r = im->red[   0 ];
    g = im->green[ 0 ];
    b = im->blue[  0 ];

    for ( i = 0, npix = im->w * im->h; i < npix; i++ )
        r[ i ] = g[ i ] = b[ i ] = gray[ i ] * scale;

    return 0;
}


/***************************************
 ***************************************/

static int
ci_to_rgba( FL_IMAGE * im )
{
    unsigned short *ci = im->ci[ 0 ];
    unsigned char *r,
                  *g,
                  *b;
    int k,
        i;

    r = im->red[   0 ];
    g = im->green[ 0 ];
    b = im->blue[ 0 ];

    for ( i = im->w * im->h; --i >= 0; )
    {
        k = ci[ i ];
        r[ i ] = im->red_lut[   k ];
        g[ i ] = im->green_lut[ k ];
        b[ i ] = im->blue_lut[  k ];
    }

    return 0;
}

/*}*********************************************************************
 * to grayscale
 *********************************************************************{*/


/***************************************
 ***************************************/

static int
packed_to_gray( FL_IMAGE * im )
{
    FL_PACKED *packed = im->packed[ 0 ];
    int i,
        total = im->w * im->h;
    unsigned short *gray;

    gray = im->ci[ 0 ];

    for ( i = 0; i < total; i++ )
        gray[ i ] = FL_RGB2GRAY( FL_GETR( packed[ i ] ),
                                 FL_GETG( packed[ i ] ),
                                 FL_GETB( packed[ i ] ) );

    return 0;
}


/***************************************
 ***************************************/

static int
rgba_to_gray( FL_IMAGE * im )
{
    int i,
        total;
    unsigned char *r,
                  *g,
                  *b;
    unsigned short *gray;

    gray = im->gray[ 0 ];

    r = im->red[   0 ];
    g = im->green[ 0 ];
    b = im->blue[  0 ];

    for ( i = 0, total = im->w * im->h; i < total; i++ )
        gray[ i ] = FL_RGB2GRAY( r[ i ], g[ i ], b[ i ] );

    return 0;
}


/***************************************
 ***************************************/

static int
ci_to_gray( FL_IMAGE * im )
{
    unsigned short *ci = im->ci[ 0 ];
    unsigned short *gray = im->gray[ 0 ];
    int i;

    for ( i = im->w * im->h; --i >= 0; )
        gray[i] = FL_RGB2GRAY( im->red_lut[   ci[ i ] ],
                               im->green_lut[ ci[ i ] ],
                               im->blue_lut[  ci[ i ] ] );

    return 0;
}


/*}*********************************************************************
 * Pack an image
 *********************************************************************{*/

/***************************************
 ***************************************/

static int
rgba_to_packed( FL_IMAGE * im )
{
    int npix, i;
    FL_PACKED *p;
    unsigned char *r,
                  *g,
                  *b,
                  *a;

    r = im->red[   0 ];
    g = im->green[ 0 ];
    b = im->blue[  0 ];
    a = im->alpha[ 0 ];

    p = im->packed[ 0 ];

    for ( i = 0, npix = im->w * im->h; i < npix; i++ )
        p[ i ] = FL_PACK4( r[ i ], g[ i ], b[ i ], a[ i ] );

    return 0;
}


/***************************************
 ***************************************/

static int
ci_to_packed( FL_IMAGE * im )
{
    int i;
    FL_PACKED *p;
    unsigned short *ci;

    p = im->packed[ 0 ];
    ci = im->ci[ 0 ];

    for ( i = im->w * im->h; --i >= 0; )
        p[ i ] = FL_PACK4( im->red_lut[   ci[ i ] ],
                           im->green_lut[ ci[ i ] ],
                           im->blue_lut[  ci[ i ] ], 0 );

    return 0;
}


/*}*******************************************************************
 * convert to color index
 *********************************************************************/

/***************************************
 ***************************************/

static int
rgb_to_ci( FL_IMAGE * im )
{
    return flimage_quantize_rgb( im->red, im->green, im->blue,
                                 im->w, im->h,
                                 im->map_len,
                                 im->ci, &im->map_len,
                                 im->red_lut, im->green_lut, im->blue_lut, im );
}


/***************************************
 ***************************************/

static int
packed_to_ci( FL_IMAGE * im )
{
    
    return flimage_quantize_packed( im->packed,
                                    im->w, im->h, im->map_len,
                                    im->ci, &im->map_len,
                                    im->red_lut, im->green_lut, im->blue_lut,
                                    im );
}


/***************************************
 ***************************************/

static int
gray_to_ci( FL_IMAGE * im )
{
    int i;
    float fact = ( FL_PCMAX + 0.001 ) / ( im->map_len - 1.0 );
    float scale = ( im->map_len - 1.0 ) / 254.999;

    for ( i = 0; i < im->map_len; i++ )
        im->red_lut[ i ] = im->green_lut[ i ] = im->blue_lut[ i ] = i * fact;

    if ( im->map_len != 256 )
        for ( i = im->w * im->h; --i >= 0; )
            im->ci[ 0 ][ i ] = im->gray[ 0 ][ i ] * scale;
    else
        for ( i = im->w * im->h; --i >= 0; )
            im->ci[ 0 ][ i ] = im->gray[ 0 ][ i ];

    return 0;
}


/***************************************
 ***************************************/

static void
scale_gray16( unsigned short * g16,
              unsigned short * g,
              int              maxval,
              int              len )
{
    float scale = ( FL_PCMAX + 0.001 ) / maxval;

    while ( --len >= 0 )
        g[ len ] = g16[ len ] * scale;
}


/***************************************
 ***************************************/

static int
gray16_to_gray( FL_IMAGE * im )
{
    scale_gray16( im->gray[ 0 ], im->gray[ 0 ], im->gray_maxval,
                  im->w * im->h );
    return 0;
}


/***************************************
 ***************************************/

static int
gray_to_gray16( FL_IMAGE * im )
{
    im->type = FL_IMAGE_GRAY16;
    im->gray_maxval = 255;
    return 0;
}


/***************************************
 ***************************************/

static int
gray16_to_ci( FL_IMAGE * im )
{
    int i;
    float fact = ( FL_PCMAX + 0.001 ) / ( im->map_len - 1.0 );

    for ( i = 0; i < im->map_len; i++ )
        im->red_lut[ i ] = im->green_lut[ i ] = im->blue_lut[ i ] = i * fact;

    scale_gray16( im->gray[ 0 ], im->ci[ 0 ], im->gray_maxval, im->w * im->h );

    return 0;
}


/*}*********************************************************************
 * Convert an image to B&W (half-toning)
 **********************************************************************/

enum
{
    FS_DITHER,
    ORDERED8,
    DITHER_THRESHOLD
};

static int dither_method = FS_DITHER;
static int dither_threshold = ( 1 << FL_PCBITS ) / 2;


/***************************************
 * do floyd-steinberg dithering
 ***************************************/

static int
fs_dither( unsigned short ** mat,
           int               h,
           int               w,
           unsigned short ** mm )
{
    unsigned short *m,
                   *ras;
    int **tmp,
         *curr,
         *next = NULL;
    int i,
        j,
        n,
        err,
        dither2,
        lut[ 1 << FL_PCBITS ];
    static int x[ 4 ] =  { 0, 15, 240, 255 };
    static int y[ 4 ] =  { 0,  5, 250, 255 };

    /* to preserve the errors on the edge, has to get one more row */

    tmp = fl_get_matrix( h + 1, w, sizeof **tmp );

    spline_int_interpolate( x, y, 4, 1, lut );

    for ( ras = mat[ 0 ], curr = tmp[ 0 ], n = h * w; --n >= 0; ras++, curr++ )
        *curr = lut[ *ras ];

    /* because we have the raster in a consecutive array, we got the edge
     * errors right for free */

    dither2 = ( 1 << FL_PCBITS ) - 1;

    for ( i = 0; i < h; i++ )
    {
        curr = tmp[ i ];

        /* can't have it run to h 'cause nextrow[j+1] will be wrong */

        if ( i < h - 1 )
            next = tmp[ i + 1 ];

        for ( m = mm[ i ], j = 0; j < w; j++, m++ )
        {
            /* the value of *m depends on how the colormap is assigned */

            err =   curr[ j ]
                  - ( ( *m = curr[ j ] <= dither_threshold ) ? 0 : dither2 );
            curr[ j + 1 ] += ( err * 7 ) / 16;

            next[ j - 1 ] += ( err * 3 ) / 16;
            next[ j     ] += ( err * 5 ) / 16;
            next[ j + 1 ] += err / 16;
        }
    }

    fl_free_matrix( tmp );

    return 0;
}


/***************************************
 ***************************************/

static int
gray_to_mono( FL_IMAGE * im )
{
    unsigned short **outm = fl_get_matrix( im->h, im->w, sizeof **outm );
    unsigned short *in,
                   *out,
                   *end;
    int status = 0;

    if ( dither_threshold <= 0 )
        dither_threshold = ( 1 << FL_PCBITS ) / 2;

    if ( dither_method == FS_DITHER )
        status = fs_dither( im->gray, im->h, im->w, outm );
    else if ( dither_method == DITHER_THRESHOLD )
    {
        in = im->gray[ 0 ];
        for ( out = outm[ 0 ], end = in + im->w * im->h; in < end; )
            *out++ = *in++ >= dither_threshold;
    }

    if ( status >= 0 )
    {
        fl_free_matrix( im->ci );
        im->ci = outm;
        im->map_len = 2;
        flimage_getcolormap( im );

        im->red_lut[ 0 ] = im->green_lut[ 0 ] = im->blue_lut[ 0 ] = FL_PCMAX;
        im->red_lut[ 1 ] = im->green_lut[ 1 ] = im->blue_lut[ 1 ] = 0;
    }

    return status;
}


/***************************************
 * need to keep the original resolution
 ***************************************/

static int
gray16_to_mono( FL_IMAGE * im )
{
    int status;
    unsigned short **gray,
                   **save = im->gray;

    if ( ! ( gray = fl_get_matrix( im->h, im->w, sizeof **gray ) ) )
        return -1;

    scale_gray16( save[ 0 ], gray[ 0 ], im->gray_maxval, im->w * im->h );

    im->gray = gray;
    status = gray_to_mono( im );
    fl_free_matrix( gray );
    im->gray = save;

    return status;
}


/***************************************
 ***************************************/

static int
rgba_to_mono( FL_IMAGE * im )
{
    int otype = im->type;

    im->type = FL_IMAGE_GRAY;
    flimage_getmem( im );
    rgba_to_gray( im );
    im->type = otype;
    gray_to_mono( im );

    return 0;
}


/***************************************
 ***************************************/

static int
packed_to_mono( FL_IMAGE * im )
{
    int otype = im->type;

    im->type = FL_IMAGE_GRAY;
    flimage_getmem( im );
    packed_to_gray( im );
    im->type = otype;
    gray_to_mono( im );

    return 0;
}


/***************************************
 ***************************************/

static int
ci_to_mono( FL_IMAGE * im )
{
    int otype = im->type;

    im->type = FL_IMAGE_GRAY;
    flimage_getmem( im );
    ci_to_gray( im );
    im->type = otype;
    gray_to_mono( im );

    return 0;
}


/***********************************************************************
 * gloabl interface to type change
 **********************************************************************/

typedef struct
{
    int from, to;
    int ( * cnvt )( FL_IMAGE * );
} Cnvt;


/***************************************
 ***************************************/

static int
noop( FL_IMAGE * im  FL_UNUSED_ARG )
{
    return 0;
}

static Cnvt cnvt[ ] =
{
    /* to gray */

    { FL_IMAGE_PACKED, FL_IMAGE_GRAY,   packed_to_gray },
    { FL_IMAGE_RGB,    FL_IMAGE_GRAY,   rgba_to_gray },
    { FL_IMAGE_CI,     FL_IMAGE_GRAY,   ci_to_gray },
    { FL_IMAGE_MONO,   FL_IMAGE_GRAY,   ci_to_gray },
    { FL_IMAGE_GRAY16, FL_IMAGE_GRAY,   gray16_to_gray },
    { FL_IMAGE_GRAY,   FL_IMAGE_GRAY16, gray_to_gray16 },

    /* to rgb */

    { FL_IMAGE_PACKED, FL_IMAGE_RGB, packed_to_rgba },
    { FL_IMAGE_GRAY,   FL_IMAGE_RGB, gray_to_rgba },
    { FL_IMAGE_GRAY16, FL_IMAGE_RGB, gray16_to_rgba },
    { FL_IMAGE_CI,     FL_IMAGE_RGB, ci_to_rgba },
    { FL_IMAGE_MONO,   FL_IMAGE_RGB, ci_to_rgba },

    /* to packed */

    { FL_IMAGE_RGB,  FL_IMAGE_PACKED, rgba_to_packed },
    { FL_IMAGE_CI,   FL_IMAGE_PACKED, ci_to_packed },
    { FL_IMAGE_MONO, FL_IMAGE_PACKED, ci_to_packed },

    /* to ci    */

    { FL_IMAGE_RGB,    FL_IMAGE_CI, rgb_to_ci },
    { FL_IMAGE_PACKED, FL_IMAGE_CI, packed_to_ci },
    { FL_IMAGE_GRAY16, FL_IMAGE_CI, gray16_to_ci },
    { FL_IMAGE_GRAY,   FL_IMAGE_CI, gray_to_ci },
    { FL_IMAGE_GRAY,   FL_IMAGE_CI, gray_to_ci },
    { FL_IMAGE_MONO,   FL_IMAGE_CI, noop },

    /* to mono */

    { FL_IMAGE_RGB,    FL_IMAGE_MONO, rgba_to_mono },
    { FL_IMAGE_PACKED, FL_IMAGE_MONO, packed_to_mono },
    { FL_IMAGE_GRAY,   FL_IMAGE_MONO, gray_to_mono },
    { FL_IMAGE_GRAY16, FL_IMAGE_MONO, gray16_to_mono },
    { FL_IMAGE_CI,     FL_IMAGE_MONO, ci_to_mono },

    /* sentinel */

    { FL_IMAGE_NONE, FL_IMAGE_NONE, 0 }
};


/***************************************
 ***************************************/

int
flimage_convert( FL_IMAGE * image,
                 int        newtype,
                 int        ncolors )
{
    int found,
        status,
        otype;
    Cnvt *p = cnvt;

    if ( ! image || image->w <= 0 || image->type == FL_IMAGE_NONE )
        return -1;

    if ( image->type == newtype )
        return 0;

    if ( image->type == FL_IMAGE_MONO )
        ncolors = 2;

    otype = image->type;

    if ( image->available_type & newtype && ! image->force_convert )
    {
        /* If CI, we also need to verify the map_len is the same */

        if ( newtype != FL_IMAGE_CI || image->map_len == ncolors )
        {
            image->type = newtype;
            image->modified = 1;
            return 0;
        }
    }

    for ( p = cnvt, found = 0; p->from != FL_IMAGE_NONE && !found; p++ )
        found = p->from == image->type && p->to == newtype;

    if ( ! found )
    {
        fprintf( stderr, "requested conversion (%d to %d) not defined\n",
                 image->type, newtype );
        return -1;
    }

    if ( newtype == FL_IMAGE_CI )
    {
        image->map_len = ncolors <= 1 ? 256 : ncolors;
        flimage_getcolormap( image );
    }

    image->type = newtype;

    if ( flimage_getmem( image ) < 0 )
    {
        image->error_message( image, "Convert: can't get memory" );
        return -1;
    }

    if ( ( status = ( --p )->cnvt( image ) ) >= 0 )
    {
        image->available_type |= otype;
        image->modified = 1;
    }
    else
    {
        image->type = p->from;
        image->error_message( image, "conversion failed" );
    }

    image->force_convert = 0;

    return status;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
