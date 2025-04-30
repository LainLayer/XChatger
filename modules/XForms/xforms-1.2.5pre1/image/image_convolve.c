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
 *   Copyright (c) 1993, 1998-2002  T.C. Zhao
 *   All rights reserved.
 *
 *  General colvolution routines for RGB and gray (both 8bit and 16bit)
 *  images. 3x3 and 5x5 kernels are manually unrolled.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"

/***********************************************************************
 * Convolution
 *******************************************************************{***/

#define VectorP3( k, b, i )     (   k[ 0 ] * b[ i - 1 ]     \
                                  + k[ 1 ] * b[ i ]         \
                                  + k[ 2 ] * b[ i + 1 ] )

#define VectorP5( k, b, i )     (   k[ 0 ] * b[ i - 2 ]     \
                                  + k[ 1 ] * b[ i - 1 ]     \
                                  + k[ 2 ] * b[ i ]         \
                                  + k[ 3 ] * b[ i + 1 ]     \
                                  + k[ 4 ] * b[ i + 2 ]     )

#define conv3x3( cm, m, r, c )  (   VectorP3( cm[ 0 ], m[ r - 1 ], c )    \
                                  + VectorP3( cm[ 1 ], m[ r + 0 ], c )    \
                                  + VectorP3( cm[ 2 ], m[ r + 1 ], c ) )

#define conv5x5( kernel, pc, row, col )                        \
                            (   VectorP5( kernel[ 0 ], pc[ row - 2 ], col )  \
                              + VectorP5( kernel[ 1 ], pc[ row - 1 ], col )  \
                              + VectorP5( kernel[ 2 ], pc[ row + 0 ], col )  \
                              + VectorP5( kernel[ 3 ], pc[ row + 1 ], col )  \
                              + VectorP5( kernel[ 4 ], pc[ row + 2 ], col ) )


/***************************************
 ***************************************/

static int
uc_conv5x5( int           ** kernel,
            unsigned char ** pc,
            int              r,
            int              c )
{
    return conv5x5( kernel, pc, r, c );
}


/***************************************
 ***************************************/

static int
us_conv5x5( int            ** kernel,
            unsigned short ** s,
            int               r,
            int               c )
{
    return conv5x5( kernel, s, r, c );
}


static void init_kernels(void);

/* normalize with weight the clamp */

#define NormAndClamp( pc, w, max )                        \
            do {                                          \
                if ( pc < 0 )                             \
                    pc = 0;                               \
                else if ( ( pc /=w ) > ( max ) )          \
                    pc = ( max );                         \
             } while ( 0 )



/***************************************
 ***************************************/

static void
rgb_convolve( unsigned char ** red,
              unsigned char ** green,
              unsigned char ** blue,
              int              h,
              int              w,
              int           ** kernel,
              int              krow,
              int              kcol,
              int              weight,
              FL_IMAGE       * im,
              const char     * what )
{
    int newr,
        newg,
        newb,
        row,
        col;
    int k_halfh = krow / 2,
        k_halfw = kcol / 2;

    for ( h -= k_halfw, w -= k_halfw, row = 1; row < h; row++ )
    {
        if ( krow == 3 && kcol == 3 )
        {
            for ( col = k_halfw; col < w; col++ )
            {
                newr = conv3x3( kernel, red, row, col );
                newg = conv3x3( kernel, green, row, col );
                newb = conv3x3( kernel, blue, row, col );

                NormAndClamp( newr, weight, FL_PCMAX );
                NormAndClamp( newg, weight, FL_PCMAX );
                NormAndClamp( newb, weight, FL_PCMAX );

                red[ row ][ col ] = newr;
                green[ row ][ col ] = newg;
                blue[ row ][ col ] = newb;
            }
        }
        else if ( krow == 5 && kcol == 5 )
        {
            for ( col = k_halfw; col < w; col++ )
            {
                newr = uc_conv5x5( kernel, red, row, col );
                newg = uc_conv5x5( kernel, green, row, col );
                newb = uc_conv5x5( kernel, blue, row, col );

                NormAndClamp( newr, weight, FL_PCMAX );
                NormAndClamp( newg, weight, FL_PCMAX );
                NormAndClamp( newb, weight, FL_PCMAX );

                red[ row ][ col ] = newr;
                green[ row ][ col ] = newg;
                blue[ row ][ col ] = newb;
            }
        }
        else
        {
            int i,
                j,
                ccol,
                ii,
                jj;

            for ( col = k_halfw; col < w; col++ )
            {
                newr = newg = newb = 0;
                ccol = col - k_halfw;

                for ( i = 0; i < krow; i++ )
                {
                    ii = row - k_halfh + i;

                    for ( jj = ccol, j = 0; j < kcol; jj++, j++ )
                    {
                        newr += kernel[ i ][ j ] * red[ ii ][ jj ];
                        newg += kernel[ i ][ j ] * green[ ii ][ jj ];
                        newb += kernel[ i ][ j ] * blue[ ii ][ jj ];
                    }
                }

                NormAndClamp( newr, weight, FL_PCMAX );
                NormAndClamp( newg, weight, FL_PCMAX );
                NormAndClamp( newb, weight, FL_PCMAX );

                red[ row ][ col ] = newr;
                green[ row ][ col ] = newg;
                blue[ row ][ col ] = newg;
            }
        }

        if ( ! ( ++im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, what );
    }
}


/***************************************
 ***************************************/

static void
gray_convolve( unsigned short ** gray,
               int               h,
               int               w,
               int            ** kernel,
               int               krow,
               int               kcol,
               int               weight,
               FL_IMAGE        * im,
               const char      * what )
{
    int newr,
        row,
        col;
    int k_halfh = krow / 2,
        k_halfw = kcol / 2;

    for ( h -= k_halfw, w -= k_halfw, row = 1; row < h; row++ )
    {
        if ( krow == 3 && kcol == 3 )
        {
            for  (col = k_halfw; col < w; col++ )
            {
                newr = conv3x3( kernel, gray, row, col );
                NormAndClamp( newr, weight, FL_PCMAX );
                gray[ row ][ col ] = newr;
            }
        }
        else if ( krow == 5 && kcol == 5 )
        {
            for ( col = k_halfw; col < w; col++ )
            {
                newr = us_conv5x5( kernel, gray, row, col );
                NormAndClamp( newr, weight, im->gray_maxval );
                gray[ row ] [col ] = newr;
            }
        }
        else
        {
            int i,
                j,
                ccol,
                ii,
                jj;

            for ( col = k_halfw; col < w; col++ )
            {
                ccol = col - k_halfw;

                for ( newr = 0, i = 0; i < krow; i++ )
                {
                    ii = row - k_halfh + i;

                    for ( jj = ccol, j = 0; j < kcol; jj++, j++ )
                        newr += kernel[ i ][ j ] * gray[ ii ][ jj ];
                }

                NormAndClamp( newr, weight, FL_PCMAX );
                gray[ row ][ col ] = newr;
            }
        }

        if ( ! ( ++im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, what );
    }
}


static int **sharpen_kernel;
static int **smooth_kernel;


/***************************************
 ***************************************/

int
flimage_convolve( FL_IMAGE  * im,
                  int      ** kernel,
                  int         krow,
                  int         kcol )
{
    int weight = 0,
        i;
    const char * what = "convolving";
    char buf[ 128 ];
    SubImage *sub;

    if ( !im || im->w <= 0 || im->type == FL_IMAGE_NONE )
    {
        M_err( "Convolve", "bad image" );
        return -1;
    }

    /* Check subimage settings */

    if ( im->subw && ( im->subw < kcol || im->subh < krow ) )
    {
        im->error_message( im, "Convolve: subimage size less than kernel" );
        return -1;
    }

    if ( ! sharpen_kernel )
        init_kernels( );

    if ( kernel == FL_SHARPEN )
    {
        kernel = sharpen_kernel;
        krow = kcol = 3;
        what = "sharpening";
    }
    else if ( kernel == FL_SMOOTH )
    {
        kernel = smooth_kernel;
        krow = kcol = 3;
        what = "smoothing";
    }

    if ( ! ( krow & 1 ) || ! ( kcol & 1 ) )
        M_err( "Convolve", "even or zero kernel size (row = %d, col = %d)!",
               krow, kcol );

    for ( i = 0; i < kcol * krow; i++ )
        weight += kernel[ 0 ][ i ];

    if ( weight <= 0 )
    {
        im->error_message( im, "bad kernel weight" );
        return -1;
    }

    /* Always convert to RGB or GRAY */

    if ( ! FL_IsGray( im->type ) )
        flimage_convert( im, FL_IMAGE_RGB, 0 );

    if ( ! ( sub = flimage_get_subimage( im, 1 ) ) )
        return -1;

    im->completed = 0;
    im->visual_cue( im, what );

    if ( FL_IsGray( im->type ) )
        gray_convolve( sub->mat[ 0 ], sub->h, sub->w,
                       kernel, krow, kcol, weight, im, what );
    else
        rgb_convolve( sub->mat[ 0 ], sub->mat[ 1 ], sub->mat[ 2 ],
                      sub->h, sub->w, kernel, krow, kcol, weight, im, what );

    im->completed = im->total;
    sprintf( buf, "%s done", what );
    im->visual_cue( im, buf );

    if (im->subw)
    {
        fl_free_matrix( sub->mat[ 0 ] );
        fl_free_matrix( sub->mat[ 1 ] );
        fl_free_matrix( sub->mat[ 2 ] );
    }

    im->modified = 1;

    return 0;
}


/***************************************
 * Almost the same as convolve except the kernel is a proper C array
 * kernel[krow][kcol]
 ***************************************/

int
flimage_convolvea( FL_IMAGE * im,
                   int      * kernel,
                   int        krow,
                   int        kcol )
{
    int **kk,
        status;

    if ( ! ( krow & 1 ) || ! ( kcol & 1 ) )
        M_err( "Convolve", "even or zero kernel size (row = %d, col = %d)!",
               krow, kcol );

    kk = fl_make_matrix( krow, kcol, sizeof **kk, kernel );
    status = flimage_convolve( im, kk, krow, kcol );
    fl_free_matrix( kk );
    return status;
}


/**********************************************************************
 * some built-in kernels
 **********************************************************************/

static void
init_kernels( void )
{
    sharpen_kernel = fl_get_matrix( 3, 3, sizeof( **sharpen_kernel ) );
    smooth_kernel = fl_get_matrix( 3, 3, sizeof( **smooth_kernel ) );

    sharpen_kernel[ 0 ][ 0 ] = -1;
    sharpen_kernel[ 0 ][ 1 ] = -2;
    sharpen_kernel[ 0 ][ 2 ] = -1;
    sharpen_kernel[ 1 ][ 0 ] = -2;
    sharpen_kernel[ 1 ][ 1 ] = 28;
    sharpen_kernel[ 1 ][ 2 ] = -2;
    sharpen_kernel[ 2 ][ 0 ] = -1;
    sharpen_kernel[ 2 ][ 1 ] = -2;
    sharpen_kernel[ 2 ][ 2 ] = -1;

    /* smoothing a bit stronger than sharpening */

    smooth_kernel[ 0 ][ 0 ] = 1;
    smooth_kernel[ 0 ][ 1 ] = 2;
    smooth_kernel[ 0 ][ 2 ] = 1;
    smooth_kernel[ 1 ][ 0 ] = 2;
    smooth_kernel[ 1 ][ 1 ] = 7;
    smooth_kernel[ 1 ][ 2 ] = 2;
    smooth_kernel[ 2 ][ 0 ] = 1;
    smooth_kernel[ 2 ][ 1 ] = 2;
    smooth_kernel[ 2 ][ 2 ] = 1;
}


/*}********************************************************************* */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
