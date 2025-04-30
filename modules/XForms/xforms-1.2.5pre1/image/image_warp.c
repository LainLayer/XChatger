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
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 * General non-perspective linear image warping.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include <stdlib.h>


/***************************************
 * linear interpolation
 ***************************************/

static void
interpol2d_short( unsigned short  * out,
                  float             y,
                  float             x,
                  unsigned short ** mat,
                  int               nrow,
                  int               ncol,
                  unsigned int      fill )
{
    float wx,
          wy,
          wx1;
    int s00,
        s01,
        s10,
        s11,
        ix,
        iy;

    if ( x <= -1.0 || y <= -1.0 || x >= ncol || y >= nrow )
    {
        *out = fill;
        return;
    }

    /* we need to fake one row/column of samples outside of the image to
       make the boundary look nice */

    ix = x < 0 ? -1 : x;
    iy = y < 0 ? -1 : y;

    /* here we use extra samples outside of the image */

    s00 = ( ix >= 0 && iy >= 0) ? mat[ iy ][ ix ] : fill;
    s10 = ( ix < ncol - 1 && iy >= 0 ) ? mat[ iy ][ ix + 1 ] : fill;
    s01 = ( ix >= 0 && iy < nrow - 1 ) ? mat[ iy + 1 ][ ix ] : fill;
    s11 = ( ix < ncol - 1 && iy < nrow - 1 ) ? mat[ iy + 1 ][ ix + 1 ] : fill;

    /* weights */

    wx = x - ix;
    wy = y - iy;
    wx1 = 1.0 - wx;

    *out =   ( s00 * wx1 + s10 * wx ) * ( 1.0 - wy )
           + ( s01 * wx1 + s11 * wx ) * wy + 0.1;

    return;
}


/***************************************
 * linear interpolation
 ***************************************/

static void
interpol2d_uc( int              out[ 3 ],
               float            y,
               float            x,
               unsigned char ** r,
               unsigned char ** g,
               unsigned char ** b,
               int              nrow,
               int              ncol,
               int              fill[ ] )
{
    int ix,
        iy;
    float wx,
          wy,
          wx1,
          wy1;
    int s00[ 3 ],
        s01[ 3 ],
        s10[ 3 ],
        s11[ 3 ];

    if ( x <= -1.0f || y <= -1.0f || x >= ncol || y >= nrow )
    {
        out[ 0 ] = fill[ 0 ];
        out[ 1 ] = fill[ 1 ];
        out[ 2 ] = fill[ 2 ];
        return;
    }

    ix = x < 0.0 ? -1 : ( int ) x;
    iy = y < 0.0 ? -1 : ( int ) y;

    /* we need to fake one row/column of samples outside of the image to
       make the boundary look nice */

    if ( ix >= 0 && iy >= 0 )
    {
        s00[ 0 ] = r[ iy ][ ix ];
        s00[ 1 ] = g[ iy ][ ix ];
        s00[ 2 ] = b[ iy ][ ix ];
    }
    else
    {
        s00[ 0 ] = fill[ 0 ];
        s00[ 1 ] = fill[ 1 ];
        s00[ 2 ] = fill[ 2 ];
    }

    if ( ix < ncol - 1 && iy >= 0 )
    {
        s10[ 0 ] = r[ iy ][ ix + 1 ];
        s10[ 1 ] = g[ iy ][ ix + 1 ];
        s10[ 2 ] = b[ iy ][ ix + 1 ];
    }
    else
    {
        s10[ 0 ] = fill[ 0 ];
        s10[ 1 ] = fill[ 1 ];
        s10[ 2 ] = fill[ 2 ];
    }

    if ( ix >= 0 && iy < nrow - 1 )
    {
        s01[ 0 ] = r[ iy + 1 ][ ix ];
        s01[ 1 ] = g[ iy + 1 ][ ix ];
        s01[ 2 ] = b[ iy + 1 ][ ix ];
    }
    else
    {
        s01[ 0 ] = fill[ 0 ];
        s01[ 1 ] = fill[ 1 ];
        s01[ 2 ] = fill[ 2 ];
    }

    if ( ix < ncol - 1 && iy < nrow - 1 )
    {
        s11[ 0 ] = r[ iy + 1 ][ ix + 1 ];
        s11[ 1 ] = g[ iy + 1 ][ ix + 1 ];
        s11[ 2 ] = b[ iy + 1 ][ ix + 1 ];
    }
    else
    {
        s11[ 0 ] = fill[ 0 ];
        s11[ 1 ] = fill[ 1 ];
        s11[ 2 ] = fill[ 2 ];
    }

    /* weights */

    wx = x - ix;
    wy = y - iy;
    wx1 = 1.0 - wx;
    wy1 = 1.0 - wy;

    out[ 0 ] =   ( s00[ 0 ] * wx1 + s10[ 0 ] * wx ) * wy1
               + ( s01[ 0 ] * wx1 + s11[ 0 ] * wx ) * wy;
    out[ 1 ] =   ( s00[ 1 ] * wx1 + s10[ 1 ] * wx ) * wy1
               + ( s01[ 1 ] * wx1 + s11[ 1 ] * wx ) * wy;
    out[ 2 ] =   ( s00[ 2 ] * wx1 + s10[ 2 ] * wx ) * wy1
               + ( s01[ 2 ] * wx1 + s11[ 2 ] * wx ) * wy;

    if (    out[ 0 ] < 0 || out[ 0 ] > FL_PCMAX
         || out[ 1 ] < 0 || out[ 1 ] > FL_PCMAX
         || out[ 2 ] < 0 || out[ 2 ] > FL_PCMAX)
    {
        M_err( "interpol2D", "out of range" );
        exit( 1 );
    }

    return;
}


#define Free( a )  if( a ) fl_free( a )


/***************************************
 ***************************************/

static int
get_luts( float ** lutx0,
          float ** lutx1,
          float ** luty0,
          float ** luty1,
          float    m[ ][ 2 ],
          int      shift[ ],
          int      w,
          int      h )
{
    int i,
        err = 0;

    *lutx0 = *luty0 = *lutx1 = *luty1 = NULL;
    err =    ! ( *lutx0 = fl_malloc( sizeof **lutx0 * ( w + 1 ) ) )
          || ! ( *luty0 = fl_malloc( sizeof **luty0 * ( w + 1 ) ) )
          || ! ( *lutx1 = fl_malloc( sizeof **lutx1 * ( h + 1 ) ) )
          || ! ( *luty1 = fl_malloc( sizeof **luty1 * ( h + 1 ) ) );

    if ( err )
    {
        Free( *lutx0 );
        Free( *luty0 );
        Free( *lutx1 );
        Free( *luty1 );
        return -1;
    }

    for ( i = 0; i <= w; i++ )
    {
        ( *lutx0 )[ i ] = m[ 0 ][ 0 ] * ( i - shift[ 0 ] );
        ( *luty0 )[ i ] = m[ 1 ][ 0 ] * ( i - shift[ 0 ] );
    }

    for ( i = 0; i <= h; i++ )
    {
        ( *lutx1 )[ i ] = m[ 0 ][ 1 ] * ( i - shift[ 1 ] );
        ( *luty1 )[ i ] = m[ 1 ][ 1 ] * ( i - shift[ 1 ] );
    }

    return 0;
}


#define Outside( ic, ir, w, h )    \
( ic < 0 || ic > ( w ) - 1 || ir < 0 || ir > ( h ) - 1 )


/***************************************
 * the short array passed in could be grayscale or color index
 ***************************************/

static int
transform_short( unsigned short ** in,
                 unsigned short ** out,
                 int               w,
                 int               h,
                 int               nw,
                 int               nh,
                 float             m[ ][ 2 ],
                 int               shift[ ],
                 unsigned int      fill,
                 int               subp,
                 FL_IMAGE        * im)
{
    float *lutx[ 2 ],
          *luty[ 2 ];
    int r,
        c,
        ir,
        ic;
    float fir,
        fic;

    if ( get_luts( lutx, lutx + 1, luty, luty + 1, m, shift, nw, nh ) < 0 )
        return -1;

    for ( r = 0; r < nh; r++, im->completed++ )
    {
        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, subp ? "GraySubP" : "Gray" );

        if ( ! subp )
        {
            for ( c = 0; c < nw; c++ )
            {
                ic = lutx[ 0 ][ c ] + lutx[ 1 ][ r ] + 0.1;
                ir = luty[ 0 ][ c ] + luty[ 1 ][ r ] + 0.1;
                out[ r ][ c ] = Outside( ic, ir, w, h ) ? fill : in[ ir ][ ic ];
            }
        }
        else
        {
            for ( c = 0; c < nw; c++ )
            {
                fic = lutx[ 0 ][ c ] + lutx[ 1 ][ r ];
                fir = luty[ 0 ][ c ] + luty[ 1 ][ r ];
                interpol2d_short( &out[ r ][ c ], fir, fic, in, h, w, fill );
            }
        }
    }

    fl_free( lutx[ 0 ] );
    fl_free( lutx[ 1 ] );
    fl_free( luty[ 0 ] );
    fl_free( luty[ 1 ] );

    return 1;
}


/***************************************
 ***************************************/

static int
transform_rgb( unsigned char ** or,
               unsigned char ** og,
               unsigned char ** ob,
               unsigned char ** nr,
               unsigned char ** ng,
               unsigned char ** nb,
               int              w,
               int              h,
               int              nw,
               int              nh,
               float            m[ ][ 2 ],
               int              shift[ ],
               unsigned int     fill,
               int              subp,
               FL_IMAGE       * im )
{
    float *lutx[ 2 ],
          *luty[ 2 ];
    int r,
        c,
        ir,
        ic,
        out[ 3 ];
    float fir,
          fic;
    unsigned char fr = FL_GETR( fill ),
                  fg = FL_GETG( fill ),
                  fb = FL_GETB( fill );
    int fillc[ 3 ];

    if ( get_luts( lutx, lutx + 1, luty, luty + 1, m, shift, nw, nh ) < 0 )
        return -1;

    fillc[ 0] = FL_GETR( fill );
    fillc[ 1] = FL_GETG( fill );
    fillc[ 2] = FL_GETB( fill );

    for ( r = 0; r < nh; r++, im->completed++ )
    {
        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, subp ? "RGBSubP" : "RGB" );

        if ( ! subp )
        {
            for ( c = 0; c < nw; c++ )
            {
                ic = lutx[ 0 ][ c ] + lutx[ 1 ][ r ] + 0.1;
                ir = luty[ 0 ][ c ] + luty[ 1 ][ r ] + 0.1;

                nr[ r ][ c ] = Outside( ic, ir, w, h ) ? fr : or[ ir ][ ic ];
                ng[ r ][ c ] = Outside( ic, ir, w, h ) ? fg : og[ ir ][ ic ];
                nb[ r ][ c ] = Outside( ic, ir, w, h ) ? fb : ob[ ir ][ ic ];
            }
        }
        else
        {
            for ( c = 0; c < nw; c++ )
            {
                fic = lutx[ 0][ c ] + lutx[ 1 ][ r ];
                fir = luty[ 0][ c ] + luty[ 1 ][ r ];

                interpol2d_uc( out, fir, fic, or, og, ob, h, w, fillc );

                nr[ r ][ c ] = out[ 0 ];
                ng[ r ][ c ] = out[ 1 ];
                nb[ r ][ c ] = out[ 2 ];
            }
        }
    }

    fl_free(lutx[ 0 ] );
    fl_free(lutx[ 1 ] );
    fl_free(luty[ 0 ] );
    fl_free(luty[ 1 ] );

    return 1;
}


/***************************************
 ***************************************/

int
flimage_warp( FL_IMAGE * im,
              float      m[ ][ 2 ],
              int        nw,
              int        nh,
              int        option )
{
    int subp = option & FLIMAGE_SUBPIXEL,
        err = 0,
        i;
    int center = ! ( ( option & FLIMAGE_NOCENTER ) == FLIMAGE_NOCENTER );
    int neww,
        newh,
        shift[ 2 ];
    unsigned short **us = NULL;
    unsigned char **r = NULL,
                  **g = NULL,
                  **b = NULL;
    unsigned int fill;
    float x[ 4 ],
          y[ 4 ],
          xmin,
          ymin,
          xmax,
          ymax,
          inv[ 2 ][ 2 ];
    double det;

    if ( ! im || im->w <= 0 )
        return -1;

    /* first check if the inverse of the warping matrix exists */

    det = m[ 0 ][ 0 ] * m[ 1 ][ 1 ] - m[ 1 ][ 0 ] * m[ 0 ][ 1 ];

    if ( FL_abs( det ) < 1.0e-6 )
    {
        flimage_error( im, "Bad warp matrix" );
        return -1;
    }

    inv[ 0 ][ 0 ] =  m[ 1 ][ 1 ] / det;
    inv[ 1 ][ 0 ] = -m[ 1 ][ 0 ] / det;
    inv[ 0 ][ 1 ] = -m[ 0 ][ 1 ] / det;
    inv[ 1 ][ 1 ] =  m[ 0 ][ 0 ] / det;

    if ( subp )
    {
        if ( im->type == FL_IMAGE_CI )
            flimage_convert( im, FL_IMAGE_RGB, 0 );
        else if ( im->type == FL_IMAGE_MONO )
            flimage_convert( im, FL_IMAGE_GRAY, 0 );
    }

    fill = im->fill_color;

    /* figure out the shifts by getting the extremas at (0,0), (w,0), (w,h),
       (0.h) */

    xmin = xmax = ymin = ymax = x[ 0 ] = y[ 0 ] = 0.0;

    x[ 1 ] = m[ 0 ][ 0 ] * im->w;
    y[ 1 ] = m[ 1 ][ 0 ] * im->w;
    x[ 2 ] = m[ 0 ][ 0 ] * im->w + m[ 0 ][ 1 ] * im->h;
    y[ 2 ] = m[ 1 ][ 0 ] * im->w + m[ 1 ][ 1 ] * im->h;
    x[ 3 ] = m[ 0 ][ 1 ] * im->h;
    y[ 3 ] = m[ 1 ][ 1 ] * im->h;

    for ( i = 1; i < 4; i++ )
    {
        if ( xmin > x[ i ] )
            xmin = x[ i ];
        if ( xmax < x[ i ] )
            xmax = x[ i ];

        if ( ymin > y[ i ] )
            ymin = y[ i ];
        if ( ymax < y[ i ] )
            ymax = y[ i ];
    }

    shift[ 0 ] = -( int ) FL_nint( xmin );
    shift[ 1 ] = -( int ) FL_nint( ymin );

    neww = xmax - xmin + 0.5;
    newh = ymax - ymin + 0.5;

    if ( ! nw || ! nh )
    {
        nw = neww;
        nh = newh;
    }

    if ( center )
    {
        shift[ 0 ] += ( nw - neww ) / 2;
        shift[ 1 ] += ( nh - newh ) / 2;
    }

    flimage_invalidate_pixels( im );

    /* try get memory */

    if ( FL_IsCI( im->type ) || FL_IsGray( im->type ) )
    {
        err = ! ( us = fl_get_matrix( nh, nw, sizeof **us ) );
    }
    else
    {
        flimage_free_ci( im );
        flimage_free_gray( im );

        err =        ! ( r = fl_get_matrix( nh, nw, sizeof **r ) );
        err = err || ! ( g = fl_get_matrix( nh, nw, sizeof **g ) );
        err = err || ! ( b = fl_get_matrix( nh, nw, sizeof **b ) );
    }

    if ( err )
    {
        im->error_message( im, "Transform: can't get memory" );
        fl_free_matrix( us );
        fl_free_matrix( r );
        fl_free_matrix( g );
        fl_free_matrix( b );
        return -1;
    }

    /* now do the transform */

    im->completed = 1;
    im->visual_cue( im, "Transforming" );

    if ( FL_IsGray( im->type ) )
    {
        fill = FL_RGB2GRAY( FL_GETR( fill ), FL_GETG( fill ), FL_GETB( fill ) );
        if ( ! ( err = ( transform_short( im->gray, us, im->w, im->h, nw, nh,
                                          inv, shift, fill, subp, im) < 0 ) ) )
            flimage_replace_image( im, nw, nh, us, 0, 0 );
    }
    else if ( FL_IsCI( im->type ) )
    {
        fill = flimage_get_closest_color_from_map( im, fill );
        if ( ! ( err = ( transform_short( im->ci, us, im->w, im->h, nw, nh,
                                          inv, shift, fill, 0, im ) < 0 ) ) )
            flimage_replace_image( im, nw, nh, us, 0, 0 );
    }
    else if ( im->type == FL_IMAGE_RGB )
    {
        if ( ! ( err = ( transform_rgb( im->red, im->green, im->blue,
                                        r, g, b, im->w, im->h, nw, nh, inv,
                                        shift, fill, subp, im ) < 0 ) ) )
            flimage_replace_image( im, nw, nh, r, g, b );
    }
    else
    {
        M_err( "Transform", "InternalError. Bad type" );
        return -1;
    }

    if ( err )
    {
        im->error_message( im, "Transform failed" );
        return -1;
    }
    else
    {
        im->completed = im->total;
        im->visual_cue( im, "Warp done" );
    }

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
