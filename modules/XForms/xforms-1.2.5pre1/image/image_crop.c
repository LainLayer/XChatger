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
 *  Copyright (c) 1993, 1998-2002  T.C. Zhao
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 ***************************************/

int
flimage_get_autocrop( FL_IMAGE     * im,
                      unsigned int   bk,
                      int          * xl,
                      int          * yt,
                      int          * xr,
                      int          * yb )
{
    int ok,
        i,
        j;
    unsigned int p;

    if ( ! im || im->w <= 0 )
        return -1;

    /* take the color at pixel(0,0) as the color */

    if ( bk == FLIMAGE_AUTOCOLOR )
    {
        if ( FL_IsCI( im->type ) )
        {
            p = im->ci[ 0 ][ 0 ];
            bk = FL_PACK( im->red_lut[   p ],
                          im->green_lut[ p ],
                          im->blue_lut[  p ] );
        }
        else if ( im->type == FL_IMAGE_RGB )
        {
            bk = FL_PACK( im->red[   0 ][ 0 ],
                          im->green[ 0 ][ 0 ],
                          im->blue[  0 ][ 0 ] );
        }
        else if ( im->type == FL_IMAGE_GRAY || im->type == FL_IMAGE_GRAY16 )
        {
            p = im->gray[ 0 ][ 0 ];
            if ( im->type == FL_IMAGE_GRAY16 )
                p = ( 255 * p ) / im->gray_maxval;
            bk = FL_PACK( p, p, p );
        }
    }

    if ( FL_IsCI(im->type ) )
        bk = flimage_get_closest_color_from_map( im, bk );
    else if ( FL_IsGray( im->type ) )
        bk = FL_RGB2GRAY( FL_GETR( bk ), FL_GETG( bk ), FL_GETB( bk ) );

    if (im->type == FL_IMAGE_RGB)
    {
        /* do xl */

        for ( *xl = 0, ok = 1; ok && *xl < im->w; ( *xl )++ )
        {
            for ( i = 0; ok && i < im->h; i++ )
            {
                p = FL_PACK( im->red[   i ][ *xl ],
                             im->green[ i ][ *xl ],
                             im->blue[  i ][ *xl ] );
                ok = p == bk;
            }
        }

        /* do xr */

        for ( *xr = 0, ok = 1; ok && *xr < im->w; ( *xr )++ )
        {
            j = im->w - 1 - *xr;

            for ( i = 0; ok && i < im->h; i++ )
            {
                p = FL_PACK( im->red[   i ][ j ],
                             im->green[ i ][ j ],
                             im->blue[  i ][ j ] );
                ok = p == bk;
            }
        }

        /* do yt */

        for ( *yt = 0, ok = 1; ok && *yt < im->h; ( *yt )++ )
        {
            for ( i = 0; ok && i < im->w; i++ )
            {
                p = FL_PACK( im->red[   *yt ][ i ],
                             im->green[ *yt ][ i ],
                             im->blue[  *yt ][ i ] );
                ok = p == bk;
            }
        }

        /* do yb */

        for ( *yb = 0, ok = 1; ok && *yb < im->h; ( *yb )++ )
        {
            j = im->h - 1 - *yb;

            for ( i = 0; ok && i < im->w; i++ )
            {
                p = FL_PACK( im->red[   j ][ i ],
                             im->green[ j ][ i ],
                             im->blue[  j ][ i ] );
                ok = p == bk;
            }
        }
    }
    else
    {
        unsigned short **pix = FL_IsGray( im->type ) ? im->gray : im->ci;

        /* do xl */

        for ( *xl = 0, ok = 1; ok && *xl < im->w; ( *xl )++ )
        {
            for ( i = 0; ok && i < im->h; i++ )
                ok = pix[ i ][ *xl ] == bk;
        }

        /* do xr */

        for ( *xr = 0, ok = 1; ok && *xr < im->w; ( *xr )++ )
        {
            j = im->w - 1 - *xr;

            for ( i = 0; ok && i < im->h; i++ )
                ok = pix[ i ][ j ] == bk;
        }

        /* do yt */

        for ( *yt = 0, ok = 1; ok && *yt < im->h; ( *yt )++ )
        {
            for ( i = 0; ok && i < im->w; i++ )
                ok = pix[ *yt ][ i ] == bk;
        }

        /* do yb */

        for ( *yb = 0, ok = 1; ok && *yb < im->h; ( *yb )++ )
        {
            j = im->h - 1 - *yb;

            for ( i = 0; ok && i < im->w; i++ )
                ok = pix[ j ][ i ] == bk;
        }
    }

    --*xl;
    --*yt;
    --*xr;
    --*yb;

    return 0;
}


/***************************************
 * crop an image using bk as the background
 ***************************************/

int
flimage_autocrop( FL_IMAGE     * im,
                  unsigned int   bk )
{
    int xl,
        xr,
        yt,
        yb;

    flimage_get_autocrop( im, bk, &xl, &yt, &xr, &yb );
    return flimage_crop( im, xl, yt, xr, yb );
}


/***************************************
 * we allow croping region to be bigger than image, and in that case
* we fill the regions that're outside of the image
 ***************************************/

int
flimage_crop( FL_IMAGE * im,
              int        xl,
              int        yt,
              int        xr,
              int        yb )
{
    int nw = im->w - xl - xr,
        nh = im->h - yt - yb;
    unsigned short **us = 0,
                   **pix = 0;
    unsigned char **red = 0,
                  **green = 0,
                  **blue = 0;
    unsigned int fill;
    int rows = FL_min( nh, im->h ),
        cols = FL_min( nw, im->w );
    int hfill,
        wfill,
        err,
        i,
        j;
    int xx = xl < 0 ? 0 : xl,
        yy = yt < 0 ? 0 : yt;   /* old image offset */
    int x = xl < 0 ? -xl : 0,
        y = yt < 0 ? -yt : 0;   /* new image offset */


    if ( ( ! xl && ! xr && ! yt && ! yb ) || ! im )
        return 0;

    im->completed = 0;
    im->visual_cue( im, "Cropping ..." );

    wfill = ( im->w < nw ) ? FL_max( FL_abs( xl ), FL_abs( xr ) ) : 0;
    hfill = ( im->h < nh ) ? FL_max( FL_abs( yt ), FL_abs( yb ) ) : 0;

    fill = im->fill_color;

    if ( FL_IsGray( im->type ) || FL_IsCI( im->type ) )
    {
        flimage_free_rgb( im );

        err = ! ( us = fl_get_matrix( nh, nw, sizeof **us ) );

        if ( FL_IsGray(im->type ) )
        {
            fill = FL_RGB2GRAY( FL_GETR( fill ), FL_GETG( fill ),
                                FL_GETB( fill ) );
            if ( im->type == FL_IMAGE_GRAY16 )
                fill = ( fill * im->gray_maxval ) / 255;
            pix = im->gray;
        }
        else
        {
            fill = flimage_get_closest_color_from_map( im, fill );
            pix = im->ci;
        }
    }
    else
    {
        flimage_free_gray( im );
        flimage_free_ci( im );
        err =        ! ( red   = fl_get_matrix( nh, nw, sizeof **red   ) );
        err = err || ! ( green = fl_get_matrix( nh, nw, sizeof **green ) );
        err = err || ! ( blue  = fl_get_matrix( nh, nw, sizeof **blue  ) );
    }

    if ( err )
    {
        im->error_message( im, "Crop: Failed to get memory" );
        return -1;
    }

    /* now it's a go */

    if ( FL_IsGray( im->type ) || FL_IsCI( im->type ) )
    {
        for ( i = 0; i < hfill; i++ )
            for ( j = 0; j < nw; j++ )
                us[ i ][ j ] = us[ nh - 1 - i ][ j ] = fill;

        for ( j = 0; j < wfill; j++ )
            for ( i = 0; i < nh; i++ )
                us[ i ][ j ] = us[ i ][ nw - 1 - j ] = fill;

        for ( i = 0; i < rows; i++ )
            memcpy( us[ i + y ] + x, pix[ i + yy ] + xx, cols * sizeof **us );

        flimage_replace_image( im, nw, nh, us, 0, 0 );
    }
    else
    {
        for ( i = 0; i < hfill; i++ )
            for (j = 0; j < nw; j++ )
            {
                red[   i ][ j ] = red[   nh - 1 - i ][ j ] = FL_GETR( fill );
                green[ i ][ j ] = green[ nh - 1 - i ][ j ] = FL_GETG( fill );
                blue[  i ][ j ] = blue[  nh - 1 - i ][ j ] = FL_GETB( fill );
            }

        for ( j = 0; j < wfill; j++ )
            for ( i = 0; i < nh; i++ )
            {
                red[   i ][ j ] = red[   i ][ nw - 1 - j ] = FL_GETR( fill );
                green[ i ][ j ] = green[ i ][ nw - 1 - j ] = FL_GETG( fill );
                blue[  i ][ j ] = blue[  i ][ nw - 1 - j ] = FL_GETB( fill );
            }

        for ( i = 0; i < rows; i++ )
        {
            memcpy( red[   i + y ] + x, im->red[   i + yy ] + xx, cols );
            memcpy( green[ i + y ] + x, im->green[ i + yy ] + xx, cols );
            memcpy( blue[  i + y ] + x, im->blue[  i + yy ] + xx, cols );
        }

        flimage_replace_image( im, nw, nh, red, green, blue );
    }

    im->completed = im->total;
    im->visual_cue( im, "Done Cropping" );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
