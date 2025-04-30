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
 *   Copyright (c) 1993, 1998-2002  T.C. Zhao
 *   All rights reserved.
 *
 *  Scale an image with or without subpixel sampling.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 * Scale an image without subpixel sampling. Parameter im is strictly
 * for reporting purposes
 ***************************************/

static int
image_zoom( void     * om[ ],
            void     * nm[ ],
            int        h,
            int        w,
            int        nh,
            int        nw,
            int        comp,
            FL_IMAGE * im  FL_UNUSED_ARG )
{
    int *lut = fl_malloc( ( nw + 1 ) * sizeof *lut );
    unsigned short **ngray = nm[ 0 ],
                   **ogray = om[ 0 ];
    unsigned char **npc[ 3 ],
                  **opc[ 3 ];
    int i,
        j,
        iy,
        ix;

    if ( ! lut )
        return -1;

    for ( i = 0; i < nw; i++ )
        lut[ i ] = ( i * ( w - 1 ) ) / ( nw - 1 );

    for ( i = 0; i < 3; i++ )
    {
        npc[ i ] = nm[ i ];
        opc[ i ] = om[ i ];
    }

    for ( i = 0; i < nh; i++ )
    {
        iy = ( i * ( h - 1 ) ) / ( nh - 1 );

        if ( comp == 1 )
        {
            for ( j = 0; j < nw; j++ )
                ngray[ i ][ j ] = ogray[ iy ][ lut[ j ] ];
        }
        else
        {
            for ( j = 0; j < nw; j++ )
            {
                ix = lut[ j ];
                npc[ 0 ][ i ][ j ] = opc[ 0 ][ iy ][ ix ];
                npc[ 1 ][ i ][ j ] = opc[ 1 ][ iy ][ ix ];
                npc[ 2 ][ i ][ j ] = opc[ 2 ][ iy ][ ix ];
            }
        }
    }

    fl_free( lut );

    return 0;
}


/***************************************
 * Box averaging. parameter im is strictly for reporting
 ***************************************/

static int
image_scale( void     * om[ ],
             void     * nm[ ],
             int        h,
             int        w,
             int        nh,
             int        nw,
             int        comp,
             FL_IMAGE * im )
{
    float xt = ( float ) w / nw;
    float yt = ( float ) h / nh;
    float s[ 3 ],
          area,
          delta;
    float width,
          height;
    float x1,
          x2,
          y1,
          y2;
    int x,
        y,
        i,
        j;
    unsigned char **npc[ 3 ],
                  **opc[ 3 ];
    unsigned short **ogray = om[ 0 ],
                   **ngray = nm[ 0 ];

    for ( i = 0; i < 3; i++ )
    {
        npc[ i ] = nm[ i ];
        opc[ i ] = om[ i ];
    }

    for ( y1 = 0.0f, j = 0; j < nh; j++, y1 += yt, im->completed++ )
    {
        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, "Scaling " );

        y2 = y1 + yt;
        if ( y2 > h )
            y2 = h;

        for ( x1 = 0.0f, i = 0; i < nw; i++, x1 += xt )
        {
            s[ 0 ] = s[ 1 ] = s[ 2 ] = area = 0.0;
            x2 = x1 + xt;
            if ( x2 > w )
                x2 = w;

            for ( y = ( int ) y1; y < y2; y++ )
            {
                if ( y < y1 )
                    height = y + 1.0 - y1;
                else if ( y + 1.0 > y2 )
                    height = y2 - y;
                else
                    height = 1.0;

                for ( x = ( int ) x1; x < x2; x++)
                {
                    if ( x < x1 )
                        width = x + 1.0 - x1;
                    else if ( x + 1.0 > x2 )
                        width = x2 - x;
                    else
                        width = 1.0;
                    area += ( delta = width * height );

                    if ( comp == 1 )
                        s[ 0 ] += delta * ogray[ y ][ x ];
                    else
                    {
                        s[ 0 ] += delta * opc[ 0 ][ y ][ x ];
                        s[ 1 ] += delta * opc[ 1 ][ y ][ x ];
                        s[ 2 ] += delta * opc[ 2 ][ y ][ x ];
                    }
                }
            }

            if ( comp == 1 )
                ngray[ j ][ i ] = s[ 0 ] / area;
            else
            {
                npc[ 0 ][ j ][ i ] = s[ 0 ] / area;
                npc[ 1 ][ j ][ i ] = s[ 1 ] / area;
                npc[ 2 ][ j ][ i ] = s[ 2 ] / area;
            }
        }
    }

    return 0;
}


/***************************************
 ***************************************/

int
flimage_scale( FL_IMAGE * im,
               int        nw,
               int        nh,
               int        option )
{
    void *om[ 3 ],
         *nm[ 3 ] = { 0, 0, 0 };
    int err = 0,
        comp;

    if ( ! im || im->w <= 0 || im->type == FL_IMAGE_NONE )
        return -1;

    /* Check if null op */

    if ( im->w == nw && im->h == nh )
        return 0;

    /* Convert to RGB only if subpixel and not gray */

    if ( option & FLIMAGE_SUBPIXEL )
    {
        if ( im->type == FL_IMAGE_CI )
            err = flimage_convert( im, FL_IMAGE_RGB, 0 ) < 0;
        else if ( im->type == FL_IMAGE_MONO )
            err = flimage_convert( im, FL_IMAGE_GRAY, 0 ) < 0;

        if ( err )
        {
            im->error_message( im, "scale: conversion to RGB/Gray failed" );
            return -1;
        }
    }

    /* Free all irrelevant pixels */

    flimage_invalidate_pixels( im );

    if ( im->type == FL_IMAGE_RGB )
    {
        om[ 0 ] = im->red;
        om[ 1 ] = im->green;
        om[ 2 ] = im->blue;

        /* For size fitting, we don't need allocate pixels here */

        if ( ! ( option & FLIMAGE_ASPECT ) )
        {
            err =    err
                  || ! ( nm[ 0 ] = fl_get_matrix( nh, nw, sizeof **im->red ) )
                  || ! ( nm[ 1 ] = fl_get_matrix( nh, nw, sizeof **im->red ) )
                  || ! ( nm[ 2 ] = fl_get_matrix( nh, nw, sizeof **im->red ) );
        }

        comp = 3;
    }
    else
    {
        om[ 0 ] = FL_IsGray( im->type ) ? im->gray : im->ci;
        err = err || ! ( nm[ 0 ] = fl_get_matrix( nh, nw, sizeof **im->gray ) );
        om[ 1 ] = nm[ 1 ] = om[ 2 ] = nm[ 2 ] = 0;
        comp = 1;
    }

    if ( err )
    {
        im->error_message( im, "Scale: malloc failed" );
        fl_free_matrix( nm[ 0 ]);
        fl_free_matrix( nm[ 1 ]);
        fl_free_matrix( nm[ 2 ]);
        im->modified = 1;
        return -1;
    }

    im->completed = 0;
    im->visual_cue( im, "Scaling" );

    if ( option & FLIMAGE_ASPECT )
    {
        static float m[ 2 ][ 2 ];

        m[ 0 ][ 0 ] = ( float ) nw / im->w;
        m[ 1 ][ 1 ] = ( float ) nh / im->h;

        m[ 0 ][ 0 ] = m[ 1 ][ 1 ] = FL_min( m[ 0 ][ 0 ], m[ 1 ][ 1 ] );
        fl_free_matrix( nm[ 0 ] );
        err = flimage_warp( im, m, nw, nh, option );
        im->completed = im->h;
        im->visual_cue( im, "Scaling Done" );
        return err;
    }
    else if ( option & FLIMAGE_SUBPIXEL )
        err = image_scale( om, nm, im->h, im->w, nh, nw, comp, im ) < 0;
    else
        err = image_zoom( om, nm, im->h, im->w, nh, nw, comp, im ) < 0;
    
    if ( ! err )
    {
        flimage_replace_image( im, nw, nh, nm[ 0 ], nm[ 1 ], nm[ 2 ] );
        im->completed = im->h;
        im->visual_cue( im, "Scaling Done" );
    }
    else
    {
        im->visual_cue( im, "Scaling failed" );
        im->error_message( im, "Scaling failed" );
    }

    return err ? -1 : 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
