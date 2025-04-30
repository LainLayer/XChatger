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
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * combine two images in the following way
 *   IM = IM1 * alpha + IM2 * (1-alpha)
 */

/*** UNFINISHED and UNTESTED */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


FL_IMAGE *
flimage_combine( FL_IMAGE * im1,
                 FL_IMAGE * im2,
                 double     alpha )
{
    FL_IMAGE *ret;
    int i,
        w,
        h,
        x,
        y;

    if ( ! im1 || im1->w <= 0 || ! im2 || im2->w <= 0 )
       return 0;

    if ( ! ( ret = flimage_alloc( ) ) )
    {
        flimage_error( im1, "can't allocate resulting image" );
        return 0;
    }

    ret->w = im1->w;
    ret->h = im1->h;
    ret->type = FLIMAGE_RGB;

    flimage_get_linearlut( ret );

    /* Convert to RGB */

    flimage_convert( im1, FLIMAGE_RGB, 0 );
    flimage_convert( im2, FLIMAGE_RGB, 0 );

    /* Populate the lut */

    for ( i = 0; i <= FL_PCMAX; i++ )
    {
        ret->llut[ 0 ][ i ] = i * alpha + 0.5;
        ret->llut[ 1 ][ i ] = i - ret->llut[ 0 ][ i ];
    }

    w = FL_min( im1->w, im2->w );
    h = FL_min( im1->h, im2->h );

    for ( y = 0; y < h; y++)
    {
         for ( x = 0; x < w; x++)
         {
             ret->red[   y ][ x ] =   ret->llut[ 0 ][ im1->red[   y ][ x ] ]
                                    + ret->llut[ 1 ][ im2->red[   y ][ x ] ];
             ret->green[ y ][ x ] =   ret->llut[ 0 ][ im1->green[ y ][ x ] ]
                                    + ret->llut[ 1 ][ im2->green[ y ][ x ] ];
             ret->blue[  y ][ x ] =   ret->llut[ 0 ][ im1->blue[  y ][ x ] ]
                                    + ret->llut[ 1 ][ im2->blue[  y ][ x ] ];
         }

         for ( ; x < im1->w; x++ )
         {
            ret->red[   y ][ x ] = im1->red[   y ][ x ];
            ret->green[ y ][ x ] = im1->green[ y ][ x ];
            ret->blue[  y ][ x ] = im1->blue[  y ][ x ];
         }
     }

     for ( ; y < im1->h; y++ )
         for ( x = 0; x < im1->w; x++ )
         {
            ret->red[   y ][ x ] = im1->red[   y ][ x ];
            ret->green[ y ][ x ] = im1->green[ y ][ x ];
            ret->blue[  y ][ x ] = im1->blue[  y ][ x ];
         }

     return ret;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
