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
 *  replace a specific pixel
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 * replace all color target with color repl
 ***************************************/

int
flimage_replace_pixel( FL_IMAGE     * im,
                       unsigned int   target,
                       unsigned int   repl )
{
    int n,
        r1,
        g1,
        b1,
        r2,
        g2,
        b2;

    if ( ! im || im->w <= 0 )
        return -1;

    FL_UNPACK( target, r1, g1, b1 );
    FL_UNPACK( repl, r2, g2, b2 );

    flimage_invalidate_pixels( im );

    if ( im->type == FL_IMAGE_RGB )
    {
        unsigned char *red   = im->red[   0 ];
        unsigned char *green = im->green[ 0 ];
        unsigned char *blue  = im->blue[  0 ];

        for ( n = im->w * im->h; --n >= 0; )
        {
            if ( ( int ) target == FL_PACK( red[ n ], green[ n ], blue[ n ] ) )
            {
                red[   n ] = r2;
                green[ n ] = g2;
                blue[  n ] = b2;
            }
        }
    }
    else if ( im->type == FL_IMAGE_PACKED )
    {
        unsigned int *packed = im->packed[ 0 ];

        for ( n = im->w * im->h; --n >= 0; )
        {
            if ( packed[ n ] == target )
                packed[ n ] = repl;
        }
    }
    else if ( FL_IsGray( im->type ) )
    {
        unsigned short *gray = im->gray[ 0 ];
        unsigned short gray1 = FL_RGB2GRAY( r1, g1, b1 );
        unsigned short gray2 = FL_RGB2GRAY( r2, g2, b2 );

        for ( n = im->w * im->h; --n >= 0; )
            if ( gray[n] == gray1 )
                gray[ n ] = gray2;
    }
    else if ( FL_IsCI( im->type ) )
    {
        unsigned short *ci = im->ci[ 0 ];
        unsigned short c1 = flimage_get_closest_color_from_map( im, target );
        unsigned short c2 = flimage_get_closest_color_from_map( im, repl );

        for ( n = im->w * im->h; --n >= 0; )
            if ( ci[ n ] == c1 )
                ci[ n ] = c2;
    }
    else
    {
        M_err( "ReplaceColor", "InternalError: bad type %d", im->type );
        return -1;
    }

    im->modified = 1;
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
