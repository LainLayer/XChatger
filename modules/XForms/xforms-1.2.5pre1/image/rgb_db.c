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
 *  Copyright (c) 1997-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  search the rgb.txt database for a specific color
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"


/***************************************
 * This function is retained for compatibility reasons only.
 * It returns 1 always.
 ***************************************/

int
fl_init_RGBdatabase( const char * f  FL_UNUSED_ARG )
{
    return 1;
}


/***************************************
 * A new implementation from Rouben Rostamian
 * Changed to make it work with machines that a color depth of 32 bit
 * but only 24 planes. It's a bit slow because each time the two colors
 * are queried but I did have any better idea at the moment how to figure
 * out how many bits the red, green and blue members of the XColor
 * structure have in every possible case and this looked like the
 * safest method...                 JTT
 ***************************************/

int fl_lookup_RGBcolor( const char * colname,
                        int *        r,
                        int *        g,
                        int *        b )
{
    XColor xc;
    XColor w;

    if (    XParseColor( fl_display, fl_state[ fl_vmode ].colormap,
                         "rgb:ffff/ffff/ffff",  &w ) == 0 
         || XParseColor( fl_display, fl_state[ fl_vmode ].colormap,
                         colname,  &xc ) == 0 )
        return -1;

    *r = ( ( xc.red   << 8 ) - 1 ) / w.red;
    *g = ( ( xc.green << 8 ) - 1 ) / w.green;
    *b = ( ( xc.blue  << 8 ) - 1 ) / w.blue;

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
