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


/**
 * \file display.c
 *
 * We need this so files that reference fl_display don't
 * have to in pull other files.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <X11/Xlib.h>


Display *fl_display;


/***************************************
 * given a mask for RGB, find the shifts and number of bits
 ***************************************/

void
fli_rgbmask_to_shifts( unsigned long   mask,
                       unsigned int  * shift,
                       unsigned int  * bits )
{
    unsigned int val;

    if ( mask == 0 )
    {
        *shift = *bits = 0;
        return;
    }

    *shift = 0;
    while ( ! ( ( 1 << *shift ) & mask ) )
        ( *shift )++;

    val = mask >> *shift;

    *bits = 0;
    while ( ( 1 << *bits ) & val )
        ( *bits )++;
}


/***************************************
 ***************************************/

void
fli_xvisual2flstate( FL_State    * s,
                     XVisualInfo * xvinfo )
{
    s->rgb_bits = xvinfo->bits_per_rgb;
    s->rmask = xvinfo->red_mask;
    s->gmask = xvinfo->green_mask;
    s->bmask = xvinfo->blue_mask;

    fli_rgbmask_to_shifts( s->rmask, &s->rshift, &s->rbits );
    fli_rgbmask_to_shifts( s->gmask, &s->gshift, &s->gbits );
    fli_rgbmask_to_shifts( s->bmask, &s->bshift, &s->bbits );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
