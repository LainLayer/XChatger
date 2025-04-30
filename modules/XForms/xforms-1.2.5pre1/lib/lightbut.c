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
 * \file lightbut.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include "include/forms.h"
#include "flinternal.h"


/***************************************
 * Draws the lightbutton
 ***************************************/

static void
draw_lightbutton( FL_OBJECT * ob )
{
    int c1,
        c2,
        libox;
    FL_Coord xx,
             yy,
             ww,
             hh,
             absbw = FL_abs( ob->bw ),
             bw2;
    FL_BUTTON_STRUCT *sp = ob->spec;

    c1 = ob->belowmouse ? FL_LIGHTBUTTON_MCOL : FL_LIGHTBUTTON_TOPCOL;
    c2 = sp->val ? ob->col2 : ob->col1;

    fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, c1, ob->bw );

    if ( ob->boxtype == FL_NO_BOX || ob->boxtype == FL_FLAT_BOX )
        absbw = FL_abs( FL_BOUND_WIDTH );

    /* Otherwise it's too close to the edge... */

    if ( absbw < 3 )
        absbw = 3;

    /* Calculate and draw the light */

    hh = FL_max( ob->h - 3 * absbw - 1, FL_LIGHTBUTTON_MINSIZE );

    ww = FL_max( hh / 2, FL_LIGHTBUTTON_MINSIZE );
    if ( ww > ob->w / 6 )
        ww = ob->w / 6;

    xx = ob->x + 1.5 * absbw + 1;
    yy = ob->y + ob->h / 2 - hh / 2;

    absbw = FL_abs( ob->bw );

    /* Adjustment for non-rectangular boxes */

    if (    ob->boxtype == FL_ROUNDED3D_UPBOX
         || ob->boxtype == FL_ROUNDED3D_DOWNBOX )
    {
        hh -= 2;
        yy += 1;
        xx += 3 + ob->w * 0.01;
        ww -= 1;
    }
    else if ( ob->boxtype == FL_RSHADOW_BOX )
    {
        hh -= 1;
        xx += 1;
    }

    switch ( ob->boxtype )
    {
        case FL_UP_BOX:
        case FL_ROUNDED3D_UPBOX:
            libox = FL_DOWN_BOX;
            break;

        case FL_DOWN_BOX:
        case FL_ROUNDED3D_DOWNBOX:
            libox = FL_DOWN_BOX;
            break;

        case FL_FRAME_BOX:
        case FL_EMBOSSED_BOX:
        case FL_ROUNDED_BOX:
            libox = ob->boxtype;
            break;

        case FL_RFLAT_BOX:
            libox = FL_ROUNDED_BOX;
            break;

        case FL_RSHADOW_BOX:
            libox = FL_ROUNDED_BOX;
            break;

        default:
            libox = FL_BORDER_BOX;
            break;
    }

    bw2 = absbw > 2 ? absbw - 1 : absbw;
    fl_draw_box( libox, xx, yy, ww, hh, c2, bw2 );

    /* Draw the label */

    if ( fl_is_center_lalign( ob->align ) )
        fl_draw_text( FL_ALIGN_LEFT, xx + ww + 1, ob->y, ob->w - ww - 3,
                      ob->h, ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        fl_draw_object_label( ob );

    ww = 0.75f * ob->h;
    if ( ww < absbw + 1 )
        ww = absbw + 1;

    if ( ob->type == FL_RETURN_BUTTON )
        fl_draw_text( 0, ob->x + ob->w - ww, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h,
                      ob->lcol, 0, 0, "@returnarrow" );
}


/***************************************
 * Creates a light-button object
 ***************************************/

FL_OBJECT *
fl_create_lightbutton( int          type,
                       FL_Coord     x,
                       FL_Coord     y,
                       FL_Coord     w,
                       FL_Coord     h,
                       const char * label )
{
    FL_OBJECT *ob;

    fl_add_button_class( FL_LIGHTBUTTON, draw_lightbutton, NULL );
    ob = fl_create_generic_button( FL_LIGHTBUTTON, type, x, y, w, h, label );

    ob->boxtype = FL_LIGHTBUTTON_BOXTYPE;
    ob->col1    = FL_LIGHTBUTTON_COL1;
    ob->col2    = FL_LIGHTBUTTON_COL2;
    ob->align   = FL_LIGHTBUTTON_ALIGN;
    ob->lcol    = FL_LIGHTBUTTON_LCOL;

    return ob;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_lightbutton( int          type,
                    FL_Coord     x,
                    FL_Coord     y,
                    FL_Coord     w,
                    FL_Coord     h,
                    const char * label )
{
    FL_OBJECT *ob = fl_create_lightbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
