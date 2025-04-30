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
 * \file roundbut.c
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
 * Draws a round button
 ***************************************/

static void
draw_roundbutton( FL_OBJECT * ob )
{
    int c1;
    FL_Coord xx,
             yy,
             rr;
    FL_BUTTON_STRUCT *sp = ob->spec;

    if ( sp->event == FL_ENTER || sp->event == FL_LEAVE )
        return;

    c1 = ob->belowmouse ? FL_ROUNDBUTTON_MCOL : FL_ROUNDBUTTON_TOPCOL;

    fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, c1, ob->bw );

    rr = 0.3 * FL_min( ob->w, ob->h ) + 0.5;
    xx = ob->x + rr + 4.1;
    yy = ob->y + 0.5 * ob->h;

    fl_circf( xx, yy, rr, ob->col1 );
    fl_circ( xx, yy, rr, FL_BLACK );

    if ( sp->val )
    {
        fl_circf( xx, yy, ( int ) ( 0.8 * rr ), ob->col2 );
        fl_circ(  xx, yy, ( int ) ( 0.8 * rr ), FL_BLACK );
    }

    if ( fl_is_center_lalign( ob->align ) )
        fl_draw_text( FL_ALIGN_LEFT, xx + rr + 1, ob->y, 0, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        fl_draw_object_label_outside( ob );

    if ( ob->type == FL_RETURN_BUTTON )
        fl_draw_text( 0,
                      ob->x + ob->w - 0.8 * ob->h, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h, ob->lcol, 0, 0,
                      "@returnarrow" );
}


/***************************************
 * Creates an object
 ***************************************/

FL_OBJECT *
fl_create_roundbutton( int          type,
                       FL_Coord     x,
                       FL_Coord     y,
                       FL_Coord     w,
                       FL_Coord     h,
                       const char * label )
{
    FL_OBJECT *ob;

    fl_add_button_class( FL_ROUNDBUTTON, draw_roundbutton, 0 );
    ob = fl_create_generic_button( FL_ROUNDBUTTON, type, x, y, w, h, label );

    ob->boxtype = FL_ROUNDBUTTON_BOXTYPE;
    ob->col1    = FL_ROUNDBUTTON_COL1;
    ob->col2    = FL_ROUNDBUTTON_COL2;
    ob->align   = FL_ROUNDBUTTON_ALIGN;
    ob->lcol    = FL_ROUNDBUTTON_LCOL;

    return ob;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_roundbutton( int          type,
                    FL_Coord     x,
                    FL_Coord     y,
                    FL_Coord     w,
                    FL_Coord     h,
                    const char * label )
{
    FL_OBJECT *ob = fl_create_roundbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
