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
 * \file labelbut.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1997-2002  T.C. Zhao
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include "include/forms.h"
#include "flinternal.h"


/********** DRAWING *************/


/***************************************
 * Draws the object
 ***************************************/

static void
draw_labelbutton( FL_OBJECT * ob )
{
    FL_COLOR scol = ob->lcol;
    FL_COLOR col = ob->lcol;
    FL_Coord dh,
             dw,
             ww,
             absbw = FL_abs( ob->bw );

    if ( ob->belowmouse )
        col = ob->col1;
    if ( ( ( FL_BUTTON_STRUCT * ) ob->spec )->val )
        col = ob->col2;

    ob->lcol = col;

    dh = 0.6 * ob->h;
    dw = FL_min( 0.6 * ob->w, dh );

    ww = 0.75 * ob->h;
    if ( ww < dw + absbw + 1 + ( ob->bw > 0 ) )
        ww = dw + absbw + 1 + ( ob->bw > 0 );

    if ( ob->type == FL_RETURN_BUTTON )
        fl_draw_text( 0, ob->x + ob->w - ww, ob->y + 0.2 * ob->h,
                      dw, dh, ob->lcol, 0, 0, "@returnarrow" );

    fl_draw_object_label( ob );
    ob->lcol = scol;
}


/***************************************
 * Creates a labelbutton object
 ***************************************/

FL_OBJECT *
fl_create_labelbutton( int          type,
                       FL_Coord     x,
                       FL_Coord     y,
                       FL_Coord     w,
                       FL_Coord     h,
                       const char * label)
{
    FL_OBJECT *obj;

    fl_add_button_class( FL_LABELBUTTON, draw_labelbutton, NULL );
    obj = fl_create_generic_button( FL_LABELBUTTON, type, x, y, w, h, label );

    obj->boxtype = FL_FLAT_BOX;
    obj->col1    = FL_RED;
    obj->col2    = FL_BLUE;
    obj->align   = FL_LIGHTBUTTON_ALIGN;
    obj->lcol    = FL_LIGHTBUTTON_LCOL;

    return obj;
}


/***************************************
 * Adds a labelbutton object
 ***************************************/

FL_OBJECT *
fl_add_labelbutton( int          type,
                    FL_Coord     x,
                    FL_Coord     y,
                    FL_Coord     w,
                    FL_Coord     h,
                    const char * label)
{
    FL_OBJECT *obj = fl_create_labelbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
