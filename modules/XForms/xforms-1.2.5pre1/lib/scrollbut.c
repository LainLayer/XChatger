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
 * \file scrollbut.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Buttons for the scrollbar. Maybe of some value in general use.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include "include/forms.h"
#include "flinternal.h"


/***************************************
 ***************************************/

static void
draw_scrollbutton( FL_OBJECT * ob )
{
    FL_COLOR c1;
    FL_Coord abw = FL_abs( ob->bw );
    FL_Coord extra = abw;
    FL_BUTTON_STRUCT *sp = ob->spec;
    int btype = FLI_TRIANGLE_UPBOX8;
    char *label = ob->label;
    int x = ob->x,
        y = ob->y,
        w = ob->w,
        h = ob->h;

    if (    ob->col2 != FL_COL1
         && ( sp->event == FL_ENTER || sp->event == FL_LEAVE ) )
        return;

    if ( sp->event == FL_DRAW )
        fl_draw_box( ob->boxtype, x, y, w, h, ob->col1, ob->bw );

    if ( *label == '#' )
    {
        w = h = FL_min( ob->w, ob->h );
        x += ( ob->w - w ) / 2;
        y += ( ob->h - h ) / 2;
        label++;
    }

    if (    ( ob->boxtype != FL_NO_BOX && ob->boxtype != FL_FLAT_BOX )
         || abw == 1 )
    {
        extra += 1 + 0.051 * FL_min( w, h );
        abw = 1;
    }

    if ( *label == '2' )
        btype = sp->val ? FLI_TRIANGLE_DOWNBOX2 : FLI_TRIANGLE_UPBOX2;
    else if ( *label == '4' )
        btype = sp->val ? FLI_TRIANGLE_DOWNBOX4 : FLI_TRIANGLE_UPBOX4;
    else if ( *label == '6' )
        btype = sp->val ? FLI_TRIANGLE_DOWNBOX6 : FLI_TRIANGLE_UPBOX6;
    else if ( *label == '8' )
        btype = sp->val ? FLI_TRIANGLE_DOWNBOX8 : FLI_TRIANGLE_UPBOX8;

    c1 = ( ob->belowmouse && sp->event != FL_RELEASE ) ? FL_MCOL : ob->col2;
    fli_draw_tbox( btype, x + extra, y + extra, w - 2 * extra, h - 2 * extra,
                   c1, abw );
}


/***************************************
 * creates an object
 ***************************************/

FL_OBJECT *
fl_create_scrollbutton( int          type,
                        FL_Coord     x,
                        FL_Coord     y,
                        FL_Coord     w,
                        FL_Coord     h,
                        const char * label )
{
    FL_OBJECT *ob;

    fl_add_button_class( FL_SCROLLBUTTON, draw_scrollbutton, 0 );
    ob = fl_create_generic_button( FL_SCROLLBUTTON, type, x, y, w, h, label );
    ob->boxtype = FL_UP_BOX;
    ob->col1    = FL_COL1;
    ob->col2    = FL_COL1;
    ob->lcol    = FL_COL1;

    return ob;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_scrollbutton( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * label )
{
    FL_OBJECT *ob = fl_create_scrollbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
