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
 * \file round3d.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
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
draw_round3dbutton( FL_OBJECT * ob )
{
    int c1;
    FL_Coord xx,
             yy,
             rr,
             bw = FL_abs( ob->bw );
    FL_BUTTON_STRUCT *sp = ob->spec;

    if (    ob->boxtype == FL_NO_BOX
         && ( sp->event == FL_ENTER || sp->event == FL_LEAVE ) )
        return;

    c1 = ob->belowmouse ? FL_ROUND3DBUTTON_MCOL : FL_ROUND3DBUTTON_TOPCOL;

    fl_draw_box(ob->boxtype, ob->x, ob->y, ob->w, ob->h, c1, ob->bw);

    rr = 0.3 * FL_min( ob->w, ob->h ) + 0.5;
    xx = ob->x + rr + 4.1;
    yy = ob->y + 0.5 * ob->h;

    if ( rr < bw / 2 )
        rr = bw / 2 + 1;

#if 1
    fl_draw_box( FL_OVAL3D_DOWNBOX, xx - rr, yy - rr,
                 2 * rr, 2 * rr, ob->col1, ob->bw );
#else
    olw = fl_get_linewidth( );
    fl_linewidth( bw );
    fl_arc( xx, yy, rr - bw / 2, 450, 2250, FL_BOTTOM_BCOL );
    fl_arc( xx, yy, rr - bw / 2, 0, 450, FL_TOP_BCOL );
    fl_arc( xx, yy, rr - bw / 2, 2250, 3600, FL_TOP_BCOL );
    fl_linewidth( olw );

    if ( fli_dithered( fl_vmode ) )
        fl_arc( xx, yy, rr - bw / 2, 0, 3600, FL_BLACK );
#endif

    if ( sp->val )
        fl_circf( xx, yy, ( int ) FL_max( 1, 0.85 * rr - 1.0 - 0.5 * bw ),
                  ob->col2 );

    if ( fl_is_center_lalign( ob->align ) )
        fl_draw_text( FL_ALIGN_LEFT, xx + rr + 1, ob->y, 0, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        fl_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                             ob->lcol, ob->lstyle, ob->lsize, ob->label );

    if ( ob->type == FL_RETURN_BUTTON )
        fl_draw_text( 0, ob->x + ob->w - 0.8 * ob->h, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h, ob->lcol, 0, 0,
                      "@returnarrow" );
}


/***************************************
 * creates an object
 ***************************************/

FL_OBJECT *
fl_create_round3dbutton( int          type,
                         FL_Coord     x,
                         FL_Coord     y,
                         FL_Coord     w,
                         FL_Coord     h,
                         const char * label )
{
    FL_OBJECT *ob;

    fl_add_button_class( FL_ROUND3DBUTTON, draw_round3dbutton, 0 );
    ob = fl_create_generic_button( FL_ROUND3DBUTTON, type, x, y, w, h, label );

    ob->boxtype = FL_ROUND3DBUTTON_BOXTYPE;
    ob->col1    = FL_ROUND3DBUTTON_COL1;
    ob->col2    = FL_ROUND3DBUTTON_COL2;
    ob->align   = FL_ROUND3DBUTTON_ALIGN;
    ob->lcol    = FL_ROUND3DBUTTON_LCOL;

    return ob;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_round3dbutton( int          type,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * label )
{
    FL_OBJECT *ob = fl_create_round3dbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
