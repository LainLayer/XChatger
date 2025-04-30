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
 * \file box.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


/***************************************
 ***************************************/

static int
handle_box( FL_OBJECT * obj,
            int         event,
            FL_Coord    mx   FL_UNUSED_ARG,
            FL_Coord    my   FL_UNUSED_ARG,
            int         key  FL_UNUSED_ARG,
            void      * ev   FL_UNUSED_ARG )
{
    switch ( event )
    {
        case FL_DRAW:
            fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h,
                         obj->col1, obj->bw );
            /* fall through */

        case FL_DRAWLABEL:
            if ( fl_is_inside_lalign( obj->align ) )
                fl_set_text_clipping( obj->x + obj->bw, obj->y + obj->bw,
                                      obj->w - 2 * obj->bw,
                                      obj->h - 2 * obj->bw );
            fl_draw_object_label( obj );
            if ( fl_is_inside_lalign( obj->align ) )
                fl_unset_text_clipping( );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_box( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label )
{
    FL_OBJECT *obj;

    obj = fl_make_object( FL_BOX, type, x, y, w, h, label, handle_box );
    obj->boxtype = type;
    obj->col1    = FL_COL1;
    obj->col2    = FL_COL1;
    obj->lcol    = FL_LCOL;
    obj->align   = FL_ALIGN_CENTER;
    obj->active  = 0;

    if ( type == FL_NO_BOX || type == FL_FLAT_BOX )
        obj->bw = 0;

    return obj;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_box( int          type,
            FL_Coord     x,
            FL_Coord     y,
            FL_Coord     w,
            FL_Coord     h,
            const char * label)
{
    FL_OBJECT *obj = fl_create_box( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
