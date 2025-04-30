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
 * \file lframe.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  similar to FL_FRAME, but label is drawn on the frame
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


/***************************************
 ***************************************/

static int
handle_lframe( FL_OBJECT * ob,
               int         event,
               FL_Coord    mx   FL_UNUSED_ARG,
               FL_Coord    my   FL_UNUSED_ARG,
               int         key  FL_UNUSED_ARG,
               void      * ev   FL_UNUSED_ARG )
{
    int sx,
        sy,
        sw,
        sh,
        align,
        bw = FL_abs( ob->bw ),
        dy;
    int margin,
        len;

    switch ( event )
    {
        case FL_ATTRIB :
            if ( ! ( ob->align & ~ FL_ALIGN_INSIDE ) )
                ob->align = FL_ALIGN_TOP;
            else
                ob->align = fl_to_outside_lalign( ob->align );

            if ( ob->align == FL_ALIGN_RIGHT )
                ob->align = FL_ALIGN_RIGHT_TOP;
            if ( ob->align == FL_ALIGN_LEFT )
                ob->align = FL_ALIGN_LEFT_TOP;
            break;

        case FL_DRAW :
            fl_draw_frame( ob->type, ob->x, ob->y, ob->w, ob->h,
                           ob->col1, ob->bw );
            /* fall through */

        case FL_DRAWLABEL :
            if ( ! ( len = strlen( ob->label ) ) )
                return 0;

            fl_get_string_dimension( ob->lstyle, ob->lsize,
                                     ob->label, len, &sw, &sh );

            align = fl_to_outside_lalign( ob->align );

            sw += 8;
            margin = 11 + ob->w * 0.02;
            dy = 0;

            if ( ob->type == FL_ROUNDED_FRAME )
                margin += 7;

            if ( ob->w - sw < 2 * margin )
            {
                margin /= 2;
                sw -= 2;
            }

            if ( ob->w - sw < 2 * margin )
            {
                margin /= 2;
                sw -= 2;
            }

            if ( ob->type == FL_UP_FRAME || ob->type == FL_DOWN_FRAME )
                dy = ( bw + 1 ) / 2;

            switch ( align )
            {
                case FL_ALIGN_RIGHT_TOP :
                case FL_ALIGN_RIGHT :
                    sx = ob->x + ob->w - margin - sw;
                    sy = ob->y - sh / 2 - dy;
                    break;

                case FL_ALIGN_TOP :
                    sx = ob->x + ( ob->w - sw ) / 2;
                    sy = ob->y - sh / 2 - dy;
                    break;

                case FL_ALIGN_LEFT_BOTTOM :
                    sx = ob->x + margin;
                    sy = ob->y + ob->h - sh / 2 + dy;
                    break;

                case FL_ALIGN_RIGHT_BOTTOM :
                    sx = ob->x + ob->w - margin - sw;
                    sy = ob->y + ob->h - sh / 2 + dy;
                    break;

                case FL_ALIGN_BOTTOM :
                    sx = ob->x + ( ob->w - sw ) / 2;
                    sy = ob->y + ob->h - sh / 2 + dy;
                    break;

                default :
                    sx = ob->x + margin;
                    sy = ob->y - sh / 2 - dy;
                    break;
            }

            fl_draw_box( FL_FLAT_BOX, sx, sy, sw, sh, ob->col2, 0 );
            fl_draw_text( FL_ALIGN_CENTER, sx, sy, sw, sh,
                          ob->lcol, ob->lstyle, ob->lsize, ob->label );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_labelframe( int          type,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * label )
{
    FL_OBJECT *ob;

    ob = fl_make_object( FL_LABELFRAME, type, x, y, w, h, label,
                         handle_lframe );
    ob->boxtype = FL_NO_BOX;
    ob->col1    = FL_FRAME_COL1;
    ob->col2    = FL_FRAME_COL2;
    ob->lcol    = FL_FRAME_LCOL;
    ob->align   = FL_ALIGN_LEFT_TOP;
    ob->active  = 0;

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_labelframe( int          type,
                   FL_Coord     x,
                   FL_Coord     y,
                   FL_Coord     w,
                   FL_Coord     h,
                   const char * label )
{
    FL_OBJECT *ob = fl_create_labelframe( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );

    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
