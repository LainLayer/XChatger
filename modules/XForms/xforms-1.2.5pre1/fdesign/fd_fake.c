/*
 * This file is part of XForms.
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
 * \file fd_fake.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *.
 *  Fdesign is not capable of handing real canvas classes. Here
 *  we use frame/box classes to simulate the appearance of a canvas
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "private/pcanvas.h"


/***************************************
 ***************************************/

static int
handle_simu_canvas( FL_OBJECT * ob,
                    int         event,
                    FL_Coord    mx   FL_UNUSED_ARG,
                    FL_Coord    my   FL_UNUSED_ARG,
                    int         key  FL_UNUSED_ARG,
                    void      * ev   FL_UNUSED_ARG )
{
    int ftype;

    switch ( event )
    {
        case FL_DRAW:
            fl_draw_box( FL_FLAT_BOX, ob->x, ob->y, ob->w, ob->h,
                         ob->col1, ob->bw );
            ftype = fli_boxtype2frametype( ob->boxtype );
            fl_draw_frame( ftype, ob->x, ob->y, ob->w, ob->h, ob->col2,
                           ob->bw );
            fl_draw_text( ob->align, ob->x, ob->y, ob->w, ob->h,
                          ob->lcol, ob->lstyle, ob->lsize, ob->label );
            break;

        case FL_DRAWLABEL:
            if ( ! fl_is_center_lalign( ob->align ) )
                fl_draw_text( ob->align, ob->x, ob->y, ob->w, ob->h,
                              ob->lcol, ob->lstyle, ob->lsize, ob->label );
            break;
    }

    return 0;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_simu_canvas( int          type,
                       FL_Coord     x,
                       FL_Coord     y,
                       FL_Coord     w,
                       FL_Coord     h,
                       const char * label )
{
    FL_OBJECT *ob;
    FLI_CANVAS_SPEC *sp;

    ob = fl_make_object( FL_CANVAS, type, x, y, w, h, label,
                         handle_simu_canvas );
    ob->boxtype   = FL_CANVAS_BOXTYPE;
    ob->col1      = FL_NoColor;
    ob->col2      = FL_BLACK;
    ob->lcol      = FL_LCOL;
    ob->align     = FL_ALIGN_CENTER;
    ob->active    = 0;
    ob->spec = sp = fl_calloc( 1, sizeof *sp );

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_simu_canvas( int          type,
                    FL_Coord     x,
                    FL_Coord     y,
                    FL_Coord     w,
                    FL_Coord     h,
                    const char * label )
{
    FL_OBJECT *ob;

    ob = fl_create_simu_canvas( type, x, y, w, h, label );
    fl_add_object( fl_current_form, ob );

    return ob;
}


/***************************************
 * glcanvas
 ***************************************/

FL_OBJECT *
fl_create_simu_glcanvas( int          type,
                         FL_Coord     x,
                         FL_Coord     y,
                         FL_Coord     w,
                         FL_Coord     h,
                         const char * label )
{
    FL_OBJECT *ob;
    FLI_CANVAS_SPEC *sp;

    ob = fl_make_object( FL_GLCANVAS, type, x, y, w, h, label,
                         handle_simu_canvas );
    ob->boxtype = FL_CANVAS_BOXTYPE;
    ob->col1    = FL_NoColor;
    ob->col2    = FL_BLACK;
    ob->lcol    = FL_LCOL;
    ob->align   = FL_ALIGN_CENTER;
    ob->active  = 0;
    ob->spec    = sp = fl_calloc( 1, sizeof *sp );

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_simu_glcanvas( int          type,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * label )
{
    FL_OBJECT *ob;

    ob = fl_create_simu_glcanvas( type, x, y, w, h, label );
    fl_add_object( fl_current_form, ob );
    return ob;
}


/***************************************
 * fake tabfolder
 ***************************************/

static int
handle_tabfolder( FL_OBJECT * ob,
                  int         event,
                  FL_Coord    mx   FL_UNUSED_ARG,
                  FL_Coord    my   FL_UNUSED_ARG,
                  int         key  FL_UNUSED_ARG,
                  void      * ev   FL_UNUSED_ARG )
{
    if ( event == FL_DRAW )
    {
        fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1,
                     ob->bw );
        fl_draw_object_label( ob );
    }

    return 0;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_ntabfolder( int          type,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * label )
{
    FL_OBJECT *ob;

    ob = fl_make_object( FL_NTABFOLDER, type, x, y, w, h, label,
                         handle_tabfolder );

    ob->boxtype = FL_UP_BOX;
    ob->resize  = FL_RESIZE_NONE;
    ob->col1    = FL_COL1;
    ob->col2    = FL_COL1;
    ob->align   = FL_ALIGN_LEFT_TOP;

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_ntabfolder( int          type,
                   FL_Coord     x,
                   FL_Coord     y,
                   FL_Coord     w,
                   FL_Coord     h,
                   const char * label )
{
    FL_OBJECT *ob = fl_create_ntabfolder( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/***************************************
 * fake formbrowser
 ***************************************/

static int
handle_formbrowser( FL_OBJECT * ob,
                    int         event,
                    FL_Coord    mx   FL_UNUSED_ARG,
                    FL_Coord    my   FL_UNUSED_ARG,
                    int         key  FL_UNUSED_ARG,
                    void      * ev   FL_UNUSED_ARG )
{
    if ( event == FL_DRAW )
    {
        fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1,
                     ob->bw );
        fl_draw_object_label( ob );
    }

    return 0;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_nformbrowser( int          type,
                        FL_Coord     x,
                        FL_Coord     y,
                        FL_Coord     w,
                        FL_Coord     h,
                        const char * label )
{
    FL_OBJECT *ob;

    ob = fl_make_object( FL_FORMBROWSER, type, x, y, w, h, label,
                         handle_formbrowser );

    ob->boxtype = FL_DOWN_BOX;
    ob->resize  = FL_RESIZE_NONE;
    ob->col1    = FL_COL1;
    ob->col2    = FL_COL1;
    ob->align   = FL_ALIGN_BOTTOM;

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_nformbrowser( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * label )
{
    FL_OBJECT *ob = fl_create_nformbrowser( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
