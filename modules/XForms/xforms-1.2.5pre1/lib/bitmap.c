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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file bitmap.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  FL_BITMAP & FL_BITMAPBUTTON class.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"



/***************************************
 ***************************************/

static void
free_bitmap( FL_BUTTON_STRUCT * p )
{
    if ( p->pixmap )
        XFreePixmap( flx->display, p->pixmap );
    p->pixmap = None;
}


/********************************************************************
 * static bitmap
 ******************************************************************{*/

static void
drawit( Window   win,
        FL_Coord x,
        FL_Coord y,
        FL_Coord w,
        FL_Coord h,
        FL_Coord src_x,
        FL_Coord src_y,
        FL_COLOR fcol,
        FL_COLOR bcol,
        Pixmap   bitmap )
{
    FL_Coord clip_x,
             clip_y,
             clip_w,
             clip_h;

    /* Get the currently set clipping */

    if ( fl_get_clipping( 1, &clip_x, &clip_y, &clip_w, &clip_h ) )
    {
        if ( w <= 0 || h <= 0 )
            return;

        /* If the bitmap is not within the clipping region nothing is
           to be drawn */

        if (    x + w < clip_x
             || x > clip_x + clip_w
             || y + h < clip_y
             || y > clip_y + clip_h )
            return;

        /* If the bitmap isn't completely within the clipping region
           recalculate what to draw */

        if (    x <= clip_x
             || x + w >= clip_x + clip_w
             || y <= clip_y
             || y + h >= clip_y + clip_h )
        {
            if ( x < clip_x )
            {
                src_x  += clip_x - x;
                w -= clip_x - x;
                x = clip_x;
            }

            if ( x + w > clip_x + clip_w )
                w = clip_x + clip_w - x;

            if ( y < clip_y )
            {
                src_y  += clip_y - y;
                h -= clip_y - y;
                y = clip_y;
            }

            if ( y + h > clip_y + clip_h )
                h = clip_y + clip_h - y;
        }
    }

    fl_color( fcol );
    fl_bk_color( bcol );

    XCopyPlane( flx->display, bitmap, win, flx->gc, src_x, src_y,
                w, h, x, y, 1 );
}


/***************************************
 ***************************************/

static void
draw_bitmap( FL_OBJECT * obj )
{
    FL_BUTTON_STRUCT *sp = obj->spec;
    FL_Coord xx,                        /* position of bitmap */
             yy;

    /* Draw the box */

    fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h,
                 obj->col1, obj->bw );

    /* Do nothing for empty data */

    if ( sp->bits_w == 0 || ! sp->pixmap )
        return;

    /* Calculate position so the bitmap is centered */

    xx = obj->x + ( obj->w - sp->bits_w ) / 2;
    yy = obj->y + ( obj->h - sp->bits_h ) / 2;

    drawit( FL_ObjWin( obj ), xx, yy, sp->bits_w, sp->bits_h, 0, 0,
            obj->lcol, obj->col1, sp->pixmap );
}



/***************************************
 * Handles an event, returns whether value has changed.
 ***************************************/

static int
handle_bitmap( FL_OBJECT * obj,
               int         event,
               FL_Coord    mx   FL_UNUSED_ARG,
               FL_Coord    my   FL_UNUSED_ARG,
               int         key  FL_UNUSED_ARG,
               void      * ev   FL_UNUSED_ARG )
{
    switch ( event )
    {
        case FL_DRAW :
            draw_bitmap( obj );
            /* fall through */

        case FL_DRAWLABEL :
            fl_draw_object_label( obj );
            break;

        case FL_FREEMEM :
            free_bitmap( obj->spec );
            fl_free( obj->spec );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * Creates an object
 ***************************************/

FL_OBJECT *
fl_create_bitmap( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    FL_OBJECT *obj;
    FL_BUTTON_STRUCT *sp;

    obj = fl_make_object( FL_BITMAP, type, x, y, w, h, label, handle_bitmap );
    obj->boxtype = FL_BITMAP_BOXTYPE;
    obj->col1    = FL_BITMAP_COL1;
    obj->col2    = FL_BITMAP_COL2;
    obj->lcol    = FL_BITMAP_LCOL;
    obj->align   = FL_BITMAP_ALIGN;
    obj->active  = type != FL_NORMAL_BITMAP;

    sp = obj->spec = fl_calloc( 1, sizeof *sp );

    sp->pixmap   = sp->mask = sp->focus_pixmap = sp->focus_mask = None;
    sp->cspecv   = NULL;
    sp->filename = sp->focus_filename = NULL;

    return obj;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_bitmap( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label )
{
    FL_OBJECT *obj = fl_create_bitmap( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 * Fills the bitmap with a bitmap.
 ***************************************/

void
fl_set_bitmap_data( FL_OBJECT     * obj,
                    int             w,
                    int             h,
                    unsigned char * data )
{
    FL_BUTTON_STRUCT *sp;
    Pixmap p;

    if ( obj == NULL || obj->objclass != FL_BITMAP )
        return;

    /* Only occurs with fdesign -convert */

    if ( ! flx->display )
        return;

    sp = obj->spec;

    p = XCreateBitmapFromData( flx->display,
                               FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_root,
                               ( char * ) data, w, h );

    if ( p == None )
    {
        M_err( "fl_set_bitmap_data", "Can't create bitmap" );
        return;
    }

    sp->bits_w = w;
    sp->bits_h = h;
    sp->pixmap = p;

    fl_redraw_object( obj );
}


/***************************************
 ***************************************/

Pixmap
fl_read_bitmapfile( Window         win,
                    const char   * file,
                    unsigned int * w,
                    unsigned int * h,
                    int          * hotx,
                    int          * hoty )
{
    Pixmap p = None;
    int status;

    status = XReadBitmapFile( flx->display, win, ( char * ) file,
                              w, h, &p, hotx, hoty );

    if ( status != BitmapSuccess )
        M_err( "fl_read_bitmapfile", "%s: %s", file,
               status == BitmapFileInvalid ? "Invalid file" : "Can't read" );
    return p;
}


/***************************************
 ***************************************/

void
fl_set_bitmap_file( FL_OBJECT  * obj,
                    const char * fname )
{
    unsigned int w,
                 h;
    int xhot,
        yhot;
    Pixmap p;

    if ( ! flx->display )
        return;

    if (    ! obj
         || ( obj->objclass != FL_BITMAP && obj->objclass != FL_BITMAPBUTTON ) )
    {
        M_err( "fl_set_bitmap_file", "object %s not bitmap or bitmap button",
               ( obj && obj->label ) ? obj->label : "null" );
        return;
    }

    p = fl_read_bitmapfile( FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_root,
                            fname, &w, &h, &xhot, &yhot );

    if ( p != None )
    {
        FL_BUTTON_STRUCT *sp = obj->spec;

        free_bitmap( sp );
        sp->pixmap = p;
        sp->bits_w = w;
        sp->bits_h = h;
    }

    fl_redraw_object( obj );
}


/***** End of static BITMAP ************************/


/*******************************************************************
 * BITMAP buttons
 ****************************************************************{*/

/***************************************
 ***************************************/

static void
draw_bitmapbutton( FL_OBJECT * obj )
{
    FL_BUTTON_STRUCT *sp = obj->spec;

    fli_draw_button( obj );

    if ( sp->pixmap != None && sp->bits_w > 0 && sp->bits_h > 0 )
    {
        int dest_x,
            dest_y,
            dest_w,
            dest_h,
            src_x,
            src_y;
        FL_COLOR col;

        /* Make sure the bitmap gets clipped to the maximum size fitting
           into the button */

        if ( obj->w - 2 * FL_abs( obj->bw ) > ( int ) sp->bits_w )
        {
            dest_x = obj->x + ( obj->w - sp->bits_w ) / 2;
            dest_w = sp->bits_w;
            src_x  = 0;
        }
        else
        {
            dest_x = obj->x + FL_abs( obj->bw );
            dest_w = obj->w - 2 * FL_abs( obj->bw );
            src_x  = ( sp->bits_w - dest_w ) / 2;
        }

        if ( obj->h - 2 * FL_abs( obj->bw ) > ( int ) sp->bits_h )
        {
            dest_y = obj->y + ( obj->h - sp->bits_h ) / 2;
            dest_h = sp->bits_h;
            src_y  = 0;
        }
        else
        {
            dest_y = obj->y + FL_abs( obj->bw );
            dest_h = obj->h - 2 * FL_abs( obj->bw );
            src_y  = ( sp->bits_h - dest_h ) / 2;
        }

        col = sp->val ? obj->col2 : obj->col1;

        if ( obj->belowmouse && col == FL_BUTTON_COL1 )
            col = FL_BUTTON_MCOL1;
        if ( obj->belowmouse && col == FL_BUTTON_COL2 )
            col = FL_BUTTON_MCOL2;

        drawit( FL_ObjWin( obj ), dest_x, dest_y, dest_w,  dest_h,
                src_x, src_y, obj->lcol, col, sp->pixmap );
    }

    fl_draw_object_label( obj );

}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_bitmapbutton( int          type,
                        FL_Coord     x,
                        FL_Coord     y,
                        FL_Coord     w,
                        FL_Coord     h,
                        const char * label )
{
    FL_OBJECT *obj;

    fl_add_button_class( FL_BITMAPBUTTON, draw_bitmapbutton, 0 );
    obj = fl_create_generic_button( FL_BITMAPBUTTON, type, x, y, w, h, label );

    obj->boxtype = FL_BITMAPBUTTON_BOXTYPE;
    obj->col1    = FL_BITMAPBUTTON_COL1;
    obj->col2    = FL_BITMAPBUTTON_COL2;
    obj->align   = FL_BITMAPBUTTON_ALIGN;
    obj->lcol    = FL_BITMAP_LCOL;

    return obj;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_bitmapbutton( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * label )
{
    FL_OBJECT *obj = fl_create_bitmapbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 ***************************************/

void
fl_set_bitmapbutton_data( FL_OBJECT     * obj,
                          int             w,
                          int             h,
                          unsigned char * bits )
{
    FL_BUTTON_STRUCT *sp;
    Window win;

    if ( ! obj || obj->objclass != FL_BITMAPBUTTON )
        return;

    win = FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_root;

    sp = obj->spec;
    free_bitmap( sp );
    sp->bits_w = w;
    sp->bits_h = h;

    sp->pixmap = XCreateBitmapFromData( flx->display, win, ( char * ) bits,
                                        sp->bits_w, sp->bits_h );

    fl_redraw_object( obj );
}


/***************************************
 ***************************************/

Pixmap
fl_create_from_bitmapdata( Window       win,
                           const char * data,
                           int          width,
                           int          height )
{
    return XCreateBitmapFromData( fl_display, win, data, width, height );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
