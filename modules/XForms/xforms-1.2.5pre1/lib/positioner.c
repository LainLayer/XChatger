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
 * \file positioner.c
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
#include "private/ppositioner.h"

#include <sys/types.h>
#include <stdlib.h>


/* The special information for positioners.
 * ymin is the value at the bottom and ymax is the value at the top */


/***************************************
 * Performs linear interpolation
 ***************************************/

static double
flinear( double val,
         double smin,
         double smax,
         double gmin,
         double gmax )
{
    if ( smin == smax )
        return gmax;

    return gmin + ( gmax - gmin ) * ( val - smin ) / ( smax - smin );
}


/***************************************
 ***************************************/

static void
handle_background( FL_OBJECT * obj,
                   int         clear_pms )
{
    FLI_POSITIONER_SPEC *sp = obj->spec;
    
    FL_Coord absbw = FL_abs( obj->bw );
    FL_Coord x0 = obj->x + absbw + 1,
             y0 = obj->y + absbw + 1;
    FL_Coord w = obj->w - 2 * absbw - 2,
             h = obj->h - 2 * absbw - 2;
    FL_Coord xo = FL_crnd( flinear( sp->lxval, sp->xmin, sp->xmax,
                                    x0, x0 + w - 1 ) ),
             yo = FL_crnd( flinear( sp->lyval, sp->ymin, sp->ymax,
                                    y0 + h - 1, y0 ) ),
             xn = FL_crnd( flinear( sp->xval, sp->xmin, sp->xmax,
                                    x0, x0 + w - 1 ) ),
             yn = FL_crnd( flinear( sp->yval, sp->ymin, sp->ymax,
                                    y0 + h - 1, y0 ) );

    /* Return immediatel if we're called for an invisible positioner or
       there's no window yet. */

    if ( obj->type == FL_INVISIBLE_POSITIONER || FL_ObjWin( obj ) == None )
        return;

    /* If no GC has been created do it now. */

    if ( sp->copy_gc == None )
        sp->copy_gc = XCreateGC( flx->display, FL_ObjWin( obj ), 0, NULL );

    /* If there's a pixmap with what was under the horizontal line copy from
       it to the window to restore what's under the line. If we're asked to
       delete the pixmap also do so. */

    if ( sp->xpm != None )
    {
        XCopyArea( flx->display, sp->xpm, FL_ObjWin( obj ), sp->copy_gc,
                   0, 0, w, 1, x0, yo );

        if ( clear_pms )
        {
            XFreePixmap( flx->display, sp->xpm );
            sp->xpm = None;
        }
    }

    /* Same for vertical line... */

    if ( sp->ypm != None )
    {
        XCopyArea( flx->display, sp->ypm, FL_ObjWin( obj ), sp->copy_gc,
                   0, 0, 1, h, xo, y0 );

        if ( clear_pms )
        {
            XFreePixmap( flx->display, sp->ypm );
            sp->ypm = None;
        }
    }

    /* If we're not asked to delete the pixmap for storing what's under the
       horizontal line to be drawn safe the background, if necessary first
       creating new pixmaps for that. */

    if ( ! clear_pms )
    {
        if ( sp->xpm == None )
            sp->xpm = XCreatePixmap( flx->display, FL_ObjWin( obj ),
                                     w, 1, fl_get_visual_depth( ) );

        if ( sp->ypm == None )
            sp->ypm = XCreatePixmap( flx->display, FL_ObjWin( obj ),
                                         1, h, fl_get_visual_depth( ) );

        XCopyArea( flx->display, FL_ObjWin( obj ), sp->xpm, sp->copy_gc,
                   x0, yn, w, 1, 0, 0 );
        XCopyArea( flx->display, FL_ObjWin( obj ), sp->ypm, sp->copy_gc,
                   xn, y0, 1, h, 0, 0 );

        sp->lxval = sp->xval;
        sp->lyval = sp->yval;
    }
}


/***************************************
 ***************************************/

static void
draw_positioner( FL_OBJECT * obj )
{
    FLI_POSITIONER_SPEC *sp = obj->spec;
    FL_Coord absbw = FL_abs( obj->bw );
    FL_Coord x0 = obj->x + absbw + 1,
             y0 = obj->y + absbw + 1;
    FL_Coord w = obj->w - 2 * absbw - 2,
             h = obj->h - 2 * absbw - 2;
    FL_Coord x = FL_crnd( flinear( sp->xval, sp->xmin, sp->xmax,
                                   x0, x0 + w - 1 ) ),
             y = FL_crnd( flinear( sp->yval, sp->ymin, sp->ymax,
                                   y0 + h - 1, y0 ) );

    if ( FL_ObjWin( obj ) == None )
        return;

    if ( ! sp->partial )
    {
        if ( obj->type != FL_OVERLAY_POSITIONER )
            fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h,
                         obj->col1, obj->bw );
        fl_draw_object_label_outside( obj );
    }

    handle_background( obj, 0 );

    if ( x > x0 + 1 )
        fl_diagline( x0, y, x - x0 - 1, 1, obj->col2 );
    if ( w > x - x0 + 2 )
        fl_diagline( x + 2, y, w - x + x0 - 2, 1, obj->col2 );

    if ( y > y0 + 1 )
        fl_diagline( x, y0, 1, y - y0 - 1, obj->col2 );
    if ( h > y - y0 + 2 )
        fl_diagline( x, y + 2, 1, h - y + y0 - 2, obj->col2 );
}


/***************************************
 * Handle a mouse position change
 ***************************************/

static int
handle_mouse( FL_OBJECT * obj,
              FL_Coord    mx,
              FL_Coord    my )
{
    FLI_POSITIONER_SPEC * sp = obj->spec;
    FL_Coord absbw = FL_abs( obj->bw );
    FL_Coord x1 = obj->x + absbw + 1,
             y1 = obj->y + absbw + 1;
    FL_Coord w1 = obj->w - 2 * absbw - 2,
             h1 = obj->h - 2 * absbw - 2;
    double oldx = sp->xval,
           oldy = sp->yval;
    double x, y;

    x = flinear( mx, x1, x1 + w1 - 1.0, sp->xmin, sp->xmax );
    y = flinear( my, y1 + h1 - 1.0, y1, sp->ymin, sp->ymax );

    /* Make sure the position is within bounds */

    if ( ! sp->validator )
    {
        if ( sp->xstep != 0.0 )
            x = FL_nlong( x / sp->xstep ) * sp->xstep;
        if ( sp->ystep != 0.0 )
            y = FL_nlong( y / sp->ystep ) * sp->ystep;

        x = fli_clamp( x, sp->xmin, sp->xmax );
        y = fli_clamp( y, sp->ymin, sp->ymax );
    }
    else
    {
        double x_repl,
               y_repl;
        int ret = sp->validator( obj, x, y, &x_repl, &y_repl );

        if ( ret == FL_POSITIONER_INVALID )
            return FL_RETURN_NONE;
        else if ( ret == FL_POSITIONER_REPLACED )
        {
            x = x_repl;
            y = y_repl;
        }
    }

    sp->xval = x;
    sp->yval = y;

    if ( sp->xval != oldx || sp->yval != oldy )
    {
        sp->partial = 1;
        fl_redraw_object( obj );

        if ( ! ( obj->how_return & FL_RETURN_END_CHANGED ) )
            return FL_RETURN_CHANGED;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * Handles an event
 ***************************************/

static int
handle_positioner( FL_OBJECT * obj,
                   int         event,
                   FL_Coord    mx,
                   FL_Coord    my,
                   int         key  FL_UNUSED_ARG,
                   void      * ev   FL_UNUSED_ARG )
{
    FLI_POSITIONER_SPEC *sp = obj->spec;
    int ret = FL_RETURN_NONE;
    static int is_in = 0;

    switch ( event )
    {
        case FL_ATTRIB :
            obj->align = fl_to_outside_lalign( obj->align );
            handle_background( obj, 1 );
            break;

        case FL_DRAW:
            if ( obj->type != FL_INVISIBLE_POSITIONER )
                draw_positioner( obj );
            sp->partial = 0;
            break;

        case FL_DRAWLABEL:
            fl_draw_object_label_outside( obj );
            break;

        case FL_PUSH:
            if (    key < FL_MBUTTON1
                 || key > FL_MBUTTON5
                 || ! sp->react_to[ key - 1 ] )
            {
                fli_int.pushobj = NULL;
                break;
            }

            sp->mousebut = key;
            sp->old_x = sp->xval;
            sp->old_y = sp->yval;
            /* fall through */

        case FL_MOTION:
            if ( obj->type != FL_INVISIBLE_POSITIONER )
            {
                if (    is_in
                     && (    mx < obj->x || mx > obj->x + obj->w
                          || my < obj->y || my > obj->y + obj->h ) )
                {
                    is_in = 0;
                    fl_reset_cursor( FL_ObjWin( obj ) );
                }

                if (    ! is_in
                     && mx >= obj->x && mx <= obj->x + obj->w
                     && my >= obj->y && my <= obj->y + obj->h )
                {
                    fl_set_cursor( FL_ObjWin( obj ), FL_INVISIBLE_CURSOR );
                    is_in = 1;
                }
            }

            ret = handle_mouse( obj, mx, my );
            break;

        case FL_RELEASE:
            if ( sp->mousebut != key )
            {
                fli_int.pushobj = obj;
                break;
            }

            if ( obj->type != FL_INVISIBLE_POSITIONER )
                fl_reset_cursor( FL_ObjWin( obj ) );
            ret = FL_RETURN_END;
            if (    obj->how_return & FL_RETURN_END_CHANGED
                 && ( sp->xval != sp->old_x || sp->yval != sp->old_y ) )
                 ret |= FL_RETURN_CHANGED;
            is_in = 0;
            break;

        case FL_FREEMEM:
            if ( sp->copy_gc != None )
            {
                if ( obj->form )
                    handle_background( obj, 1 );
                else
                {
                    if ( sp->xpm != None )
                        XFreePixmap( flx->display, sp->xpm );
                    if ( sp->ypm != None )
                        XFreePixmap( flx->display, sp->ypm );
                }
                XFreeGC( flx->display, sp->copy_gc );
            }

            fl_free( obj->spec );
            break;
    }

    return ret;
}


/***************************************
 * Creates a posiioner object
 ***************************************/

FL_OBJECT *
fl_create_positioner( int          type,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * label )
{
    FL_OBJECT * obj;
    FLI_POSITIONER_SPEC * sp;
    int i;

    obj = fl_make_object( FL_POSITIONER, type, x, y, w, h, label,
                          handle_positioner );
    obj->boxtype = FL_POSITIONER_BOXTYPE;
    obj->col1    = FL_POSITIONER_COL1;
    obj->col2    = FL_POSITIONER_COL2;
    obj->align   = FL_POSITIONER_ALIGN;
    obj->lcol    = FL_POSITIONER_LCOL;

    if (    obj->type == FL_OVERLAY_POSITIONER
         || obj->type == FL_INVISIBLE_POSITIONER )
    {
        obj->bw = 0;
        obj->boxtype = FL_NO_BOX;
    }

    obj->spec = sp = fl_calloc( 1, sizeof *sp );

    sp->xmin = 0.0;
    sp->ymin = 0.0;
    sp->xmax = 1.0;
    sp->ymax = 1.0;
    sp->xval = 0.5;
    sp->yval = 0.5;
    sp->xpm = sp->ypm = None;
    sp->copy_gc = None;
    sp->validator = NULL;

    /* Per default a positioner reacts to the left mouse button only */

    sp->react_to[ 0 ] = 1;
    for ( i = 1; i < 5; i++ )
        sp->react_to[ i ] = 0;

    fl_set_object_return( obj, FL_RETURN_CHANGED );

    return obj;
}


/***************************************
 * Adds a positioner object
 ***************************************/

FL_OBJECT *
fl_add_positioner( int          type,
                   FL_Coord     x,
                   FL_Coord     y,
                   FL_Coord     w,
                   FL_Coord     h,
                   const char * label )
{
    FL_OBJECT *ob = fl_create_positioner( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/***************************************
 ***************************************/

int
fl_set_positioner_values( FL_OBJECT * obj,
                          double      new_x,
                          double      new_y )
{
    FLI_POSITIONER_SPEC * sp = obj->spec;
    int ret;
    double x = new_x;
    double y = new_y;

    if ( ! sp->validator )
    {
        if ( sp->xstep != 0.0 )
            x = FL_nlong( x / sp->xstep ) * sp->xstep;
        x = fli_clamp( x, sp->xmin, sp->xmax );

        if ( sp->ystep != 0.0 )
            y = FL_nlong( y / sp->ystep ) * sp->ystep;
        y = fli_clamp( y, sp->ymin, sp->ymax );
        
        ret = x == new_x && y == new_y ?
              FL_POSITIONER_VALID : FL_POSITIONER_REPLACED;
    }
    else
    {
        ret = sp->validator( obj, new_x, new_y, &x, &y );

        if ( ret == FL_POSITIONER_INVALID )
            return ret;
        else if ( ret != FL_POSITIONER_REPLACED )
        {
            x = new_x;
            y = new_y;
        }
    }

    if ( sp->xval != x || sp->yval != y )
    {
        sp->xval = x;
        sp->yval = y;
        sp->partial = 1;

        fl_redraw_object( obj );
    }

    return ret;
}


/***************************************
 ***************************************/

int
fl_set_positioner_xvalue( FL_OBJECT * obj,
                          double      val)
{
    FLI_POSITIONER_SPEC * sp = obj->spec;

    return fl_set_positioner_values( obj, val, sp->yval );
}


/***************************************
 ***************************************/

int
fl_set_positioner_yvalue( FL_OBJECT * obj,
                          double      val )
{
    FLI_POSITIONER_SPEC * sp = obj->spec;

    return fl_set_positioner_values( obj, sp->xval, val );
}


/***************************************
 ***************************************/

void
fl_set_positioner_xbounds( FL_OBJECT * obj,
                           double      min,
                           double      max )
{
    FLI_POSITIONER_SPEC * sp = obj->spec;

    if ( min == max )
    {
        M_err( "fl_set_positioner_xbounds",
               "Minimum and maximum value are identical" );
        return;
    }

    if ( sp->xmin == min && sp->xmax == max )
        return;

    sp->xmin = min;
    sp->xmax = max;

    if ( ! sp->validator )
        sp->xval = fli_clamp( sp->xval, sp->xmin, sp->xmax );
    else
    {
        double x, y;
        
        if ( sp->validator( obj, sp->xval, sp->yval, &x, &y )
                                                     == FL_POSITIONER_REPLACED )
        {
            sp->xval = x;
            sp->yval = y;
        }
    }

    fl_redraw_object( obj );
}


/***************************************
 ***************************************/

void
fl_set_positioner_ybounds( FL_OBJECT * obj,
                           double      min,
                           double     max )
{
    FLI_POSITIONER_SPEC * sp = obj->spec;

    if ( min == max )
    {
        M_err( "fl_set_positioner_ybounds",
               "Minimum and maximum value are identical" );
        return;
    }

    if ( sp->ymin == min && sp->ymax == max )
        return;

    sp->ymin = min;
    sp->ymax = max;

    if ( ! sp->validator )
        sp->yval = fli_clamp( sp->yval, sp->ymin, sp->ymax );
    else
    {
        double x, y;
        
        if ( sp->validator( obj, sp->xval, sp->yval, &x, &y )
                                                     == FL_POSITIONER_REPLACED )
        {
            sp->xval = x;
            sp->yval = y;
        }
    }

    fl_redraw_object( obj );
}


/***************************************
 ***************************************/

double
fl_get_positioner_xvalue( FL_OBJECT * obj )
{
    return ( ( FLI_POSITIONER_SPEC * ) obj->spec )->xval;
}


/***************************************
 ***************************************/

double
fl_get_positioner_yvalue( FL_OBJECT * obj )
{
    return ( ( FLI_POSITIONER_SPEC * ) obj->spec )->yval;
}


/***************************************
 ***************************************/

void
fl_get_positioner_xbounds( FL_OBJECT * obj,
                           double    * min,
                           double    * max )
{
    *min = ( ( FLI_POSITIONER_SPEC * ) obj->spec)->xmin;
    *max = ( ( FLI_POSITIONER_SPEC * ) obj->spec)->xmax;
}

void
fl_get_positioner_ybounds( FL_OBJECT * obj,
                           double    * min,
                           double    * max)
{
    *min = ( ( FLI_POSITIONER_SPEC * ) obj->spec)->ymin;
    *max = ( ( FLI_POSITIONER_SPEC * ) obj->spec)->ymax;
}


/***************************************
 * Sets the step size to which values are rounded.
 ***************************************/

void
fl_set_positioner_xstep( FL_OBJECT * obj,
                         double      value )
{
    ( ( FLI_POSITIONER_SPEC * ) obj->spec )->xstep = value;
}


/***************************************
 * Returns the step size to which values are rounded.
 ***************************************/

double
fl_get_positioner_xstep( FL_OBJECT * obj )
{
    return ( ( FLI_POSITIONER_SPEC * ) obj->spec )->xstep;
}


/***************************************
 * Sets the step size to which values are rounded.
 ***************************************/

void
fl_set_positioner_ystep( FL_OBJECT * obj,
                         double      value )
{
    ( ( FLI_POSITIONER_SPEC * ) obj->spec )->ystep = value;
}


/***************************************
 * Returns the step size to which values are rounded.
 ***************************************/

double
fl_get_positioner_ystep( FL_OBJECT * obj )
{
    return ( ( FLI_POSITIONER_SPEC * ) obj->spec )->ystep;
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as deprecated and
 * fl_set_object_return() should be used instead.
 * Please note that this function doesn't work like the other
 * object specific functions for setting the return policy!
 ***************************************/

void
fl_set_positioner_return( FL_OBJECT    * obj,
                          unsigned int   when )
{
    if ( when )
        fl_set_object_return( obj, FL_RETURN_CHANGED );
    else
        fl_set_object_return( obj, FL_RETURN_END );
}


/***************************************
 * Function allows to set up to which mouse
 * buttons the positioner object will react.
 ***************************************/

void
fl_set_positioner_mouse_buttons( FL_OBJECT    * obj,
                                 unsigned int   mouse_buttons )
{
    FLI_POSITIONER_SPEC *sp = obj->spec;
    unsigned int i;

    for ( i = 0; i < 5; i++, mouse_buttons >>= 1 )
        sp->react_to[ i ] = mouse_buttons & 1;
}


/***************************************
 * Function returns a value via 'mouse_buttons', indicating
 * which mouse buttons the positioner object will react to.
 ***************************************/

void
fl_get_positioner_mouse_buttons( FL_OBJECT    * obj,
                                 unsigned int * mouse_buttons )
{
    FLI_POSITIONER_SPEC *sp;
    int i;
    unsigned int k;

    if ( ! obj )
    {
        M_err( "fl_get_positioner_mouse_buttons", "NULL object" );
        return;
    }

    if ( ! mouse_buttons )
        return;

    sp = obj->spec;

    *mouse_buttons = 0;
    for ( i = 0, k = 1; i < 5; i++, k <<= 1 )
        *mouse_buttons |= sp->react_to[ i ] ? k : 0;
}


/***************************************
 * Returns the number of the last used mouse button.
 * fl_mouse_button will also return the mouse number
 ***************************************/

int
fl_get_positioner_numb( FL_OBJECT * obj )
{
    return ( ( FLI_POSITIONER_SPEC * ) obj->spec )->mousebut;
}


/***************************************
 * Allows to set a validator function for new positions
 ***************************************/

FL_POSITIONER_VALIDATOR
fl_set_positioner_validator( FL_OBJECT               * obj,
                             FL_POSITIONER_VALIDATOR   validator )
{
    FLI_POSITIONER_SPEC *sp = obj->spec;

    FL_POSITIONER_VALIDATOR old_validator = sp->validator;

    if ( ! validator )
    {
        if ( sp->xstep != 0.0 )
            sp->xval = FL_nlong( sp->xval / sp->xstep ) * sp->xstep;

        if ( sp->ystep != 0.0 )
            sp->yval = FL_nlong( sp->yval / sp->ystep ) * sp->ystep;

        sp->xval = fli_clamp( sp->xval, sp->xmin, sp->xmax );
        sp->yval = fli_clamp( sp->yval, sp->ymin, sp->ymax );
    }
    else
    {
        int ret;
        double x, y;

        ret = validator( obj, sp->xval, sp->yval, &x, &y );

        if ( ret == FL_POSITIONER_INVALID )
            M_warn( "fl_set_positioner_validator",
                    "Current positioner values not within valid range" );
        else if ( ret == FL_POSITIONER_REPLACED )
        {
            sp->xval = x;
            sp->yval = y;
        }
    }

    sp->validator = validator;
    fl_redraw_object( obj );

    return old_validator;
}


/***************************************
 * Function to be called for overlay positioners before what it is on top
 * of is changed: undraws the lines of the positioner - they will get
 * redrawn once the object under the positioner has been redrawn.
 ***************************************/

void
fl_reset_positioner( FL_OBJECT * obj )
{
    if ( obj->type == FL_OVERLAY_POSITIONER )
        handle_background( obj, 1 );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
