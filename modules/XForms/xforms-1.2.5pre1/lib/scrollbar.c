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
 * \file scrollbar.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Scrollbar
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pscrollbar.h"


static void get_geom( FL_OBJECT * );

static void attrib_change( FL_OBJECT * );


#define IsVThin( t )  (    t == FL_VERT_THIN_SCROLLBAR    \
                        || t == FL_VERT_PLAIN_SCROLLBAR )
#define IsHThin( t )  (    t == FL_HOR_THIN_SCROLLBAR     \
                        || t == FL_HOR_PLAIN_SCROLLBAR )
#define IsThin( t )   ( IsVThin( t ) || IsHThin( t ) )


/***************************************
 ***************************************/

static int
handle_scrollbar( FL_OBJECT * obj,
                  int         event,
                  FL_Coord    mx   FL_UNUSED_ARG,
                  FL_Coord    my   FL_UNUSED_ARG,
                  int         key  FL_UNUSED_ARG,
                  void      * ev   FL_UNUSED_ARG )
{
    switch ( event )
    {
        case FL_ATTRIB :
        case FL_RESIZED :
            obj->align = fl_to_outside_lalign( obj->align );
            attrib_change( obj );
            get_geom( obj );
            break;

        case FL_DRAW :
            if ( IsThin( obj->type ) )
                fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h,
                             obj->col1, obj->bw );
            /* fall through */

        case FL_DRAWLABEL :
            fl_draw_object_label_outside( obj );
            break;

        case FL_FREEMEM :
            /* children will take care of themselves */
            fl_free( obj->spec );
            break;
    }

    return FL_RETURN_NONE;
}

#define IS_HORIZ( o )  ( ( o )->type & FL_HOR_FLAG )


/***************************************
 ***************************************/

static void
attrib_change( FL_OBJECT * obj )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    sp->slider->col1 = obj->col1;
    sp->slider->col2 = obj->col2;
    sp->up->col1     = sp->down->col1    = obj->col1;
    sp->up->col2     = sp->down->col2    = obj->col2;
    sp->up->boxtype  = sp->down->boxtype = sp->slider->boxtype = obj->boxtype;

    fli_notify_object( sp->slider, FL_ATTRIB );
}


/***************************************
 ***************************************/

static void
get_geom( FL_OBJECT * obj )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;
    FL_OBJECT *up     = sp->up,
              *down   = sp->down,
              *slider = sp->slider;
    int x = obj->x,
        y = obj->y,
        w = obj->w,
        h = obj->h;
    int absbw = FL_abs( obj->bw );
    int t = obj->type;

    if ( IS_HORIZ( obj ) )
    {
        down->x = x;
        up->x = x + w - h;
        up->y = down->y = y;
        down->h = up->h = h;
        down->w = up->w = FL_min( w, h );

        slider->x = x + h;
        slider->y = y;
        slider->h = h;

        if ( ( slider->w = w - 2 * up->w ) < 0 )
        {
            slider->w = up->w / 3;
            slider->x = x + up->w / 3;
        }
    }
    else
    {
        up->x = down->x = x;
        up->y = y;
        up->w = down->w = w;
        up->h = down->h = FL_min( w, h );

        slider->x = x;
        slider->y = y + up->h;
        slider->w = w;

        if ( ( slider->h = h - 2 * up->h ) < 0 )
        {
            slider->h = h / 3;
            slider->y = y + up->h / 3;
        }

        down->y = y + h - down->h;
    }

    up->bw     = obj->bw;
    down->bw   = obj->bw;
    slider->bw = obj->bw;

    if ( absbw > 2 )
        absbw--;

    if ( obj->bw > 0 )
        up->bw = down->bw = absbw;
    else
        up->bw = down->bw = -absbw;

    if ( IsThin( t ) )
    {
        absbw = IS_FLATBOX( obj->boxtype ) ? 1 : absbw;

        up->boxtype = down->boxtype = FL_NO_BOX;
        up->bw = down->bw = absbw;

        /* Due to slider double buffering we have to be completely clear of
           the scrollbar bounding box, otherwise the slider will wipe out the
           scrollbars bounding box */

        if ( IsVThin( t ) )
        {
            slider->x += absbw + 1;
            slider->w -= 2 * absbw + 2;
            slider->y -= absbw + ( absbw > 1 );
            slider->h += 2 * absbw + ( absbw > 1 );
        }
        else
        {
            slider->y += absbw + 1;
            slider->h -= 2 * absbw + 2;
            slider->x -= absbw + ( absbw > 1 );
            slider->w += 2 * absbw + ( absbw > 1 );
        }
    }

    fli_notify_object( slider, FL_RESIZED );
}


/***************************************
 * Callback for the slider in the scrollbar
 ***************************************/

static void
slider_cb( FL_OBJECT * obj,
           long        data  FL_UNUSED_ARG )
{
    FLI_SCROLLBAR_SPEC *sp = obj->parent->spec;

    if ( obj->returned & FL_RETURN_END )
        obj->parent->returned |= FL_RETURN_END;

    if (    obj->parent->how_return & FL_RETURN_END_CHANGED
         && obj->returned & FL_RETURN_END )
    {
        double nval = fl_get_slider_value( obj );

        if ( nval != sp->old_val )
            obj->parent->returned |= FL_RETURN_CHANGED;
        sp->old_val = nval;
    }
    else if ( obj->returned & FL_RETURN_CHANGED )
        obj->parent->returned |= FL_RETURN_CHANGED;
}


/***************************************
 * Callback for the buttons of the scrollbar
 ***************************************/

static void
button_cb( FL_OBJECT * obj,
           long        data )
{
    FLI_SCROLLBAR_SPEC *sp = obj->parent->spec;
    double ival = fl_get_slider_value( sp->slider ),
           nval = ival,
           slmax,
           slmin;

    /* Update the slider and get the new value */

    if ( obj->returned == FL_RETURN_TRIGGERED )
        obj->returned = FL_RETURN_END | FL_RETURN_CHANGED;

    if ( obj->returned & FL_RETURN_CHANGED )
    {
        fl_get_slider_bounds( sp->slider, &slmin, &slmax );

        if ( slmax > slmin )
            nval = ival + data * sp->increment;
        else
            nval = ival - data * sp->increment;

        fl_set_slider_value( sp->slider, nval );

        nval = fl_get_slider_value( sp->slider );
    }

    if ( obj->returned & FL_RETURN_END )
        obj->parent->returned |= FL_RETURN_END;

    /* If we're supposed to return only on end and change check if the
       slider value changed since interaction started, if we have to return
       on everty change check if if it changed this time round */

    if (    obj->parent->how_return & FL_RETURN_END_CHANGED
         && obj->returned & FL_RETURN_END )
    {
        if ( nval != sp->old_val )
        {
            obj->parent->returned |= FL_RETURN_CHANGED;
            sp->old_val = nval;
        }
    }
    else if ( ival != nval )
        obj->parent->returned |= FL_RETURN_CHANGED;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_scrollbar( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * l )
{
    FLI_SCROLLBAR_SPEC *sp;
    FL_OBJECT *obj;

    obj = fl_make_object( FL_SCROLLBAR, type, x, y, w, h, l, handle_scrollbar );

    obj->spec       = sp = fl_calloc( 1, sizeof *sp );
    obj->col1       = FL_COL1;
    obj->col2       = FL_COL1;
    obj->align      = FL_SCROLLBAR_ALIGN;
    obj->set_return = fl_set_scrollbar_return;

    if ( IsThin( type ) )
        obj->boxtype = FL_DOWN_BOX;
    else if ( type == FL_HOR_NICE_SCROLLBAR || type == FL_VERT_NICE_SCROLLBAR )
        obj->boxtype = FL_FRAME_BOX;
    else
        obj->boxtype = FL_UP_BOX;

    if ( IS_HORIZ( obj ) )
    {
        fl_set_object_resize( obj, FL_RESIZE_X );

        sp->up   = fl_create_scrollbutton( FL_TOUCH_BUTTON, 1, 1, 1, 1, "6" );
        sp->down = fl_create_scrollbutton( FL_TOUCH_BUTTON, 1, 1, 1, 1, "4" );
        fl_set_object_callback( sp->up, button_cb, 1 );
        fl_set_object_callback( sp->down, button_cb, -1 );
        fl_set_object_resize( sp->up, FL_RESIZE_NONE );
        fl_set_object_resize( sp->down, FL_RESIZE_NONE );

        if ( type == FL_HOR_SCROLLBAR )
            sp->slider = fl_create_slider( FL_HOR_BROWSER_SLIDER2,
                                           1, 1, 1, 1, "" );
        else if ( type == FL_HOR_THIN_SCROLLBAR )
            sp->slider = fl_create_slider( FL_HOR_THIN_SLIDER,
                                           1, 1, 1, 1, "" );
        else if ( type == FL_HOR_PLAIN_SCROLLBAR )
            sp->slider = fl_create_slider( FL_HOR_BASIC_SLIDER,
                                           1, 1, 1, 1, "" );
        else if ( type == FL_HOR_NICE_SCROLLBAR )
            sp->slider = fl_create_slider( FL_HOR_NICE_SLIDER2,
                                           1, 1, 1, 1, "" );

        fl_set_object_resize( sp->slider, FL_RESIZE_NONE );
    }
    else
    {
        fl_set_object_resize( obj, FL_RESIZE_Y );

        sp->up = fl_create_scrollbutton( FL_TOUCH_BUTTON, 1, 1, 1, 1, "8" );
        sp->down = fl_create_scrollbutton( FL_TOUCH_BUTTON, 1, 1, 1, 1, "2" );
        fl_set_object_callback( sp->up, button_cb, -1 );
        fl_set_object_callback( sp->down, button_cb, 1 );
        fl_set_object_resize( sp->up, FL_RESIZE_NONE );
        fl_set_object_resize( sp->down, FL_RESIZE_NONE );

        if ( type == FL_VERT_SCROLLBAR )
            sp->slider = fl_create_slider( FL_VERT_BROWSER_SLIDER2, 1, 1,
                                           1, 1, "" );
        else if ( type == FL_VERT_THIN_SCROLLBAR )
            sp->slider = fl_create_slider( FL_VERT_THIN_SLIDER, 1, 1,
                                           1, 1, "" );
        else if ( type == FL_VERT_PLAIN_SCROLLBAR )
            sp->slider = fl_create_slider( FL_VERT_BASIC_SLIDER, 1, 1,
                                           1, 1, "" );
        else if ( type == FL_VERT_NICE_SCROLLBAR )
            sp->slider = fl_create_slider( FL_VERT_NICE_SLIDER2, 1, 1,
                                           1, 1, "" );
        else
            M_err( "fl_create_scrollbar", "Unknown type %d", type );

        fl_set_object_resize( sp->slider, FL_RESIZE_NONE );
    }

    sp->increment = 0.02;
    fl_set_slider_increment( sp->slider, 5 * sp->increment, sp->increment );
    fl_set_object_callback( sp->slider, slider_cb, 0 );
    fl_set_slider_bounds( sp->slider, 0.0, 1.0 );

    sp->old_val = fl_get_slider_value( sp->slider );

    fl_add_child( obj, sp->slider );
    fl_add_child( obj, sp->down );
    fl_add_child( obj, sp->up );

    /* In older versions scrollbars and browsers didn't return to the
       application on e.g. fl_do_forms() but still a callback associated
       with the object got called. To emulate the old behaviour we have
       to set the return policy to default to FL_RETURN_NONE and only
       change that to FL_RETURN_CHANGED when a callback is installed
       (which is done in fl_set_object_callback()) */

#if ! USE_BWC_BS_HACK
    fl_set_object_return( obj, FL_RETURN_CHANGED );
#else
    fl_set_object_return( obj, FL_RETURN_NONE );
#endif

    return obj;
}


/*
 * User routines
 */

#define ISSCROLLBAR( o )  ( ( o ) && ( o )->objclass == FL_SCROLLBAR )


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_scrollbar( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * l )
{
    FL_OBJECT *obj = fl_create_scrollbar( type, x, y, w, h, l );

    attrib_change( obj );
    get_geom( obj );
    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 ***************************************/

double
fl_get_scrollbar_value( FL_OBJECT * obj )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    if ( ! ISSCROLLBAR( obj ) )
    {
        M_err( "fl_get_scrollbar_value", "%s not a scrollbar",
               obj ? obj->label : "Object" );
        return - HUGE_VAL;
    }

    return fl_get_slider_value( sp->slider );
}


/***************************************
 ***************************************/

void
fl_set_scrollbar_value( FL_OBJECT * obj,
                        double      val )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    if ( ! ISSCROLLBAR( obj ) )
    {
        M_err( "fl_set_scrollbar_value", "%s not a scrollbar",
               obj ? obj->label : "Object" );
        return;
    }

    sp->old_val = val;
    fl_set_slider_value( sp->slider, val );
}


/***************************************
 * Sets the size of the knob of the scrollbar
 * (the function name is a bit of misnomer)
 ***************************************/

void
fl_set_scrollbar_size( FL_OBJECT * obj,
                       double      val )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    fl_set_slider_size( sp->slider, val );
    get_geom( obj );
}


/***************************************
 * Sets the size of the knob of the scrollbar
 * (the function name is a bit of misnomer)
 ***************************************/

double
fl_get_scrollbar_size( FL_OBJECT * obj )
{
    return fl_get_slider_size( ( ( FLI_SCROLLBAR_SPEC * ) obj->spec )->slider );
}


/***************************************
 ***************************************/

void
fl_set_scrollbar_increment( FL_OBJECT * obj,
                            double      l,
                            double      r )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    fl_set_slider_increment( sp->slider, l, r );
    sp->increment = r;
}


/***************************************
 ***************************************/

void
fl_get_scrollbar_increment( FL_OBJECT * obj,
                            double    * a,
                            double    * b )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    fl_get_slider_increment( sp->slider, a, b );
}


/***************************************
 ***************************************/

void
fl_set_scrollbar_bounds( FL_OBJECT * obj,
                         double      b1,
                         double      b2 )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    if ( ! ISSCROLLBAR( obj ) )
    {
        M_err( "fl_set_scrollbar_bounds", "%s not a scrollbar",
               obj ? obj->label : "Object" );
        return;
    }

    fl_set_slider_bounds( sp->slider, b1, b2 );
}


/***************************************
 ***************************************/

void
fl_get_scrollbar_bounds( FL_OBJECT * obj,
                         double    * b1,
                         double    * b2 )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    fl_get_slider_bounds( sp->slider, b1, b2 );
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as for internal use
 * only and fl_set_object_return() should be used instead (which then
 * will call this function).
 ***************************************/

void
fl_set_scrollbar_return( FL_OBJECT    * obj,
                         unsigned int   when )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    if ( when & FL_RETURN_END_CHANGED )
        when &= ~ ( FL_RETURN_NONE | FL_RETURN_CHANGED );

    obj->how_return = when;

    fl_set_object_return( sp->slider, FL_RETURN_ALWAYS );
    fl_set_object_return( sp->up,     FL_RETURN_ALWAYS );
    fl_set_object_return( sp->down,   FL_RETURN_ALWAYS );

    /* We may need the value of the slider at this moment in the
       callback function... */

    sp->old_val = fl_get_slider_value( sp->slider );
}


/***************************************
 ***************************************/

void
fl_set_scrollbar_step( FL_OBJECT * obj,
                       double      step )
{
    FLI_SCROLLBAR_SPEC *sp = obj->spec;

    fl_set_slider_step( sp->slider, step );
}


/***************************************
 ***************************************/

int
fl_get_scrollbar_repeat( FL_OBJECT * obj )
{
    return
        fl_get_slider_repeat( ( ( FLI_SCROLLBAR_SPEC * ) obj->spec )->slider );
}


/***************************************
 ***************************************/

void
fl_set_scrollbar_repeat( FL_OBJECT * obj,
                         int         millisec )
{
    fl_set_slider_repeat( ( ( FLI_SCROLLBAR_SPEC * ) obj->spec )->slider,
                          millisec );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
