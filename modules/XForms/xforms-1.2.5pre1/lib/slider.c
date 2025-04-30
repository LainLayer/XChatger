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
 * \file slider.c
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
#include "private/pslider.h"
#include <sys/types.h>
#include <stdlib.h>


#define IS_NORMAL( o )  (    ( o )->type == FL_HOR_SLIDER            \
                          || ( o )->type == FL_VERT_SLIDER )

#define IS_NICE( o )    (    ( o )->type == FL_VERT_NICE_SLIDER      \
                          || ( o )->type == FL_VERT_NICE_SLIDER2     \
                          || ( o )->type == FL_HOR_NICE_SLIDER       \
                          || ( o )->type == FL_HOR_NICE_SLIDER2 )

enum
{
    COMPLETE      = 0,
    FOCUS         = 1,
    SLIDER_MOTION = 2,
    SLIDER_JUMP   = 4
};


#define VAL_BOXW   FL_max( 35, 0.18 * ob->w )   /* reporting boxsize */
#define VAL_BOXH   25                           /* vertical RBW      */


/***************************************
 ***************************************/

static void
compute_bounds( FL_OBJECT * ob )
{
    FLI_SLIDER_SPEC *sp = ob->spec;

    sp->x = 0;
    sp->y = 0;
    sp->w = ob->w;
    sp->h = ob->h;

    if ( ob->objclass == FL_VALSLIDER )
    {
        if ( IS_VSLIDER( ob ) )
        {
            sp->y += VAL_BOXH;
            sp->h -= VAL_BOXH;
        }
        else if ( IS_HSLIDER( ob ) )
        {
            sp->x += VAL_BOXW;
            sp->w -= VAL_BOXW;
        }
    }
}


/***************************************
 ***************************************/

static void
draw_motion( FL_OBJECT * ob )
{
    FLI_SLIDER_SPEC *sp = ob->spec;
    XRectangle xrec[ 2 ];
    int abbw = FL_abs( ob->bw );
    FL_COLOR col;

    if (    ob->type != FL_VERT_BROWSER_SLIDER2
         && ob->type != FL_HOR_BROWSER_SLIDER2
         && ob->type != FL_VERT_THIN_SLIDER
         && ob->type != FL_HOR_THIN_SLIDER )
    {
        FLI_SCROLLBAR_KNOB knob;

        fli_calc_slider_size( ob, &knob );

        if ( IS_HSLIDER( ob ) )
        {
            xrec[ 0 ].x      = ob->x + sp->x;
            xrec[ 0 ].y      = ob->y + sp->y;
            xrec[ 0 ].width  = knob.x + 1;
            xrec[ 0 ].height = sp->h;

            xrec[ 1 ].x      = xrec[ 0 ].x + knob.x + knob.w - 1;
            xrec[ 1 ].y      = xrec[ 0 ].y;
            xrec[ 1 ].width  = sp->w - knob.x - knob.w + 1;
            xrec[ 1 ].height = sp->h;
        }
        else
        {
            xrec[ 0 ].x      = ob->x + sp->x;
            xrec[ 0 ].y      = ob->y + sp->y;
            xrec[ 0 ].width  = sp->w;
            xrec[ 0 ].height = knob.y + 1;

            xrec[ 1 ].x      = xrec[ 0 ].x;
            xrec[ 1 ].y      = xrec[ 0 ].y + knob.y + knob.h - 1;
            xrec[ 1 ].width  = sp->w;
            xrec[ 1 ].height = sp->h - knob.y - knob.h + 1;
        }

        XSetClipRectangles( flx->display, flx->gc, 0, 0, xrec, 2, Unsorted );
        fl_draw_box( FL_FLAT_BOX, ob->x + sp->x + abbw, ob->y + sp->y + abbw,
                     sp->w - 2 * abbw, sp->h - 2 * abbw, ob->col1, 0 );
    }
    else if (    ob->type == FL_HOR_THIN_SLIDER
              || ob->type == FL_VERT_THIN_SLIDER
              || ob->type == FL_HOR_BASIC_SLIDER
              || ob->type == FL_VERT_BASIC_SLIDER )
        fl_draw_box( FL_FLAT_BOX, ob->x + sp->x, ob->y + sp->y,
                     sp->w, sp->h, ob->col1, 1 );
    else if (    ob->type == FL_HOR_BROWSER_SLIDER2
              || ob->type == FL_VERT_BROWSER_SLIDER2 )
        fl_draw_box( ob->boxtype, ob->x + sp->x, ob->y + sp->y,
                     sp->w, sp->h, ob->col1, ob->bw > 0 ? 1 : -1 );
    else
        fl_draw_box( FL_UP_BOX, ob->x + sp->x, ob->y + sp->y,
                     sp->w, sp->h, ob->col1, ob->bw > 0 ? 1 : -1 );

    fl_unset_clipping( );

    col = ( IS_SCROLLBAR( ob ) && sp->mouse == FLI_SLIDER_KNOB ) ?
          FL_MCOL : ob->col2;

    fli_draw_slider( ob, ob->col1, col, NULL, FLI_SLIDER_KNOB );
}


/***************************************
 * Draws a slider
 ***************************************/

static void
draw_slider( FL_OBJECT * ob )
{
    FLI_SLIDER_SPEC *sp = ob->spec;
    char valstr[ 64 ];
    FL_Coord bx = ob->x,    /* value box */
             by = ob->y,
             bw = ob->w,
             bh = ob->h;

    /* Draw the value box */

    if ( ob->objclass == FL_VALSLIDER )
    {
        if ( IS_VSLIDER( ob ) )
            bh = VAL_BOXH;
        else
            bw = VAL_BOXW;

        if ( sp->filter )
            strcpy( valstr, sp->filter( ob, sp->val, sp->prec ) );
        else
            sprintf( valstr, "%.*f", sp->prec, sp->val );

        fl_draw_box( ob->boxtype, bx, by, bw, bh, ob->col1, ob->bw );
        fl_draw_text( FL_ALIGN_CENTER, bx, by, bw, bh,
                      ob->lcol, ob->lstyle, ob->lsize, valstr );
    }

    if (    ( sp->draw_type == SLIDER_MOTION || sp->draw_type == SLIDER_JUMP )
         && ( IS_SCROLLBAR( ob ) || IS_NORMAL( ob ) || IS_NICE( ob ) ) )
    {
        draw_motion( ob );
        return;
    }

    /* Draw the slider */

    if ( fl_is_center_lalign( ob->align ) )
    {
        fli_draw_slider( ob, ob->col1, ob->col2,
                         IS_FILL( ob ) ? NULL : ob->label,
                         FLI_SLIDER_ALL & ~sp->mouse );
        
        /* Added 10/21/00 TCZ: need this to get the inside label right
           otherwise fli_draw_slider() draws the lable centered on the
           xfilled part!*/

        if ( IS_FILL( ob ) )
            fl_draw_object_label( ob );
    }
    else
    {
        fli_draw_slider( ob, ob->col1, ob->col2, "",
                         FLI_SLIDER_ALL & ~sp->mouse );

        if ( fl_is_inside_lalign( ob->align ) )
            fl_draw_object_label( ob );
        else
            fl_draw_object_label_outside( ob );
    }

    if ( sp->mouse != FLI_SLIDER_NONE )
        fli_draw_slider( ob, ob->col1, sp->mouse ? FL_MCOL : ob->col2,
                         "", sp->mouse );
}


/***************************************
 * Checks if mouse is not on the knob of the slider. returns -1 if
 * the mouse is above or to the left of the knob, +1 if it's below
 * or to the right of the knob and 0 if it's on the knob.
 ***************************************/

static int
is_off_knob( FL_OBJECT * obj,
             FL_Coord    mx,
             FL_Coord    my )
{
    FLI_SCROLLBAR_KNOB knob;
    FLI_SLIDER_SPEC *sp = obj->spec;

    fli_calc_slider_size( obj, &knob );

    if ( IS_VSLIDER( obj ) )
    {
        if ( IS_FILL( obj ) )
            sp->mw = 0;
        else
            sp->mh = knob.h;

        if ( my < knob.y )
            return -1;
        if ( my >= knob.y + knob.h )
            return 1;

        sp->offy = knob.y + knob.h / 2 - my;

        if ( IS_FILL( obj ) )
             sp->offy = 0;
    }
    else
    {
        if ( IS_FILL( obj ) )
            sp->mw = 0;
        else
             sp->mw = knob.w;

        if ( mx < knob.x )
            return -1;
        if ( mx >= knob.x + knob.w )
            return 1;

        sp->offx = knob.x + knob.w / 2 - mx;

        if ( IS_FILL( obj ) )
            sp->offx = 0;
    }

    return 0;
}


/***************************************
 * Get the slider value for the current mouse position
 ***************************************/

static double
get_newvalue( FL_OBJECT    * ob,
              FL_Coord       mx,
              FL_Coord       my )
{
    FLI_SLIDER_SPEC *sp = ob->spec;
    double newval = 0.0;
    int absbw = FL_abs( ob->bw );

    if ( IS_HSLIDER( ob ) )
    {
        double dmx = mx + sp->offx;

        if ( dmx < 0.5 * sp->mw + absbw )
            newval = sp->min;
        else if ( dmx > sp->w - 0.5 * sp->mw - absbw )
            newval = sp->max;
        else
            newval = sp->min + ( sp->max - sp->min )
                     * ( dmx - 0.5 * sp->mw - absbw )
                     / ( sp->w - sp->mw - 2 * absbw );
    }
    else
    {
        double dmy = my + sp->offy;

        if ( dmy < 0.5 * sp->mh + absbw )
            newval = sp->min;
        else if ( dmy > sp->h - 0.5 * sp->mh - absbw )
            newval = sp->max;
        else
            newval = sp->min + ( sp->max - sp->min )
                     * ( dmy - 0.5 * sp->mh - absbw )
                     / ( sp->h - sp->mh - 2 * absbw );
    }

    return newval;
}


/***************************************
 ***************************************/

static void
scrollbar_timeout( int    val   FL_UNUSED_ARG,
                   void * data )
{
    ( ( FLI_SLIDER_SPEC * ) data )->timeout_id = -1;
}


/***************************************
 ***************************************/

static void
handle_enter( FL_OBJECT * obj,
              FL_Coord    mx,
              FL_Coord    my )
{
    FLI_SLIDER_SPEC *sp = obj->spec;

    /* When a scrollbar is entered we want to keep track of the mouse
       movements in order to be able to highlight the knob when the mouse
       is on top of it ('sp->mouse' keeps track of that). */

    if ( IS_SCROLLBAR( obj ) )
    {
        obj->want_motion = 1;

        sp->mouse_off_knob = is_off_knob( obj, mx, my );

        if ( ! sp->mouse_off_knob )
        {
            sp->mouse = FLI_SLIDER_KNOB;
            fl_redraw_object( obj );
        }
    }
}


/***************************************
 ***************************************/

static void
handle_leave( FL_OBJECT * obj )
{
    FLI_SLIDER_SPEC *sp = obj->spec;

    /* When the mouse leaves a scrollbar we no longer need reports
       about mouse movements and may have to un-highlight the knob */

    if ( IS_SCROLLBAR( obj ) )
    {
        obj->want_motion = 0;

        if ( sp->mouse == FLI_SLIDER_KNOB )
        {
            sp->mouse = FLI_SLIDER_NONE;
            fl_redraw_object( obj );
        }
    }
}


/***************************************
 * Handle a mouse position change
 ***************************************/

static int
handle_mouse( FL_OBJECT    * obj,
              FL_Coord       mx,
              FL_Coord       my,
              int            key )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    double newval;

    if ( sp->mouse_off_knob )
    {
        if ( sp->timeout_id == -1 )
        {
            if ( key == FL_MBUTTON1 )
                newval = sp->val + sp->mouse_off_knob * sp->ldelta;
            else if ( key == FL_MBUTTON2 || key == FL_MBUTTON3 )
                newval = sp->val + sp->mouse_off_knob * sp->rdelta;
            else
                return FL_RETURN_NONE;
        }
        else
            return FL_RETURN_NONE;
    }
    else if ( sp->react_to[ key - 1 ] )
        newval = get_newvalue( obj, mx, my );
    else
        return FL_RETURN_NONE;

    newval = fli_valuator_round_and_clamp( obj, newval );
    
    if ( sp->val == newval )
        return FL_RETURN_NONE;

    /* When we're doing jumps in a scrollbar (re)start the timer, wait a bit
       longer the first time round to allow the user to release the mouse
       button before jumping starts */

    if ( sp->mouse_off_knob )
    {
        sp->timeout_id =
                 fl_add_timeout( ( obj->want_update ? 1 : 2 ) * sp->repeat_ms,
                                 scrollbar_timeout, sp );
        obj->want_update = 1;
    }

    sp->val = newval;
    sp->draw_type = sp->mouse_off_knob ? SLIDER_JUMP : SLIDER_MOTION;
    fl_redraw_object( obj );

    sp->val = newval;

    return FL_RETURN_CHANGED;
}


/***************************************
 ***************************************/

static int
handle_motion( FL_OBJECT * obj,
               FL_Coord    mx,
               FL_Coord    my,
               int         key,
               void      * ev )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    int ret;

    /* If this is a motion while in "jump mode" for a scrollbar do nothing */

    if ( IS_SCROLLBAR( obj ) && sp->mouse_off_knob && key )
        return FL_RETURN_NONE;

    /* If we get here without the left mouse button being pressed we're
       monitoring the mouse movements to change hightlighting of the
       knob of a scrollbar */

    if ( IS_SCROLLBAR( obj ) && key != FL_MBUTTON1 )
    {
        int old_state = sp->mouse_off_knob;

        sp->mouse_off_knob = is_off_knob( obj, mx, my );

        if ( old_state != sp->mouse_off_knob )
        {
            sp->mouse = sp->mouse_off_knob ? FLI_SLIDER_NONE : FLI_SLIDER_KNOB;
            fl_redraw_object( obj );
        }

        return FL_RETURN_NONE;
    }

    /* For non-scrollbar objects we're going to update the sliders position -
       if a shift key is pressed we here fake a smaller mouse movement */

    if ( ! IS_SCROLLBAR( obj ) && sp->react_to[ key - 1 ] )
    {
        if ( shiftkey_down( ( ( XEvent * ) ev )->xmotion.state ) )
        {
            if ( ! sp->was_shift )
            {
                sp->old_mx = mx;
                sp->old_my = my;
                sp->was_shift = 1;
            }
            
            if ( IS_HSLIDER( obj ) )
                mx = sp->old_mx + ( mx - sp->old_mx ) * FL_SLIDER_FINE;
            else
                my = sp->old_my + ( my - sp->old_my ) * FL_SLIDER_FINE;
        }
        else
            sp->was_shift = 0;
    }

    if (    ( ret = handle_mouse( obj, mx, my, key ) )
         && ! ( obj->how_return & FL_RETURN_END_CHANGED ) )
        sp->start_val = sp->val;

    return ret;
}


/***************************************
 ***************************************/

static int
handle_push( FL_OBJECT * obj,
             FL_Coord    mx,
             FL_Coord    my,
             int         key,
             void      * ev )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    int ret;

    if ( key < FL_MBUTTON1 || key > FL_MBUTTON3 )
        return FL_RETURN_NONE;

    sp->start_val = sp->val;
    sp->timeout_id = -1;
    sp->offx = sp->offy = 0;

    /* For value sliders we do not want the slider to jump to one of the
       extreme positions just because the user clicked on the number field -
       they may just be trying if it's possible to edit the number... */

    if (    obj->objclass == FL_VALSLIDER
         && (    ( IS_HSLIDER( obj ) && mx < 0 )
              || ( IS_VSLIDER( obj ) && my < 0 ) ) )
        return FL_RETURN_NONE;

    /* Check where the mouse button was clicked */

    sp->mouse_off_knob = is_off_knob( obj, mx, my );

    /* If the object is a scrollbar and the mouse is on its knob nothing
       happens yet and we're just going to wait for mouse movements. If it's
       not on the knob we will set an artifical timer events to make the knob
       jump. For non-scrollbars we're going to jump the slider so the mouse
       will be on top of the "knob" and will stay there (and we will get
       updates about mouse movements via FL_MOTION events). */

    if ( IS_SCROLLBAR( obj ) )
    {
        if ( ! sp->mouse_off_knob )
            return FL_RETURN_NONE;
    }
    else
        sp->mouse_off_knob = 0;

    /* If we got here the slider position got to be changed, for scrollbars by
       a jump, for normal sliders by moving the slider to the current mouse
       postion. We then need to record the position for faked slowing down of
       the mouse */

    ret = handle_mouse( obj, mx, my, key );

    /* If a shift key is pressed record the current mouse position */

    if ( shiftkey_down( ( ( XEvent * ) ev )->xbutton.state ) )
    {
        sp->old_mx = mx;
        sp->old_my = my;
        sp->was_shift = 1;
    }
    else
        sp->was_shift = 0;

    if ( ret && ! ( obj->how_return & FL_RETURN_END_CHANGED ) )
        sp->start_val = sp->val;

    return ret;
}


/***************************************
 ***************************************/

static int
handle_update( FL_OBJECT * obj,
               FL_Coord    mx,
               FL_Coord    my,
               int         key )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    int ret;

    if (    ( ret = handle_mouse( obj, mx, my, key ) )
         && ! ( obj->how_return & FL_RETURN_END_CHANGED ) )
        sp->start_val = sp->val;

    return ret;
}


/***************************************
 ***************************************/

static int
handle_scroll( FL_OBJECT * obj,
               int         key,
               int         key_state )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    double newval;

    if ( key == FL_MBUTTON4 )
        newval = sp->val - ( shiftkey_down( key_state ) ?
                             sp->rdelta : sp->ldelta / 2 );
    else if ( key == FL_MBUTTON5 )
        newval = sp->val + ( shiftkey_down( key_state ) ?
                             sp->rdelta : sp->ldelta / 2 );
    else
        return FL_RETURN_NONE;

    newval = fli_valuator_round_and_clamp( obj, newval );
    
    if ( sp->val == newval )
        return FL_RETURN_NONE;
   
    sp->val = newval;
    sp->draw_type = SLIDER_JUMP;
    fl_redraw_object( obj );

    return FL_RETURN_CHANGED | FL_RETURN_END;
}


/***************************************
 ***************************************/

static int
handle_release( FL_OBJECT * obj,
                FL_Coord    mx,
                FL_Coord    my,
                int         key,
                void      * ev )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    int ret = FL_RETURN_NONE;
    int old_state = sp->mouse_off_knob;

    obj->want_update = 0;

    if ( sp->timeout_id != -1 )
    {
        fl_remove_timeout( sp->timeout_id );
        sp->timeout_id = -1;
    }

    /* Scrollwheel only is used with scrollbars */

    if (    ! IS_SCROLLBAR( obj )
         && ( key == FL_MBUTTON4 || key == FL_MBUTTON5 ) )
        return FL_RETURN_NONE;

    /* Take care, 'ev' might be NULL - on hiding the buttons form a fake
       FL_RELEASE event gets send */

    if (    ev
         && ( ret = handle_scroll( obj, key,
                                   ( ( XEvent * ) ev )->xbutton.state ) ) )
        return ret;

    if ( ( sp->mouse_off_knob = is_off_knob( obj, mx, my ) ) != old_state )
    {
        sp->mouse = sp->mouse_off_knob ? FLI_SLIDER_NONE : FLI_SLIDER_KNOB;
        fl_redraw_object( obj );
    }

    ret = FL_RETURN_END;
    if ( sp->start_val != sp->val )
        ret |= FL_RETURN_CHANGED;

    return ret;
}


/***************************************
 * Handles an event for a slider
 ***************************************/

static int
handle_slider( FL_OBJECT * ob,
               int         event,
               FL_Coord    mx,
               FL_Coord    my,
               int         key,
               void      * ev )
{
    FLI_SLIDER_SPEC *sp = ob->spec;
    int ret = FL_RETURN_NONE;

    mx -= ob->x + sp->x;
    my -= ob->y + sp->y;

    switch ( event )
    {
        case FL_ATTRIB :
        case FL_RESIZED :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
            {
                ob->align = fl_to_outside_lalign( ob->align );
                if ( fl_is_center_lalign( ob->align ) )
                    ob->align = FL_SLIDER_ALIGN;
            }
            compute_bounds( ob );
            break;

        case FL_DRAW :
            sp->draw_type = COMPLETE;
            draw_slider( ob );
            break;

        case FL_DRAWLABEL :
            if ( fl_is_inside_lalign( ob->align ) )
                fl_draw_object_label( ob );
            else
                fl_draw_object_label_outside( ob );
            break;

        case FL_FREEMEM :
            fli_safe_free( ob->spec );
            break;

        case FL_ENTER :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
                handle_enter( ob, mx, my );
            break;

        case FL_LEAVE :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
                handle_leave( ob );
            break;

        case FL_PUSH :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
                ret |= handle_push( ob, mx, my, key, ev );
            break;

        case FL_MOTION :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
                ret |= handle_motion( ob, mx, my, key, ev );
            break;

        case FL_UPDATE :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
                ret |= handle_update( ob, mx, my, key );
            break;

        case FL_RELEASE :
            if ( ! ( ob->type & FL_VERT_PROGRESS_BAR ) )
                ret |= handle_release( ob, mx, my, key, ev );
            break;
    }

    return ret;
}


/***************************************
 * Creates a slider object
 ***************************************/

static FL_OBJECT *
create_slider( int          objclass,
               int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label )
{
    FL_OBJECT *ob;
    FLI_SLIDER_SPEC *sp;
    int i;

    ob = fl_make_object( objclass, type, x, y, w, h, label, handle_slider );
    ob->boxtype = FL_SLIDER_BOXTYPE;
    ob->col1    = FL_SLIDER_COL1;
    ob->col2    = FL_SLIDER_COL2;
    ob->align   = FL_SLIDER_ALIGN;
    ob->lcol    = FL_SLIDER_LCOL;
    ob->lsize   = FL_TINY_SIZE;
    ob->spec    = sp = fl_calloc( 1, sizeof *sp );
    sp->min            = 0.0;
    sp->max            = 1.0;
    sp->val            = sp->start_val = 0.5;
    sp->filter         = NULL;
    sp->slsize         = FL_SLIDER_WIDTH;
    sp->prec           = 2;
    sp->repeat_ms      = 100;
    sp->timeout_id     = -1;
    sp->mouse_off_knob = 0;
    sp->was_shift      = 0;
    sp->cross_over     = 0;
    sp->old_mx = sp->old_my = 0;
    if ( IS_SCROLLBAR( ob ) )
        sp->slsize    *= 1.5;

    sp->ldelta         = 0.1;
    sp->rdelta         = 0.05;

    fl_set_object_dblbuffer( ob, 1 );

    /* Per default a slider reacts to the left mouse button only */

    sp->react_to[ 0 ] = 1;
    for ( i = 1; i < 3; i++ )
        sp->react_to[ i ] = 0;

    return ob;
}


/***************************************
 * Adds a slider object
 ***************************************/

static FL_OBJECT *
add_slider( int          objclass,
            int          type,
            FL_Coord     x,
            FL_Coord     y,
            FL_Coord     w,
            FL_Coord     h,
            const char * label )
{
    FL_OBJECT *obj = create_slider( objclass, type, x, y, w, h, label );

    /* Set the default return policy for the object */

    fl_set_object_return( obj, FL_RETURN_CHANGED );

    fl_add_object( fl_current_form, obj );

    compute_bounds( obj );

    return obj;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_slider( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    return create_slider( FL_SLIDER, type, x, y, w, h, label );
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_slider( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label )
{
    return add_slider( FL_SLIDER, type, x, y, w, h, label );
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_valslider( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * label )
{
    return create_slider( FL_VALSLIDER, type, x, y, w, h, label );
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_valslider( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    return add_slider( FL_VALSLIDER, type, x, y, w, h, label );
}


/***************************************
 ***************************************/

void
fl_set_slider_value( FL_OBJECT * ob,
                     double      val )
{
    FLI_SLIDER_SPEC *sp;
    double smin,
           smax;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_SLIDER ) && ! IsValidClass( ob, FL_VALSLIDER ) )
    {
        M_err( "fl_set_slider_value", "%s is not a slider",
               ob ? ob->label : "" );
        return;
    }
#endif

    sp = ob->spec;
    smin = FL_min( sp->min, sp->max );
    smax = FL_max( sp->min, sp->max );
    val = FL_clamp( val, smin, smax );

    if ( sp->val != val )
    {
        sp->val = sp->start_val = val;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_slider_bounds( FL_OBJECT * ob,
                      double      min,
                      double      max )
{
    FLI_SLIDER_SPEC *sp;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_SLIDER ) && ! IsValidClass( ob, FL_VALSLIDER ) )
    {
        M_err( "fl_set_slider_bounds", "%s is not a slider",
               ob ? ob->label : "" );
        return;
    }
#endif

    sp = ob->spec;
    if ( sp->min == min && sp->max == max )
        return;

    sp->min = min;
    sp->max = max;
    if ( sp->val < sp->min && sp->val < sp->max )
        sp->val = FL_min( sp->min, sp->max );
    if ( sp->val > sp->min && sp->val > sp->max )
        sp->val = FL_max( sp->min, sp->max );

    fl_redraw_object( ob );
}


/***************************************
 * Returns value of the slider
 ***************************************/

double
fl_get_slider_value( FL_OBJECT * ob )
{
#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_SLIDER ) && ! IsValidClass( ob, FL_VALSLIDER ) )
    {
        M_err( "fl_get_slider_value", "%s is not a slider",
               ob ? ob->label : "" );
        return 0;
    }
#endif
    return ( ( FLI_SLIDER_SPEC * ) ob->spec )->val;
}


/***************************************
 * Returns the slider bounds
 ***************************************/

void
fl_get_slider_bounds( FL_OBJECT * ob,
                      double    * min,
                      double    * max )
{
    *min = ( ( FLI_SLIDER_SPEC * ) ob->spec )->min;
    *max = ( ( FLI_SLIDER_SPEC * ) ob->spec )->max;
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as deprecated and
 * fl_set_object_return() should be used instead.
 ***************************************/

void
fl_set_slider_return( FL_OBJECT    * obj,
                      unsigned int   when )
{
    if ( when & FL_RETURN_END_CHANGED )
        when &= ~ ( FL_RETURN_NONE | FL_RETURN_CHANGED );

    fl_set_object_return( obj, when );
}


/***************************************
 * Sets the step size to which values are rounded
 ***************************************/

void
fl_set_slider_step( FL_OBJECT * ob,
                    double      value )
{
    ( ( FLI_SLIDER_SPEC * ) ob->spec )->step = value;
}


/***************************************
 * Set slider increments for clicks with left and middle mouse button
 ***************************************/

void
fl_set_slider_increment( FL_OBJECT * ob,
                         double      l,
                         double      r )
{
    ( ( FLI_SLIDER_SPEC * ) ob->spec )->ldelta = l;
    ( ( FLI_SLIDER_SPEC * ) ob->spec )->rdelta = r;
}


/***************************************
 ***************************************/

void
fl_get_slider_increment( FL_OBJECT * ob,
                         double    * l,
                         double    * r )
{
    *l = ( ( FLI_SLIDER_SPEC * ) ob->spec )->ldelta;
    *r = ( ( FLI_SLIDER_SPEC * ) ob->spec )->rdelta;
}


/***************************************
 * Sets the portion of the slider box covered by the slider
 ***************************************/

void
fl_set_slider_size( FL_OBJECT * ob,
                    double      size )
{
    FLI_SLIDER_SPEC *sp = ob->spec;
    double dim;
    int min_knob = IS_SCROLLBAR( ob ) ? MINKNOB_SB : MINKNOB_SL;

    if ( size <= 0.0 )
        size = 0.0;
    else if (size >= 1.0)
        size = 1.0;

    /* Impose minimum knob size */

    dim = IS_VSLIDER( ob ) ? ob->h : ob->w;
    dim -= 2 * FL_abs( ob->bw );
    if ( dim * size < min_knob && dim > 0.0 )
        size = min_knob / dim;

    if ( size != sp->slsize )
    {
        sp->slsize = size;
        fl_redraw_object( ob );
    }
}


/***************************************
 * Sets the portion of the slider box covered by the slider
 ***************************************/

double
fl_get_slider_size( FL_OBJECT * obj )
{
    return ( ( FLI_SLIDER_SPEC * ) obj->spec )->slsize;
}


/***************************************
 * Only for value sliders.
 ***************************************/

void
fl_set_slider_precision( FL_OBJECT * ob,
                         int         prec )
{
    FLI_SLIDER_SPEC *sp = ob->spec;


    if ( prec > FL_SLIDER_MAX_PREC )
        prec = FL_SLIDER_MAX_PREC;
    else if ( prec < 0 )
        prec = 0;

    if ( sp->prec != prec )
    {
        sp->prec = prec;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_slider_filter( FL_OBJECT     * ob,
                      FL_VAL_FILTER   filter )
{
    ( ( FLI_SLIDER_SPEC * ) ob->spec )->filter = filter;
}


/***************************************
 * This function makes only sense for scrollbars and should't be
 * used for simple sliders (for which it doesn't do anything).
 ***************************************/

int
fl_get_slider_repeat( FL_OBJECT * ob )
{
    return ( ( FLI_SLIDER_SPEC * ) ob->spec )->repeat_ms;
}


/***************************************
 * This function makes only sense for scrollbars and should't be
 * used for simple sliders (for which it doesn't do anything).
 ***************************************/

void
fl_set_slider_repeat( FL_OBJECT * ob,
                      int         millisec )
{
    if ( millisec > 0 )
        ( ( FLI_SLIDER_SPEC * ) ob->spec )->repeat_ms = millisec;
}


/***************************************
 * Function allows to set up to which mouse
 * buttons the slider object will react.
 ***************************************/

void
fl_set_slider_mouse_buttons( FL_OBJECT    * obj,
                             unsigned int   mouse_buttons )
{
    FLI_SLIDER_SPEC *sp = obj->spec;
    unsigned int i;

    for ( i = 0; i < 3; i++, mouse_buttons >>= 1 )
        sp->react_to[ i ] = mouse_buttons & 1;
}


/***************************************
 * Function returns a value via 'mouse_buttons', indicating
 * which mouse buttons the slider object will react to.
 ***************************************/

void
fl_get_slider_mouse_buttons( FL_OBJECT    * obj,
                             unsigned int * mouse_buttons )
{
    FLI_SLIDER_SPEC *sp;
    int i;
    unsigned int k;

    if ( ! obj )
    {
        M_err( "fl_get_slider_mouse_buttons", "NULL object" );
        return;
    }

    if ( ! mouse_buttons )
        return;

    sp = obj->spec;

    *mouse_buttons = 0;
    for ( i = 0, k = 1; i < 3; i++, k <<= 1 )
        *mouse_buttons |= sp->react_to[ i ] ? k : 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
