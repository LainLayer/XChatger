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
 * \file counter.c
 *.
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Counter class
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pcounter.h"

#include <string.h>
#include <stdlib.h>
#include <float.h>


/* Give each component a name. parts are numbered 01 4 23, i.e. OB0 is the
   button for reducing the counter value in large steps, OB1 the one for
   reducing the value in small steps, OB2 the one for increasing the value in
   small steps, OB3 the one for increasing the value in large steps and
   finally OB4 the field with the counters value. */

enum {
    NONE,
    OB0 =  1,
    OB1 =  2,
    OB2 =  4,
    OB3 =  8,
    OB4 = 16,
    ALL = 31
};


/***************************************
 * Draws a counter
 ***************************************/

static void
draw_counter( FL_OBJECT * ob )
{
    char str[ 64 ];
    int i,
        btype[ 5 ];
    FLI_COUNTER_SPEC *sp = ob->spec;

    /* Compute boxtypes if pushed */

    for ( i = 0; i < 5; i++ )
        if (    ob->pushed
             && FL_IS_UPBOX( ob->boxtype )
             && ( sp->mouseobj & ( 1 << i ) ) )
            btype[i] = FL_TO_DOWNBOX( ob->boxtype );
        else
            btype[ i ] = ob->boxtype;

    if ( btype[ 4 ] == FL_UP_BOX )
        btype[ 4 ] = FL_DOWN_BOX;

    /* Compute sizes. Must not leave any gaps otherwise double buffering will
       not work correctly */

    if ( ob->type == FL_NORMAL_COUNTER )
    {
        /* Button is numbered 01 4 23 */

        sp->ww[ 0 ] = sp->ww[ 1 ] = sp->ww[ 2 ] = sp->ww[ 3 ] =
                                                 FL_min( 0.18 * ob->w, ob->h );
        sp->ww[ 4 ] = ob->w - 4 * sp->ww[ 0 ];  /* must calculate this way */
        sp->xx[ 0 ] = ob->x;
        sp->xx[ 1 ] = sp->xx[ 0 ] + sp->ww[ 0 ];
        sp->xx[ 4 ] = sp->xx[ 1 ] + sp->ww[ 1 ];
        sp->xx[ 2 ] = sp->xx[ 4 ] + sp->ww[ 4 ];
        sp->xx[ 3 ] = sp->xx[ 2 ] + sp->ww[ 2 ];
    }
    else
    {
        /* 1  4  2 */

        sp->ww[ 1 ] = sp->ww[ 2 ] = FL_min( 0.20 * ob->w, ob->h );
        sp->ww[ 4 ] = ob->w - 2 * sp->ww[ 1 ];
        sp->xx[ 1 ] = ob->x;
        sp->xx[ 4 ] = ob->x + sp->ww[ 1 ];
        sp->xx[ 2 ] = sp->xx[ 4 ] + sp->ww[ 4 ];
    }

    if ( sp->filter )
        strcpy( str, sp->filter( ob, sp->val, sp->prec ) );
    else
        sprintf( str, "%.*f", sp->prec, sp->val );

    /* Only draw the parts that need to be drawn  */

    if ( ob->type == FL_NORMAL_COUNTER && sp->draw_type & OB0 )
    {
        fl_draw_box( btype[ 0 ], sp->xx[ 0 ], ob->y, sp->ww[ 0 ], ob->h,
                     ob->col1, ob->bw );
        fl_draw_text( FL_ALIGN_CENTER, sp->xx[ 0 ], ob->y, sp->ww[ 0 ], ob->h,
                      ob->col2, 0, 0, "@#<<" );
    }

    if ( sp->draw_type & OB1 )
    {
        fl_draw_box( btype[ 1 ], sp->xx[ 1 ], ob->y, sp->ww[ 1 ], ob->h,
                     ob->col1, ob->bw );
        fl_draw_text( FL_ALIGN_CENTER, sp->xx[ 1 ], ob->y, sp->ww[ 1 ], ob->h,
                      ob->col2, 0, 0, "@#<" );
    }

    if ( sp->draw_type & OB4 )
    {
        fl_draw_box( btype[ 4 ], sp->xx[ 4 ], ob->y, sp->ww[ 4 ], ob->h,
                     ob->col1, ob->bw );
        fl_set_text_clipping( sp->xx[ 4 ], ob->y, sp->ww[ 4 ], ob->h );
        fl_draw_text( FL_ALIGN_CENTER, sp->xx[ 4 ], ob->y, sp->ww[ 4 ], ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, str );
        fl_unset_text_clipping( );
    }

    if ( sp->draw_type & OB2 )
    {
        fl_draw_box( btype[ 2 ], sp->xx[ 2 ], ob->y, sp->ww[ 2 ], ob->h,
                     ob->col1, ob->bw );
        fl_draw_text( FL_ALIGN_CENTER, sp->xx[ 2 ], ob->y, sp->ww[ 2 ], ob->h,
                      ob->col2, 0, 0, "@#>" );
    }

    if ( ob->type == FL_NORMAL_COUNTER && sp->draw_type & OB3 )
    {
        fl_draw_box( btype[ 3 ], sp->xx[ 3 ], ob->y, sp->ww[ 3 ], ob->h,
                     ob->col1, ob->bw );
        fl_draw_text( FL_ALIGN_CENTER, sp->xx[ 3 ], ob->y, sp->ww[ 3 ], ob->h,
                      ob->col2, 0, 0, "@#>>" );
    }

    if ( sp->draw_type == ALL )
        fl_draw_object_label_outside( ob );

    sp->draw_type = ALL;
}


/***************************************
 * Buttons are numbered as 01 4 23
 ***************************************/

static void
calc_mouse_obj( FL_OBJECT * ob,
                FL_Coord    mx,
                FL_Coord    my )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

    sp->mouseobj = NONE;

    if ( my < ob->y || my > ob->y + ob->h || mx < ob->x )
        return;

    /* 01 4 23 */

    if ( ob->type == FL_NORMAL_COUNTER )
    {
        if ( mx < ob->x + sp->ww[ 0 ] )
            sp->mouseobj = OB0;
        else if ( mx < sp->ww[ 1 ] + sp->xx[ 1 ] )
            sp->mouseobj = OB1;
        else if ( mx < sp->ww[ 4 ] + sp->xx[ 4 ] )
            sp->mouseobj = OB4;
        else if ( mx < sp->ww[ 2 ] + sp->xx[ 2 ] )
            sp->mouseobj = OB2;
        else if ( mx < sp->ww[ 3 ] + sp->xx[ 3 ] )
            sp->mouseobj = OB3;
    }
    else
    {
        /* 1  4  2 */

        if ( mx < ob->x + sp->ww[ 1 ] )
            sp->mouseobj = OB1;
        else if ( mx < sp->xx[ 4 ] + sp->ww[ 4 ] )
            sp->mouseobj = OB4;
        else if ( mx < sp->xx[ 2 ] + sp->ww[ 2 ] )
            sp->mouseobj = OB2;
    }
}


/***************************************
 ***************************************/

int fl_get_counter_repeat( FL_OBJECT * ob )
{
    return ( ( FLI_COUNTER_SPEC * ) ob->spec )->repeat_ms;
}


/***************************************
 ***************************************/

void fl_set_counter_repeat( FL_OBJECT * ob,
                            int         millisec )
{
    if ( millisec <= 0 )
    {
        M_warn( "fl_set_counter_repeat", "Invalid argument, disregarded" );
        return;
    }

    ( ( FLI_COUNTER_SPEC * ) ob->spec )->repeat_ms = millisec;
}


/***************************************
 ***************************************/

int fl_get_counter_min_repeat( FL_OBJECT * ob )
{
    return ( ( FLI_COUNTER_SPEC * ) ob->spec )->min_repeat_ms;
}


/***************************************
 ***************************************/

void fl_set_counter_min_repeat( FL_OBJECT * ob,
                                int         millisec )
{
    if ( millisec <= 0 )
    {
        M_warn( "fl_set_counter_min_repeat", "Invalid argument, disregarded" );
        return;
    }

    ( ( FLI_COUNTER_SPEC * ) ob->spec )->min_repeat_ms = millisec;
}


/***************************************
 ***************************************/

int fl_get_counter_speedjump( FL_OBJECT * ob )
{
    return ( ( FLI_COUNTER_SPEC * ) ob->spec )->do_speedjump;
}


/***************************************
 ***************************************/

void fl_set_counter_speedjump( FL_OBJECT * ob,
                               int         yes_no )
{
    ( ( FLI_COUNTER_SPEC * ) ob->spec )->do_speedjump = yes_no != 0;
}


/***************************************
 ***************************************/

static void
timeoutCB( int    val  FL_UNUSED_ARG,
           void * data )
{
    ( ( FLI_COUNTER_SPEC * ) data )->timeout_id = -1;
}


/***************************************
 * Show which button is active by highlighting the button
 ***************************************/

static void
show_focus_obj( FL_OBJECT * ob,
                FL_Coord    mx,
                FL_Coord    my )
{
    FLI_COUNTER_SPEC *sp = ob->spec;
    unsigned int oldobj = sp->mouseobj;

    calc_mouse_obj( ob, mx, my );

    /* If same object, do nothing */

    if ( sp->mouseobj == oldobj )
        return;

    if ( sp->mouseobj && sp->mouseobj != OB4 && sp->mouseobj != oldobj )
    {
        FL_COLOR old = ob->col1;
        sp->draw_type = sp->mouseobj;
        ob->col1 = FL_MCOL;
        fl_redraw_object( ob );
        sp->draw_type = oldobj;
        ob->col1 = old;
        fl_redraw_object( ob );
    }
    else if ( ( sp->mouseobj == NONE || sp->mouseobj == OB4 ) && oldobj )
    {
        sp->draw_type = oldobj;
        fl_redraw_object( ob );
    }
}


/***************************************
 * Handles mouse related events
 ***************************************/

static int
handle_mouse( FL_OBJECT * ob,
              int         event,
              FL_Coord    mx,
              FL_Coord    my )
{
    FLI_COUNTER_SPEC *sp = ob->spec;
    int ret = FL_RETURN_NONE;

    switch ( event )
    {
        /* On mouse push store the old value of the counter, set up the time
           values for speeding up updates while the mouse is pressed down,
           check where the mouse is and, if it's on one of the buttons, we're
           going to change the counters value. Reset the value for the timeout
           just to make sure */

        case FL_PUSH :
            sp->start_val = sp->val;
            sp->cur_repeat_ms = sp->repeat_ms;
            calc_mouse_obj( ob, mx, my );
            if ( sp->mouseobj != NONE )
                ret |= FL_RETURN_CHANGED;
            sp->timeout_id = -1;
            break;

        /* On release stop the update timer (if it's still running), set
           flag that indicates we're on a button and return end of inter-
           action */

        case FL_RELEASE :
            if ( sp->timeout_id != -1 )
            {
                fl_remove_timeout( sp->timeout_id );
                sp->timeout_id = -1;
            }

            sp->mouseobj = NONE;
            fl_redraw_object( ob );
            ret |= FL_RETURN_END;
            break;

        /* During an update (and if we're on a button) and the timer has
           expired a change of the counters value is in order */

        case FL_UPDATE :
            if ( sp->mouseobj != NONE && sp->timeout_id == -1 )
                ret |= FL_RETURN_CHANGED;
            break;
    }

    /* Handle changes of the counter value */

    if ( ret == FL_RETURN_CHANGED )
    {
        double oval = sp->val;

        /* (Re)start the timer */

        sp->timeout_id = fl_add_timeout( sp->cur_repeat_ms, timeoutCB, sp );

        /* If 'speedjump' hasn't been switched on and we didn't reach the
           final speed reduce the timeout value by a third of the remaining
           difference (the extra substraction of 2 makes sure we can reach it
           in all circumstances) */

        if ( ! sp->do_speedjump && sp->cur_repeat_ms > sp->min_repeat_ms )
        {
            sp->cur_repeat_ms -=
                             ( sp->cur_repeat_ms - sp->min_repeat_ms ) / 3 + 2;
            sp->cur_repeat_ms = FL_max( sp->cur_repeat_ms, sp->min_repeat_ms );
        }

        /* If 'speedjump' has been switched on but initial and final speed
           aren't identical it means that we have a long delay at the start
           and then short timeouts afterwards */

        if ( sp->do_speedjump && sp->cur_repeat_ms > sp->min_repeat_ms )
            sp->cur_repeat_ms = sp->min_repeat_ms;

        /* Change the counters value according to which button we're on */

        if ( sp->mouseobj == OB0 )
            sp->val -= sp->lstep;
        if ( sp->mouseobj == OB1 )
            sp->val -= sp->sstep;
        if ( sp->mouseobj == OB2 )
            sp->val += sp->sstep;
        if ( sp->mouseobj == OB3 )
            sp->val += sp->lstep;

        sp->val = fli_clamp( sp->val, sp->min, sp->max );

        /* Redraw the central field with the new value */

        if ( sp->val != oval )
        {
            sp->draw_type = sp->mouseobj | OB4;
            fl_redraw_object( ob );
        }
    }

    return ret;
}


/***************************************
 * Handles an event
 ***************************************/

static int
handle_counter( FL_OBJECT * ob,
                int         event,
                FL_Coord    mx,
                FL_Coord    my,
                int         key  FL_UNUSED_ARG,
                void *      ev   FL_UNUSED_ARG )
{
    FLI_COUNTER_SPEC *sp = ob->spec;
    int ret = FL_RETURN_NONE;

    switch ( event )
    {
        case FL_ATTRIB :
            ob->align = fl_to_outside_lalign( ob->align );
            break;

        case FL_DRAW:
            draw_counter( ob );
            break;

        case FL_DRAWLABEL:
            fl_draw_object_label_outside( ob );
            break;

        case FL_PUSH:
        case FL_UPDATE:
            if ( key != FL_MBUTTON1 )
                break;

            if (    ( ret |= handle_mouse( ob, event, mx, my ) )
                 && ! ( ob->how_return & FL_RETURN_END_CHANGED ) )
                sp->start_val = sp->val;
            break;

        case FL_RELEASE:
            if ( key != FL_MBUTTON1 )
                break;

            ret |= handle_mouse( ob, event, mx, my );
            show_focus_obj( ob, mx, my );
            if ( sp->start_val != sp->val )
                ret |= FL_RETURN_CHANGED;
            break;

        case FL_MOTION:
        case FL_ENTER:
        case FL_LEAVE:
            show_focus_obj( ob, mx, my );
            break;

        case FL_FREEMEM:
            fl_free( ob->spec );
            break;
    }

    return ret;
}


/***************************************
 * Creates an object
 ***************************************/

FL_OBJECT *
fl_create_counter( int          type,
                   FL_Coord     x,
                   FL_Coord     y,
                   FL_Coord     w,
                   FL_Coord     h,
                   const char * label )
{
    FL_OBJECT *ob;
    FLI_COUNTER_SPEC *sp;

    ob = fl_make_object( FL_COUNTER, type, x, y, w, h, label, handle_counter );
    ob->boxtype     = FL_COUNTER_BOXTYPE;
    ob->col1        = FL_COUNTER_COL1;
    ob->col2        = FL_COUNTER_COL2;
    ob->align       = FL_COUNTER_ALIGN;
    ob->lcol        = FL_COUNTER_LCOL;
    ob->want_motion = 1;
    ob->want_update = 1;
//    ob->bw          = FL_COUNTER_BW;

    sp = ob->spec     = fl_calloc( 1, sizeof *sp );
    sp->min           = -1000000.0;
    sp->max           = 1000000.0;
    sp->sstep         = 0.1;
    sp->lstep         = 1.0;
    sp->val           = 0.0;
    sp->prec          = 1;
    sp->mouseobj      = NONE;
    sp->draw_type     = ALL;
    sp->filter        = NULL;
    sp->min_repeat_ms = 50;
    sp->repeat_ms     = 600;
    sp->do_speedjump  = 0;
    sp->timeout_id    = -1;

    /* Set default return policy for the object */

    fl_set_object_return( ob, FL_RETURN_CHANGED );

    return ob;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_counter( int          type,
                FL_Coord     x,
                FL_Coord     y,
                FL_Coord     w,
                FL_Coord     h,
                const char * label )
{
    FL_OBJECT *ob = fl_create_counter( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );

    return ob;
}


/***************************************
 ***************************************/

void
fl_set_counter_value( FL_OBJECT * ob,
                      double      val )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_COUNTER ) )
    {
        M_err( "fl_set_counter_value", "%s not a counter",
               ob ? ob->label : "" );
        return;
    }
#endif

    val = fli_clamp( val, sp->min, sp->max );
    if ( sp->val != val )
    {
        sp->val = sp->start_val = val;
        sp->draw_type = ( ob->visible && ob->form->visible ) ? OB4 : ALL;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_get_counter_bounds( FL_OBJECT * ob,
                       double    * min,
                       double    * max )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

    *min = sp->min;
    *max = sp->max;
}


/***************************************
 ***************************************/

void
fl_set_counter_bounds( FL_OBJECT * ob,
                       double      min,
                       double      max )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_COUNTER ) )
    {
        M_err( "fl_set_counter_bounds", "%s not a counter",
               ob ? ob->label : "" );
        return;
    }
#endif

    if ( sp->min != min || sp->max != max )
    {
        sp->min = min;
        sp->max = max;
        sp->val = fli_clamp( sp->val, sp->min, sp->max );
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_counter_step( FL_OBJECT * ob,
                     double      s,
                     double      l )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

    if ( sp->sstep != s || sp->lstep != l )
    {
        sp->sstep = s;
        sp->lstep = l;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_get_counter_step( FL_OBJECT * ob,
                     double *    s,
                     double *    l )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

    *s = sp->sstep;
    *l = sp->lstep;
}


/***************************************
 ***************************************/

void
fl_set_counter_precision( FL_OBJECT * ob,
                          int         prec )
{
    FLI_COUNTER_SPEC *sp = ob->spec;

    if ( prec < 0 )
        prec = 0;
    if ( prec > DBL_DIG )
        prec = DBL_DIG;

    if ( sp->prec != prec )
    {
        sp->prec = prec;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_get_counter_precision( FL_OBJECT * ob )
{
    return ( ( FLI_COUNTER_SPEC * ) ob->spec )->prec;
}


/***************************************
 ***************************************/

double
fl_get_counter_value( FL_OBJECT * ob )
{
#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_COUNTER ) )
    {
        M_err( "fl_get_counter_value", "%s not a counter",
               ob ? ob->label : "" );
        return 0;
    }
#endif

    return ( ( FLI_COUNTER_SPEC * ) ob->spec )->val;
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as deprecated and
 * fl_set_object_return() should be used instead.
 ***************************************/

void
fl_set_counter_return( FL_OBJECT    * obj,
                       unsigned int   when )
{
    fl_set_object_return( obj, when );
}


/***************************************
 ***************************************/

void
fl_set_counter_filter( FL_OBJECT *   ob,
                       FL_VAL_FILTER filter )
{
    ( ( FLI_COUNTER_SPEC * ) ob->spec )->filter = filter;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
