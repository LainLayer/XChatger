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
 * \file timer.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Forms Object class: TIMER
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include "include/forms.h"
#include "flinternal.h"


/* Extra information need for input boxes. */

typedef struct
{
    double time_left;       /* the time (sec) left to wait */
    double timer;           /* total duration              */
    long sec,               /* start time                  */
         usec;
    int on,
        up;
    FL_TIMER_FILTER filter;
} SPEC;


/***************************************
 ***************************************/

static char *
default_filter( FL_OBJECT * ob  FL_UNUSED_ARG,
                double      totalsec )
{
    static char buf[ 32 ];
    int minutes;
    double sec;

    if ( totalsec >= 3600.0 )
    {
        int hr = totalsec / 3600.0 + 0.001;

        minutes = totalsec / 60.0 + 0.001;
        minutes -= hr * 60;
        sec = totalsec - 60 * ( minutes + 60 * hr );
        sprintf( buf, "%d:%02d:%04.1f", hr, minutes, sec );
    }
    else if ( totalsec >= 60.0 )
    {
        minutes = totalsec / 60.0 + 0.001;
        sec = totalsec - minutes * 60;
        sprintf( buf, "%d:%04.1f", minutes, sec );
    }
    else
        sprintf( buf, "%.1f", totalsec );

    return buf;
}


/***************************************
 * draws the timer
 ***************************************/

static void
draw_timer( FL_OBJECT * ob )
{
    FL_COLOR col;
    char *str;
    SPEC *sp = ob->spec;

    if ( ob->type == FL_HIDDEN_TIMER )
        return;

    if ( ! sp->on || sp->time_left > 0.0 )
        col = ob->col1;
    else if ( ( int ) ( sp->time_left / FL_TIMER_BLINKRATE ) % 2 )
        col = ob->col1;
    else
        col = ob->col2;

    fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, col, ob->bw );

    if ( ob->type == FL_VALUE_TIMER && sp->time_left > 0.0 )
    {
        double time_shown = sp->up ? sp->timer - sp->time_left : sp->time_left;

        str = ( sp->filter ? sp->filter : default_filter )( ob, time_shown );
        fl_draw_text( FL_ALIGN_CENTER, ob->x, ob->y, ob->w, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, str );
    }
}


/***************************************
 * Handles an event
 ***************************************/

static int
handle_timer( FL_OBJECT * ob,
              int         event,
              FL_Coord    mx   FL_UNUSED_ARG,
              FL_Coord    my   FL_UNUSED_ARG,
              int         key  FL_UNUSED_ARG,
              void      * ev   FL_UNUSED_ARG )
{
    SPEC *sp = ob->spec;
    long sec,
         usec;
    double lasttime_left;
    int ret = FL_RETURN_NONE;
    static int update_only;

    switch ( event )
    {
        case FL_ATTRIB :
            if ( ob->type == FL_VALUE_TIMER )
                ob->align = fl_to_outside_lalign( ob->align );
            break;

        case FL_DRAW:
            draw_timer( ob );
            /* fall through */

        case FL_DRAWLABEL:
            if (    ob->type == FL_HIDDEN_TIMER
                 || ( ob->type == FL_VALUE_TIMER && update_only ) )
                break;
            if ( fl_is_outside_lalign( ob->align ) )
                fl_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                                     ob->lcol, ob->lstyle, ob->lsize,
                                     ob->label );
            else
                fl_draw_text( ob->align, ob->x, ob->y, ob->w, ob->h,
                              ob->lcol, ob->lstyle, ob->lsize,
                              ob->label );
            break;

        case FL_RELEASE:
            if ( ob->type != FL_HIDDEN_TIMER && sp->time_left < 0.0 )
                fl_set_timer( ob, 0.0 );
            break;

        case FL_STEP:
            if ( ! sp->on )
                break;
            lasttime_left = sp->time_left;
            fl_gettime( &sec, &usec );
            sp->time_left = sp->timer - ( sec - sp->sec )
                            - ( usec - sp->usec ) * 1.0e-6;
            update_only = 1;

            /* Don't check for zero, we can overshoot quite a bit. Instead try
               to split the error by already returning 10 ms too early. */

            if ( sp->time_left > 0.01 )
            {
                if (    ob->type == FL_VALUE_TIMER
                     && ( int ) ( 10.0 * sp->time_left ) !=
                                              ( int ) ( 10.0 * lasttime_left ) )
                    fl_redraw_object( ob );
            }
            else if ( lasttime_left > 0.0 )
            {
                if ( ob->type == FL_HIDDEN_TIMER )
                    fl_set_timer( ob, 0.0 );
                else
                    fl_redraw_object( ob );
                update_only = 0;
                ret = FL_RETURN_CHANGED | FL_RETURN_END;
                break;
            }
            else if ( ( int ) ( lasttime_left / FL_TIMER_BLINKRATE ) !=
                                ( int ) ( sp->time_left / FL_TIMER_BLINKRATE ) )
                fl_redraw_object( ob );

            update_only = 0;
            break;

        case FL_FREEMEM:
            fl_free( ob->spec );
            break;
    }

    return ret;
}


/***************************************
 * creates an object
 ***************************************/

FL_OBJECT *
fl_create_timer( int          type,
                 FL_Coord     x,
                 FL_Coord     y,
                 FL_Coord     w,
                 FL_Coord     h,
                 const char * l )
{
    FL_OBJECT *ob;
    SPEC *sp;

    ob = fl_make_object( FL_TIMER, type, x, y, w, h, l, handle_timer );

    ob->boxtype   = FL_TIMER_BOXTYPE;
    ob->col1      = FL_TIMER_COL1;
    ob->col2      = FL_TIMER_COL2;
    if ( type != FL_VALUE_TIMER )
        ob->align     = FL_TIMER_ALIGN;
    else
        ob->align     = FL_ALIGN_LEFT;
    ob->lcol      = FL_TIMER_LCOL;
    ob->spec = sp = fl_calloc( 1, sizeof *sp );

    fl_set_timer( ob, 0.0 );       /* disabled timer */
    sp->filter = default_filter;

    return ob;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_timer( int          type,
              FL_Coord     x,
              FL_Coord     y,
              FL_Coord     w,
              FL_Coord     h,
              const char * l )
{
    FL_OBJECT *ob= fl_create_timer( type, x, y, w, h, l );

    fl_add_object( fl_current_form, ob );
    if ( ob->type == FL_VALUE_TIMER )
        fl_set_object_dblbuffer( ob, 1 );
    return ob;
}


/***************************************
 * Sets the timer clock to the particular delay. (0.0 to reset)
 ***************************************/

void
fl_set_timer( FL_OBJECT * ob,
              double      total )
{
    SPEC *sp = ob->spec;

    sp->time_left = sp->timer = total;
    sp->on = total > 0.0;
    fl_set_object_automatic( ob, sp->on );
    fl_gettime( &sp->sec, &sp->usec );
    if ( ob->type != FL_HIDDEN_TIMER )
        fl_redraw_object( ob );
}


/***************************************
 * returns the amount of time left
 ***************************************/

double
fl_get_timer( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;

    return sp->time_left > 0.0 ? sp->time_left : 0.0;
}


/***************************************
 ***************************************/

void
fl_set_timer_countup( FL_OBJECT * ob,
                      int         yes )
{
    ( ( SPEC * ) ob->spec )->up = yes;
}


/***************************************
 ***************************************/

FL_TIMER_FILTER
fl_set_timer_filter( FL_OBJECT       * ob,
                     FL_TIMER_FILTER   filter )
{
    SPEC *sp = ob->spec;
    FL_TIMER_FILTER old = sp->filter;

    if ( filter != sp->filter )
    {
        sp->filter = filter;
        fl_redraw_object( ob );
    }
    return old;
}


/***************************************
 ***************************************/

void
fl_suspend_timer( FL_OBJECT * ob )
{
    ( ( SPEC * ) ob->spec )->on = 0;
    fl_set_object_automatic( ob, 0 );
}


/***************************************
 ***************************************/

void
fl_resume_timer( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;
    long sec, usec;
    double elapsed;

    if ( sp->on )
        return;

    elapsed = sp->timer - sp->time_left;
    fl_gettime( &sec, &usec );
    sp->sec = sec - ( long ) elapsed;
    sp->usec = usec - ( long ) ( ( elapsed - ( long ) elapsed ) * 1.0e6 );
    fl_set_object_automatic( ob, 1 );
    sp->on = 1;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
