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
 * \file thumbwheel.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  The thumbwheel
 *
 * TODO:   cursor keys
 *         home key
 *         do we need increments a la slider?
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"

#include <math.h>
#include "private/ptwheel.h"

#ifndef M_PI
#define M_PI    3.14159265359
#endif

static const double arc = ( M_PI * 0.48 );  /* about 90 degrees */

#define GRID       0.190    /* angular grid for ridges */
#define NEAR       600.0    /* near plane distance     */
#define DEFSTEP    0.005


/***************************************
 ***************************************/

static void
draw( FL_OBJECT * ob )
{
    int h2 = ob->h / 2,
        w2 = ob->w / 2;
    int absbw = FL_abs( ob->bw );
    double delta = GRID - ( ( h2 + w2 ) > 300 ? 0.02 : 0.0 );
    FLI_THUMBWHEEL_SPEC *sp = ob->spec;
    double yo = ob->y + h2;
    double x0 = ob->x + w2;
    int x,
        y,
        w,
        h;
    double theta;
    double dx,
           dy;
    double offset = sp->val / ( sp->step == 0.0 ? DEFSTEP : sp->step );
    double junk;
    FL_COLOR c1,
             c2;

    if ( sp->draw_type == COMPLETE_DRAW )
        fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1,
                     ob->bw );

    x = ob->x + absbw;
    y = ob->y + absbw;
    w = ob->w - 2 * absbw;
    h = ob->h - 2 * absbw;

    if ( ob->type == FL_VERT_THUMBWHEEL )
    {
        double extra = h2 * ( NEAR / ( NEAR - h2 ) - 0.96 );

        /* (Fake) depth-cue */

        fl_rectf( x, y + 1, w, h - 2, FL_DARKER_COL1 );
        fl_rectf( x, yo - ob->h / 4, w, ob->h / 2, FL_COL1 );
        fl_rectf( x, yo - ob->h / 10, w, ob->h / 5, FL_LIGHTER_COL1 );

        for ( theta = arc - modf( offset / delta, &junk );
              theta > -arc; theta -= delta )
        {
            dy = ( h2 + extra ) * sin( theta );
            dx = ob->h - ( h2 + extra ) * cos( theta );
            y = yo + FL_nint( dy * NEAR / ( NEAR + dx ) );

            if ( y > ob->y + 3 && y < ob->y + ob->h - 3 )
            {
                int d = 1;
                if ( y < yo + h2 / 4 && y > yo - h2 / 4 )
                {
                    c1 = FL_LEFT_BCOL;
                    c2 = FL_RIGHT_BCOL;
                }
                else if ( y < ob->y + h2 / 5 || y > yo + h2 - h2 / 5 )
                {
                    c1 = FL_LIGHTER_COL1;
                    c2 = FL_BOTTOM_BCOL;
                    d = 0;
                }
                else
                {
                    c1 = FL_MCOL;
                    c2 = FL_BOTTOM_BCOL;
                }

                fl_line( x + 1, y - 1, x + w - 2, y - 1, c1 );
                fl_line( x + 1, y + d, x + w - 2, y + d, c2 );
            }
        }

        /* Bottom */

        y = ob->y + absbw;
        fl_rectf( x - 1, ob->y + ob->h - 6, w, 3, FL_RIGHT_BCOL );

        /* Top */

        fl_rectf( x - 1, y, w, 3, FL_RIGHT_BCOL );

        /* Left */

        fl_line( x - 1, y, x - 1, y + h - 1, FL_BLACK );

        /* right */

        fl_rectf( x + w - 1, y, 2, h, FL_RIGHT_BCOL );

        /* Highlight */

        fl_line( x + 1, yo - h2 + 10, x + 1, yo + h2 - 10, FL_LEFT_BCOL );
    }
    else
    {
        double extra = w2 * ( NEAR / ( NEAR - w2 ) - 0.96 );

        fl_rectf( x, y, w, h, FL_DARKER_COL1 );
        fl_rectf( x0 - w / 4, y, w / 2, h, FL_COL1 );
        dx = ob->w / 10;
        fl_rectf( x0 - dx, y, 2 * dx, h, FL_LIGHTER_COL1 );

        for ( theta = arc + modf( offset / delta, &junk );
              theta > -arc; theta -= delta )
        {
            dx = ( w2 + extra ) * sin( theta );
            dy = ob->w - ( w2 + extra ) * cos( theta );
            x = x0 + FL_nint( dx * NEAR / ( NEAR + dy ) );

            if ( x > ob->x + absbw + 1 && x < x0 + w2 - absbw - 2 )
            {
                int d = 1;

                if ( x < x0 + w2 / 4 && x > x0 - w2 / 4 )
                {
                    c1 = FL_LEFT_BCOL;
                    c2 = FL_RIGHT_BCOL;
                }
                else if ( x < ob->x + ( w2 / 4 ) || x > x0 + w2 - ( w2 / 4 ) )
                {
                    c1 = FL_LIGHTER_COL1;
                    c2 = FL_BOTTOM_BCOL;
                }
                else
                {
                    c1 = FL_MCOL;
                    c2 = FL_BOTTOM_BCOL;
                }

                fl_line( x - 1, y + 2, x - 1, yo + h2 - 2 * absbw, c1 );
                fl_line( x + d, y + 2, x + d, yo + h2 - 2 * absbw, c2 );
            }

            x = ob->x + absbw;
            y = ob->y + absbw;
            w = ob->w - 2 * absbw;
            h = ob->h - 2 * absbw;

            /* Top shadow */

            fl_line( x, y - 1, x + w - 2, y - 1, FL_BLACK );
            fl_line( x, y, x + w - 4, y, FL_BLACK );

            /* Bottom shadow */

            fl_line( x + 5, y + h - 2, x + w - 4, y + h - 2, FL_BLACK );
            fl_line( x, y + h - 1, x + w - 2, y + h - 1, FL_BLACK );
            fl_line( x, y + h, x + w - 2, y + h, FL_BLACK );

            /* Left & right */

            fl_rectf( x, y - 1, 3, h + 1, FL_RIGHT_BCOL );
            fl_rectf( x + w - 4, y - 1, 3, h + 1, FL_RIGHT_BCOL );

            /* High light */

            fl_line( x0 - w2 + 11, y + 1, x0 + w2 - 11, y + 1, FL_TOP_BCOL );
        }
    }

    if ( sp->draw_type == COMPLETE_DRAW )
        fl_draw_object_label_outside( ob );
}


/***************************************
 ***************************************/

static int
handle_thumbwheel( FL_OBJECT * ob,
                   int         ev,
                   int         mx,
                   int         my,
                   int         key,
                   void      * xev  FL_UNUSED_ARG )
{
    FLI_THUMBWHEEL_SPEC *sp = ob->spec;
    int cur_pos,
        old_pos;
    double value;
    double step = sp->step != 0.0 ? sp->step : DEFSTEP;
    int ret = FL_RETURN_NONE;

    switch ( ev )
    {
        case FL_ATTRIB :
            ob->align = fl_to_outside_lalign( ob->align );
            break;

        case FL_DRAW:
            draw( ob );
            sp->draw_type = COMPLETE_DRAW;
            break;

        case FL_DRAWLABEL:
            if ( sp->draw_type == COMPLETE_DRAW )
                fl_draw_object_label_outside( ob );
            break;

        case FL_PUSH:
            if ( key != FL_MBUTTON1 )
                break;

            sp->old_mx = mx;
            sp->old_my = my;
            sp->start_val = sp->val;
            /* fall through */

        case FL_MOTION:
            if ( key != FL_MBUTTON1 )
                break;

            cur_pos = ob->type == FL_VERT_THUMBWHEEL ? sp->old_my : mx;
            old_pos = ob->type == FL_VERT_THUMBWHEEL ? my : sp->old_mx;
            value = sp->val + step * ( cur_pos - old_pos );
            sp->old_mx = mx;
            sp->old_my = my;
            ret |= fli_valuator_handle_drag( ob, value );
            break;

        case FL_KEYPRESS:
            value = sp->val;
            if ( IsHome( key ) )
                value = 0.5 * ( sp->min + sp->max );
            else if ( IsUp( key ) && ob->type == FL_VERT_THUMBWHEEL )
                value = sp->val + step;
            else if ( IsDown( key ) && ob->type == FL_VERT_THUMBWHEEL )
                value = sp->val - step;
            else if ( IsRight( key ) && ob->type == FL_HOR_THUMBWHEEL )
                value = sp->val + step;
            else if ( IsLeft( key ) && ob->type == FL_HOR_THUMBWHEEL )
                value = sp->val - step;
            ret |= fli_valuator_handle_release( ob, value );
            break;

        case FL_RELEASE:
            if (    ! ( key == FL_MBUTTON1
                 || (    ob->type == FL_VERT_THUMBWHEEL
                      && (    key == FL_MBUTTON4
                           || key == FL_MBUTTON5 ) ) ) )
                break;

            if (    ob->type == FL_VERT_THUMBWHEEL
                 && ( key == FL_MBUTTON4 || key == FL_MBUTTON5 ) )
                value = sp->val + ( key == FL_MBUTTON4 ? step : -step );
            else
                value = sp->val;
            ret |= fli_valuator_handle_release( ob, value );
            break;
    }

    return ret;
}


/***************************************
 ***************************************/

double
fl_get_thumbwheel_value( FL_OBJECT * ob )
{
#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_THUMBWHEEL ) )
    {
        M_err( "fl_get_thumbwheel_value", "%s is not a thumbwheel",
               ob ? ob->label : "null" );
        return 1.0;
    }
#endif

    return ( ( FLI_THUMBWHEEL_SPEC * ) ob->spec )->val;
}


/***************************************
 ***************************************/

double
fl_set_thumbwheel_value( FL_OBJECT * ob,
                         double      value )
{
    FLI_THUMBWHEEL_SPEC *sp;
    double oldval;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_THUMBWHEEL ) )
    {
        M_err( "fl_set_thumbwheel_value", "%s is not a thumbwheel",
               ob ? ob->label : "null" );
        return 1.0;
    }
#endif

    sp = ob->spec;
    oldval = sp->val;

    value = FL_clamp( value, sp->min, sp->max );
    if ( sp->val != value )
    {
        sp->val = sp->start_val = value;
        fl_redraw_object( ob );
    }

    return oldval;
}


/***************************************
 ***************************************/

void
fl_set_thumbwheel_bounds( FL_OBJECT * ob,
                          double      min,
                          double      max )
{
    FLI_THUMBWHEEL_SPEC *sp;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_THUMBWHEEL ) )
    {
        M_err( "fl_set_thumbwheel_bounds", "%s is not a thumbwheel",
               ob ? ob->label : "null" );
        return;
    }
#endif

    sp = ob->spec;
    if ( sp->min != min || sp->max != max )
    {
        sp->min = min;
        sp->max = max;
        sp->val = FL_clamp( sp->val, min, max );
        fl_redraw_object( ob );
    }

}


/***************************************
 ***************************************/

void
fl_get_thumbwheel_bounds( FL_OBJECT * ob,
                          double    * min,
                          double    * max )
{
    FLI_THUMBWHEEL_SPEC *sp = ob->spec;

    *min = sp->min;
    *max = sp->max;
}


/***************************************
 ***************************************/

double
fl_get_thumbwheel_step( FL_OBJECT * ob )
{
    return ( ( FLI_THUMBWHEEL_SPEC * ) ob->spec )->step;
}


/***************************************
 ***************************************/

double
fl_set_thumbwheel_step( FL_OBJECT * ob,
                        double      step )
{
    FLI_THUMBWHEEL_SPEC *sp = ob->spec;
    double old = sp->step;

    if ( sp->step != step )
        sp->step = step;

    return old;
}


/***************************************
 * Unused, undocumented function  JTT
 ***************************************/

int fl_set_thumbwheel_crossover( FL_OBJECT * ob,
                                 int         flag )
{
     FLI_THUMBWHEEL_SPEC *sp;
     int old;

     if ( ! ob || ! ( ob->objclass != FL_THUMBWHEEL ) )
         return -1;

     sp = ob->spec;
     old = sp->cross_over;
     sp->cross_over = flag;
     return old;
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as deprecated and
 * fl_set_object_return() should be used instead.
 ***************************************/

int
fl_set_thumbwheel_return( FL_OBJECT    * obj,
                          unsigned int   when )
{
    return fl_set_object_return( obj, when );
}


/***************************************
 * Creates a thumbwheel object *
 ***************************************/

FL_OBJECT *
fl_create_thumbwheel( int          type,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * label )
{
    FL_OBJECT *obj;
    FLI_THUMBWHEEL_SPEC *sp;

    obj = fl_make_object( FL_THUMBWHEEL, type, x, y, w, h, label,
                          handle_thumbwheel );
    obj->col1    = FL_THUMBWHEEL_COL1;
    obj->col2    = FL_THUMBWHEEL_COL2;
    obj->lcol    = FL_THUMBWHEEL_LCOL;
    obj->align   = FL_THUMBWHEEL_ALIGN;
    obj->boxtype = FL_THUMBWHEEL_BOXTYPE;
    obj->wantkey = FL_KEY_SPECIAL;
    obj->spec    = NULL;

    sp = fli_init_valuator( obj );
    sp->step = DEFSTEP;

    fl_set_object_return( obj, FL_RETURN_CHANGED );

    return obj;
}


/***************************************
 * Adds a thumbwheel object
 ***************************************/

FL_OBJECT *
fl_add_thumbwheel( int          type,
                   FL_Coord     x,
                   FL_Coord     y,
                   FL_Coord     w,
                   FL_Coord     h,
                   const char * label )
{
    FL_OBJECT *obj = fl_create_thumbwheel( type, x, y, w, h, label );

    /* Set default return policy for the object */

    fl_set_object_return( obj, FL_RETURN_CHANGED );

    fl_add_object( fl_current_form, obj );
    fl_set_object_dblbuffer( obj, 1 );

    return obj;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
