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
 * \file dial.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Default 0 is at 6 oclock and clock-wise is positive.
 */

#define SIX_OCLOCK 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pdial.h"

#include <math.h>
#include <sys/types.h>
#include <stdlib.h>


#ifndef M_PI
#define M_PI 3.14159265359
#endif


static double xo,
              yo;


/***************************************
 ***************************************/

static void
rotate_it( FL_POINT * xp,
           double     x,
           double     y,
           double     a )
{
    double sina = sin( a );
    double cosa = cos( a );

    xp->x = FL_crnd( xo + ( x - xo ) * cosa + ( y - yo ) * sina );
    xp->y = FL_crnd( yo - ( x - xo ) * sina + ( y - yo ) * cosa );
}


/***************************************
 * Draws a dial
 ***************************************/

static void
draw_dial( FL_OBJECT * obj )
{
    FL_Coord x,
             y,
             w,
             h,
             radius;
    double dangle;
    FLI_DIAL_SPEC *sp = obj->spec;
    FL_POINT xp[ 5 ];             /* need one extra for closing of polygon! */
    int boxtype,
        iradius;

    /* Since rotate_it() always does the rotation in the math way, i.e. 0 at
       three o'clock and CCW, need to translate the current theta into that
       coordiante system */

    dangle = ( sp->val - sp->b ) / sp->a;

    if ( sp->direction == FL_DIAL_CW )
        dangle = sp->origin - dangle;
    else
        dangle += sp->origin;

    if ( ( dangle = fmod( dangle, 360.0 ) ) < 0.0 )
        dangle += 360.0;

    dangle *= M_PI / 180.0;

    w = obj->w - 3;
    h = obj->h - 3;

    x = xo = obj->x + obj->w / 2;
    y = yo = obj->y + obj->h / 2;

    if ( FL_IS_UPBOX( obj->boxtype ) )
        boxtype = FL_OVAL3D_UPBOX;
    else if ( FL_IS_DOWNBOX( obj->boxtype ) )
        boxtype = FL_OVAL3D_DOWNBOX;
    else if ( obj->boxtype == FL_FRAME_BOX )
        boxtype = FL_OVAL3D_FRAMEBOX;
    else if ( obj->boxtype == FL_EMBOSSED_BOX )
        boxtype = FL_OVAL3D_EMBOSSEDBOX;
    else
        boxtype = FL_OVAL_BOX;

    /* the dial itself */

    radius = 0.5 * FL_min( w, h );
    iradius = radius - 1;         /* internal radius */

    fl_draw_box( boxtype, x - radius, y - radius, 2 * radius, 2 * radius,
                 obj->col1, obj->bw );

    /* the "hand" */

    if ( obj->type == FL_NORMAL_DIAL )
    {
        FL_Coord r;

        r = FL_min( 0.5 * iradius, 15 );

        rotate_it( xp,     x + iradius - 1,     y - 2, dangle );
        rotate_it( xp + 1, x + iradius - 1 - r, y - 2, dangle );
        rotate_it( xp + 2, x + iradius - 1 - r, y + 2, dangle );
        rotate_it( xp + 3, x + iradius - 1,     y + 2, dangle );

        fl_polyf( xp, 4, obj->col2 );
    }
    else if ( obj->type == FL_LINE_DIAL )
    {
        double dx = 0.1 + 0.08 * iradius,
               dy = 0.1 + 0.08 * iradius;

        rotate_it( xp,     x,               y,      dangle );
        rotate_it( xp + 1, x + dx,          y - dy, dangle );
        rotate_it( xp + 2, x + iradius - 2, y,      dangle );
        rotate_it( xp + 3, x + dx,          y + dy, dangle );

        fl_polybound( xp, 4, obj->col2 );
    }
    else if ( obj->type == FL_FILL_DIAL )
    {
        double ti,
               delta;

        delta = ( sp->val - sp->b ) / sp->a;
        delta = FL_abs( sp->thetai - delta );
        delta = sp->direction == FL_DIAL_CW ? -delta : delta;

        iradius -= boxtype != FL_OVAL_BOX;

        if ( sp->direction == FL_DIAL_CCW )
            ti = sp->thetai + sp->origin;
        else
            ti = sp->origin - sp->thetai;
        
        if ( ( ti = fmod( ti, 360.0 ) ) < 0.0 )
            ti += 360.0;

        fl_ovalarc( 1, xo - iradius, yo - iradius, 2 * iradius, 2 * iradius,
                    ti * 10, delta * 10, obj->col2 );

        rotate_it( xp,     xo + iradius - 1, yo, dangle );
        rotate_it( xp + 1, xo + iradius - 1, yo, ti * M_PI / 180.0 );
        fl_simple_line( FL_crnd( xo ), FL_crnd( yo ),
                        xp[ 0 ].x, xp[ 0 ].y, FL_BLACK );
        fl_simple_line( FL_crnd( xo ), FL_crnd( yo ),
                        xp[ 1 ].x, xp[ 1 ].y, FL_BLACK );

        if ( boxtype == FL_OVAL_BOX )
            fl_circ( x, y, iradius, FL_BLACK );
    }
    else
        M_err( "draw_dial", "Bad type" );

    fl_draw_text_beside( obj->align, obj->x, obj->y, obj->w, obj->h,
                         obj->lcol, obj->lstyle, obj->lsize, obj->label );
}


/***************************************
* Handle a mouse position change
 ***************************************/

static int
handle_mouse( FL_OBJECT * obj,
              FL_Coord    mousex,
              FL_Coord    mousey )
{
    FLI_DIAL_SPEC *sp = obj->spec;
    double oldv,
           val,
           olda;
    double mx,
           my,
           angle,
           range = sp->max - sp->min;

    oldv = sp->val;
    olda = ( oldv - sp->b ) / sp->a;

    /* convert to sane FL_coordinate system, i.e., +y up */

    mx =   mousex - ( obj->x + obj->w * 0.5 );
    my = - mousey + ( obj->y + obj->h * 0.5 );

    /* Don't react to clicks very close to center */

    if ( fabs( mx ) < 2 && fabs( my ) < 2 )
        return FL_RETURN_NONE;

    /* Get angle and normalize to [0, 2 * PI] */

    angle = atan2( my, mx ) * 180.0 / M_PI;

    if ( sp->direction == FL_DIAL_CW )
        angle = sp->origin - angle;
    else
        angle -= sp->origin;

    if ( ( angle = fmod( angle, 360.0 ) ) < 0.0 )
        angle += 360.0;

    val = fli_clamp( sp->a * angle + sp->b, sp->min, sp->max );

    /* Check if crossed boundary. Fix it if it did. Fixing is necessary
       otherwise might be unable to reach thetaf(360) */

    if ( ! sp->cross_over && fabs( oldv - val ) > 0.6 * range )
    {
        if ( fabs( olda - sp->thetai ) < fabs( olda - sp->thetaf ) )
            angle = sp->thetai;
        else
            angle = sp->thetaf;
        val = sp->a * angle + sp->b;
    }

    if ( sp->step != 0.0 )
        val = ( int ) ( val / sp->step + 0.5 ) * sp->step;

    /* Allow a resolution of about 0.2 degrees */

    if ( fabs( val - oldv ) > range / 1800.0 )
    {
        sp->val = val;
        fl_redraw_object( obj );
        return FL_RETURN_CHANGED;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * Function for handling mouse wheel events
 ***************************************/

static int
handle_mouse_wheel( FL_OBJECT * obj,
                    XEvent *    xev,
                    int         key )
{
    FLI_DIAL_SPEC *sp = obj->spec;
    double val,
           step,
           oldv = sp->val,
           range = sp->max - sp->min;

    if ( key != FL_MBUTTON4 && key != FL_MBUTTON5 )
        return FL_RETURN_NONE;

    step = sp->step > 0.0 ? 10.0 * sp->step : 0.1 * range;

    if ( shiftkey_down( ( ( XButtonEvent * ) xev )->state ) )
        step *= 0.1;
    else if ( controlkey_down( ( ( XButtonEvent * ) xev )->state ) )
        step *= 2.5;

    if ( sp->direction == FL_DIAL_CW )
        step = key == FL_MBUTTON4 ? - step : step;
    else
        step = key == FL_MBUTTON4 ? step : - step;

    val = sp->val + step;

    if ( sp->cross_over )
    {
        while ( val > sp->max )
            val -= range;
        while ( val < sp->min )
            val += range;
    }
    else
    {
        if ( val > sp->max )
            val = sp->max;
        else if ( val < sp->min )
            val = sp->min;
    }
        
    if ( val != oldv )
    {
        sp->val = val;
        fl_redraw_object( obj );
        return FL_RETURN_CHANGED;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * Handles an event
 ***************************************/

static int
handle_dial( FL_OBJECT * obj,
             int         event,
             FL_Coord    mx,
             FL_Coord    my,
             int         key  FL_UNUSED_ARG,
             void *      ev )
{
    FLI_DIAL_SPEC *sp = obj->spec;
    int ret = FL_RETURN_NONE;

    switch ( event )
    {
        case FL_ATTRIB :
            obj->align = fl_to_outside_lalign( obj->align );
            break;

        case FL_DRAW:
            draw_dial( obj );
            break;

        case FL_DRAWLABEL:
            fl_draw_text_beside( obj->align, obj->x, obj->y, obj->w, obj->h,
                                 obj->lcol, obj->lstyle, obj->lsize,
                                 obj->label );
            break;

        case FL_PUSH:
            if ( key != FL_MBUTTON1 )
                break;
            sp->start_val = sp->val;
            /* fall through */

        case FL_MOTION:
            if ( key != FL_MBUTTON1 )
                break;

            if (    ( ret = handle_mouse( obj, mx, my ) )
                 && ! ( obj->how_return & FL_RETURN_END_CHANGED ) )
                sp->start_val = sp->val;
            break;

        case FL_RELEASE:
            if ( key == FL_MBUTTON2 || key == FL_MBUTTON3 )
                break;

            ret = handle_mouse_wheel( obj, ev, key ) | FL_RETURN_END;
            if ( sp->start_val != sp->val )
                ret |= FL_RETURN_CHANGED;
            break;

        case FL_FREEMEM:
            fl_free( obj->spec );
            break;
    }

    return ret;
}


/***************************************
 ***************************************/

static void
get_mapping( FLI_DIAL_SPEC *sp )
{
    sp->a = ( sp->max - sp->min ) / ( sp->thetaf - sp->thetai );
    sp->b = sp->max - sp->a * sp->thetaf;
}


/***************************************
 * Creates an object
 ***************************************/

FL_OBJECT *
fl_create_dial( int          type,
                FL_Coord     x,
                FL_Coord     y,
                FL_Coord     w,
                FL_Coord     h,
                const char * label )
{
    FL_OBJECT *obj;
    FLI_DIAL_SPEC *sp;

    obj = fl_make_object( FL_DIAL, type, x, y, w, h, label, handle_dial );
    obj->col1     = FL_DIAL_COL1;
    obj->col2     = FL_DIAL_COL2;
    obj->align    = FL_DIAL_ALIGN;
    obj->lcol     = FL_DIAL_LCOL;
    obj->boxtype  = FL_DIAL_BOXTYPE;
    obj->spec     = sp = fl_calloc( 1, sizeof *sp );

    sp->min       = 0.0;
    sp->max       = 1.0;
    sp->val       = 0.5;
    sp->step      = 0.0;
    sp->thetai    = 0.0;
    sp->thetaf    = 360.0;
    sp->origin    = 270.0;
    sp->direction = FL_DIAL_CW;
    get_mapping( sp );

    return obj;
}


/*************************************** 
 * Add an object
***************************************/

FL_OBJECT *
fl_add_dial( int          type,
             FL_Coord     x,
             FL_Coord     y,
             FL_Coord     w,
             FL_Coord     h,
             const char * label )
{
    FL_OBJECT *obj = fl_create_dial( type, x, y, w, h, label );

    /* Set default return policy for the object */

    fl_set_object_return( obj, FL_RETURN_END_CHANGED );

    fl_add_object( fl_current_form, obj );
    fl_set_object_dblbuffer( obj, 1 );

    return obj;
}


/***************************************
 ***************************************/

void
fl_set_dial_value( FL_OBJECT * obj,
                   double      val )
{
    FLI_DIAL_SPEC *sp = obj->spec;

    if ( sp->val != val )
    {
        sp->val = sp->start_val = val;
        fl_redraw_object( obj );
    }
}


/***************************************
 ***************************************/

void
fl_set_dial_bounds( FL_OBJECT * obj,
                    double      min,
                    double      max )
{
    FLI_DIAL_SPEC *sp = obj->spec;

    if ( sp->min != min || sp->max != max )
    {
        sp->min = min;
        sp->max = max;
        get_mapping( sp );
        sp->val = fli_clamp( sp->val, sp->min, sp->max );
        fl_redraw_object( obj );
    }
}


/***************************************
 ***************************************/

void
fl_set_dial_angles( FL_OBJECT * obj,
                    double      amin,
                    double      amax )
{
    FLI_DIAL_SPEC *sp = obj->spec;

    if ( ( amin = fmod( amin, 360.0 ) ) < 0.0 )
        amin += 360.0;
    if ( ( amax = fmod( amax, 360.0 ) ) <= 0.0 )
        amax += 360.0;

    if ( sp->thetaf != amax || sp->thetai != amin )
    {
        sp->thetaf = amax;
        sp->thetai = amin;
        get_mapping( sp );
        fl_redraw_object( obj );
    }
}


/***************************************
 ***************************************/

void
fl_get_dial_angles( FL_OBJECT * obj,
                    double    * amin,
                    double    * amax )
{
    FLI_DIAL_SPEC *sp = obj->spec;

    *amin = sp->thetai;
    *amax = sp->thetaf;
}


/***************************************
 ***************************************/

void
fl_set_dial_cross( FL_OBJECT * obj,
                   int         flag )
{
    ( ( FLI_DIAL_SPEC * ) obj->spec )->cross_over = flag;
}


/***************************************
 ***************************************/

double
fl_get_dial_value( FL_OBJECT * obj )
{
    return ( ( FLI_DIAL_SPEC * ) obj->spec )->val;
}


/***************************************
 ***************************************/

void
fl_get_dial_bounds( FL_OBJECT * obj,
                    double *    min,
                    double *    max )
{
    *min = ( ( FLI_DIAL_SPEC * ) obj->spec )->min;
    *max = ( ( FLI_DIAL_SPEC * ) obj->spec )->max;
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as deprecated and
 * fl_set_object_return() should be used instead.
 ***************************************/

void
fl_set_dial_return( FL_OBJECT    * obj,
                    unsigned int   when )
{
    fl_set_object_return( obj, when );
}


/***************************************
 * Sets the step size to which values are rounded.
 ***************************************/

void
fl_set_dial_step( FL_OBJECT * obj,
                  double      value )
{
    ( ( FLI_DIAL_SPEC * ) obj->spec )->step = value;
}


/***************************************
 * Returns the step size to which values are rounded.
 ***************************************/

double
fl_get_dial_step( FL_OBJECT * obj )
{
    return ( ( FLI_DIAL_SPEC * ) obj->spec )->step;
}


/***************************************
 ***************************************/

void
fl_set_dial_direction( FL_OBJECT * obj,
                       int         dir )
{
    FLI_DIAL_SPEC *sp = obj->spec;

    if ( sp->direction != dir )
    {
        sp->direction = dir;
        get_mapping( sp );
        fl_redraw_object( obj );
    }
}


/***************************************
 ***************************************/

int
fl_get_dial_direction( FL_OBJECT * obj )
{
    return ( ( FLI_DIAL_SPEC * ) obj->spec )->direction;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
