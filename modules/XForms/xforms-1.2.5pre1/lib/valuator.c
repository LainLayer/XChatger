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
 * \file valuator.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Handle some common valuator tasks.
 *   TODO: move slider and counter handler here
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pvaluator.h"


/***************************************
 ***************************************/

void *
fli_init_valuator( FL_OBJECT * ob )
{
    FLI_VALUATOR_SPEC *sp = ob->spec;

    if ( ! sp )
        ob->spec = sp = fl_calloc( 1, sizeof *sp );

    sp->min       = 0.0;
    sp->max       = 1.0;
    sp->val       = 0.5;
    sp->prec      = 2;
    sp->step      = 0.01;
    sp->draw_type = COMPLETE_DRAW;

    return sp;
}

#define CROSS_OVER( v, vmin, vmax )  \
    ( ( v ) < ( vmin ) ? ( vmax ) : ( ( v ) > ( vmax ) ? ( vmin ) : ( v ) ) )


/***************************************
 ***************************************/

double
fli_valuator_round_and_clamp( FL_OBJECT * ob,
                              double      val )
{
    FLI_VALUATOR_SPEC *sp = ob->spec;
    double vmin,
           vmax;

    if ( sp->step != 0.0 )
    {
       val /= sp->step;
       val = sp->step * ( val >= 0 ? floor( val + 0.5 ) : ceil( val - 0.5 ) );
    }

    vmin = FL_min( sp->min, sp->max );
    vmax = FL_max( sp->min, sp->max );

    if ( ! sp->cross_over )
        return FL_clamp( val, vmin, vmax );
    else
        return CROSS_OVER( val, vmin, vmax );
}


/***************************************
 ***************************************/

int
fli_valuator_handle_drag( FL_OBJECT * ob,
                          double      value )
{
    FLI_VALUATOR_SPEC *sp = ob->spec;
    int ret = FL_RETURN_NONE;

    value = fli_valuator_round_and_clamp( ob, value );

    if ( value != sp->val )
    {
        sp->val = value;
        sp->draw_type = VALUE_DRAW;
        fl_redraw_object( ob );
        ret |= FL_RETURN_CHANGED;
    }

    return ret;
}


/***************************************
 ***************************************/

int
fli_valuator_handle_release( FL_OBJECT * ob,
                             double      value )
{
    FLI_VALUATOR_SPEC *sp = ob->spec;
    int ret = FL_RETURN_END;
    
    value = fli_valuator_round_and_clamp( ob, value );

    if ( value != sp->val )
    {
        sp->val = value;
        sp->draw_type = VALUE_DRAW;
        fl_redraw_object( ob );
        if ( ! ( ob->how_return & FL_RETURN_END_CHANGED ) )
            ret |= FL_RETURN_CHANGED;
    }

    if ( sp->start_val != sp->val && ob->how_return & FL_RETURN_END_CHANGED )
        ret |= FL_RETURN_CHANGED;

    return ret;
}


/***************************************
 ***************************************/

double
fli_clamp( double val,
           double min,
           double max)
{
    double vmin = FL_min( min, max ),
           vmax = FL_max( min, max );

    return FL_clamp( val, vmin, vmax );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
