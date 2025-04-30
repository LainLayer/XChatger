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
 * \file sp_twheel.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting twheel class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_twheel.h"
#include "private/ptwheel.h"
#include "private/pvaluator.h"
#include "spec/twheel_spec.h"

static FD_twheelattrib * twheel_attrib;
FL_OBJECT * curobj;


/***************************************
 ***************************************/

FL_FORM *
thwheel_create_spec_form( void )
{
    if ( twheel_attrib )
        return twheel_attrib->twheelattrib;

    twheel_attrib = create_form_twheelattrib( );

    setup_how_return_menu( twheel_attrib->returnsetting );
    fl_set_menu_item_mode( twheel_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( twheel_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    return twheel_attrib->twheelattrib;
}


/***************************************
 ***************************************/

void
twheel_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_THUMBWHEEL_SPEC *sp = obj->spec;

    curobj = obj;

    set_finput_value( twheel_attrib->minval,      sp->min, -1 );
    set_finput_value( twheel_attrib->maxval,      sp->max, -1 );
    set_finput_value( twheel_attrib->initial_val, sp->val, -1 );
    set_finput_value( twheel_attrib->step,        sp->step, 3 );

    reset_how_return_menu( twheel_attrib->returnsetting, obj->how_return );
}


/***************************************
 ***************************************/

void
twheel_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    if (    get_checked_float( fl_get_input( twheel_attrib->minval ), &r1 )
         && get_checked_float( fl_get_input( twheel_attrib->maxval ), &r2 ) )
        fl_set_thumbwheel_bounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( twheel_attrib->initial_val ), &r1 ) )
        fl_set_thumbwheel_value( obj, r1 );

    if ( get_checked_float( fl_get_input( twheel_attrib->step ), &r1 ) )
        fl_set_thumbwheel_step( obj, r1 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
twheel_emit_spec_fd_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_thumbwheel( obj->type, 0, 0, 0, 0, "" );
    FLI_THUMBWHEEL_SPEC *sp    = obj->spec,
                        *defsp = defobj->spec;

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    bounds: %g %g\n", sp->min, sp->max );

    if ( sp->val != defsp->val )
        fprintf( fp, "    value: %g\n", sp->val );

    if ( sp->ldelta != defsp->ldelta || sp->rdelta != defsp->rdelta )
        fprintf( fp, "    increment: %g %g\n", sp->ldelta, sp->rdelta );

    if ( sp->slsize != defsp->slsize )
        fprintf( fp, "    slsize: %.2f\n", sp->slsize );

    if ( sp->step != defsp->step )
        fprintf( fp, "    step: %g\n", sp->step );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
twheel_emit_spec_c_code( FILE      * fp,
                         FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_thumbwheel( obj->type, 0, 0, 0, 0, "" );
    FLI_THUMBWHEEL_SPEC *sp    = obj->spec,
                        *defsp = defobj->spec;

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    fl_set_thumbwheel_bounds( obj, %g, %g );\n",
                 sp->min, sp->max );

    if ( sp->val != defsp->val )
        fprintf( fp, "    fl_set_thumbwheel_value( obj, %g );\n", sp->val );

    if ( sp->step != defsp->step )
        fprintf( fp, "    fl_set_thumbwheel_step( obj, %g );\n", sp->step );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
twheel_minmax_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                      long        data  FL_UNUSED_ARG )
{
    fl_set_thumbwheel_bounds( curobj,
                              get_finput_value( twheel_attrib->minval ),
                              get_finput_value( twheel_attrib->maxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
twheel_step_change( FL_OBJECT * obj,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_thumbwheel_step( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
twheel_initialvalue_change( FL_OBJECT * obj,
                            long        data  FL_UNUSED_ARG )
{
    fl_set_thumbwheel_value( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
twheel_returnsetting_change( FL_OBJECT * obj,
                             long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


#include "spec/twheel_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
