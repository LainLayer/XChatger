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
 * \file sp_slider.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting slider class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_slider.h"
#include "spec/slider_spec.h"
#include "private/pslider.h"


static FD_sliderattrib * sl_attrib;
static FL_OBJECT * curobj;


/***************************************
 ***************************************/

FL_FORM *
slider_create_spec_form( void )
{
    if ( sl_attrib )
        return sl_attrib->sliderattrib;

    sl_attrib = create_form_sliderattrib( );

    setup_how_return_menu( sl_attrib->returnsetting );
    fl_set_menu_item_mode( sl_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( sl_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    fl_set_counter_step( sl_attrib->prec, 1, 2 );
    fl_set_counter_precision( sl_attrib->prec, 0 );
    fl_set_counter_bounds( sl_attrib->prec, 0, FL_SLIDER_MAX_PREC );

    return sl_attrib->sliderattrib;
}


/***************************************
 ***************************************/

void
slider_adjust_spec_form( FL_OBJECT * obj )
{
    curobj = obj;

    if ( obj->objclass == FL_VALSLIDER )
        fl_show_object( sl_attrib->prec );
    else
        fl_hide_object( sl_attrib->prec );

    if ( obj->type & FL_HOR_FLAG )
    {
        fl_set_object_label( sl_attrib->minval, "Value at left" );
        fl_set_object_label( sl_attrib->maxval, "Value at right" );
    }
    else
    {
        fl_set_object_label( sl_attrib->minval, "Value at top" );
        fl_set_object_label( sl_attrib->maxval, "Value at bottom" );
    }
}


/***************************************
 ***************************************/

void
slider_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_SLIDER_SPEC *sp = obj->spec;

    set_finput_value( sl_attrib->minval, sp->min, sp->prec );
    set_finput_value( sl_attrib->maxval, sp->max, sp->prec );
    set_finput_value( sl_attrib->initial_val, sp->val, sp->prec );
    set_finput_value( sl_attrib->slsize, sp->slsize, 2 );
    set_finput_value( sl_attrib->step, sp->step, 3 );
    set_finput_value( sl_attrib->ldelta, sp->ldelta, -1 );
    set_finput_value( sl_attrib->rdelta, sp->rdelta, -1 );
    fl_set_counter_value( sl_attrib->prec, sp->prec );

    reset_how_return_menu( sl_attrib->returnsetting, curobj->how_return );
}


/***************************************
 ***************************************/

void
slider_emit_spec_fd_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = ( obj->objclass == FL_SLIDER ?
                          fl_create_slider : fl_create_valslider )
                          ( obj->type, 0, 0, 0, 0, "" );
    FLI_SLIDER_SPEC *sp    = obj->spec,
                    *defsp = defobj->spec;

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    bounds: %g %g\n", sp->min, sp->max );
    if ( sp->prec != defsp->prec )
        fprintf( fp, "    precision: %d\n", sp->prec );
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
slider_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    if (    get_checked_float( fl_get_input( sl_attrib->minval ), &r1 )
         && get_checked_float( fl_get_input( sl_attrib->maxval ), &r2 ) )
        fl_set_slider_bounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( sl_attrib->initial_val ), &r1 ) )
         fl_set_slider_value( obj, r1 );

    if ( get_checked_float( fl_get_input( sl_attrib->step ), &r1 ) )
        fl_set_slider_step( obj, r1 );

    if ( get_checked_float( fl_get_input( sl_attrib->slsize ), &r1 ) )
        fl_set_slider_size( obj, r1 );

    if (    get_checked_float( fl_get_input( sl_attrib->ldelta ), &r1 )
         && get_checked_float( fl_get_input( sl_attrib->rdelta ), &r2 ) )
        fl_set_slider_increment( obj, r1, r2 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
slider_emit_spec_c_code( FILE      * fp,
                         FL_OBJECT * obj )
{
    FL_OBJECT *defobj = ( obj->objclass == FL_SLIDER ?
                          fl_create_slider : fl_create_valslider )
                          ( obj->type, 0, 0, 0, 0, "" );
    FLI_SLIDER_SPEC *sp    = obj->spec,
                    *defsp = defobj->spec;

    if ( sp->prec != defsp->prec )
        fprintf( fp, "    fl_set_slider_precision( obj, %d );\n", sp->prec );

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    fl_set_slider_bounds( obj, %g, %g );\n",
                 sp->min, sp->max );

    if ( sp->val != defsp->val )
        fprintf( fp, "    fl_set_slider_value( obj, %g );\n", sp->val );

    if ( sp->slsize != defsp->slsize )
        fprintf( fp, "    fl_set_slider_size( obj, %.2f );\n", sp->slsize );

    if ( sp->step != defsp->step )
        fprintf( fp, "    fl_set_slider_step( obj, %g );\n", sp->step );

    if ( sp->ldelta != defsp->ldelta || sp->rdelta != defsp->rdelta )
        fprintf( fp, "    fl_set_slider_increment( obj, %g, %g );\n",
                 sp->ldelta, sp->rdelta );


    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
adjust_precision( FL_OBJECT * ob,
                  long        data  FL_UNUSED_ARG )
{
    fl_set_slider_precision( curobj, fl_get_counter_value( ob ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
minmax_change( FL_OBJECT * ob    FL_UNUSED_ARG,
               long        data  FL_UNUSED_ARG )
{
    fl_set_slider_bounds( curobj,
                          get_finput_value( sl_attrib->minval ),
                          get_finput_value( sl_attrib->maxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
slsize_change( FL_OBJECT * obj,
               long        data  FL_UNUSED_ARG )
{
    fl_set_slider_size( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
step_change( FL_OBJECT * obj,
             long        data  FL_UNUSED_ARG )
{
    FLI_SLIDER_SPEC *sp = curobj->spec;

    set_finput_value( obj, get_finput_value( obj ), sp->prec );
    fl_set_slider_step( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
increment_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
    fl_set_slider_increment( curobj,
                             get_finput_value( sl_attrib->ldelta ),
                             get_finput_value( sl_attrib->rdelta ) );
}


/***************************************
 ***************************************/

void
initialvalue_change( FL_OBJECT * obj,
                     long        data  FL_UNUSED_ARG )
{
    FLI_SLIDER_SPEC *sp = curobj->spec;

    set_finput_value( obj, get_finput_value( obj ), sp->prec );
    fl_set_slider_value( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
returnsetting_change( FL_OBJECT * obj,
                      long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


#include "spec/slider_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
