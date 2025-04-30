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
 * \file sp_counter.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting counter class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <float.h>

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_counter.h"
#include "private/pcounter.h"
#include "private/pvaluator.h"
#include "spec/counter_spec.h"

static FD_counterattrib * cnt_attrib;
static FL_OBJECT * curobj;

/***************************************
 ***************************************/

FL_FORM *
counter_create_spec_form( void )
{
    if ( cnt_attrib )
        return cnt_attrib->counterattrib;

    cnt_attrib = create_form_counterattrib( );

    setup_how_return_menu( cnt_attrib->returnsetting );
    fl_set_menu_item_mode( cnt_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( cnt_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    fl_set_counter_precision( cnt_attrib->prec, 0 );
    fl_set_counter_step( cnt_attrib->prec, 1, 2 );
    fl_set_counter_bounds( cnt_attrib->prec, 0, DBL_DIG );

    return cnt_attrib->counterattrib;
}


/***************************************
 ***************************************/

void
counter_adjust_spec_form( FL_OBJECT * obj )
{
    curobj = obj;

    if ( obj->type == FL_SIMPLE_COUNTER )
        fl_hide_object( cnt_attrib->step2 );
}


/***************************************
 ***************************************/

void
counter_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_COUNTER_SPEC *sp = obj->spec;

    fl_set_counter_value( cnt_attrib->prec, sp->prec );

    set_finput_value( cnt_attrib->minval,     sp->min,   sp->prec );
    set_finput_value( cnt_attrib->maxval,     sp->max,   sp->prec );
    set_finput_value( cnt_attrib->initialval, sp->val,   sp->prec );
    set_finput_value( cnt_attrib->step1,      sp->sstep, sp->prec );
    set_finput_value( cnt_attrib->step2,      sp->lstep, sp->prec );

    reset_how_return_menu( cnt_attrib->returnsetting, curobj->how_return );
}


/***************************************
 ***************************************/

void
counter_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    if (    get_checked_float( fl_get_input( cnt_attrib->minval ), &r1 )
         && get_checked_float( fl_get_input( cnt_attrib->maxval ), &r2 ) )
        fl_set_counter_bounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( cnt_attrib->initialval ), &r1 ) )
         fl_set_counter_value( obj, r1 );

    if (    get_checked_float( fl_get_input( cnt_attrib->step1 ), &r1 )
         && get_checked_float( fl_get_input( cnt_attrib->step2 ), &r2 ) )
        fl_set_counter_step( obj, r1, r2 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
counter_emit_spec_fd_code( FILE      * fp,
                           FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_counter( obj->type, 0, 0, 0, 0, "" );
    FLI_COUNTER_SPEC *sp    = obj->spec,
                     *defsp = defobj->spec;

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    bounds: %.*f %.*f\n",
                 sp->prec, sp->min, sp->prec, sp->max );

    if ( sp->prec != defsp->prec )
        fprintf( fp, "    precision: %d\n", sp->prec );

    if ( sp->val != defsp->val )
        fprintf( fp, "    value: %.*f\n", sp->prec, sp->val );

    if ( sp->sstep != defsp->sstep )
        fprintf( fp, "    sstep: %.*f\n", sp->prec, sp->sstep );

    if ( sp->lstep != defsp->lstep )
        fprintf( fp, "    lstep: %.*f\n", sp->prec, sp->lstep );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
counter_emit_spec_c_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_counter( obj->type, 0, 0, 0, 0, "" );
    FLI_COUNTER_SPEC *sp    = obj->spec,
                     *defsp = defobj->spec;

    if ( sp->prec != defsp->prec )
        fprintf( fp, "    fl_set_counter_precision( obj, %d );\n", sp->prec );

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    fl_set_counter_bounds( obj, %.*f, %.*f );\n",
                 sp->prec, sp->min, sp->prec, sp->max );

    if ( sp->val != defsp->val )
        fprintf( fp, "    fl_set_counter_value( obj, %.*f );\n",
                 sp->prec, sp->val );

    if ( sp->sstep != defsp->sstep || sp->lstep != defsp->lstep )
        fprintf( fp, "    fl_set_counter_step( obj, %.*f, %.*f );\n",
                 sp->prec, sp->sstep, sp->prec, sp->lstep );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
cnt_precision_cb( FL_OBJECT * obj,
                  long        data  FL_UNUSED_ARG )
{
    fl_set_counter_precision( curobj, fl_get_counter_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
cnt_minmax_change( FL_OBJECT * obj   FL_UNUSED_ARG,
                   long        data  FL_UNUSED_ARG )
{
    fl_set_counter_bounds( curobj,
                           get_finput_value( cnt_attrib->minval ),
                           get_finput_value( cnt_attrib->maxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
cnt_stepchange_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                   long        data  FL_UNUSED_ARG )
{
    fl_set_counter_step( curobj,
                         get_finput_value( cnt_attrib->step1 ),
                         get_finput_value( cnt_attrib->step2 ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
cnt_initialvalue_change( FL_OBJECT * obj,
                         long        data  FL_UNUSED_ARG )
{
    FLI_COUNTER_SPEC *sp = curobj->spec;

    set_finput_value( obj, get_finput_value( obj ), sp->prec );
    fl_set_counter_value( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
cnt_returnsetting_change( FL_OBJECT * obj,
                          long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


#include "spec/counter_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
