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
 * \file sp_scrollbar.c
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
#include "sp_scrollbar.h"
#include "spec/scrollbar_spec.h"
#include "private/pscrollbar.h"


static FD_scrollbarattrib *scb_attrib;
static FL_OBJECT * curobj;


/***************************************
 ***************************************/

FL_FORM *
scrollbar_create_spec_form( void )
{
    if ( scb_attrib )
        return scb_attrib->scrollbarattrib;

    scb_attrib = create_form_scrollbarattrib( );

    setup_how_return_menu( scb_attrib->returnsetting );
    fl_set_menu_item_mode( scb_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( scb_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    return scb_attrib->scrollbarattrib;
}


/***************************************
 ***************************************/

#define is_vert( t ) (    t == FL_VERT_SCROLLBAR      \
                       || t == FL_VERT_NICE_SCROLLBAR \
                       || t == FL_VERT_THIN_SCROLLBAR )


void
scrollbar_adjust_spec_form( FL_OBJECT * obj )
{
    curobj = obj;

    if ( is_vert( obj->type ) )
    {
        fl_set_object_label( scb_attrib->minval, "Value at top" );
        fl_set_object_label( scb_attrib->maxval, "Value at bottom" );
    }
    else
    {
        fl_set_object_label( scb_attrib->minval, "Value at left" );
        fl_set_object_label( scb_attrib->maxval, "Value at right" );
    }
}


/***************************************
 ***************************************/

void
scrollbar_fill_in_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    fl_get_scrollbar_bounds( obj, &r1, &r2 );
    set_finput_value( scb_attrib->minval, r1, -1 );
    set_finput_value( scb_attrib->maxval, r2, -1 );

    set_finput_value( scb_attrib->initial_val,
                      fl_get_scrollbar_value( obj ), -1 );

    set_finput_value( scb_attrib->slsize, fl_get_scrollbar_size( obj ), 2 );

    fl_get_scrollbar_increment( obj, &r1, &r2 );
    set_finput_value( scb_attrib->ldelta, r1, -1 );
    set_finput_value( scb_attrib->rdelta, r2, -1 );

    reset_how_return_menu( scb_attrib->returnsetting, obj->how_return );
}


/***************************************
 ***************************************/

void
scrollbar_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    if (    get_checked_float( fl_get_input( scb_attrib->minval ), &r1 )
         && get_checked_float( fl_get_input( scb_attrib->maxval ), &r2 ) )
        fl_set_scrollbar_bounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( scb_attrib->initial_val ), &r1 ) )
         fl_set_scrollbar_value( obj, r1 );

    if ( get_checked_float( fl_get_input( scb_attrib->slsize ), &r1 ) )
        fl_set_scrollbar_size( obj, r1 );

    if (    get_checked_float( fl_get_input( scb_attrib->ldelta ), &r1 )
         && get_checked_float( fl_get_input( scb_attrib->ldelta ), &r2 ) )
        fl_set_scrollbar_increment( obj, r1, r2 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
scrollbar_emit_spec_fd_code( FILE      * fp,
                             FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_scrollbar( obj->type, 0, 0, 0, 0, "" );
    double r1, r2, def_r1, def_r2;

    fl_get_scrollbar_bounds( obj, &r1, &r2 );
    fl_get_scrollbar_bounds( defobj, &def_r1, &def_r2 );

    if ( r1 != def_r1 || r2 != def_r2 )
        fprintf( fp, "    bounds: %g %g\n", r1, r2 );

    r1     = fl_get_scrollbar_value( obj );
    def_r1 = fl_get_scrollbar_value( defobj );

    if ( r1 != def_r1 )
        fprintf( fp, "    value: %g\n", r1 );

    r1     = fl_get_scrollbar_size( obj );
    def_r1 = fl_get_scrollbar_size( defobj );

    if ( r1 != def_r1 )
        fprintf( fp, "    slsize: %.2f\n", r1 );

    fl_get_scrollbar_increment( obj, &r1, &r2 );
    fl_get_scrollbar_increment( defobj, &def_r1, &def_r2 );

    if ( r1 != def_r1 || r2 != def_r2 )
        fprintf( fp, "    increment: %g %g\n", r1, r2 );
}


/***************************************
 ***************************************/

void
scrollbar_emit_spec_c_code( FILE      * fp,
                            FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_scrollbar( obj->type, 0, 0, 0, 0, "" );
    double r1, r2, def_r1, def_r2;

    fl_get_scrollbar_bounds( obj, &r1, &r2 );
    fl_get_scrollbar_bounds( defobj, &def_r1, &def_r2 );

    if ( r1 != def_r1 || r2 != def_r2 )
        fprintf( fp, "    fl_set_scrollbar_bounds( obj, %g, %g );\n",
                 r1, r2 );

    r1     = fl_get_scrollbar_value( obj );
    def_r1 = fl_get_scrollbar_value( defobj );

    if ( r1 != def_r1 )
        fprintf( fp, "    fl_set_scrollbar_value( obj, %g );\n", r1 );

    r1     = fl_get_scrollbar_size( obj );
    def_r1 = fl_get_scrollbar_size( defobj );

    if ( r1 != def_r1 )
        fprintf( fp, "    fl_set_scrollbar_size( obj, %.2f );\n", r1 );

    fl_get_scrollbar_increment( obj, &r1, &r2 );
    fl_get_scrollbar_increment( defobj, &def_r1, &def_r2 );

    if ( r1 != def_r1 || r2 != def_r2 )
        fprintf( fp, "    fl_set_scrollbar_increment( obj, %g, %g );\n",
                 r1, r2 );
}


/***************************************
 ***************************************/

void
scb_minmax_change( FL_OBJECT * obj   FL_UNUSED_ARG,
                   long        data  FL_UNUSED_ARG )
{
    double min = get_finput_value( scb_attrib->minval );
    double max = get_finput_value( scb_attrib->maxval );

    fl_set_scrollbar_bounds( curobj, min, max );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
scb_delta_change( FL_OBJECT * obj   FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
    double ldelta = get_finput_value( scb_attrib->ldelta );
    double rdelta = get_finput_value( scb_attrib->rdelta );

    fl_set_scrollbar_increment( curobj, ldelta, rdelta );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
scb_slsize_change( FL_OBJECT * obj,
                   long        data  FL_UNUSED_ARG )
{
    double slsize = get_finput_value( obj );

    fl_set_scrollbar_size( curobj, slsize );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
scb_initialvalue_change( FL_OBJECT * obj,
                         long        data  FL_UNUSED_ARG )
{
    double val = get_finput_value( obj );

    fl_set_scrollbar_value( curobj, val );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
scb_returnsetting_change( FL_OBJECT * obj,
                          long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


#include "spec/scrollbar_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
