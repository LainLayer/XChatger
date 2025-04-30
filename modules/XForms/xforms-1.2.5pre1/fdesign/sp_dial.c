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
 * \file sp_dial.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Settting dial class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_dial.h"
#include "private/pdial.h"
#include "spec/dial_spec.h"

static FD_dialattrib * dial_attrib;
static FL_OBJECT * curobj;

#define VN( a )  { a, #a }

static FLI_VN_PAIR dial_dir[ ] =
{
    VN( FL_DIAL_CW ),
    VN( FL_DIAL_CCW ),
    { -1, NULL }
};


/***************************************
 ***************************************/

int
get_direction_value( const char * s )
{
    return fli_get_vn_value( dial_dir, s );
}


/***************************************
 ***************************************/

FL_FORM *
dial_create_spec_form( void )
{
    if ( dial_attrib )
        return dial_attrib->dialattrib;

    dial_attrib = create_form_dialattrib( );
    fl_addto_choice( dial_attrib->dir, dial_dir[ 0 ].name );
    fl_addto_choice( dial_attrib->dir, dial_dir[ 1 ].name );

    setup_how_return_menu( dial_attrib->returnsetting );
    fl_set_menu_item_mode( dial_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( dial_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );
    return dial_attrib->dialattrib;
}


/***************************************
 ***************************************/

void
dial_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_DIAL_SPEC *sp = obj->spec;
    curobj = obj;

    set_finput_value( dial_attrib->minval,     sp->min,    -1 );
    set_finput_value( dial_attrib->maxval,     sp->max,    -1 );
    set_finput_value( dial_attrib->initialval, sp->val,    -1 );
    set_finput_value( dial_attrib->thetai,     sp->thetai, -1 );
    set_finput_value( dial_attrib->thetaf,     sp->thetaf, -1 );
    set_finput_value( dial_attrib->step,       sp->step,   -1 );

    fl_set_choice_text( dial_attrib->dir,
                        fli_get_vn_name( dial_dir, sp->direction ) );

    reset_how_return_menu( dial_attrib->returnsetting, curobj->how_return );
}


/***************************************
 ***************************************/

void
dial_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;
    int dir = fl_get_choice( dial_attrib->dir ) - 1;

    if (    get_checked_float( fl_get_input( dial_attrib->minval ), &r1 )
         && get_checked_float( fl_get_input( dial_attrib->maxval ), &r2 ) )
         fl_set_dial_bounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( dial_attrib->initialval ), &r1 ) )
        fl_set_dial_value( obj, r1 );

    if (    get_checked_float( fl_get_input( dial_attrib->thetai ), &r1 )
         && get_checked_float( fl_get_input( dial_attrib->thetaf ), &r2 ) )
        fl_set_dial_angles( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( dial_attrib->step ), &r1 ) )
        fl_set_dial_step( obj, r1 );

    if ( dir >= 0 )
        fl_set_dial_direction( obj, dial_dir[ dir ].val );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
dial_emit_spec_fd_code( FILE      * fp,
                        FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_dial( obj->type, 0, 0, 0, 0, "" );
    FLI_DIAL_SPEC *sp    = obj->spec,
                  *defsp = defobj->spec;

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    bounds: %g %g\n", sp->min, sp->max );

    if ( sp->thetai != defsp->thetai || sp->thetaf != defsp->thetaf )
        fprintf( fp, "    angles: %g %g\n", sp->thetai, sp->thetaf );

    if ( sp->val != defsp->val )
        fprintf( fp, "    value: %g\n", sp->val );

    if ( sp->step != defsp->step )
        fprintf( fp, "    step: %g\n", sp->step );

    if ( sp->direction != defsp->direction )
        fprintf( fp, "    dir: %s\n",
                 fli_get_vn_name( dial_dir, sp->direction ) );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
dial_emit_spec_c_code( FILE      * fp,
                       FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_dial( obj->type, 0, 0, 0, 0, "" );
    FLI_DIAL_SPEC *sp    = obj->spec,
                  *defsp = defobj->spec;

    if ( sp->min != defsp->min || sp->max != defsp->max )
        fprintf( fp, "    fl_set_dial_bounds( obj, %g, %g );\n",
                 sp->min, sp->max );

    if ( sp->thetai != defsp->thetai || sp->thetaf != defsp->thetaf )
        fprintf( fp, "    fl_set_dial_angles( obj, %g, %g );\n",
                 sp->thetai, sp->thetaf );

    if ( sp->val != defsp->val )
        fprintf( fp, "    fl_set_dial_value( obj, %g );\n", sp->val );

    if ( sp->step != defsp->step )
        fprintf( fp, "    fl_set_dial_step( obj, %g );\n", sp->step );

    if ( sp->direction != defsp->direction )
        fprintf( fp, "    fl_set_dial_direction( obj, %s );\n",
                 fli_get_vn_name( dial_dir, sp->direction ) );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
dial_minmax_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_dial_bounds( curobj, get_finput_value( dial_attrib->minval ),
                        get_finput_value( dial_attrib->maxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
dial_thetachange_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
                     long        data  FL_UNUSED_ARG )
{
    fl_set_dial_angles( curobj, get_finput_value( dial_attrib->thetai ),
                        get_finput_value( dial_attrib->thetaf ));
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
dial_stepchange_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_dial_step( curobj, get_finput_value( dial_attrib->step ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
dial_initialvalue_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                          long        data  FL_UNUSED_ARG )
{
    fl_set_dial_value( curobj, get_finput_value( dial_attrib->initialval ) );
    redraw_the_form( 0 );
}


/***************************************
 * direction change
 ***************************************/

void
dir_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
        long        data  FL_UNUSED_ARG )
{
    int dir = fl_get_choice( dial_attrib->dir ) - 1;

    if ( dir >= 0 )
    {
        fl_set_dial_direction( dial_attrib->vdata, dial_dir[ dir ].val );
        redraw_the_form( 0 );
    }
}


/***************************************
 ***************************************/

void
dial_returnsetting_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                           long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( dial_attrib->returnsetting, curobj );
}


#include "spec/dial_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
