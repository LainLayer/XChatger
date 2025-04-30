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
 * \file sp_positioner.c
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

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_positioner.h"
#include "private/ppositioner.h"
#include "spec/positioner_spec.h"

static FD_posattrib * pos_attrib;
static FL_OBJECT * curobj;


/***************************************
 ***************************************/

FL_FORM *
positioner_create_spec_form( void )
{
    if ( pos_attrib )
        return pos_attrib->posattrib;

    pos_attrib = create_form_posattrib( );

    setup_how_return_menu( pos_attrib->returnsetting );
    fl_set_menu_item_mode( pos_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( pos_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    return pos_attrib->posattrib;
}


/***************************************
 ***************************************/

void
positioner_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_POSITIONER_SPEC *sp = obj->spec;


    curobj = obj;

    set_finput_value( pos_attrib->xminval, sp->xmin, -1 );
    set_finput_value( pos_attrib->xmaxval, sp->xmax, -1 );
    set_finput_value( pos_attrib->yminval, sp->ymin, -1 );
    set_finput_value( pos_attrib->ymaxval, sp->ymax, -1 );

    set_finput_value( pos_attrib->initialxval, sp->xval, -1 );
    set_finput_value( pos_attrib->initialyval, sp->yval, -1 );

    set_finput_value( pos_attrib->xstep, sp->xstep, -1 );
    set_finput_value( pos_attrib->ystep, sp->ystep, -1 );

    reset_how_return_menu( pos_attrib->returnsetting, obj->how_return );
}


/***************************************
 ***************************************/

void
positioner_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    if (    get_checked_float( fl_get_input( pos_attrib->xminval ), &r1 )
         && get_checked_float( fl_get_input( pos_attrib->xmaxval ), &r2 ) )
        fl_set_positioner_xbounds( obj, r1, r2 );

    if (    get_checked_float( fl_get_input( pos_attrib->yminval ), &r1 )
         && get_checked_float( fl_get_input( pos_attrib->ymaxval ), &r2 ) )
        fl_set_positioner_ybounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( pos_attrib->initialxval ), &r1 ) )
         fl_set_positioner_xvalue( obj, r1 );
    if ( get_checked_float( fl_get_input( pos_attrib->initialyval ), &r1 ) )
         fl_set_positioner_yvalue( obj, r1 );

    if ( get_checked_float( fl_get_input( pos_attrib->xstep ), &r1 ) )
         fl_set_positioner_xstep( obj, r1 );
    if ( get_checked_float( fl_get_input( pos_attrib->ystep ), &r1 ) )
         fl_set_positioner_ystep( obj, r1 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
positioner_emit_spec_fd_code( FILE      * fp,
                              FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_positioner( obj->type, 0, 0, 0, 0, "" );
    FLI_POSITIONER_SPEC *sp    = obj->spec,
                        *defsp = defobj->spec;

    if ( sp->xmin != defsp->xmin || sp->xmax != defsp->xmax )
        fprintf( fp, "    xbounds: %g %g\n", sp->xmin, sp->xmax );

    if ( sp->ymin != defsp->ymin || sp->ymax != defsp->ymax )
        fprintf( fp, "    ybounds: %g %g\n", sp->ymin, sp->ymax );

    if ( sp->xval != defsp->xval )
        fprintf( fp, "    xvalue: %g\n", sp->xval );

    if ( sp->yval != defsp->yval )
        fprintf( fp, "    yvalue: %g\n", sp->yval );

    if ( sp->xstep != defsp->xstep )
        fprintf( fp, "    xstep: %g\n", sp->xstep );

    if ( sp->ystep != defsp->ystep )
        fprintf( fp, "    ystep: %g\n", sp->ystep );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
positioner_emit_spec_c_code( FILE      * fp,
                             FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_positioner( obj->type, 0, 0, 0, 0, "" );
    FLI_POSITIONER_SPEC *sp    = obj->spec,
                        *defsp = defobj->spec;

    if ( sp->xmin != defsp->xmin || sp->xmax != defsp->xmax )
        fprintf( fp, "    fl_set_positioner_xbounds( obj, %g, %g );\n",
                 sp->xmin, sp->xmax );

    if ( sp->ymin != defsp->ymin || sp->ymax != defsp->ymax )
        fprintf( fp, "    fl_set_positioner_ybounds( obj, %g, %g );\n",
                 sp->ymin, sp->ymax );

    if ( sp->xval != defsp->xval )
        fprintf( fp, "    fl_set_positioner_xvalue( obj, %g );\n", sp->xval );

    if ( sp->yval != defsp->yval )
        fprintf( fp, "    fl_set_positioner_yvalue( obj, %g );\n", sp->yval );

    if ( sp->xstep != defsp->xstep )
        fprintf( fp, "    fl_set_positioner_xstep( obj, %g );\n", sp->xstep );

    if ( sp->ystep != defsp->ystep )
        fprintf( fp, "    fl_set_positioner_ystep( obj, %g );\n", sp->ystep );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
pos_xminmax_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_positioner_xbounds( curobj,
                               get_finput_value( pos_attrib->xminval ),
                               get_finput_value( pos_attrib->xmaxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
pos_yminmax_change( FL_OBJECT * ob    FL_UNUSED_ARG,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_positioner_ybounds( curobj,
                               get_finput_value( pos_attrib->yminval ),
                               get_finput_value( pos_attrib->ymaxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
pos_xstepchange_cb( FL_OBJECT * obj,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_positioner_xstep( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
pos_ystepchange_cb( FL_OBJECT * obj,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_positioner_ystep( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
pos_initialxvalue_change( FL_OBJECT * obj,
                          long        data  FL_UNUSED_ARG )
{
    fl_set_positioner_xvalue( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
pos_initialyvalue_change( FL_OBJECT * obj,
                          long        data  FL_UNUSED_ARG)
{
    fl_set_positioner_yvalue( curobj, get_finput_value( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
pos_returnsetting_change( FL_OBJECT * obj,
                          long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}

#include "spec/positioner_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
