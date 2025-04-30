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
 * \file sp_xyplot.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting xyplot class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_xyplot.h"
#include "private/pxyplot.h"
#include "spec/xyplot_spec.h"

static FD_xyplotattrib *xyplot_attrib;
static FL_OBJECT *curobj;


/***************************************
 ***************************************/

FL_FORM *
xyplot_create_spec_form( void )
{
    if ( xyplot_attrib )
        return xyplot_attrib->xyplotattrib;

    xyplot_attrib = create_form_xyplotattrib( );

    fl_addto_choice( xyplot_attrib->xscale, get_scale_string( ) );
    fl_addto_choice( xyplot_attrib->yscale, get_scale_string( ) );
    fl_addto_choice( xyplot_attrib->xgrid, get_grid_string( ) );
    fl_addto_choice( xyplot_attrib->ygrid, get_grid_string( ) );
    fl_addto_choice( xyplot_attrib->gridstyle, get_linestyle_string( ) );

    setup_how_return_menu( xyplot_attrib->how_return );
    fl_set_menu_item_mode( xyplot_attrib->how_return, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( xyplot_attrib->how_return, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    return xyplot_attrib->xyplotattrib;
}


/***************************************
 ***************************************/

void
xyplot_adjust_spec_form( FL_OBJECT * obj )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;

    curobj = obj;

    if ( obj->type != FL_ACTIVE_XYPLOT )
    {
        fl_hide_object( xyplot_attrib->how_return );
        fl_hide_object( xyplot_attrib->mark_active );
    }
    else
    {
        fl_show_object( xyplot_attrib->how_return );
        fl_show_object( xyplot_attrib->mark_active );
    }

    if ( sp->xscale != FL_LOG )
        fl_hide_object( xyplot_attrib->xbase );
    else
        fl_show_object( xyplot_attrib->xbase );

    if ( sp->yscale != FL_LOG )
        fl_hide_object( xyplot_attrib->ybase );
    else
        fl_show_object( xyplot_attrib->ybase );

    if ( sp->xgrid || sp->ygrid )
        fl_show_object( xyplot_attrib->gridstyle );
    else
        fl_hide_object( xyplot_attrib->gridstyle );
}


/***************************************
 ***************************************/

void
xyplot_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;

    fl_set_counter_value( xyplot_attrib->xmajor, sp->xmajor );
    fl_set_counter_value( xyplot_attrib->xminor, sp->xminor );
    fl_set_counter_value( xyplot_attrib->ymajor, sp->ymajor );
    fl_set_counter_value( xyplot_attrib->yminor, sp->yminor );

    fl_set_choice( xyplot_attrib->xgrid, sp->xgrid + 1 );
    fl_set_choice( xyplot_attrib->ygrid, sp->ygrid + 1 );
    fl_set_choice( xyplot_attrib->xscale, sp->xscale + 1 );
    fl_set_choice( xyplot_attrib->yscale, sp->yscale + 1 );

    fl_set_choice( xyplot_attrib->gridstyle, sp->grid_linestyle + 1 );

    set_finput_value( xyplot_attrib->xbase, sp->xbase, -1 );
    set_finput_value( xyplot_attrib->ybase, sp->ybase, -1 );

    reset_how_return_menu( xyplot_attrib->how_return, obj->how_return );

    fl_set_button( xyplot_attrib->mark_active, sp->mark_active );
}


/***************************************
 ***************************************/

void
xyplot_emit_spec_fd_code( FILE      * fp,
                          FL_OBJECT * ob )
{
    FL_OBJECT *defobj;
    SuperSPEC *defsp,
              *sp;

    if ( ob->objclass != FL_XYPLOT )
        return;

    /* create a default object */

    defobj = fl_create_xyplot( ob->type, 0, 0, 0, 0, "" );

    defsp = get_superspec( defobj );
    sp = get_superspec( ob );

    if ( sp->xmajor != defsp->xmajor || sp->xminor != defsp->xminor )
        fprintf( fp, "    xtics: %d %d\n", sp->xmajor, sp->xminor );

    if ( sp->ymajor != defsp->ymajor || sp->yminor != defsp->yminor )
        fprintf( fp, "    ytics: %d %d\n", sp->ymajor, sp->yminor );

    if ( sp->xgrid != defsp->xgrid || sp->ygrid != defsp->ygrid )
        fprintf( fp, "    grid: %s %s\n",
                 get_grid_name( sp->xgrid ), get_grid_name( sp->ygrid ) );

    if ( sp->grid_linestyle != defsp->grid_linestyle )
        fprintf( fp, "    gridstyle: %s\n",
                 get_linestyle_name( sp->grid_linestyle ) );

    if ( sp->xscale != defsp->xscale || sp->xbase != defsp->xbase )
        fprintf( fp, "    xscale: %s %g\n",
                 get_scale_name( sp->xscale ), sp->xbase );

    if ( sp->yscale != defsp->yscale || sp->ybase != defsp->ybase )
        fprintf( fp, "    yscale: %s %g\n",
                 get_scale_name( sp->yscale ), sp->ybase );

    if ( ob->type == FL_ACTIVE_XYPLOT )
    {
        if ( sp->mark_active != defsp->mark_active )
            fprintf( fp, "    markactive: %d\n", sp->mark_active );
    }

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
xyplot_emit_spec_c_code( FILE      * fp,
                         FL_OBJECT * ob )
{
    FL_OBJECT *defobj;
    SuperSPEC *sp,
              *defsp;

    if ( ob->objclass != FL_XYPLOT )
    {
        M_err( "EmitXYPlotCode", "not xyplot class!" );
        return;
    }

    /* create a default object */

    defobj = fl_create_xyplot( ob->type, 0, 0, 0, 0, "" );

    defsp = get_superspec( defobj );
    sp = get_superspec( ob );

    if ( sp->xmajor != defsp->xmajor || sp->xminor != defsp->xminor )
        fprintf( fp, "    fl_set_xyplot_xtics( obj, %d, %d );\n",
                 sp->xmajor, sp->xminor );

    if ( sp->ymajor != defsp->ymajor || sp->yminor != defsp->yminor )
        fprintf( fp, "    fl_set_xyplot_ytics( obj, %d, %d );\n",
                 sp->ymajor, sp->yminor );

    if (    sp->xscale != defsp->xscale
         || ( sp->xscale == FL_LOG && sp->xbase != defsp->xbase ) )
        fprintf( fp, "    fl_set_xyplot_xscale( obj, %s, %g );\n",
                 get_scale_name( sp->xscale ), sp->xbase );

    if (    sp->yscale != defsp->yscale
         || ( sp->yscale == FL_LOG && sp->ybase != defsp->ybase ) )
        fprintf( fp, "    fl_set_xyplot_yscale( obj, %s, %g );\n",
                 get_scale_name( sp->yscale ), sp->ybase );

    if ( sp->xgrid != defsp->xgrid )
        fprintf( fp, "    fl_set_xyplot_xgrid( obj, %s );\n",
                 get_grid_name( sp->xgrid ) );

    if ( sp->ygrid != defsp->ygrid )
        fprintf( fp, "    fl_set_xyplot_ygrid( obj, %s );\n",
                 get_grid_name( sp->ygrid ) );

    if ( sp->grid_linestyle != defsp->grid_linestyle )
        fprintf( fp, "    fl_set_xyplot_grid_linestyle( obj, %s );\n",
                 get_linestyle_name( sp->grid_linestyle ) );

    if ( ob->type == FL_ACTIVE_XYPLOT )
    {
        if ( sp->mark_active != defsp->mark_active )
            fprintf( fp, "    fl_set_xyplot_mark_active( obj, %d );\n",
                     sp->mark_active );
    }

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
grid_change_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                long        data  FL_UNUSED_ARG )
{
    int xg = fl_get_choice( xyplot_attrib->xgrid ) - 1;
    int yg = fl_get_choice( xyplot_attrib->ygrid ) - 1;

    if ( xg || yg )
        fl_show_object( xyplot_attrib->gridstyle );
    else
        fl_hide_object( xyplot_attrib->gridstyle );

    fl_set_xyplot_xgrid( curobj, xg );
    fl_set_xyplot_ygrid( curobj, yg );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
markactive_change_cb( FL_OBJECT * obj,
                      long        data  FL_UNUSED_ARG )
{
    fl_set_xyplot_mark_active( curobj, fl_get_button( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
gridstyle_change_cb( FL_OBJECT * obj,
                     long        data  FL_UNUSED_ARG )
{
    fl_set_xyplot_grid_linestyle( curobj, fl_get_choice( obj ) - 1 );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
xscale_change_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
    int s = fl_get_choice( xyplot_attrib->xscale ) - 1;

    if ( s == FL_LOG )
        fl_show_object( xyplot_attrib->xbase );
    else
        fl_hide_object( xyplot_attrib->xbase );

    fl_set_xyplot_xscale( curobj, s, get_finput_value( xyplot_attrib->xbase ) );
    redraw_the_form( 0 );

}


/***************************************
 ***************************************/

void
yscale_change_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
    int s = fl_get_choice( xyplot_attrib->yscale ) - 1;

    if ( s == FL_LOG )
        fl_show_object( xyplot_attrib->ybase );
    else
        fl_hide_object( xyplot_attrib->ybase );

    fl_set_xyplot_yscale( curobj, s, get_finput_value( xyplot_attrib->ybase ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
ymajorminor_change_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                       long        data  FL_UNUSED_ARG )
{
    /* fill-in code for callback */

    fl_set_xyplot_ytics( curobj,
                         fl_get_counter_value( xyplot_attrib->ymajor ),
                         fl_get_counter_value( xyplot_attrib->yminor ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
xmajorminor_change_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                       long        data  FL_UNUSED_ARG )
{
    fl_set_xyplot_xtics( curobj,
                         fl_get_counter_value( xyplot_attrib->xmajor ),
                         fl_get_counter_value( xyplot_attrib->xminor ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
xyplot_returnsetting_change( FL_OBJECT * obj,
                             long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


#include "spec/xyplot_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
