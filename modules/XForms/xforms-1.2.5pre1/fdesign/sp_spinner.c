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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <float.h>

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_spinner.h"
#include "private/pspinner.h"
#include "spec/spinner_spec.h"

static FD_spinnerattrib * spn_attrib;
FL_OBJECT *curobj;


/***************************************
 ***************************************/

void
spinner_change_type( FL_OBJECT * obj,
                     int         new_type )
{
    FLI_SPINNER_SPEC *sp = obj->spec;

    if ( obj->type == FL_INT_SPINNER )
    {
        sp->f_min  = sp->i_min;
        sp->f_max  = sp->i_max;
        sp->f_val  = sp->i_val;
        sp->f_incr = sp->i_incr;
    }
    else
    {
        if ( sp->f_min < INT_MIN )
            sp->i_min = INT_MIN;
        else if ( sp->f_min > INT_MAX )
            sp->i_min = INT_MAX;
        else
            sp->i_min = sp->f_min;


        if ( sp->f_max > INT_MAX )
            sp->i_max = INT_MAX;
        else if ( sp->f_max > INT_MAX )
            sp->i_max = INT_MAX;
        else
            sp->i_max = sp->f_max;

        if ( sp->f_val < INT_MIN )
            sp->i_val = INT_MIN;
        else if ( sp->f_val > INT_MAX )
            sp->i_val = INT_MAX;
        else
            sp->i_val = sp->f_val;
\
        if ( ( sp->i_incr = sp->f_incr ) == 0 )
            sp->i_incr = 1;
    }

    obj->type = new_type;
}


/***************************************
 ***************************************/

FL_FORM *
spinner_create_spec_form( void )
{
    if ( spn_attrib )
        return spn_attrib->spinnerattrib;

    spn_attrib = create_form_spinnerattrib( );

    setup_how_return_menu( spn_attrib->returnsetting );
    fl_set_menu_item_mode( spn_attrib->returnsetting, 5,
                           FL_PUP_BOX | FL_PUP_GRAY );
    fl_set_menu_item_mode( spn_attrib->returnsetting, 6,
                           FL_PUP_BOX | FL_PUP_GRAY );

    return spn_attrib->spinnerattrib;
}


/***************************************
 ***************************************/

void
spinner_adjust_spec_form( FL_OBJECT * obj )
{
    curobj = obj;

    if ( obj->type == FL_INT_SPINNER )
        fl_hide_object( spn_attrib->prec );
    else
    {
        fl_set_counter_step( spn_attrib->prec, 1, 2 );
        fl_set_counter_bounds( spn_attrib->prec, 0, DBL_DIG );
        fl_set_counter_precision( spn_attrib->prec, 0 );
        fl_show_object( spn_attrib->prec );
    }

    fl_set_object_return( spn_attrib->minval, FL_RETURN_END );
    fl_set_object_return( spn_attrib->maxval, FL_RETURN_END );
    fl_set_object_return( spn_attrib->initialval, FL_RETURN_END );
    fl_set_object_return( spn_attrib->step, FL_RETURN_END );
}


/***************************************
 ***************************************/

void
spinner_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_SPINNER_SPEC *sp = obj->spec;

    fl_set_counter_value( spn_attrib->prec, sp->prec );

    if ( obj->type == FL_INT_SPINNER )
    {
        set_finput_value( spn_attrib->minval,     sp->i_min,  0 );
        set_finput_value( spn_attrib->maxval,     sp->i_max,  0 );
        set_finput_value( spn_attrib->initialval, sp->i_val,  0 );
        set_finput_value( spn_attrib->step,       sp->i_incr, 0 );
    }
    else
    {
        set_finput_value( spn_attrib->minval,     sp->f_min,  sp->prec );
        set_finput_value( spn_attrib->maxval,     sp->f_max,  sp->prec );
        set_finput_value( spn_attrib->initialval, sp->f_val,  sp->prec );
        set_finput_value( spn_attrib->step,       sp->f_incr, sp->prec );
    }

    reset_how_return_menu( spn_attrib->returnsetting, obj->how_return );
}


/***************************************
 ***************************************/

void
spinner_reread_spec_form( FL_OBJECT * obj )
{
    double r1, r2;

    if (    get_checked_float( fl_get_input( spn_attrib->minval ), &r1 )
         && get_checked_float( fl_get_input( spn_attrib->maxval ), &r2 ) )
        fl_set_spinner_bounds( obj, r1, r2 );

    if ( get_checked_float( fl_get_input( spn_attrib->initialval ), &r1 ) )
         fl_set_spinner_value( obj, r1 );

    if ( get_checked_float( fl_get_input( spn_attrib->step ), &r1 ) )
        fl_set_spinner_step( obj, r1 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
spinner_emit_spec_fd_code( FILE      * fp,
                           FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_spinner( obj->type, 0, 0, 0, 0, "" );
    FLI_SPINNER_SPEC *sp    = obj->spec,
                     *defsp = defobj->spec;

    if ( obj->type == FL_FLOAT_SPINNER && sp->prec != defsp->prec )
        fprintf( fp, "    precision: %d\n", sp->prec );

    if ( obj->type == FL_INT_SPINNER )
    {
        if ( sp->i_min != defsp->i_min || sp->i_max != defsp->i_max )
            fprintf( fp, "    bounds: %d %d\n", sp->i_min, sp->i_max );

        if ( sp->i_val != defsp->i_val )
            fprintf( fp, "    value: %d\n", sp->i_val );

        if ( sp->i_incr != defsp->i_incr )
            fprintf( fp, "    step: %d\n", sp->i_incr );
    }
    else
    {
        if ( sp->f_min != defsp->f_min || sp->f_max != defsp->f_max )
            fprintf( fp, "    bounds: %.*f %.*f\n",
                     sp->prec, sp->f_min, sp->prec, sp->f_max );

        if ( sp->f_val != defsp->f_val )
            fprintf( fp, "    value: %.*f\n", sp->prec, sp->f_val );

        if ( sp->f_incr != defsp->f_incr )
            fprintf( fp, "    step: %.*f\n", sp->prec, sp->f_incr );
    }

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
spinner_emit_spec_c_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_spinner( obj->type, 0, 0, 0, 0, "" );
    FLI_SPINNER_SPEC *sp    = obj->spec,
                     *defsp = defobj->spec;

    if ( obj->type == FL_FLOAT_SPINNER && sp->prec != defsp->prec )
        fprintf( fp, "    fl_set_spinner_precision( obj, %d );\n", sp->prec );

    if ( obj->type == FL_INT_SPINNER )
    {
        if ( sp->i_min != defsp->i_min || sp->i_max != defsp->i_max )
            fprintf( fp, "    fl_set_spinner_bounds( obj, %d, %d );\n",
                     sp->i_min, sp->i_max );

    if ( sp->i_val != defsp->i_val )
        fprintf( fp, "    fl_set_spinner_value( obj, %d );\n", sp->i_val );

    if ( sp->i_incr != defsp->i_incr )
        fprintf( fp, "    fl_set_spinner_step( obj, %d );\n", sp->i_incr );
    }
    else
    {
        if ( sp->f_min != defsp->f_min || sp->f_max != defsp->f_max )
            fprintf( fp, "    fl_set_spinner_bounds( obj, %.*f, %.*f );\n",
                     sp->prec, sp->f_min, sp->prec, sp->f_max );

        if ( sp->f_val != defsp->f_val )
            fprintf( fp, "    fl_set_spinner_value( obj, %.*f );\n",
                     sp->prec, sp->f_val );

        if ( sp->f_incr != defsp->f_incr )
            fprintf( fp, "    fl_set_spinner_step( obj, %.*f );\n",
                     sp->prec, sp->f_incr );
    }

    if ( obj->lsize != defobj->lsize )
        fprintf( fp, "    fl_set_object_lsize( fl_get_spinner_input( obj ), "
                 "%s );\n", lsize_name( obj->lsize ) );

    if ( obj->lstyle != defobj->lstyle )
        fprintf( fp, "    fl_set_object_lstyle( fl_get_spinner_input( obj ), "
                 "%s );\n", style_name( obj->lstyle ) );

    if ( obj->col1 != defobj->col1 || obj->col2 != defobj->col2 )
        fprintf( fp, "    fl_set_object_color( fl_get_spinner_input( obj ), "
                 "%s, %s );\n", fli_query_colorname( obj->col1 ),
                 fli_query_colorname( obj->col2 ) );

    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
spn_precision_cb( FL_OBJECT * obj,
                  long        data  FL_UNUSED_ARG )
{
    fl_set_spinner_precision( curobj, fl_get_counter_value( obj ) );

    spn_minmax_change( NULL, 0 );
    spn_stepchange_cb( NULL, 0 );
    spn_initialvalue_change( NULL, 0 );
}


/***************************************
 ***************************************/

void
spn_minmax_change( FL_OBJECT * obj   FL_UNUSED_ARG,
                   long        data  FL_UNUSED_ARG )
{
    FLI_SPINNER_SPEC *sp = curobj->spec;

    set_finput_value( spn_attrib->minval,
                      get_finput_value( spn_attrib->minval ),
                      curobj->type == FL_INT_SPINNER ? 0 : sp->prec );
    set_finput_value( spn_attrib->maxval,
                      get_finput_value( spn_attrib->maxval ),
                      curobj->type == FL_INT_SPINNER ? 0 : sp->prec );

    fl_set_spinner_bounds( curobj, get_finput_value( spn_attrib->minval ),
                           get_finput_value( spn_attrib->maxval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
spn_stepchange_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                   long        data  FL_UNUSED_ARG )
{
    FLI_SPINNER_SPEC *sp = curobj->spec;

    set_finput_value( spn_attrib->step, get_finput_value( spn_attrib->step ),
                      curobj->type == FL_INT_SPINNER ? 0 : sp->prec );
    fl_set_spinner_step( curobj, get_finput_value( spn_attrib->step ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
spn_initialvalue_change( FL_OBJECT * obj   FL_UNUSED_ARG,
                         long        data  FL_UNUSED_ARG )
{
    FLI_SPINNER_SPEC *sp = curobj->spec;

    set_finput_value( spn_attrib->initialval,
                      get_finput_value( spn_attrib->initialval ),
                      curobj->type == FL_INT_SPINNER ? 0 : sp->prec );
    fl_set_spinner_value( curobj, get_finput_value( spn_attrib->initialval ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
spn_returnsetting_change( FL_OBJECT * obj,
                          long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


#include "spec/spinner_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
