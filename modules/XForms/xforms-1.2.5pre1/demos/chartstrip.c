/*
 *  This file is part of XForms.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with XForms; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 59 Temple Place - Suite 330, Boston,
 *  MA 02111-1307, USA.
 */


/*
 * A demo of a moving chart
 *
 *  This file is part of xforms package
 *  M. Overmars and T.C. Zhao   (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include "include/forms.h"


static long func = 1;
static double x = 0.0;
static double step = 0.15;

static FL_FORM * form;

static FL_OBJECT * chartobj,
                 * sinobj,
                 * exitbut,
                 * stepobj,
                 * timerobj;

static void create_form_form(void);


/***************************************
 ***************************************/

static void
set_function( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        arg )
{
    func = arg;
    fl_clear_chart( chartobj );
    x = 0.0;
}


/***************************************
 ***************************************/

static void
set_step( FL_OBJECT * obj  FL_UNUSED_ARG,
          long        arg  FL_UNUSED_ARG )
{
    step = fl_get_slider_value( stepobj );
}


/***************************************
 ***************************************/

static double
next_step( void )
{
    double res = 0.0;

    switch ( func)
    {
        case 1:
            res = sin( x );
            break;

        case 2:
            res = sin( 2 * x ) * cos( x );
            break;

        case 3:
            res = sin( 2 * x ) + cos( x );
            break;

        case 4:
            res = sin( 3 * x ) + cos( x );
            break;

        case 5:
            res = sin( x ) * sin( x ) + cos( x );
            break;

        case 6:
            res = sin( x ) * sin( x ) * sin( x );
            break;
    }

    x += step;

    return res;
}


/***************************************
 ***************************************/

static void
timer_cb( FL_OBJECT * obj,
          long        data  FL_UNUSED_ARG )
{
    fl_insert_chart_value( chartobj, 1, next_step( ), "", 1 );
    fl_set_timer( obj, 0.05 );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_flip_yorigin( );
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    create_form_form( );
    fl_set_chart_bounds( chartobj, -1.5, 1.5 );
    fl_set_chart_maxnumb( chartobj, 80 );
    fl_set_chart_autosize( chartobj, 0 );
    fl_set_button( sinobj, 1 );
    fl_set_slider_value( stepobj, 0.5 );
    fl_set_slider_bounds( stepobj, 0.0, 1.0 );

    fl_show_form( form,FL_PLACE_CENTER | FL_FREE_SIZE, FL_TRANSIENT,
                  "StripChart" );

    fl_set_timer( timerobj, 0.05 );

    while ( fl_do_forms( ) != exitbut )
        /* empty */ ;

    fl_finish( );
    return 0;
}


/***************************************
 ***************************************/

static void
create_form_form( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 490, 320 );

    fl_add_box( FL_BORDER_BOX, 0, 0, 490, 320, "" );

    chartobj = obj = fl_add_chart( FL_LINE_CHART, 20, 160, 390, 140, "" );
    fl_set_object_color( obj, FL_BLACK, FL_INACTIVE );
    fl_set_object_dblbuffer( obj, 1 );

    fl_bgn_group( );

    sinobj = obj = fl_add_lightbutton( FL_RADIO_BUTTON, 30, 120, 170, 30,
                                       "sin(x)" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_function, 1 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 30, 90, 170, 30,
                              "sin(2x)*cos(x)" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_function, 2 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 30, 60, 170, 30,
                              "sin(2x)+cos(x)" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_function, 3 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 240, 120, 160, 30,
                              "sin(3x)+cos(x)" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_function, 4 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 240, 90, 160, 30,
                              "sin(x)^2 + cos(x)" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_function, 5 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 240, 60, 160, 30,
                              "sin(x)^3" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_function, 6 );

    fl_end_group( );

    exitbut = obj = fl_add_button( FL_NORMAL_BUTTON, 150, 20, 140, 30, "Exit" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );

    stepobj = obj = fl_add_valslider( FL_VERT_SLIDER, 430, 20, 40, 280, "" );
    fl_set_object_return( obj, FL_RETURN_END_CHANGED );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_callback( obj, set_step, 0 );

    timerobj = obj = fl_add_timer( FL_HIDDEN_TIMER, 0, 0, 0, 0, "" );
    fl_set_object_callback( obj, timer_cb, 0 );

    fl_end_form( );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
