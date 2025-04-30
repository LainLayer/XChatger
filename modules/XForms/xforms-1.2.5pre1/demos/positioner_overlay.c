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


/* This demo shows the use of a overlay positioner with a position validator */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <math.h>
#include "include/forms.h"
#include "colorwheel.xpm"


static FL_OBJECT * xval,
                 * yval;


/***************************************
 * Validator function for positioner, makes
 sure that it's restricted to a circle
 ***************************************/

static int
validator( FL_OBJECT * obj  FL_UNUSED_ARG,
           double      x,
           double      y,
           double    * x_repl,
           double    * y_repl )
{
    double angle;

    /* If the new position is within the circle (with radius 1) it's fine,
       tell the positioner to use it as is */

    if ( x * x + y * y <= 1 )
        return FL_POSITIONER_VALID;

    /* Otherwise replace the new position by one at the circle's border
       in the direction from the center to the new coordinates */

    angle = atan2( y, x );
    *x_repl = cos( angle );
    *y_repl = sin( angle );

    /* Tell the positioner to use the values in x_repl and y_repl */

    return FL_POSITIONER_REPLACED;
}


/***************************************
 * Callback routine for new position
 ***************************************/

static void
positioner_cb( FL_OBJECT * obj,
               long        data   FL_UNUSED_ARG )
{
    double x = fl_get_positioner_xvalue( obj ),
           y = fl_get_positioner_yvalue( obj );
    double angle = 45 * atan2( y, x ) / atan( 1 );

    if ( angle < 0 )
        angle += 360;

    fl_set_object_label_f( xval, "%f", angle );
    fl_set_object_label_f( yval, "%f", sqrt( x * x + y * y ) );
}


/***************************************
 * Creates the form and then does the interaction
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM   * form;
    FL_OBJECT * pm;
    FL_OBJECT * pos;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 400, 280 );

    pm = fl_add_pixmap( FL_NORMAL_PIXMAP, 40, 40, 203, 203, "" );
    fl_set_pixmap_data( pm, colorwheel );

    pos = fl_add_positioner( FL_OVERLAY_POSITIONER, 40, 40, 203, 203, "" );
    fl_set_positioner_xbounds( pos, -1, 1 );
    fl_set_positioner_ybounds( pos, -1, 1 );
    fl_set_object_callback( pos, positioner_cb, 0 );
    fl_set_positioner_xvalue( pos, 0.0 );
    fl_set_positioner_yvalue( pos, 0.0 );
    fl_set_positioner_validator( pos, validator );
    fl_set_object_color( pos, FL_COL1, FL_BLACK );

    xval = fl_add_box( FL_DOWN_BOX, 270, 40, 100, 30, "" );
    fl_set_object_color( xval, FL_COL1, FL_COL1 );

    yval = fl_add_box( FL_DOWN_BOX, 270, 90, 100, 30, "" );
    fl_set_object_color( yval, FL_COL1, FL_COL1 );

    fl_add_button( FL_NORMAL_BUTTON, 270, 210, 100, 30, "Exit" );

    fl_end_form( );

    fl_show_form( form, FL_PLACE_CENTER, FL_FULLBORDER, "positioner_v" );

    positioner_cb( pos, 0 );

    fl_do_forms( );
    fl_finish( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
