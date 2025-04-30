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
 * Built-in xforms clock
 * T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

FL_FORM *fclock;


/***************************************
 ***************************************/

void
exit_cb( FL_OBJECT * ob  FL_UNUSED_ARG,
         long        q   FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void
create_form_clock( void )
{
    FL_OBJECT *obj;

    fclock = fl_bgn_form( FL_NO_BOX, 500, 350 );

    fl_add_box( FL_UP_BOX, 0, 0, 500, 350, "" );

    obj = fl_add_clock( FL_DIGITAL_CLOCK, 185, 20, 150, 35, "" );
    fl_set_object_boxtype( obj, FL_ROUNDED_BOX );
    fl_set_object_color( obj, FL_COL1,FL_BLACK );
    fl_set_object_lsize( obj, FL_MEDIUM_SIZE );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    obj = fl_add_clock( FL_ANALOG_CLOCK, 30, 70, 220, 200, "" );
    fl_set_object_boxtype( obj, FL_UP_BOX );

    obj = fl_add_clock( FL_ANALOG_CLOCK, 260, 70, 220, 200, "" );
    fl_set_object_boxtype( obj, FL_OVAL3D_UPBOX );

    obj = fl_add_button( FL_NORMAL_BUTTON, 375, 300, 110, 35, "Exit" );
    fl_set_object_callback( obj, exit_cb, 0 );

    fl_end_form( );

   fl_scale_form( fclock, 0.7, 0.7 );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0,  0 );

    create_form_clock( );
    fl_show_form( fclock, FL_PLACE_CENTER, FL_TRANSIENT,"clocks" );

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
