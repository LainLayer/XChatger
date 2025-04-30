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


/* A demo of the forms library using light buttons for
   radio buttons and input fields.
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "include/forms.h"


FL_FORM *form;
FL_OBJECT *but;


/***************************************
 ***************************************/

void
make_form1( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_UP_BOX, 500, 400 );

    fl_bgn_group( );

    obj = fl_add_box( FL_UP_BOX, 150, 295, 300, 65, "Children  " );
    fl_set_object_lalign( obj, FL_ALIGN_LEFT);
    fl_add_lightbutton( FL_RADIO_BUTTON, 175, 310, 50, 35, "1" );
    fl_add_lightbutton( FL_RADIO_BUTTON, 241, 310, 50, 35, "2" );
    fl_add_lightbutton( FL_RADIO_BUTTON, 308, 310, 50, 35, "3" );
    fl_add_lightbutton( FL_RADIO_BUTTON, 375, 310, 50, 35, "4" );

    fl_end_group( );

    fl_bgn_group( );

    obj = fl_add_box( FL_UP_BOX, 150, 230, 300, 65, "Married  " );
    fl_set_object_lalign( obj, FL_ALIGN_LEFT );
    fl_add_lightbutton( FL_RADIO_BUTTON, 175, 245, 100, 35, "Yes" );
    fl_add_lightbutton( FL_RADIO_BUTTON, 325, 245, 100, 35, "No" );

    fl_end_group( );

    fl_bgn_group( );

    obj = fl_add_box( FL_UP_BOX, 150, 165, 300, 65, "Sex  " );
    fl_set_object_lalign( obj, FL_ALIGN_LEFT );
    fl_add_lightbutton( FL_RADIO_BUTTON, 175, 180, 100, 35, "Male" );
    fl_add_lightbutton( FL_RADIO_BUTTON, 325, 180, 100, 35, "Female" );

    fl_end_group( );

    fl_add_input( FL_NORMAL_INPUT, 150, 30, 300, 30, "Name  " );

    fl_add_input( FL_NORMAL_INPUT, 150, 75, 300, 30, "Address  " );

    fl_add_input( FL_NORMAL_INPUT, 150, 120, 300, 30, "City  " );

    but = fl_add_button( FL_NORMAL_BUTTON, 25, 360, 75, 30, "OK" );

    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    make_form1( );

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, "Demo06" );

    while ( 1 )
    {
        do
            obj = fl_do_forms( );
        while ( obj != but );

        if ( fl_show_question( "Do you really want to Quit?", 0 ))
            break;
    }

    fl_finish( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
