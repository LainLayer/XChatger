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


/* Demo showing secret input fields
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *but,
              *password1,
              *password2,
              *info;
   char str[ 256 ];

   fl_initialize( &argc, argv, "FormDemo", 0, 0 );

   form = fl_bgn_form( FL_UP_BOX, 400, 300 );

   password1 = fl_add_input( FL_SECRET_INPUT, 140, 40, 160, 40, "Password 1:" );
   fl_set_object_return( password1, FL_RETURN_CHANGED );

   password2 = fl_add_input( FL_SECRET_INPUT, 140, 100, 160, 40,
                             "Password 2:" );
   fl_set_object_return( password2, FL_RETURN_CHANGED );

   info = fl_add_box( FL_SHADOW_BOX, 20, 160, 360, 60, "" );

   but = fl_add_button( FL_NORMAL_BUTTON, 280, 240, 100, 40, "Quit" );

   fl_end_form( );

   fl_show_form( form, FL_PLACE_MOUSE, FL_FULLBORDER, "Secret Input Demo" );

   while ( fl_do_forms( ) != but )
   {
       sprintf( str, "Password 1 is: %s\n, Password 2 is: %s",
                fl_get_input( password1 ), fl_get_input( password2 ) );
       fl_set_object_label( info, str );
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
