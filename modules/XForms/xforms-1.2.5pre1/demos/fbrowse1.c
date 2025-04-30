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


/* This demo shows the use of a browser and fl_call_object_callback.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"

FL_FORM *form;
FL_OBJECT *br, *but;


/***************************************
 ***************************************/

void
load_file( FL_OBJECT * ob   FL_UNUSED_ARG,
           long        arg  FL_UNUSED_ARG )
{
  if ( ! fl_load_browser( br, fl_show_input( "Filename to load", "" ) ) )
      fl_add_browser_line( br, "NO SUCH FILE!" );
}


/***************************************
 ***************************************/

void
set_size( FL_OBJECT * ob  FL_UNUSED_ARG,
          long        arg )
{
  fl_set_browser_fontsize( br, arg );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 130, 100 );

    br = fl_add_browser( FL_NORMAL_BROWSER, 5, 5, 95, 90, "" );

    but = fl_add_button( FL_NORMAL_BUTTON, 105, 5, 20, 8, "Exit" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 105, 75, 20, 8, "Load" );
    fl_set_object_callback( obj, load_file, 0 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 105, 60, 20, 8, "Small" );
    fl_set_object_callback( obj, set_size, FL_SMALL_SIZE );
    fl_call_object_callback( obj );
    fl_set_button( obj, 1 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 105, 50, 20, 8, "Normal" );
    fl_set_object_callback( obj, set_size, FL_NORMAL_SIZE );
    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 105, 40, 20, 8, "Large" );

    fl_set_object_callback( obj, set_size, FL_LARGE_SIZE );

    fl_end_form( );

    fl_scale_form( form, 4.0, 4.0 );
    fl_adjust_form_size( form );

    fl_clear_browser( br );
    fl_add_browser_line( br,"LOAD A FILE." );

    fl_show_form( form,FL_PLACE_FREE, FL_FULLBORDER, "Browser" );

    do
        obj = fl_do_forms( );
    while ( obj != but );

    fl_hide_form( form );
    fl_finish( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
