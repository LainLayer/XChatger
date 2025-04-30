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



/* Demo showing activating and deactivating objects
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "include/forms.h"


FL_FORM *form;

FL_OBJECT *button1,
          *button2,
          *button3,
          *button4,
          *group,
          *firstbut;


/***************************************
 ***************************************/

void
exit_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
         long        arg  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void
setit( FL_OBJECT * obj,
       int         val )
{
    if ( val )
    {
        fl_set_object_lcolor( obj, FL_BLACK );
        fl_activate_object( obj );
    }
    else
    {
        fl_set_object_lcolor( obj, FL_INACTIVE );
        fl_deactivate_object( obj );
    }
}


/***************************************
 ***************************************/

void
doit( int b1,
      int b2,
      int b3,
      int b4 )
{
    setit( button1, b1 );
    setit( button2, b2 );
    setit( button3, b3 );
    setit( button4, b4 );
}


/***************************************
 ***************************************/

void
set_active( FL_OBJECT * obj  FL_UNUSED_ARG,
            long        arg)
{
    switch ( arg )
    {
        case 0 :
            doit( 1, 1, 1, 1 );
            break;

        case 1 :
            doit( 0, 0, 0, 0 );
            break;

        case 2 :
            doit( 0, 1, 0, 1 );
            break;

        case 3 :
            doit( 1, 0, 1, 0 );
            break;
    }
}


/***************************************
 ***************************************/

void
create_form( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 420, 230 );

    obj = fl_add_box( FL_UP_BOX, 0, 0, 420, 230, "" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );

    button1 = obj = fl_add_button( FL_NORMAL_BUTTON, 20, 170, 150, 40,
                                   "Button 1" );
    fl_set_object_lsize( obj ,FL_LARGE_SIZE );
    fl_set_button_shortcut( obj, "1", 1 );

    button2 = obj = fl_add_button( FL_NORMAL_BUTTON, 20, 120, 150, 40,
                                   "Button 2" );
    fl_set_object_lsize( obj, FL_LARGE_SIZE );
    fl_set_button_shortcut( obj, "2", 1 );

    button3 = obj = fl_add_button( FL_NORMAL_BUTTON, 20, 70, 150, 40,
                                   "Button 3" );
    fl_set_object_lsize( obj, FL_LARGE_SIZE );
    fl_set_button_shortcut( obj, "3", 1 );

    button4 = obj = fl_add_button( FL_NORMAL_BUTTON, 20, 20, 150, 40,
                                   "Button 4" );
    fl_set_button_shortcut( obj, "4", 1 );
    fl_set_object_lsize( obj,FL_LARGE_SIZE );

    group = fl_bgn_group( );

    firstbut = obj = fl_add_lightbutton( FL_RADIO_BUTTON, 260, 180, 140, 30,
                                         "All active" );
    fl_set_object_callback( obj, set_active, 0 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 260, 150, 140, 30,
                              "Non active" );
    fl_set_object_callback( obj, set_active, 1 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 260, 120, 140 ,30,
                              "Even active" );
    fl_set_object_callback(obj, set_active, 2 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 260, 90, 140, 30, "Odd active" );
    fl_set_object_callback( obj, set_active, 3 );

    fl_end_group( );

    obj = fl_add_button( FL_NORMAL_BUTTON, 270, 20, 130, 30, "Quit" );
    fl_set_object_callback( obj, exit_cb, 0 );

    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    create_form( );

    fl_set_button( firstbut, 1 );

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, NULL );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
