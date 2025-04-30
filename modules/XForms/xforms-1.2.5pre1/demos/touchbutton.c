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


/* This demo shows the use of a touch buttons.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"

static void show_val( FL_OBJECT *, long );
FL_OBJECT *valobj;


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 360, 140);

    obj = fl_add_button( FL_TOUCH_BUTTON, 50, 30, 40, 30, "@<<" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_color( obj, FL_COL1, FL_INDIANRED );
    fl_set_object_callback( obj, show_val, -5 );
    fl_set_button_shortcut( obj, "1", 0 );

    obj = fl_add_button( FL_TOUCH_BUTTON, 90, 30, 40, 30, "@<" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_color( obj, FL_COL1, FL_INDIANRED );
    fl_set_object_callback( obj,  show_val, -1 );
    fl_set_button_shortcut( obj, "2",  0 );

    valobj = obj = fl_add_box( FL_BORDER_BOX, 130, 30, 100, 30, "" );
    fl_set_object_color( obj, FL_LEFT_BCOL, FL_LEFT_BCOL );

    obj = fl_add_button( FL_TOUCH_BUTTON, 230, 30, 40, 30, "@>" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_color( obj, FL_COL1, FL_INDIANRED );
    fl_set_object_callback( obj, show_val, 1 );
    fl_set_button_shortcut( obj, "3", 0 );

    obj = fl_add_button( FL_TOUCH_BUTTON, 270, 30, 40, 30, "@>>" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_callback( obj, show_val, 5 );
    fl_set_object_color( obj, FL_COL1, FL_INDIANRED );
    fl_set_button_shortcut( obj, "4", 0 );

    fl_add_button( FL_NORMAL_BUTTON, 220, 90, 100, 30, "Exit" );

    fl_end_form( );

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, "Touch Buttons" );

    fl_do_forms( );
    fl_finish( );

    return 0;
}


/***************************************
 ***************************************/

static void
show_val( FL_OBJECT * ob  FL_UNUSED_ARG,
          long        delta )
{
    static int val = 0;
    char str[ 32 ];

    val += delta;
    sprintf( str,"%d", val );
    fl_set_object_label( valobj, str );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
