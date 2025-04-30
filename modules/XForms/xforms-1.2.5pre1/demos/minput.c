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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"


/***************************************
 ***************************************/

void
input_cb( FL_OBJECT * ob,
          long        data  FL_UNUSED_ARG )
{
    int x, y;

    fl_get_input_cursorpos( ob, &x , &y );
    fprintf( stderr," x = %d y = %d\n", x, y );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *but,
              *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 400, 450 );

    fl_add_input( FL_MULTILINE_INPUT, 30, 270, 340, 150, "" );

    obj =  fl_add_input( FL_MULTILINE_INPUT, 30, 90, 340, 150, "" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_callback( obj, input_cb, 0 );

    but = fl_add_button( FL_NORMAL_BUTTON, 160, 30, 80, 30, "Exit" );

    fl_end_form( );

    fl_show_form( form, FL_PLACE_CENTERFREE, FL_FULLBORDER, "MultiLineInput" );

    do
        obj = fl_do_forms( );
    while ( obj != but );

    fl_finish( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
