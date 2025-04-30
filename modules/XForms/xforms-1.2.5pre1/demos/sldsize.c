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


/* This demo shows the use of a setting slider sizes */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *sl1,
              *sl2,
              *but,
              *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    form = fl_bgn_form( FL_UP_BOX, 150, 300 );
    sl1 = fl_add_slider( FL_VERT_SLIDER, 20, 20, 40, 180, "X" );
    sl2 = fl_add_slider( FL_VERT_SLIDER, 90, 20, 40, 180, "Y" );
    but = fl_add_button( FL_NORMAL_BUTTON, 40, 250, 70, 30, "Exit" );
    fl_end_form( );

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, "Slider Size" );

    do
    {
        fl_set_slider_size( sl2, fl_get_slider_value( sl1 ) );
        fl_set_slider_size( sl1, fl_get_slider_value( sl2 ) );
        obj = fl_do_forms( );
    } while ( obj != but );

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
