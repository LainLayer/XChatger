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


/* This demo shows the use of a slider as radio object */

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
    FL_OBJECT *sl,
              *but1,
              *but2,
              *but3,
              *but,
              *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 300, 300 );
    sl = fl_add_slider( FL_VERT_SLIDER, 40, 40, 60, 220, "X" );
    sl->radio = 1;
    but1 = fl_add_lightbutton( FL_RADIO_BUTTON, 140, 220, 120, 40, "0.0" );
    but2 = fl_add_lightbutton( FL_RADIO_BUTTON, 140, 160, 120, 40, "0.5" );
    but3 = fl_add_lightbutton( FL_RADIO_BUTTON, 140, 100, 120, 40, "1.0" );
    but = fl_add_button( FL_NORMAL_BUTTON, 140, 40, 120, 40, "Exit" );
    fl_end_form( );

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, "slRadio" );

    do
    {
        obj = fl_do_forms( );
        if ( obj == but1 )
            fl_set_slider_value( sl, 0.0 );
        if ( obj == but2 )
            fl_set_slider_value( sl, 0.5 );
        if ( obj == but3 )
            fl_set_slider_value( sl, 1.0 );
    } while ( obj != but );

    fl_finish( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
