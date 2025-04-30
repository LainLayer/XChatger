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



static FL_OBJECT *sl,
                 *but1,
                 *but2,
                 *but3;


/***************************************
 ***************************************/

static void
slider_callback( FL_OBJECT * a,
                 long        b  FL_UNUSED_ARG )

{
    double val = fl_get_slider_value( a );

    fl_set_button( but1, 0 );
    fl_set_button( but2, 0 );
    fl_set_button( but3, 0 );

    if ( val <= 0.01 )
        fl_set_button( but1, 1 );
    else if ( val >= 0.49 && val <= 0.51 )
        fl_set_button( but2, 1 );
    else if ( val >= 0.99 )
        fl_set_button( but3, 1 );
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
    form = fl_bgn_form( FL_UP_BOX, 300, 300 );
    sl = fl_add_slider( FL_VERT_SLIDER, 40, 40, 60, 220, "X" );
    fl_set_slider_value( sl, 0.5 );
    fl_set_object_callback( sl, slider_callback, 0 );
    but1 = fl_add_lightbutton( FL_PUSH_BUTTON, 140, 220, 120, 40, "0.0" );
    but2 = fl_add_lightbutton( FL_PUSH_BUTTON, 140, 160, 120, 40, "0.5" );
    fl_set_button( but2, 1 );
    but3 = fl_add_lightbutton( FL_PUSH_BUTTON, 140, 100, 120, 40, "1.0" );
    but = fl_add_button( FL_NORMAL_BUTTON, 140, 40, 120, 40, "Exit" );
    fl_end_form();

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, "slRadio" );

    while ( ( obj = fl_do_forms( ) ) != but )
        if ( obj == but1 )
        {
            if ( fl_get_button( but1 ) )
            {
                fl_set_slider_value( sl, 0.0 );
                fl_set_button( but2, 0 );
                fl_set_button( but3, 0 );
            }
            else
                fl_set_button( but1, 1 );
        }
        else if ( obj == but2 )
        {
            if ( fl_get_button( but2 ) )
            {
                fl_set_slider_value( sl, 0.5 );
                fl_set_button( but1, 0 );
                fl_set_button( but3, 0 );
            }
            else
                fl_set_button( but2, 1 );
        }
        else if ( obj == but3 )
        {
            if ( fl_get_button( but3 ) )
            {
                fl_set_slider_value( sl, 1.0 );
                fl_set_button( but1, 0 );
                fl_set_button( but2, 0 );
            }
            else
                fl_set_button( but3, 1 );
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
