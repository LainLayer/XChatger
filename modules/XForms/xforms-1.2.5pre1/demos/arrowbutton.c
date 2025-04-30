
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
 * This demo shows the use of special symbol labels
 *
 * This file is part of xforms packge
 * M. Overmars and T.C. Zhao (1997)
 */

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
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_FLAT_BOX, 400, 400 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 50, 250, 100, 100, "@1" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 150, 250, 100, 100, "@2" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 250, 250, 100, 100, "@3" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 50, 150, 100, 100, "@4" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 250, 150, 100, 100, "@6" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 50, 50, 100, 100, "@7" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 150, 50, 100, 100, "@8" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 250, 50, 100, 100, "@9" );
    fl_set_object_lcolor( obj, FL_BLUE );

    obj = fl_add_button( FL_NORMAL_BUTTON, 150, 150, 100, 100, "@square" );
    fl_set_object_lcolor( obj, FL_GREEN );
    fl_set_object_color( obj, FL_MAGENTA, FL_RED );

    fl_end_form( );

    fl_show_form( form, FL_PLACE_ASPECT, FL_TRANSIENT, "Buttons" );

    while ( fl_do_forms( ) != obj )
        /* empty */ ;

    fl_finish( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
