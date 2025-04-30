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


/* A box with two buttons and a string. Simple boxes like this
   are very usefull for asking questions
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "include/forms.h"


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *yes;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 320, 120 );

    fl_add_box( FL_NO_BOX, 0, 10, 320, 40, "Do you want to quit?" );
    yes = fl_add_button( FL_NORMAL_BUTTON, 40, 70, 80, 30," Yes" );
    fl_add_button( FL_NORMAL_BUTTON, 200, 70, 80, 30, "No" );

    fl_end_form( );

    fl_show_form( form, FL_PLACE_MOUSE, FL_TRANSIENT, "Question" );

    while ( 1 )
    {
        if ( fl_do_forms( ) == yes )
        {
            fprintf( stderr, "\"Yes\" has been pushed\n" );
            break;
        }
        else
            fprintf( stderr, "No is pushed\n" );
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
