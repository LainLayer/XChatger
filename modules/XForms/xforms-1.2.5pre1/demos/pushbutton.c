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


/* A demo that shows the use of push buttons.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"

FL_FORM *form;
FL_OBJECT  *abox[ 8 ];


/***************************************
 ***************************************/

static void
push_cb( FL_OBJECT * ob,
         long        n )
{
    if ( fl_get_button( ob ) )
        fl_show_object( abox[ n ] );
    else
        fl_hide_object( abox[ n ] );
}


/***************************************
 ***************************************/

static void
makeform( void )
{
    int i;
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_UP_BOX, 400, 400 );

    for ( i = 0; i < 8; i++ )
    {
        obj = fl_add_button( FL_PUSH_BUTTON, 40, 310 - 40 * i, 80, 30, "" );
        fl_set_object_color( obj, FL_BLACK + i + 1, FL_BLACK + i + 1 );
        fl_set_object_callback( obj, push_cb, i );

        abox[ i ] = fl_add_box( FL_DOWN_BOX, 150 + 30 * i, 40, 25, 320, "" );
        fl_set_object_color( abox[ i ], FL_BLACK + i + 1, FL_BLACK + i + 1 );
        fl_hide_object( abox[ i ] );
    }

    fl_add_button( FL_NORMAL_BUTTON, 40, 350, 80, 30, "Exit" );
    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    makeform( );

    fl_show_form( form, FL_PLACE_CENTER, FL_NOBORDER, "Push Buttons" );

    /* fl_do_forms will return only when Exit is pressed */

    fl_do_forms( );
    fl_finish( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
