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


/* This is an example of the use of dials.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"

FL_FORM *form;
FL_OBJECT * dials[ 3 ],
          * texts[ 3 ],
          * result;


/***************************************
 ***************************************/

void
cb( FL_OBJECT * obj,
    long        data )
{
    static int cols[ 3 ] = { 128, 128, 128 };
    char str[ 4 ];

    cols[ data ] = fl_get_dial_value( obj );
    fl_mapcolor( FL_FREE_COL1, cols[ 0 ], cols[ 1 ], cols[ 2 ] );
    fl_redraw_object( result );
    sprintf( str, "%d", cols[ data ] );
    fl_set_object_label( texts[ data ], str );
    
}


/***************************************
 ***************************************/

void
makeform( void )
{
    FL_OBJECT *obj;
    const char *label[ 3 ] = { "Red", "Green", "Blue" };
    FL_COLOR col[ 3 ] = { FL_RED, FL_GREEN, FL_BLUE };
    int i;
    int y = 70;

    form = fl_bgn_form( FL_UP_BOX, 300, 330 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 45, 15, 210, 45, "Color Editor" );
    fl_set_object_lsize( obj, FL_LARGE_SIZE );

    for ( i = 0; i < 3; y += 85, i++ )
    {
        dials[ i ] = obj = fl_add_dial( FL_NORMAL_DIAL, 30, y, 60, 60,
                                        label[ i ] );
        fl_set_object_boxtype( obj, FL_UP_BOX );
        fl_set_dial_bounds( obj, 0.0, 255.0 );
        fl_set_dial_value( obj, 128.0 );
        fl_set_object_color( obj, col[ i ], FL_DIAL_COL2 );
        fl_set_object_callback( obj, cb, i );
        fl_set_object_return( obj, FL_RETURN_CHANGED );

        texts[ i ] = fl_add_box( FL_DOWN_BOX, 105, y + 17, 50, 25, "128" );
    }

    result = fl_add_box( FL_DOWN_BOX, 180, 70, 90, 245, "" );
    fl_set_object_color( result, FL_FREE_COL1, FL_FREE_COL1 );
    fl_mapcolor( FL_FREE_COL1, 128, 128, 128 );
    fl_set_object_dblbuffer( result, 1 );     /* to avoid flicker */

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

    fl_show_form( form, FL_PLACE_MOUSE, FL_TRANSIENT, "A Form" );

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
