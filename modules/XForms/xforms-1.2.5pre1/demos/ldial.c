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


/* This is an example of the use of dials.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <stdio.h>
#include "include/forms.h"


FL_FORM *form;
FL_OBJECT *dial[ 3 ],
          *text[ 3 ],
          *result;

enum {
    RED,
    GREEN,
    BLUE
};


/***************************************
 ***************************************/

static void
dial_callback( FL_OBJECT * obj  FL_UNUSED_ARG,
               long        arg )
{
    int clr[ 3 ];
    size_t i;
    char str[ 60 ];

    for ( i = RED; i <= BLUE; i++ )
        clr[ i ] = fl_get_dial_value( dial[ i ] );

    sprintf( str, "%d", clr[ arg ] );
    fl_set_object_label( text[ arg ], str );

    fl_mapcolor( FL_FREE_COL1, clr[ 0 ], clr[ 1 ], clr[ 2 ] );
    fl_redraw_object( result );
}


/***************************************
 ***************************************/

static void
makeform( void )
{
    FL_OBJECT *quit;
    size_t i;
    const char *txt[ ] = { "Red",  "Green",  "Blue"  };
    FL_COLOR clr[ ]    = { FL_RED, FL_GREEN, FL_BLUE };

    form = fl_bgn_form( FL_UP_BOX, 300, 330 );

    quit = fl_add_button( FL_NORMAL_BUTTON, 45, 15, 210, 45, "A Color Editor" );
    fl_set_object_lsize( quit, FL_LARGE_SIZE );

    for ( i = RED; i <= BLUE; i++ )
    {
        dial[ i ] = fl_add_dial( FL_LINE_DIAL, 30, 240 - i * 85, 60, 60,
                                 txt[ i ] );
        fl_set_dial_bounds( dial[ i ], 0.0, 255.0 );
        fl_set_dial_angles( dial[ i ], 15.0, 345.0 );
        fl_set_dial_value( dial[ i ], 128.0 );
        fl_set_object_color( dial[ i ], clr[ i ], FL_DIAL_COL2 );
        fl_set_object_return( dial[ i ], FL_RETURN_CHANGED );
        fl_set_object_callback( dial[ i ], dial_callback, i );

        text[ i ] = fl_add_box( FL_DOWN_BOX, 105, 255 - i * 85, 50, 25, "128" );
    }

    result = fl_add_box( FL_DOWN_BOX, 180, 70, 90, 245, "" );
    fl_mapcolor( FL_FREE_COL1, 128, 128, 128 );
    fl_set_object_color( result, FL_FREE_COL1, FL_FREE_COL1 );
    fl_set_object_dblbuffer( result, 1 );

    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "ColorEditor", 0, 0 );
    makeform( );

    fl_show_form( form, FL_PLACE_MOUSE, FL_TRANSIENT, "Color Editor" );
    fl_do_forms( );

    fl_finish();
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
