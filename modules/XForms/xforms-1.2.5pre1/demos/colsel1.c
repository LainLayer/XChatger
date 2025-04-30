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


/************
 * Show the use of setting object colors and call-back routines.
 ************/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"


FL_FORM *form;
FL_OBJECT *topbox;


/***************************************
 ***************************************/

void
change_color( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        col )
{
    fl_set_object_color( topbox, col,  col );
}


/***************************************
 ***************************************/

void
makeform( void )
{
    FL_OBJECT *obj;
    int i, j;
    char str[ 32 ];

    form = fl_bgn_form( FL_UP_BOX, 100, 100 );

    for ( i = 0; i < 8; i++ )
        for ( j = 0; j < 8; j++ )
        {
            sprintf( str, "%d", 8 * j + i );
            obj = fl_add_button( FL_RADIO_BUTTON,
                                 11 + 10 * i, 15 + 10 * j, 8, 6, str );
            fl_set_object_color( obj, 8 * j + i, 8 * j + i );
            fl_set_object_lalign( obj, FL_ALIGN_BOTTOM );
            fl_set_object_callback( obj, change_color, ( long ) ( 8 * j + i ) );
        }

    topbox = fl_add_button( FL_NORMAL_BUTTON, 30, 5, 40, 8, "The Color Map" );
    fl_set_object_lsize( topbox, FL_LARGE_SIZE );
    fl_set_object_lstyle( topbox, FL_BOLD_STYLE );

    fl_end_form( );

    fl_adjust_form_size( form );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_OBJECT *ret;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    makeform( );
    fl_scale_form( form, 4.0, 4.0 );
    fl_show_form( form, FL_PLACE_FREE, FL_TRANSIENT, "colsel" );

    do
        ret = fl_do_forms( );
    while ( ret != topbox );

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
