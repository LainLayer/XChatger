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


/* This demo is meant to demonstrate the use of a free
   object in a form.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>


int on = 1,
    dcol = 1;
FL_COLOR cole;

/***************************************
 * The call back routine
 ***************************************/

int
handle_free1( FL_OBJECT * obj,
			  int         event,
			  FL_Coord    mx   FL_UNUSED_ARG,
			  FL_Coord    my   FL_UNUSED_ARG,
			  int         key  FL_UNUSED_ARG,
			  void      * ev   FL_UNUSED_ARG )
{
    static int dcol = 1;

    switch ( event )
    {
        case FL_DRAW:
            fl_rectf( obj->x, obj->y, obj->w, obj->h, obj->u_ldata );
            break;

        case FL_RELEASE:
            on = ! on;
            break;

        case FL_STEP:
            if ( on )
            {
                if ( ( FL_COLOR ) obj->u_ldata >= cole )
                    dcol = -1;
                if ( obj->u_ldata <= FL_FREE_COL1 )
                    dcol = 1;
                obj->u_ldata += dcol;
                fl_redraw_object( obj );
            }
            break;
    }
    return 0;
}


/***************************************
 ***************************************/

void done( FL_OBJECT * ob    FL_UNUSED_ARG,
           long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *obj;
    FL_COLOR i;
    int j,
        depth,
        col;

    fl_initialize(&argc, argv, "FormDemo", 0, 0);

    form = fl_bgn_form( FL_UP_BOX, 400, 400 );
    obj = fl_add_button( FL_NORMAL_BUTTON, 320, 20, 40, 30, "Exit" );
    fl_set_object_callback( obj, done, 0 );
    obj = fl_add_free( FL_CONTINUOUS_FREE, 40, 80, 320, 280, "", handle_free1 );
    fl_end_form( );

    /* Can't do it if less than 4 bit deep... */

    depth  = fl_get_visual_depth( );

    if ( depth < 4 )
    {
        fprintf( stderr,"This Demo requires a depth of at least 4 bits\n" );
        fl_finish( );
        exit( 1 );
    }

    /* ...but too large a depth also won't do */

    if ( depth > 7 )
        depth = 7;

    cole = ( 1 << depth ) - 1;
    if ( cole > 64 )
        cole = 64;

    obj->u_ldata = col = FL_FREE_COL1;
    cole += col;

    for ( i = col; i <= cole; i++ )
    {
        j =  255 * ( i - col ) / ( double ) ( cole  - col );
        fl_mapcolor( i, j, j, j );
    }

    fl_show_form( form,FL_PLACE_CENTER, FL_NOBORDER, "Free Object" );
    fl_do_forms( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
