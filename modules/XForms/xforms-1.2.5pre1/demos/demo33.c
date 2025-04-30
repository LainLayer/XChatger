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


/* Testing bitmaps Class. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "srs.xbm"


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 200, 200 );

    obj = fl_add_bitmap( FL_NORMAL_BITMAP, 50, 50, 100, 100, "A bitmap" );
    fl_set_object_lcolor( obj, FL_BLUE );
    fl_add_button( FL_HIDDEN_BUTTON, 50, 50, 100, 100, "" );

    fl_end_form( );

    fl_set_bitmap_data( obj, sorceress_width, sorceress_height,
                        sorceress_bits );

    fl_show_form( form, FL_PLACE_MOUSE, FL_NOBORDER, "X Bitmap" );

    fl_do_forms( ) ;

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
