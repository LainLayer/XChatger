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
 * Test iconification
 *
 * T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "crab.xpm"

FL_FORM * create_form_form(void);


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    Pixmap p,
           mask;
    unsigned int w,
                 h;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = create_form_form( );
    p = fl_read_pixmapfile( fl_root, "crab.xpm", &w, &h, &mask, 0, 0, 0 );
    fl_set_form_icon( form, p, mask );

    fl_show_form( form, FL_PLACE_CENTER, FL_FULLBORDER, "IconTest" );
    fl_do_forms( );

	fl_finish( );
    return 0;
}


/***************************************
 ***************************************/

FL_FORM *
create_form_form( void )
{
    FL_OBJECT *obj;
    FL_FORM *form = fl_bgn_form( FL_NO_BOX, 151, 111 );

    obj = fl_add_pixmapbutton( FL_NORMAL_BUTTON, 0, 0, 151, 111,
                               "Iconify Me\nvia Window Manager" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_BOTTOM ) );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );
    fl_set_pixmapbutton_data( obj, crab );

    fl_end_form( );

    return form;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
