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

FL_FORM *form;
FL_OBJECT *readyobj;


/***************************************
 ***************************************/

static int
cb( FL_POPUP_RETURN *r )
{
    fprintf( stderr, "CallBack: %s\n", r->label );
    return 0;
}


/***************************************
 ***************************************/

void
create_form( void )
{
    FL_OBJECT *sexobj,
              *childobj,
              *licenceobj,
              *marriedobj;
    FL_POPUP_ITEM items[ ] = { { "Male%SM",   cb,   "M",  0, 0 },
                               { "Female%SF", cb,   "F",  0, 0 },
                               { NULL,        NULL, NULL, 0, 0 } };

    form = fl_bgn_form( FL_NO_BOX, 420, 360 );

    fl_add_box( FL_UP_BOX, 0, 0, 420, 360, "" );

    fl_add_input( FL_NORMAL_INPUT, 70, 300, 320, 30, "Name" );

    fl_add_input( FL_NORMAL_INPUT, 70, 260, 320, 30, "Address" );

    fl_add_input( FL_NORMAL_INPUT, 70, 220, 320, 30, "City" );

    fl_add_input( FL_NORMAL_INPUT, 70, 180, 320, 30, "Country" );

    sexobj = fl_add_select( FL_NORMAL_SELECT, 70, 130, 110, 30, "Sex");
    fl_set_select_items( sexobj, items );
    fl_set_object_shortcut( sexobj, "S", 1 );

    childobj = fl_add_select( FL_MENU_SELECT, 280, 130, 110, 30,
                              "Children" );
    fl_add_select_items( childobj, "Zero|One|Two|Three|Four|Many" );
    fl_set_object_shortcut( childobj, "C", 1 );
    fl_popup_set_title( fl_get_select_popup( childobj ), "Kids" );

    licenceobj = fl_add_select( FL_NORMAL_SELECT, 280, 80, 110, 30, "Licence" );
    fl_add_select_items( licenceobj, "Yes|No" );
    fl_set_select_policy( licenceobj, FL_POPUP_DRAG_SELECT );

    marriedobj = fl_add_select( FL_DROPLIST_SELECT, 70, 80, 110, 27,
                                "Married" );
    fl_add_select_items( marriedobj, "Yes|No" );

    readyobj = fl_add_button( FL_NORMAL_BUTTON, 150, 20, 140, 30, "Quit" );

    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_flip_yorigin( );
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    create_form( );

    fl_show_form( form, FL_PLACE_CENTER | FL_FREE_SIZE, FL_TRANSIENT,
                  "Select Object Demo" );

    while ( fl_do_forms( ) != readyobj )
        /* empty */ ;

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
