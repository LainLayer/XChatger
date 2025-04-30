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
 *  This demo shows the use of choice objects.
 *
 *  This file is part of xforms package
 *  M. Overmars and T.C. Zhao    (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"

FL_FORM *form;
FL_OBJECT *sexobj,
          *childobj,
          *licenceobj,
          *marriedobj,
          *readyobj;


/***************************************
 ***************************************/

static void
cb( FL_OBJECT * ob,
    long        data  FL_UNUSED_ARG )
{
    fprintf( stderr, "CallBack: %d\n", fl_get_choice( ob ) );
}


/***************************************
 ***************************************/

void
create_form( void )
{
    form = fl_bgn_form( FL_NO_BOX, 420, 360 );

    fl_add_box( FL_UP_BOX, 0, 0, 420, 360, "" );

    fl_add_input( FL_NORMAL_INPUT, 70, 300, 320, 30, "Name" );

    fl_add_input( FL_NORMAL_INPUT, 70, 260, 320, 30, "Address" );

    fl_add_input( FL_NORMAL_INPUT, 70, 220, 320, 30, "City" );

    fl_add_input( FL_NORMAL_INPUT, 70, 180, 320, 30, "Country" );

    sexobj = fl_add_choice( FL_NORMAL_CHOICE, 70, 130, 110, 30, "Sex");
    fl_set_choice_notitle( sexobj, 1 );
    fl_set_object_shortcut( sexobj, "S", 1 );

    childobj = fl_add_choice( FL_NORMAL_CHOICE2, 280, 130, 110, 30,
                              "Children" );

    licenceobj = fl_add_choice( FL_NORMAL_CHOICE, 280, 80, 110, 30, "Licence" );
    fl_set_choice_align_bottom( licenceobj, 1 );

    marriedobj = fl_add_choice( FL_DROPLIST_CHOICE, 70, 80, 110, 27,
                                "Married" );
    fl_set_object_callback( marriedobj, cb, 0 );
    fl_set_object_boxtype( marriedobj, FL_UP_BOX );

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
    fl_addto_choice( sexobj,"Male" );
    fl_addto_choice( sexobj,"Female" );
    fl_addto_choice( childobj, "Zero|One|Two|Three|Four|Many" );
    fl_addto_choice( licenceobj, "Yes|No" );
    fl_addto_choice( marriedobj, "Yes" );
    fl_addto_choice( marriedobj, "No" );

    fl_show_form( form, FL_PLACE_CENTER | FL_FREE_SIZE, FL_TRANSIENT,
                  "ChoiceDemo" );

    while ( fl_do_forms( ) != readyobj )
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
