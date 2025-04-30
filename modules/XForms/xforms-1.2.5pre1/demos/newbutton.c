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
 * Demo showing the use of user defined object class: CROSSBUTTON
 *
 * Form definition file generated with fdesign.
 * changed stub button to crossbutton
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "crossbut.h"
#include <stdlib.h>

/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * newbut;
    void      * vdata;
    FL_OBJECT * bexit;
} FD_newbut;

extern FD_newbut *create_form_newbut(void);


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
      FD_newbut *cbform ;

      fl_initialize( &argc, argv, "FormDemo", 0, 0 );
      cbform = create_form_newbut( );
      fl_show_form( cbform->newbut, FL_PLACE_CENTER, FL_TRANSIENT,
                    "newbutton" );

      while( fl_do_forms( ) != cbform->bexit )
          /* empty */;

      fl_finish( );
      return 0;
}


/***************************************
 ***************************************/

FD_newbut *
create_form_newbut( void )
{
    FL_OBJECT *obj;
    FD_newbut *fdui = fl_malloc( sizeof *fdui );
    int oldbw = fl_get_border_width( );

    fl_set_border_width( -2 );

    fdui->newbut = fl_bgn_form( FL_NO_BOX, 310, 190 );

    fl_add_box( FL_UP_BOX, 0, 0, 310, 190, "" );
    obj = fl_add_labelframe( FL_ENGRAVED_FRAME, 40, 45, 100, 120, "CrossA" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_lstyle( obj ,FL_BOLD_STYLE );

    obj = fl_add_crossbutton( FL_RADIO_BUTTON, 50, 115, 80, 30, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_RED );

    obj = fl_add_crossbutton( FL_RADIO_BUTTON, 50, 85, 80, 30, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_GREEN );

    obj = fl_add_crossbutton( FL_RADIO_BUTTON, 50, 55, 80, 30, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    obj = fl_add_labelframe( FL_ENGRAVED_FRAME, 180, 45, 100, 120, "CrossB" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    obj = fl_add_crossbutton( FL_PUSH_BUTTON, 190, 115, 80, 30, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_RED );

    obj = fl_add_crossbutton( FL_PUSH_BUTTON, 190, 85, 90, 30, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_GREEN );

    obj = fl_add_crossbutton( FL_PUSH_BUTTON, 190, 55, 80, 30, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    fdui->bexit = fl_add_button( FL_NORMAL_BUTTON, 125, 10, 65, 25, "Exit" );

    fl_end_form( );

    fl_set_border_width( oldbw );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
