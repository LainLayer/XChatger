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
#include <stdlib.h>


typedef struct {
    FL_FORM   * form0;
    void      * vdata;
    long        ldata;
    FL_OBJECT * text;
} FD_form0;


static FD_form0 * fd_form0;


/***************************************
 ***************************************/

static void
exit_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

static void
input_cb( FL_OBJECT * ob,
          long        data  FL_UNUSED_ARG )
{
    const char * s = fl_get_input( ob );
    int w = fl_get_string_width( ob->lstyle, ob->lsize, s, strlen( s ) );
    int h = fl_get_string_height( ob->lstyle, ob->lsize, s, strlen( s ), 0, 0 );
    char buf[ 50 ];

    sprintf( buf, "w = %d, h = %d", w, h );
    fl_set_object_label( fd_form0->text, buf );
}


/***************************************
 ***************************************/

static FD_form0 *
create_form_form0( void )
{
    FL_OBJECT * obj;
    FD_form0 * fdui = fl_calloc( 1, sizeof *fdui );

    fdui->form0 = fl_bgn_form( FL_FLAT_BOX, 311, 181 );

    obj = fl_add_input( FL_NORMAL_INPUT, 20, 30, 280, 30, "" );
    fl_set_object_callback( obj, input_cb, 0 );
    fl_set_object_return( obj, FL_RETURN_ALWAYS );

    fdui->text = obj = fl_add_text( FL_NORMAL_TEXT, 60, 90, 130, 30, "Text" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_LEFT ) );

    obj = fl_add_button( FL_NORMAL_BUTTON, 220, 130, 80, 30, "Done" );
    fl_set_object_callback( obj, exit_cb, 0 );

    fl_end_form( );

    return fdui;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, 0, 0, 0 );

    fd_form0 = create_form_form0( );

    fl_show_form( fd_form0->form0, FL_PLACE_CENTER, FL_FULLBORDER, "form0" );

    fl_do_forms( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
