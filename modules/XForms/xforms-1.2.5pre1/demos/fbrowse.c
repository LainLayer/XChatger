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
 * This demo shows the use of a browser and a file selector.
 * Good browser/scrollbar test
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "include/forms.h"

typedef struct {
    FL_FORM *   form;
    void *      vdata;
    char *      cdata;
    long        ldata;
    FL_OBJECT * br;
} FD_form;


/***************************************
 ***************************************/

void
load_file( FL_OBJECT * ob,
           long        arg  FL_UNUSED_ARG )
{
    const char *fname;
    FD_form *fdui = ob->form->fdui;

    if ( ( fname = fl_show_file_selector( "File To Load", "", "*", "" ) ) )
    {
        if ( ! fl_load_browser( fdui->br, fname ) )
            fl_add_browser_line( fdui->br,"NO SUCH FILE!" );
    }
}


/***************************************
 ***************************************/

void
set_size( FL_OBJECT * ob,
          long        arg)
{
    FD_form *fdui = ob->form->fdui;

    fl_set_browser_fontsize( fdui->br, arg );
}


/***************************************
 ***************************************/

void
exit_program( FL_OBJECT * ob    FL_UNUSED_ARG,
              long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void
hide_show( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
    FD_form *fdui = ob->form->fdui;

    if ( fl_object_is_visible( fdui->br ) )
        fl_hide_object( fdui->br );
    else
        fl_show_object( fdui->br );
}


/***************************************
 ***************************************/

FD_form *
create_form( void )
{
    FL_OBJECT *obj;
    FL_Coord x  = 20,
             dx = 80,
             dy = 28;
    FD_form *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->form = fl_bgn_form( FL_NO_BOX, 590, 610 );

    fl_add_box( FL_UP_BOX, 0, 0, 590, 610, "" );

    fdui->br = obj = fl_add_browser( FL_NORMAL_BROWSER, 20, 20, 550, 530, "" );

    obj = fl_add_button( FL_NORMAL_BUTTON, x, 565, dx-5, dy, "Load" );
    fl_set_object_callback( obj, load_file, 0 );
    x += dx ;

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, x, 565, dx, dy, "Tiny" );
    fl_set_object_callback( obj, set_size, FL_TINY_SIZE );
    x += dx;

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, x , 565, dx, dy, "Small" );
    fl_set_object_callback( obj, set_size, FL_SMALL_SIZE );
    fl_set_button( obj, FL_SMALL_SIZE == FL_BROWSER_FONTSIZE );
    x += dx;

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, x , 565, dx, dy, "Normal" );
    fl_set_object_callback( obj, set_size, FL_NORMAL_SIZE );
    fl_set_button( obj, FL_NORMAL_SIZE == FL_BROWSER_FONTSIZE );
    x += dx;

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, x , 565, dx, dy, "Large" );
    fl_set_object_callback( obj, set_size, FL_LARGE_SIZE );
    x += dx + 4;

    obj = fl_add_button( FL_NORMAL_BUTTON, x, 565, dx, dy, "Hide/Show" );
    fl_set_object_callback( obj, hide_show, 0 );
    x += dx + 5;

    obj = fl_add_button( FL_NORMAL_BUTTON, x, 565, 60, dy, "Exit" );
    fl_set_object_callback( obj, exit_program, 0 );

    fl_end_form();

    fl_adjust_form_size( fdui->form );
    fdui->form->fdui = fdui;

    return fdui;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
   FD_form *fdui;
   FL_OBJECT *o;

   fl_initialize( &argc, argv, "FormDemo", 0, 0 );

   fdui = create_form( );

   fl_clear_browser( fdui->br );
   fl_add_browser_line( fdui->br, "LOAD A FILE." );
   fl_set_browser_fontstyle( fdui->br,FL_FIXED_STYLE );

   fl_show_form( fdui->form, FL_PLACE_FREE, FL_FULLBORDER, "Browser" );

   o = fl_do_forms( );
   fprintf( stderr, "%p %d %s\n", o, o->objclass, o->label ? o->label: "" );

   fl_hide_form( fdui->form );

   fl_finish( );
   return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
