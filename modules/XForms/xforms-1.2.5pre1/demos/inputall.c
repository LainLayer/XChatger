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
 * Show all the input field types
 *
 * This file is part of xforms package.
 *  T.C. Zhao and M. Overmars, 1997
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd/inputall_gui.h"
#include <stdlib.h>

/* callbacks for form input */

/***************************************
 ***************************************/

void
done_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void
input_cb( FL_OBJECT * ob,
          long        data  FL_UNUSED_ARG )
{
    int cx,
        cy;
    char buf[ 128 ];

    fl_get_input_cursorpos( ob, &cx, &cy );
    sprintf( buf,"x = %d y = %d", cx, cy );
    fl_set_object_label( ( ( FD_input * ) ob->form->fdui )->report, buf );
}


/***************************************
 ***************************************/

void
hide_show_cb( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
    FD_input *fd = ob->form->fdui;

    if ( fl_object_is_visible( fd->multiinput ) )
        fl_hide_object( fd->multiinput );
    else
        fl_show_object( fd->multiinput );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_input *fd_input;

    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_input = create_form_input( );

    fl_set_object_dblbuffer( fd_input->report, 1 );
    fl_set_object_return( fd_input->norminput, FL_RETURN_ALWAYS );
    fl_set_object_return( fd_input->intinput, FL_RETURN_ALWAYS );
    fl_set_object_return( fd_input->floatinput, FL_RETURN_ALWAYS );
    fl_set_object_return( fd_input->dateinput, FL_RETURN_ALWAYS );
    fl_set_object_return( fd_input->secretinput, FL_RETURN_ALWAYS );
    fl_set_object_return( fd_input->multiinput, FL_RETURN_ALWAYS );

    /* Show the form */

    fl_show_form( fd_input->input, FL_PLACE_CENTERFREE, FL_FULLBORDER,
                  "input" );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
