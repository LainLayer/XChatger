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
 * All button types
 *
 * This file is part of xforms package
 * T.C. Zhao and M. Overmars   (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd/butttypes_gui.h"
#include <stdlib.h>


/* callbacks for form form0 */

/***************************************
 ***************************************/

void
button_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
    FD_form0 *ui = ( FD_form0 * ) ob->form->fdui;
    char buf[ 128 ];

    if ( ob->type == FL_HIDDEN_BUTTON )
    {
       if ( fl_show_question( "Want to Quit ?", 1 ) == 1 )
       {
           fl_free( ob->form->fdui );
           fl_finish( );
           exit( 0 );
       }
    }
    else
    {
       sprintf( buf, "%s callback called: %d", ob->label, fl_get_button( ob ) );
       fl_addto_browser( ui->br, buf );
    }
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_form0 *fd_form0;

    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_form0 = create_form_form0( );

    /* fill-in form initialization code */

    /* show the first form */

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
