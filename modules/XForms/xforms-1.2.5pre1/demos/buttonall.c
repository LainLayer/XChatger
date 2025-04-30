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
 * All button classes
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd/buttons_gui.h"   /* from fd/ directory */
#include <stdlib.h>


/* callbacks for form buttform */

/***************************************
 ***************************************/

void done_cb( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
    fl_free( ob->form->fdui );
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void bw_cb( FL_OBJECT * ob,
            long        data  FL_UNUSED_ARG )
{
    int bws[ ] = { -4, -3, -2, -1, 1, 2, 3, 4 };
    int n = fl_get_choice( ob ) - 1;
    FD_buttform *fdui = ob->form->fdui;

    fl_freeze_form( ob->form );

    fl_set_object_bw( fdui->backface, bws[ n ] );
    fl_set_object_bw( fdui->objsgroup, bws[ n ] );
    fl_set_object_bw( fdui->done, bws[ n ] );

    fl_unfreeze_form( ob->form );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_buttform *fd_buttform;

    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_buttform = create_form_buttform( );

    /* fill-in form initialization code */

    fl_set_pixmapbutton_file( fd_buttform->pbutt,"crab45.xpm" );
    fl_set_bitmapbutton_file( fd_buttform->bbutt,"bm1.xbm" );
    fl_addto_choice( fd_buttform->bw_obj,
                     " -4 | -3 | -2 | -1 |  1|  2|  3|  4" );
    fl_set_choice( fd_buttform->bw_obj, 5 );

    /* show the first form */

    fl_show_form( fd_buttform->buttform, FL_PLACE_CENTER, FL_FULLBORDER,
                  "buttform" );

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
