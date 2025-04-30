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
 * test of fl_get_dirlist() and its kin.
 *
 * This file is part of xforms package
 * T.C. Zhao and M. Overmars (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <time.h>
#include <stdlib.h>
#include "fd/fbtest_gui.h"


/***************************************
 ***************************************/

static void
fill_browser( FL_OBJECT * ob )
{
    FD_fbform *fdui = ( FD_fbform * ) ob->form->fdui;
    int nfiles = 0;
    const FL_Dirlist *dl = fl_get_dirlist( ".", "*", &nfiles, 0 );
    const FL_Dirlist *ds;
    const FL_Dirlist *dlend = dl + nfiles;
    char buf[ 2048 ];

    fl_freeze_form( ob->form );
    sprintf( buf,"Total %d files", nfiles );
    fl_set_object_label( fdui->total, buf );
    fl_clear_browser( fdui->browser );

    for ( ds = dl; ds < dlend; ds++ )
    {
        sprintf( buf, "%-20s\t\t%5ldK\t%s", ds->name, ds->dl_size >> 10,
                 ctime( &ds->dl_mtime ) + 3 );
        fl_addto_browser_chars( fdui->browser, buf );
    }

    fl_free_dirlist( dl );
    fl_unfreeze_form( ob->form );
}


/* callbacks and freeobj handles for form fbform */

/***************************************
 ***************************************/

void
sort_method_cb( FL_OBJECT * ob,
                long        data )
{
    fl_set_dirlist_sort( data );
    fill_browser( ob );
}


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

int
main( int    argc,
      char * argv[ ] )
{
    FD_fbform *fd_fbform;

    fl_initialize( &argc, argv, "FormDemo", NULL, 0 );
    fd_fbform = create_form_fbform( );
    fl_set_browser_fontstyle( fd_fbform->browser, FL_FIXED_STYLE );

    /* fill-in form initialization code */

    fill_browser( fd_fbform->browser );

    /* show the first form */

    fl_show_form( fd_fbform->fbform, FL_PLACE_CENTERFREE, FL_FULLBORDER,
                  "fbform" );

    fl_do_forms( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
