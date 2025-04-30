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
 * menubar routines demo.
 *
 *  T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "include/forms.h"
#include "bm1.xbm"
#include "bm2.xbm"

typedef struct {
    FL_FORM * menubar;
    void    * vdata;
    long      ldata;
} FD_menubar;

extern FD_menubar *create_form_menubar( void );


/***************************************
 ***************************************/

void
done_cb( FL_OBJECT * ob,
         long        data )
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
    FD_menubar *fd_menubar;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_menubar = create_form_menubar( );

    fl_show_form( fd_menubar->menubar, FL_PLACE_CENTER, FL_FULLBORDER,
                  "menubar" );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}


FL_PUP_ENTRY file_menu[ ] = { { "_Open" },
                              { "Save" },
                              { "_Save As ..." },
                              { "Exit" },
                              { NULL }
                            };


/***************************************
 ***************************************/

FD_menubar *
create_form_menubar( void )
{
    FL_OBJECT *obj;
    FD_menubar *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->menubar = fl_bgn_form( FL_NO_BOX, 325, 175 );

    fl_add_box( FL_UP_BOX, 0, 0, 325, 175, "" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 250, 140, 60, 25, "Done" );
    fl_set_object_callback( obj, done_cb, 0 );

    fl_add_menubar( 0, 0, 0, 325, 30, "test" );

    fl_end_form( );

   fl_set_menubar( obj, "File|Message|Find" );
   fl_set_menubar_entries( obj,"File", file_menu );

   return fdui;
}
/*---------------------------------------*/


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
