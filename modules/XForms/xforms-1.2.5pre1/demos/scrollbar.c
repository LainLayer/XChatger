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
 * scrollbar functionality check-out
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>
#include "fd/scrollbar_gui.h"   /* from fd/ directory */


/***************************************
 ***************************************/

void hide_cb( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
    FD_scb *fdui = ob->form->fdui;

    if ( fl_object_is_visible( fdui->hor_thin ) )
    {
        fl_set_object_label( fdui->hide,"Show" );
        fl_hide_object( fdui->hor_thin );
    }
    else
    {
        fl_set_object_label( fdui->hide,"Hide" );
        fl_show_object( fdui->hor_thin );
    }
}


/***************************************
 ***************************************/

void deactivate_cb( FL_OBJECT * ob,
                    long        data  FL_UNUSED_ARG )
{
    FD_scb *fdui = ob->form->fdui;

    if ( fl_object_is_active( fdui->hor_thin ) )
    {
        fl_set_object_label( fdui->deactivate,"Activate" );
        fl_deactivate_object( fdui->hor_thin );
    }
    else
    {
        fl_set_object_label( fdui->deactivate,"Deactivate" );
        fl_activate_object( fdui->hor_thin );
    }
}


/***************************************
 ***************************************/

void done_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
              long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void noop_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
              long        data  FL_UNUSED_ARG )
{
}


/***************************************
 ***************************************/

int main( int    argc,
          char * argv[ ] )
{
    FD_scb *fd_scb;

    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_scb = create_form_scb( );

    fl_show_form( fd_scb->scb, FL_PLACE_CENTERFREE, FL_FULLBORDER, "form0" );

    fl_do_forms( );
    fl_finish( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
