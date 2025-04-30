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
#include "fd/formbrowser_gui.h"


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
hide_show_cb( FL_OBJECT * ob,
              long        data )
{
    FD_mainform *fdui = ob->form->fdui;

    ( data ? fl_show_object : fl_hide_object )( fdui->formbrowser );
}


/***************************************
 ***************************************/

void
reshow_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
    fl_hide_form( ob->form );
    fl_show_form( ob->form, FL_PLACE_POSITION, FL_FULLBORDER, "formbrowser" );
}


/***************************************
 ***************************************/

void
scroll_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
     static int n;
     FD_mainform *fdui = ob->form->fdui;

     fl_set_object_label( ob, n ? "Jump" : "Smooth" );
     fl_set_formbrowser_scroll( fdui->formbrowser, n ^= 1 );
}


/***************************************
 ***************************************/

void
deactivate_cb( FL_OBJECT * ob,
               long        data  FL_UNUSED_ARG )
{
    FD_mainform *fdui = ob->form->fdui;

    if ( fl_object_is_active( fdui->formbrowser ) )
    {
        fl_set_object_label( ob, "Activate" );
        fl_deactivate_object( fdui->formbrowser );
    }
    else
    {
        fl_set_object_label( ob,"Deactivate" );
        fl_activate_object( fdui->formbrowser );
    }
}


/***************************************
 ***************************************/

int main( int    argc,
          char * argv[ ] )
{
    FD_buttonform *fd_buttonform;
    FD_staticform *fd_staticform;
    FD_mainform *fd_mainform;
    FD_valuatorform *fd_valuatorform;
    FD_choiceform *fd_choiceform;
    FD_big *fd_big;

    fl_set_border_width( -2 );
    fl_initialize( &argc, argv, 0, 0, 0 );

    fd_buttonform = create_form_buttonform( );
    fd_staticform = create_form_staticform( );
    fd_mainform = create_form_mainform( );
    fd_valuatorform = create_form_valuatorform( );
    fd_choiceform = create_form_choiceform( );
    create_form_inputform( );

    fd_big = create_form_big( );
    {
        float xx[ 5 ] = { 1, 2, 3, 4, 5 };
        float yy[ 5 ] = { 1, 2, 3, 4, 5 };

        fl_set_xyplot_data( fd_big->xyplot, xx, yy, 5, "title", "x", "y" );
    }

	/* fl_set_object_boxtype( fd_mainform->formbrowser, FL_SHADOW_BOX ); */

    fl_addto_formbrowser( fd_mainform->formbrowser, fd_buttonform->buttonform );
    fl_addto_formbrowser( fd_mainform->formbrowser,
                          fd_valuatorform->valuatorform);
    fl_addto_formbrowser( fd_mainform->formbrowser, fd_big->big);
    fl_addto_formbrowser( fd_mainform->formbrowser, fd_choiceform->choiceform );
    fl_addto_formbrowser( fd_mainform->formbrowser, fd_staticform->staticform );

    /* show the first form */

    fl_show_form( fd_mainform->mainform,
                  FL_PLACE_CENTERFREE, FL_FULLBORDER, "buttonform" );

    fl_do_forms( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
