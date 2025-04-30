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
 * Tabbed folder demo and tester
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd/folder_gui.h"
#include <stdlib.h>


static void make_folder( FL_OBJECT * );


/* callback routines */

/***************************************
 ***************************************/

void
hide_show_cb( FL_OBJECT * ob,
              long        data )
{
    FD_mainform *fdui = ob->form->fdui;

    ( data ? fl_show_object : fl_hide_object )( fdui->folder );
}


/***************************************
 ***************************************/

void
reshow_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
   fl_hide_form( ob->form );
   fl_show_form( ob->form, FL_PLACE_CENTER, FL_FULLBORDER, "TabFolder" );

}

/***************************************
 ***************************************/

void
set_cb( FL_OBJECT * ob,
        long        data  FL_UNUSED_ARG )
{
    FD_mainform *fdui = ob->form->fdui;
    int n = fl_get_active_folder_number( fdui->folder );

    fl_set_folder_bynumber( fdui->folder, n % 5 + 1 );
}


/***************************************
 ***************************************/

void
deactivate_cb( FL_OBJECT * ob,
               long        data  FL_UNUSED_ARG )
{
    FD_mainform *fdui = ob->form->fdui;

    if ( fl_object_is_active( fdui->folder ) )
    {
        fl_set_object_label( ob, "Activate" );
        fl_deactivate_object( fdui->folder );
    }
    else
    {
        fl_set_object_label( ob, "Deactivate" );
        fl_activate_object( fdui->folder );
    }
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
    FD_mainform *fd_mainform;

    fl_set_border_width( -2 );
    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_mainform = create_form_mainform( );

    make_folder( fd_mainform->folder );

    /* show the first form */

    fl_show_form( fd_mainform->mainform, FL_PLACE_CENTER, FL_FULLBORDER,
                  "TabFolder" );

    while ( fl_do_forms( ) )
        /* empty */ ;

   return 0;
}


/***************************************
 ***************************************/

static void
make_folder( FL_OBJECT * folder  FL_UNUSED_ARG )
{
    FD_buttonform *fd_buttonform;
    FD_staticform *fd_staticform;
    FD_valuatorform *fd_valuatorform;
    FD_choiceform *fd_choiceform;
    FD_inputform *fd_inputform;
    float y[ 6 ] = { 5.5, 4, 4.5, 3.8, 4, 5 };
    char *label[ ] = { "Mon", "Tue", "Wed", "Thur", "Fri", "Sat" };
    size_t i;
    int xx,
        yy,
        ww,
        hh;

    fd_buttonform = create_form_buttonform( );
    fd_staticform = create_form_staticform( );
    fd_valuatorform = create_form_valuatorform( );
    fd_choiceform = create_form_choiceform( );
    fd_inputform = create_form_inputform( );

    /* form initialization code */

    for ( i = 0; i < sizeof y / sizeof *y; i++ )
        fl_add_chart_value( fd_staticform->chart, y[ i ], label[ i ], i + 1 );

    fl_addto_menu( fd_choiceform->pulldown,
                   "MenuEntry1|MenuEntry2|MenuEntry3|MenuEntry4" );
    fl_addto_menu( fd_choiceform->pushmenu,
                   "MenuEntry1|MenuEntry2|MenuEntry3" );
    fl_addto_choice( fd_choiceform->choice,
                     "Choice1|Choice2|Choice3|Choice4|Choice5|Choice6" );

    fl_load_browser( fd_choiceform->browser, "01Readme" );

    fl_get_folder_area( folder, &xx, &yy, &ww, &hh );
    fl_addto_tabfolder( folder, "ButtonObj", fd_buttonform->buttonform );
    fl_addto_tabfolder( folder, "StaticObj", fd_staticform->staticform );
    fl_addto_tabfolder( folder, "ValuatorObj", fd_valuatorform->valuatorform );
    fl_addto_tabfolder( folder, "ChoiceObj", fd_choiceform->choiceform );
    fl_addto_tabfolder( folder, "InputObj", fd_inputform->inputform );
    fl_get_folder_area( folder, &xx, &yy, &ww, &hh );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
