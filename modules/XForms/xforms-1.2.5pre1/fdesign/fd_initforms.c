/*
 * This file is part of XForms.
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
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file fd_initforms.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  create and initialize all control panels
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd/ui_attrib.h"       /* from  directory fd */
#include "fd/ui_theforms.h" /* from  directory fd */

FD_control *fd_control;
FD_test *fd_test;
FD_align *fd_align;
FD_resize *fd_resize;
FD_helpform *fd_help;
FD_attrib *fd_attrib;
FD_generic_attrib *fd_generic_attrib;

extern int fd_helpfontsize;
extern int fd_align_fontsize,
           fd_type_fontsize;

static void init_helpform( void );
static void init_controlform( void );
static void init_attribform( void );
static void init_testform( void );


/***************************************
 ***************************************/

void
create_the_forms( void )
{
    static int init;

    if ( init )
    {
        fprintf( stderr, "fd forms already initialized\n" );
        return;
    }

    init = 1;

    fd_control = create_form_control( );
    init_controlform( );        /* GUI  */
    control_init( fd_control ); /* menu */

    fd_attrib = create_form_attrib( );
    fd_generic_attrib = create_form_generic_attrib( );

    init_attribform( );

    fd_test = create_form_test( );
    init_testform( );

    fd_align = create_form_align( );
    init_align( );

    fd_resize = create_form_resize( );

    /* Help form */

    fd_help = create_form_helpform( );
    init_helpform( );
}


/***************************************
 * Conditionally modify the basic color of attribute form
 ***************************************/

void
modify_attrib_basic_color( FL_COLOR col1,
                           FL_COLOR col2 )
{
    fl_set_object_color( fd_generic_attrib->text[ 0 ], col1, col2 );
    fl_set_object_color( fd_generic_attrib->text[ 1 ], col1, col2 );
    fl_set_object_color( fd_generic_attrib->text[ 2 ], col1, col2 );
    fl_set_object_color( fd_generic_attrib->text[ 3 ], col1, col2 );
    fl_set_object_color( fd_generic_attrib->background, col1, col2 );
}


/***************************************
 ***************************************/

void
clearlog_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
             long        data  FL_UNUSED_ARG )
{
    fl_clear_browser( fd_test->browser );
}


/***************************************
 ***************************************/

static void
init_helpform( void )
{
    fl_adjust_form_size( fd_help->helpform );
    fl_set_form_position( fd_help->helpform, -1, 1 );

    /* load one help */

    fl_set_button( fd_help->vbutt, 1 );
    fl_call_object_callback( fd_help->vbutt );
}


/***************************************
 ***************************************/

static void
init_controlform( void )
{
    /* sort of auto-resizing depending on the font size */

    if ( fli_cntl.buttonFontSize > FL_DEFAULT_SIZE )
    {
        fd_align_fontsize = FL_SMALL_SIZE;
        fd_type_fontsize = FL_SMALL_SIZE;
    }

    if ( fd_control->objectbrowser->lsize > FL_NORMAL_SIZE )
    {
        fl_set_object_lsize( fd_control->objectbrowser, FL_NORMAL_SIZE );
        fl_set_object_lsize( fd_control->formbrowser, FL_NORMAL_SIZE );
        fl_set_object_lsize( fd_control->groupbrowser, FL_NORMAL_SIZE );
    }

//    fl_fit_object_label( fd_control->renameform, 1, 0 );
//    fl_fit_object_label( fd_control->resizeform, 1, 0 );
    fl_fit_object_label( fd_control->objectmenu, -3, 0 );
}


/***************************************
 ***************************************/

static void
init_attribform( void )
{
    FL_OBJECT *t;

    if ( fl_get_visual_depth( ) <= 2 )
        modify_attrib_basic_color( FL_WHITE, FL_WHITE );

    fl_adjust_form_size( fd_attrib->attrib );
    fl_fit_object_label( fd_attrib->readyobj, 12, 1 );
    fd_attrib->attrib->y = 5;

    fl_set_tabfolder_autofit( fd_attrib->attrib_folder, FL_ENLARGE_ONLY );

    t = fl_addto_tabfolder( fd_attrib->attrib_folder, " Generic ",
                            fd_generic_attrib->generic_attrib );
    fl_set_object_shortcut( t, "#G", 1 );
}


/***************************************
 ***************************************/

static void
init_testform( void )
{
    fl_fit_object_label( fd_test->stoptesting, 2, 1 );
    fl_set_object_dblbuffer( fd_test->browser, 1 );
}


#include "fd/ui_attrib.c"
#include "fd/ui_theforms.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
