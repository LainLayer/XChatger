/*
 *  This file is part of the XForms library package.
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
 * \file goodie_yesno.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <ctype.h>


/************* Ask yes/no question **********************{****/

typedef struct
{
    FL_FORM   * form;
    FL_OBJECT * str;
    FL_OBJECT * yes;
    FL_OBJECT * no;
} FD_yesno;


/***************************************
 ***************************************/

static FD_yesno *
create_yesno( void )
{
    FD_yesno *fdui = malloc( sizeof *fdui );
    int oldy = fli_inverted_y;
    int oldu = fl_get_coordunit( );

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fdui->form = fl_bgn_form( FL_FLAT_BOX, 460, 130 );
    fl_set_form_title( fdui->form, "Question" );

    fdui->str = fl_add_box( FL_FLAT_BOX, 20, 15, 420, 65, "" );

    fdui->yes = fl_add_button( FL_NORMAL_BUTTON, 85, 90, 80, 27, "Yes" );
    fl_set_button_shortcut( fdui->yes, "Yy", 1 );

    fdui->no = fl_add_button( FL_NORMAL_BUTTON, 295, 90, 80, 27, "No" );
    fl_set_button_shortcut( fdui->no, "Nn", 1 );

    fli_add_q_icon( 10, 20, 33, 33 );

    fl_end_form( );

    fl_register_raw_callback( fdui->form, FL_ALL_EVENT,
                              fli_goodies_preemptive );

    fl_set_form_atclose( fdui->form, fl_goodies_atclose, fdui->no );

    if ( fli_cntl.buttonFontSize != FL_DEFAULT_SIZE )
        fl_fit_object_label( fdui->no, 22, 2 );

    fli_inverted_y = oldy;
    fl_set_coordunit( oldu );

    return fdui;
}


static FD_yesno *fd_yesno = NULL;
static int default_ans;


/***************************************
 * Shows a question with two buttons, yes and no
 ***************************************/

int
fl_show_question( const char * str,
                  int          ans )
{
    FL_OBJECT *retobj;
    char shortcut[ 4 ];
    int k = 0;

    if ( fd_yesno )
    {
        fl_hide_form( fd_yesno->form );
        fl_free_form( fd_yesno->form );
        fl_free( fd_yesno );
    }
    else
        fl_deactivate_all_forms( );

    fd_yesno = create_yesno( );

    default_ans = ans;

    fli_parse_goodies_label( fd_yesno->yes, FLQuestionYesLabel );
    fli_parse_goodies_label( fd_yesno->no, FLQuestionNoLabel );

    /* We don't set a shortcut if the first letter of the "yes" label
       is identical to all letters in the "no" label */

    while (    fd_yesno->no->label[ k ]
            && tolower( ( int ) fd_yesno->yes->label[ 0 ] ) ==
                                 tolower( ( int ) fd_yesno->yes->label[ k ] ) )
        k++;

    if ( fd_yesno->no->label[ k ] )
    {
        shortcut[ 0 ] = fd_yesno->yes->label[ 0 ];
        shortcut[ 1 ] = tolower( ( int ) fd_yesno->yes->label[ 0 ] );
        shortcut[ 2 ] = toupper( ( int ) fd_yesno->yes->label[ 0 ] );
        shortcut[ 3 ] = '\0';
        fl_set_button_shortcut( fd_yesno->yes, shortcut, 1 );

        shortcut[ 0 ] = fd_yesno->no->label[ k ];
        shortcut[ 1 ] = toupper( ( int ) fd_yesno->no->label[ k ] );
        shortcut[ 2 ] = tolower( ( int ) fd_yesno->no->label[ k ] );
        fl_set_button_shortcut( fd_yesno->no, shortcut, 1 );
    }

    fli_get_goodie_title( fd_yesno->form, FLQuestionTitle );
    fli_handle_goodie_font( fd_yesno->yes, fd_yesno->str );
    fli_handle_goodie_font( fd_yesno->no, NULL );

    fl_set_object_label( fd_yesno->str, str );

    if ( ans == 1 )
        fl_set_form_hotobject( fd_yesno->form, fd_yesno->yes );
    else if ( ans == 0 )
        fl_set_form_hotobject( fd_yesno->form, fd_yesno->no );
    else
        fl_set_form_hotspot( fd_yesno->form, -1, -1 );

    fl_show_form( fd_yesno->form, FL_PLACE_HOTSPOT, FL_TRANSIENT,
                  fd_yesno->form->label );
    fl_update_display( 0 );

    while ( ( retobj = fl_do_only_forms( ) ) != fd_yesno->yes
            && retobj != fd_yesno->no )
        /* empty */;

    k = retobj == fd_yesno->yes;

    fl_hide_form( fd_yesno->form );
    fl_free_form( fd_yesno->form );
    fli_safe_free( fd_yesno );
    fl_activate_all_forms( );

    return k;
}


/***************************************
 ***************************************/

void
fl_hide_question( void )
{
    if ( fd_yesno )
        fl_trigger_object( default_ans == 1 ? fd_yesno->yes : fd_yesno->no );
    else
        M_warn( "fl_hide_question", "No question box is shown" );
}


/***************************************
 ***************************************/

void
fli_question_cleanup( void )
{
    fli_safe_free( fd_yesno );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
