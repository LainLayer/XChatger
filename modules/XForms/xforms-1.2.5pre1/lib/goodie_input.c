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
 * \file goodie_input.c
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
#include <stdlib.h>


typedef struct
{
    FL_FORM   * form;
    FL_OBJECT * input;
    FL_OBJECT * cancel;
    FL_OBJECT * clear;
    FL_OBJECT * ok;
} FD_input;


/***************************************
 * Callback for "Clear" button
 ***************************************/

static void
clear_cb( FL_OBJECT * ob,
          long        data  FL_UNUSED_ARG )
{
    fl_set_input( ( ( FD_input * ) ob->form->fdui )->input, "" );
}


/***************************************
 ***************************************/

static FD_input *
create_form_input( const char *str1,
                   const char *defstr )
{
    FL_OBJECT *obj;
    FD_input *fdui = fl_calloc( 1, sizeof *fdui );
    int oldy = fli_inverted_y;
    int oldu = fl_get_coordunit( );

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fdui->form = fl_bgn_form( FL_FLAT_BOX, 410, 120 );
    fl_set_form_title( fdui->form, "Input" );

    fl_add_frame( FL_ENGRAVED_FRAME, 8, 9, 394, 67, "" );

    fdui->input = obj = fl_add_input( FL_NORMAL_INPUT, 20, 33, 370, 30, str1 );
    fl_set_object_lalign( obj, FL_ALIGN_LEFT_TOP );
    fl_set_input( obj, defstr );

    fdui->cancel = obj = fl_add_button( FL_NORMAL_BUTTON, 30, 85, 80, 26,
                                        "Cancel" );
    fli_parse_goodies_label( obj, FLInputCancelLabel );
    fl_set_button_shortcut( obj, "^[", 1 );

    fdui->clear = obj = fl_add_button( FL_NORMAL_BUTTON, 300, 85, 80, 26,
                                       "Clear" );
    fli_parse_goodies_label( obj, FLInputClearLabel );
    fl_set_object_callback( obj, clear_cb, 0 );

    fdui->ok = obj = fl_add_button( FL_RETURN_BUTTON, 165, 85, 80, 26, "Ok" );
    fli_parse_goodies_label( obj, FLOKLabel );

    fl_end_form( );

    fl_adjust_form_size( fdui->form );

    fdui->form->fdui = fdui;

    fl_set_form_hotobject( fdui->form, fdui->ok );
    fl_set_form_atclose( fdui->form, fl_goodies_atclose, fdui->ok );
    fl_register_raw_callback( fdui->form, FL_ALL_EVENT,
                              fli_goodies_preemptive );

    fli_handle_goodie_font( fdui->ok, fdui->input );
    fli_handle_goodie_font( fdui->cancel, fdui->clear );

    fli_get_goodie_title( fdui->form, FLInputTitle );

    fli_inverted_y = oldy;
    fl_set_coordunit( oldu );

    return fdui;
}


static FD_input *fd_input = NULL;
static char *ret_str = NULL;


/***************************************
 * Asks the user for textual input
 ***************************************/

const char *
fl_show_input( const char *str1,
               const char *defstr )
{
    FL_OBJECT *retobj;

    if ( fd_input )
    {
        fl_hide_form( fd_input->form );
        fl_free_form( fd_input->form );
        fli_safe_free( fd_input );
    }
    else
        fl_deactivate_all_forms( );

    fli_safe_free( ret_str );

    fd_input = create_form_input( str1, defstr );

    fl_show_form( fd_input->form, FL_PLACE_HOTSPOT, FL_TRANSIENT,
                  fd_input->form->label );

    fl_update_display( 0 );

    /* Grab keyboard focus */

    fl_winfocus( fd_input->form->window );

    while (    ( retobj = fl_do_only_forms( ) ) != fd_input->ok
            && retobj != fd_input->cancel )
        /* empty */ ;

    if ( retobj == fd_input->ok )
        ret_str = fl_strdup( fl_get_input( fd_input->input ) );

    fl_hide_form( fd_input->form );
    fl_free_form( fd_input->form );
    fli_safe_free( fd_input );

    fl_activate_all_forms( );

    return ret_str;
}


/***************************************
 ***************************************/

void
fl_hide_input( void )
{
    if ( fd_input )
        fl_trigger_object( fd_input->cancel );
    else
        M_warn( "fl_hide_input", "No input box is shown" );
}


/***************************************
 ***************************************/

void
fli_input_cleanup( void )
{
    fli_safe_free( fd_input );
    fli_safe_free( ret_str );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
