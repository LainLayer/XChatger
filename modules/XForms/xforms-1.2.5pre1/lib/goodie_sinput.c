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
 * \file goodie_sinput.c
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


/***********    Simple input    ********************{*******/

typedef struct
{
    FL_FORM   * form;
    FL_OBJECT * str1;
    FL_OBJECT * input;
    FL_OBJECT * but;
} FD_input;


/***************************************
 ***************************************/

static FD_input *
create_input( const char * str1,
              const char * defstr )
{
    FD_input *fdui = fl_calloc( 1, sizeof *fdui );
    int oldy = fli_inverted_y;
    int oldu = fl_get_coordunit( );

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fdui->form = fl_bgn_form( FL_FLAT_BOX, 460, 130 );

    fdui->input = fl_add_input( FL_NORMAL_INPUT, 30, 50, 400, 30, str1 );
    fl_set_input( fdui->input, defstr );

    fdui->but = fl_add_button( FL_RETURN_BUTTON, 185, 94, 90, 27, "OK" );
    fli_parse_goodies_label( fdui->but, FLOKLabel );

    fl_set_form_hotobject( fdui->form, fdui->but );

    fl_end_form( );

    fli_handle_goodie_font( fdui->but, fdui->input );

    fl_register_raw_callback( fdui->form, FL_ALL_EVENT,
                              fli_goodies_preemptive );
    fl_set_form_atclose( fdui->form, fl_goodies_atclose, fdui->but );

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
fl_show_simple_input( const char * str1,
                      const char * defstr )
{
    if ( fd_input )
    {
        fl_hide_form( fd_input->form );
        fl_free_form( fd_input->form );
        fli_safe_free( fd_input );
    }
    else
        fl_deactivate_all_forms( );

    fli_safe_free( ret_str );

    fd_input = create_input( str1, defstr );

    fl_show_form( fd_input->form, FL_PLACE_HOTSPOT, FL_TRANSIENT, "Input" );
    fl_update_display( 0 );

    while ( fl_do_only_forms( ) != fd_input->but )
        /* empty */ ;

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
fli_sinput_cleanup( void )
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
