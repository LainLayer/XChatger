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
 * \file goodie_msg.c
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
#include "private/flvasprintf.h"


/*************** Three line messages *******************{*****/

typedef struct
{
    FL_FORM   * form;
    FL_OBJECT * str;
    FL_OBJECT * but;
} FD_msg;


/***************************************
 ***************************************/

static FD_msg *
create_msg( const char * str )
{
    FD_msg *fdui = fl_calloc( 1, sizeof *fdui );
    int oldy = fli_inverted_y;
    int oldu = fl_get_coordunit( );
    int style,
        size;
    int w_msg,
        h_msg,
        w_but,
        h_but;
    int box_w,
        box_h,
        but_w;
    char but_text[ 256 ] = "Ok";

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fli_get_goodies_font( &style, &size );

    /* Get size of box that fits the message. The message will have 20 px
       around spacing it (and the box a minimum width of 400 px) */

    fl_get_string_dimension( style, size, str, strlen( str ), &w_msg, &h_msg );

    box_w = FL_max( 400, w_msg + 40 );
    box_h = h_msg + 40;

    /* Get the text for the button (default is "Ok") and the size needed for
       it. The button should have at least 20 px space to the left and right
       and 10 px inner horizontal margins (and a minimum width of 90 px).
       Vertical inner margins are 5 px and the button should have 10 px
       spacing to the lower border of the box. */

    fl_get_resource( FLOKLabel, NULL, FL_STRING, NULL, but_text, 256 );

    fl_get_string_dimension( style, size, but_text, strlen( but_text ),
                             &w_but, &h_but );

    but_w = FL_max( 90, w_but + 20 );

    box_w = FL_max( box_w, but_w + 40 );
    box_h += h_but + 20;

    fdui->form = fl_bgn_form( FL_FLAT_BOX, box_w, box_h );

    fdui->str = fl_add_box( FL_FLAT_BOX, ( box_w - w_msg ) / 2, 20,
                            w_msg, h_msg, str );
    fl_set_object_lstyle( fdui->str, style );
    fl_set_object_lsize( fdui->str, size );

    fdui->but = fl_add_button( FL_RETURN_BUTTON, ( box_w - but_w ) / 2,
                               box_h - h_but - 20, but_w, h_but + 10, "Ok" );
    fl_set_form_hotobject( fdui->form, fdui->but );
    fl_set_object_lstyle( fdui->but, style );
    fl_set_object_lsize( fdui->but, size );

    fl_end_form( );

    fl_register_raw_callback( fdui->form, FL_ALL_EVENT,
                              fli_goodies_preemptive );

    fl_set_form_atclose( fdui->form, fl_goodies_atclose, fdui->but );

    fli_inverted_y = oldy;
    fl_set_coordunit( oldu );

    return fdui;
}


static FD_msg *fd_msg = NULL;


/***************************************
 ***************************************/

void
fl_show_messages( const char *str )
{
    if ( ! str || ! * str )
    {
        M_warn( "fl_show_messages", "NULL or empty string" );
        return;
    }

    if ( fd_msg )
    {
        fl_hide_form( fd_msg->form );
        fl_free_form( fd_msg->form );
        fli_safe_free( fd_msg );
    }
    else
        fl_deactivate_all_forms( );

    fd_msg = create_msg( str );

    fl_show_form( fd_msg->form, FL_PLACE_HOTSPOT, FL_TRANSIENT, "Message" );

    fl_update_display( 1 );

    while ( fl_do_only_forms( ) != fd_msg->but )
        /* empty */ ;

    fl_hide_form( fd_msg->form );
    fl_free_form( fd_msg->form );
    fli_safe_free( fd_msg );
    fl_activate_all_forms( );
}


/***************************************
 ***************************************/

void
fl_show_messages_f( const char * fmt,
                    ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_show_messages( buf );
    fl_free( buf );
}


/***************************************
 ***************************************/

void
fl_show_message( const char * s1,
                 const char * s2,
                 const char * s3 )
{
    char *buf;
    size_t len;

    len =   ( s1 ? strlen( s1 ) : 0 ) + 1
          + ( s2 ? strlen( s2 ) : 0 ) + 1
          + ( s3 ? strlen( s3 ) : 0 ) + 1;

    if ( len == 3 )
    {
        M_warn( "fl_show_message", "Only NULL or empty strings" );
        return;
    }

    buf = fl_malloc( len );

    fli_snprintf( buf, len, "%s\n%s\n%s",
                  s1 ? s1 : "", s2 ? s2 : "", s3 ? s3 : "" );

    fl_show_messages( buf );

    fl_free( buf );
}


/***************************************
 ***************************************/

void
fl_hide_message( void )
{
    if ( fd_msg )
        fl_trigger_object( fd_msg->but );
    else
        M_warn( "fl_hide_message", "No message box is shown" );
}


/***************************************
 ***************************************/

void
fli_msg_cleanup( void )
{
    fli_safe_free( fd_msg );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
