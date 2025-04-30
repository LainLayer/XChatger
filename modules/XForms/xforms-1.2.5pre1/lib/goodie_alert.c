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
 * \file goodie_alert.c
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


/****************** Alert dialog ********************{**/

typedef struct
{
    FL_FORM   * form;
    FL_OBJECT * str;
    FL_OBJECT * but;
    FL_OBJECT * title;
} FD_alert;


static FD_alert *fd_alert;


/***************************************
 ***************************************/

static FD_alert *
create_alert( const char * title,
              const char * msg )
{
    FD_alert *fdui = fl_calloc( 1, sizeof *fdui );
    int oldy = fli_inverted_y;
    int oldu = fl_get_coordunit( );
    int style,
        size;
    int w_tit = 0,
        h_tit = 0,
        w_msg = 0,
        h_msg = 0,
        w_but = 0,
        h_but;
    int box_w,
        box_h,
        but_w;
    char but_text[ 256 ] = "Dismiss";

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fli_get_goodies_font( &style, &size );

    if ( title )
        fl_get_string_dimension( FL_BOLD_STYLE, FL_NORMAL_SIZE,
                                 title, strlen( title ), &w_tit, &h_tit );

    if ( msg )
        fl_get_string_dimension( style, size, msg, strlen( msg ),
                                 &w_msg, &h_msg );

    fl_get_resource( FLAlertDismissLabel, NULL, FL_STRING, NULL,
                     but_text, 256 );

    fl_get_string_dimension( style, size, but_text, strlen( but_text ),
                             &w_but, &h_but );

    but_w = FL_max( 90, w_but + 20 );

    box_w = FL_max( 400, FL_max( FL_max( w_tit, w_msg ), but_w ) + 80 );
    box_h = FL_max( h_tit + 20, 30 ) + 5 + h_msg + 30 + h_but + 20;

    fdui->form = fl_bgn_form( FL_FLAT_BOX, box_w, box_h );
    fl_set_form_title( fdui->form, "Alert" );

    fli_get_goodie_title( fdui->form, FLAlertTitle );

    fdui->title = fl_add_box( FL_FLAT_BOX, 60, 10, box_w - 80, h_tit,
                              title ? title : "" );
    fl_set_object_lstyle( fdui->title, FL_BOLD_STYLE );
    fl_set_object_lsize( fdui->title, FL_NORMAL_SIZE );

    fli_add_warn_icon( 8, h_tit + 20 - 15, 35, 35 );

    fl_add_box( FL_FLAT_BOX, 50, h_tit + 20, box_w - 60, 5, "@DnLine" );

    fdui->str = fl_add_text( FL_FLAT_BOX, 60, h_tit + 35,
                             box_w - 80, h_msg + 10, msg ? msg : "" );
    fl_set_object_lalign( fdui->str, FL_ALIGN_CENTER );
    fl_set_object_lstyle( fdui->str, style );
    fl_set_object_lsize( fdui->str, size );

    fdui->but = fl_add_button( FL_RETURN_BUTTON, ( box_w - but_w ) / 2,
                               box_h - h_but - 20, but_w, h_but + 10,
                               but_text );
    fl_set_object_lstyle( fdui->but, style );
    fl_set_object_lsize( fdui->but, size );

    fl_set_form_hotobject( fdui->form, fdui->but );

    fl_end_form( );

    fl_register_raw_callback( fdui->form, FL_ALL_EVENT,
                              fli_goodies_preemptive );
    fl_set_form_atclose( fdui->form, fl_goodies_atclose, fdui->but );
    fdui->form->fdui = fdui;

    fli_inverted_y = oldy;
    fl_set_coordunit( oldu );

    return fdui;
}


/***************************************
 ***************************************/

static void
show_it( const char * title,
         const char * msg,
         int          c )
{
    if ( fd_alert )
    {
        fl_hide_form( fd_alert->form );
        fl_free_form( fd_alert->form );
        fd_alert = NULL;
    }

    fl_deactivate_all_forms( );

    fd_alert = create_alert( title, msg );

    fl_show_form( fd_alert->form, c ? FL_PLACE_CENTER : FL_PLACE_HOTSPOT,
                  FL_TRANSIENT, fd_alert->form->label );

    fl_update_display( 1 );

    while ( fl_do_only_forms( ) != fd_alert->but )
        /* empty */ ;

    fl_hide_form( fd_alert->form );
    fl_free_form( fd_alert->form );
    fli_safe_free( fd_alert );
    fl_activate_all_forms( );
}


/***************************************
 * Show a simple message with an alert icon and a dismiss button
 ***************************************/

void
fl_show_alert( const char * title,
               const char * str1,
               const char * str2,
               int          c )
{
    char *buf;

    buf = fl_malloc(   ( str1 ? strlen( str1 ) : 0 ) + 1
                     + ( str2 ? strlen( str2 ) : 0 ) + 1 );
    sprintf( buf, "%s\n%s", str1 ? str1 : "", str2 ? str2 : "" );
    show_it( title, buf, c );
    fl_free( buf );
}


/***************************************
 ***************************************/

void
fl_show_alert_f( int c,
                 const char * fmt,
                 ... )
{
    char *buf,
         *p;

    EXPAND_FORMAT_STRING( buf, fmt );

    if ( buf )
    {
        p = strchr( buf, '\f' );
        if ( p )
            *p++ = '\0';

        fl_show_alert( buf, p, NULL, c );

        fl_free( buf );
    }
}


/***************************************
 ***************************************/

void
fl_hide_alert( void )
{
    if ( fd_alert && fd_alert->form->visible )
        fl_trigger_object( fd_alert->but );
    else
        M_warn( "fl_hide_alert", "No alert box is shown" );
}


/***************************************
 ***************************************/

void
fli_alert_cleanup( void )
{
    fli_safe_free( fd_alert );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
