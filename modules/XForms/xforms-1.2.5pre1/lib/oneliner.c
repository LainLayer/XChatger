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
 * \file oneliner.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 * Show message in a top-level unmanaged window.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


static int fntstyle = FL_NORMAL_STYLE,
           fntsize  = FL_DEFAULT_SIZE;
static FL_COLOR background = FL_YELLOW,
                textcolor  = FL_BLACK;
static FL_FORM *oneliner;
static FL_OBJECT *text;


/***************************************
 ***************************************/

static void
create_it( void )
{
    if ( oneliner )
        return;

    oneliner = fl_bgn_form( FL_NO_BOX, 5, 5 );

    text = fl_add_box( FL_BORDER_BOX, 0, 0, 5, 5, "" );

    fl_set_object_lstyle( text, fntstyle );
    fl_set_object_lsize( text, fntsize );
    fl_set_object_lcolor( text, textcolor );
    fl_set_object_color( text, background, background );
    fl_end_form( );
}


/***************************************
 ***************************************/

void
fl_show_oneliner( const char * s,
                  FL_Coord     x,
                  FL_Coord     y )
{
    int w,
        h;

    if ( ! s )
        return;

    create_it( );

    fl_get_string_dimension( fntstyle, fntsize, s, strlen( s ), &w, &h );

    w += ( 2 * fntsize ) / 3;
    h += ( 2 * fntsize ) / 3;

    fl_freeze_form( oneliner );
    fl_set_form_geometry( oneliner, x, y, w, h );
    fl_set_object_label( text, s );
    fl_unfreeze_form( oneliner );

    if ( oneliner->visible == FL_INVISIBLE )
        fl_show_form( oneliner, FL_PLACE_GEOMETRY | FL_FREE_SIZE,
                      FL_NOBORDER, "OneLiner" );

    fl_update_display( 1 );
}


/***************************************
 ***************************************/

void
fl_hide_oneliner( void )
{
    if ( oneliner && oneliner->visible )
        fl_hide_form( oneliner );
}


/***************************************
 ***************************************/

void
fl_set_oneliner_color( FL_COLOR tc,
                       FL_COLOR bc )
{
    create_it( );
    fl_set_object_lcolor( text, textcolor = tc );
    background = bc;
    fl_set_object_color( text, background, background );
}


/***************************************
 ***************************************/

void
fl_set_oneliner_font( int style,
                      int size )
{
    create_it( );
    fl_set_object_lstyle( text, fntstyle = style );
    fl_set_object_lsize( text, fntsize = size );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
