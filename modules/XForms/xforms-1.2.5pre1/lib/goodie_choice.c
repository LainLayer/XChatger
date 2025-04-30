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
 * \file goodie_choice.c
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
#include "private/flsnprintf.h"


/****************** Make a choice ***********************{**/

typedef struct
{
    FL_FORM    * form;
    FL_OBJECT  * str;
    FL_OBJECT  * but[ 3 ];
    const char * sc[ 3 ];
} FD_choice;

static FD_choice *fd_choice;
static int default_choice;


/***************************************
 ***************************************/

static FD_choice *
create_choice( void )
{
    FD_choice *fdui = fl_malloc( sizeof *fdui );
    int oldy = fli_inverted_y;
    int oldu = fl_get_coordunit();

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fdui->form = fl_bgn_form( FL_FLAT_BOX, 460, 130 );
    fl_set_form_title( fdui->form, "Choice" );

    fdui->str = fl_add_box( FL_FLAT_BOX, 20, 15, 420, 65, "" );

    fdui->but[ 0 ] = fl_add_button( FL_NORMAL_BUTTON,  40, 93, 90, 27, "" );
    fdui->but[ 1 ] = fl_add_button( FL_NORMAL_BUTTON, 185, 93, 90, 27, "" );
    fdui->but[ 2 ] = fl_add_button( FL_NORMAL_BUTTON, 330, 93, 90, 27, "" );

    fdui->sc[ 0 ] = fl_strdup( "1" );
    fdui->sc[ 1 ] = fl_strdup( "2" );
    fdui->sc[ 2 ] = fl_strdup( "3" );

    fl_end_form( );

    fli_inverted_y = oldy;
    fl_set_coordunit( oldu );

    return fdui;
}


/***************************************
 ***************************************/

int
fl_show_choices( const char * msg,
                 int          numb,
                 const char * c0,
                 const char * c1,
                 const char * c2,
                 int          def )
{
    FL_OBJECT *retobj;
    const char *c[ ] = { c0, c1, c2 };
    int i;

    if ( ! fd_choice )
        fd_choice = create_choice( );

    fli_handle_goodie_font( fd_choice->but[ 0 ], fd_choice->but[ 1 ] );
    fli_handle_goodie_font( fd_choice->but[ 2 ], fd_choice->str );
    fl_set_object_label( fd_choice->str, msg );

    fl_hide_object( fd_choice->but[ 0 ] );
    fl_hide_object( fd_choice->but[ 1 ] );
    fl_hide_object( fd_choice->but[ 2 ] );

    default_choice = def;

    switch ( numb )
    {
        case 3:
            for ( i = 0; i < 3; i++ )
            {
                fl_set_object_label( fd_choice->but[ i ], c[ i ] );
                fl_set_object_shortcut( fd_choice->but[ i ],
                                        fd_choice->sc[ i ], 1 );
                fl_show_object( fd_choice->but[ i ] );
                fl_fit_object_label( fd_choice->but[ i ], 1, 1 );
            }
            break;

        case 2:
            /* pick button 0 and 2 */

            fl_set_object_label( fd_choice->but[ 0 ], c[ 0 ] );
            fl_set_object_shortcut( fd_choice->but[ 0 ],
                                    fd_choice->sc[ 0 ], 1 );
            fl_show_object( fd_choice->but[ 0 ] );
            fl_fit_object_label( fd_choice->but[ 0 ], 1, 1 );

            fl_set_object_label( fd_choice->but[ 2 ], c[ 1 ] );
            fl_set_object_shortcut( fd_choice->but[ 2 ],
                                    fd_choice->sc[ 2 ], 1 );
            fl_show_object( fd_choice->but[ 2 ] );
            fl_fit_object_label( fd_choice->but[ 2 ], 1, 1 );
            break;

        case 1:
            fl_set_object_label( fd_choice->but[ 0 ], c[ 0 ] );
            fl_set_object_shortcut( fd_choice->but[ 0 ],
                                    fd_choice->sc[ 0 ], 1 );
            fl_show_object( fd_choice->but[ 0 ] );
            fl_fit_object_label( fd_choice->but[ 0 ], 1, 1 );
            break;

        default:
            return 0;
    }

    fli_get_goodie_title( fd_choice->form, FLChoiceTitle );

    if ( ! fd_choice->form->visible )
        fl_deactivate_all_forms( );

    if ( def > 0 && def <= 3 )
        fl_set_form_hotobject( fd_choice->form, fd_choice->but[ def - 1 ] );
    else
        fl_set_form_hotspot( fd_choice->form, -1, -1 );

    fl_show_form( fd_choice->form, FL_PLACE_HOTSPOT, FL_TRANSIENT,
                  fd_choice->form->label );

    fl_update_display( 0 );

    retobj = fl_do_only_forms( );

    fl_hide_form( fd_choice->form );
    fl_activate_all_forms( );

    return retobj == fd_choice->but[ 0 ] ?
           1 : ( ( retobj == fd_choice->but[ 1 ] || numb == 2 ) ? 2 : 3);
}


/***************************************
 ***************************************/

int
fl_show_choice( const char * m1,
                const char * m2,
                const char * m3,
                int          numb,
                const char * c1,
                const char * c2,
                const char * c3,
                int          def )
{
    char *buf;
    size_t len;
    int ret;

    len =   ( m1 ? strlen( m1 ) : 0 ) + 1
          + ( m2 ? strlen( m2 ) : 0 ) + 1
          + ( m3 ? strlen( m3 ) : 0 ) + 1;

    if ( len == 3 )
    {
        M_warn( "fl_show_choice", "Only NULL or empty strings" );
        return 0;
    }

    buf = fl_malloc( len );

    sprintf( buf, "%s\n%s\n%s",
             m1 ? m1 : "", m2 ? m2 : "", m3 ? m3 : "" );

    ret = fl_show_choices( buf, numb, c1, c2, c3, def );

    fl_free( buf );

    return ret;
}


/***************************************
 ***************************************/

void
fl_set_choices_shortcut( const char * a,
                         const char * b,
                         const char * c )
{
    if ( ! fd_choice )
        fd_choice = create_choice( );

    if ( fd_choice->sc[ 0 ] )
        fl_free( ( char * ) fd_choice->sc[ 0 ] );
    fd_choice->sc[ 0 ] = ( a && *a ) ? fl_strdup( a ) : NULL;

    if ( fd_choice->sc[ 1 ] )
        fl_free( ( char * ) fd_choice->sc[ 1 ] );
    fd_choice->sc[ 1 ] = ( b && *b ) ? fl_strdup( b ) : NULL;

    if ( fd_choice->sc[ 2 ] )
        fl_free( ( char * ) fd_choice->sc[ 2 ] );
    fd_choice->sc[ 2 ] = ( c && *c ) ? fl_strdup( c ) : NULL;
}


/***************************************
 ***************************************/

void
fl_hide_choice( void )
{
    if ( fd_choice && fd_choice->form->visible )
    {
        if ( default_choice <= 0 || default_choice > 3 )
            default_choice = 1;

        fl_trigger_object( fd_choice->but[ default_choice ] );
    }
}


/***************************************
 ***************************************/

void
fli_choice_cleanup( void )
{
    if ( ! fd_choice )
        return;

    if ( fd_choice->sc[ 0 ] )
        fl_free( ( char * ) fd_choice->sc[ 0 ] );

    if ( fd_choice->sc[ 1 ] )
        fl_free( ( char * ) fd_choice->sc[ 1 ] );

    if ( fd_choice->sc[ 2 ] )
        fl_free( ( char * ) fd_choice->sc[ 2 ] );

    fli_safe_free( fd_choice );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
