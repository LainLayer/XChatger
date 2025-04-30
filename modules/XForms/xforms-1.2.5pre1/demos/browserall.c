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
 *  This is a demo that shows the different types of browsers.
 *
 *  This file is part of xforms package
 *  M. Overmars and T.C. Zhao  (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include "include/forms.h"


FL_FORM * form;
FL_OBJECT * br[ 4 ],
          * exitobj,
          * readout;

static void create_form( void );
static void fill_browsers( void );


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    create_form( );
    fill_browsers( );

    fl_show_form( form,FL_PLACE_CENTER | FL_FREE_SIZE, FL_TRANSIENT,
                  "All Browsers" );

    fl_do_forms( );

    fl_finish( );
    return 0;
}


static const char *bnames[ ] =
{
    "NORMAL_BROWSER",
    "SELECT_BROWSER",
    "HOLD_BROWSER",
    "MULTI_BROWSER"
};


/***************************************
 ***************************************/

static void
deselect( FL_OBJECT * obj  FL_UNUSED_ARG,
          long        arg  FL_UNUSED_ARG )
{
    int i;

    for ( i = 2; i < 4; i++ )
        fl_deselect_browser( br[ i ] );
}


/***************************************
 ***************************************/

static void
set_size( FL_OBJECT * obj  FL_UNUSED_ARG,
          long        arg )
{
    int i;

    for ( i = 0; i < 4; i++ )
        fl_set_browser_fontsize( br[ i ], arg );
}


/***************************************
 ***************************************/

static void
set_style( FL_OBJECT * obj  FL_UNUSED_ARG,
           long        arg )
{
    int i;

    for ( i = 0; i < 4; i++ )
        fl_set_browser_fontstyle( br[ i ], arg );
}


/***************************************
 ***************************************/

static void
br_callback( FL_OBJECT * ob,
             long        arg )
{
    char buf[ 1024 ];
    const char * mb[ ] = { "left", "middle", "right",
                           "scroll-up", "scroll-down" };
    int i;

    if (    ( i = fl_mouse_button( ) ) >= FL_LEFT_MOUSE
         && i <= FL_SCROLLDOWN_MOUSE )
        sprintf( buf, "In %s [%s]: ", bnames[ arg ], mb[ i - FL_LEFT_MOUSE ] );
    else
        sprintf( buf, "In %s: ", bnames[ arg ] );

    if ( ( i = fl_get_browser( ob ) ) )
    {
        strcat( buf, fl_get_browser_line( ob, i > 0 ? i : -i ) );
        strcat( buf, i > 0 ? " was selected" : " was deselected." );
    }

    fl_set_object_label( readout, buf );
}


/***************************************
 ***************************************/

static void
vcallback( FL_OBJECT * ob       FL_UNUSED_ARG,
           int         topline  FL_UNUSED_ARG,
           void      * data     FL_UNUSED_ARG )
{
     int i;
     int yoffset = fl_get_browser_yoffset( br[ 0 ] );

     for ( i = 1; i < 4; i++ )
         fl_set_browser_yoffset( br[ i ], yoffset ); 
}


/***************************************
 ***************************************/

static void
link_browsers( FL_OBJECT * ob,
               long        data  FL_UNUSED_ARG )
{
    int sync = fl_get_button( ob );
    int i;

    fl_set_object_label( ob, sync ? "Unlink": "Link" );

    if ( sync )
    {
        int yoffset = fl_get_browser_yoffset( br[ 0 ] );

        for ( i = 1; i < 4; i++ )
        {
            fl_set_browser_vscrollbar( br[ i ], FL_OFF );
            fl_set_browser_yoffset( br[ i ], yoffset );
        }

       fl_set_browser_vscroll_callback( br[ 0 ], vcallback, 0 );
    }
    else
    {
        for ( i = 1; i < 4; i++ )
            fl_set_browser_vscrollbar( br[ i ], FL_ON );

       fl_set_browser_vscroll_callback( br[ 0 ], NULL, 0 );
    }
}


/***************************************
 ***************************************/

static void
create_form( void )
{
    FL_OBJECT * obj;

    form = fl_bgn_form( FL_FLAT_BOX, 700, 570 );

    readout = fl_add_text( FL_NORMAL_TEXT, 50, 30, 600, 50, "" );
    fl_set_object_lsize( readout, FL_NORMAL_SIZE );
    fl_set_object_lalign( readout, FL_ALIGN_CENTER );
    fl_set_object_lstyle( readout, FL_BOLD_STYLE );
    fl_set_object_boxtype( readout, FL_UP_BOX );
    fl_set_object_color( readout, FL_MAGENTA, FL_MAGENTA );

    br[ 0 ] = obj = fl_add_browser( FL_NORMAL_BROWSER, 20, 120, 150, 290,
                                    bnames[ 0 ] );
    fl_set_object_callback( obj, br_callback, 0 );

    br[ 1 ] = obj = fl_add_browser( FL_SELECT_BROWSER, 190, 120, 150, 290,
                                    bnames[ 1 ] );
    fl_set_object_callback( obj, br_callback, 1 );

    br[ 2 ] = obj = fl_add_browser( FL_HOLD_BROWSER, 360, 120, 150, 290,
                                    bnames[ 2 ] );
    fl_set_object_color( obj, FL_WHITE, FL_GREEN );
    fl_set_object_callback( obj, br_callback, 2 );

    br[ 3 ] = obj = fl_add_browser( FL_MULTI_BROWSER, 530, 120, 150, 290,
                                    bnames[ 3 ] );
    fl_set_object_color( obj,FL_WHITE, FL_CYAN );
    fl_set_object_callback( obj, br_callback, 3 );

    exitobj = fl_add_button( FL_NORMAL_BUTTON, 560, 510, 120, 30, "Exit" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 560, 460, 120, 30, "Deselect" );
    fl_set_object_callback( obj, deselect, 0 );

    fl_bgn_group( );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 20, 500, 100, 30, "Tiny" );
    fl_set_object_callback( obj, set_size, FL_TINY_SIZE );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 130, 500, 100, 30, "Small" );
    fl_set_object_callback( obj, set_size, FL_SMALL_SIZE );
    fl_set_button( obj, 1 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 240, 500, 100, 30, "Normal" );
    fl_set_object_callback( obj, set_size, FL_NORMAL_SIZE );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 350, 500, 100, 30, "Large" );
    fl_set_object_callback( obj, set_size, FL_LARGE_SIZE );

    obj = fl_add_button( FL_BUTTON, 470, 510, 45,30, "Link" );
    fl_set_object_callback( obj, link_browsers, 0 );

    fl_end_group( );

    fl_bgn_group( );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 20, 450, 100, 30, "Normal" );
    fl_set_object_callback( obj, set_style, FL_NORMAL_STYLE );
    fl_set_button( obj, 1 );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 120, 450, 100, 30, "Bold" );
    fl_set_object_callback( obj, set_style, FL_BOLD_STYLE );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 220, 450, 100, 30, "Italic" );
    fl_set_object_callback( obj, set_style, FL_ITALIC_STYLE );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 320, 450, 100, 30,
                              "BoldItalic" );
    fl_set_object_callback( obj, set_style, FL_BOLDITALIC_STYLE );

    obj = fl_add_lightbutton( FL_RADIO_BUTTON, 420, 450, 100, 30, "Fixed" );
    fl_set_object_callback( obj, set_style, FL_FIXED_STYLE );

    fl_end_group( );

    fl_end_form( );
}


/***************************************
 ***************************************/

static void
fill_browsers( void )
{
    int i,
        j;
    char buf[ 128 ];

    for ( i = 0; i < 4; i++ )
        for ( j = 1; j <= 100; j++ )
        {
            if ( j == 5 || j == 6 )
                sprintf( buf, "@NLine with qb %3d", j );
            else if ( j == 10 )
                strcpy( buf, "@-trailing text should be ignored" );
            else if ( j == 40 )
                sprintf( buf, "@mLine with qb %3d", j );
            else
                sprintf( buf, "Line with qb %3d",j );

            fl_add_browser_line( br[ i ], buf );
        }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
