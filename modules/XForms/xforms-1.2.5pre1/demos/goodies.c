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


/* This demo program uses the routines in the
 * goodies section, that help you create easy
 * forms in an even easier way.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "include/forms.h"


/***************************************
 ***************************************/

void
timeout_remove_alert( int    id    FL_UNUSED_ARG,
                      void * data  FL_UNUSED_ARG )
{
    fl_hide_alert( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    int choice;
    char str1[ 100 ],
         str2[ 100 ];
    const char *s;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

#if 0
    fl_set_resource( FLOKLabel, "Go" );
#endif

    if( fl_show_question( "Do you want bold font ?",1 ) )
        fl_set_goodies_font( FL_BOLD_STYLE, FL_NORMAL_SIZE );

    fl_show_messages( "This is a test program for the goodies of the "
                      "forms library" );

    fl_add_timeout( 5000, timeout_remove_alert, 0 );
    fl_show_alert( "Alert", "Alert form can be used to inform",
                   "about recoverable errors", 0 );

    if ( fl_show_question( "Do you want to quit?", 0 ) )
        exit( 0 );

    strcpy( str1, ( s = fl_show_input( "Enter a string:","" ) ) ? s : "" );
    fl_show_message( "You typed:", "", str1 );
    choice = fl_show_choices( "Pick a choice", 3, "One", "Two", "Three", 2 );
    switch ( choice )
    {
        case 1:
            fl_show_message( "You typed: One", "", "" );
            break;

        case 2:
            fl_show_message( "You typed: Two", "", "" );
            break;

        case 3:
            fl_show_message( "You typed: Three", "", "" );
            break;

        default:
            fl_show_message( "An error occured!", "", "" );
            break;
    }

    strcpy( str2,
            ( s = fl_show_input( "Enter another string:", str1 ) ) ?
            s : "<Cancel>" );
    fl_show_message( "You typed:", "", str2 );
    fl_show_messages( "Good Bye" );

    fl_finish( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
