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


/**
 * \file demo.c
 *
 * Driver for the demo/test suite
 *
 *  This file is part of xforms package
 *  M. Overmars and T.C. Zhao
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "include/forms.h"

FL_FORM *form;
static void create_the_forms( void );
static int load_the_menu( const char * );
static void push_menu( const char * );


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    char buf[ 1024 ],
         *p;
    int version,
        revision;

    /* Make sure the distribution is consistent wrt version numbers */

    if ( FL_INCLUDE_VERSION != fl_library_version( &version, &revision ) )
    {
        fprintf( stderr, "header/library version mismatch\n" );
        fprintf( stderr, "   Header: %d.%d.%s\n",
                 FL_VERSION, FL_REVISION, FL_FIXLEVEL );
        fprintf( stderr, "  Library: %d.%d\n", version, revision );
        exit( 1 );
    }

    /* to cut down the "bug" reports of "can't run the demos", put . on path */

#ifndef __VMS
    if ( ( p = getenv( "PATH" ) ))
        putenv( strcat( strcat( strcpy( buf, "PATH=" ), p ), ":." ) );
#else
     printf( "  -------->WARNING<-----------" );
     printf( "  The subdemos will not run unless DCL$PATH has been defined\n" );
     printf( "  to include the directory where they live\n" );
#endif

     fl_set_border_width( 1 );

     fl_initialize( &argc, argv, "FormDemo", 0, 0 );
     fl_clear_command_log( );

     create_the_forms( );

     if ( ! load_the_menu( "demo.menu" ) )
         exit( -1 );

     push_menu( "@main" );

     fl_show_form( form, FL_PLACE_CENTER, FL_TRANSIENT, "Demo" );
     fl_do_forms( );

     return 0;
}


FL_OBJECT *but[ 9 ];

/* Maintaining and building up the menus. */

typedef struct
{
    char name[ 64 ];
    int  numb;
    char iname[ 9 ][ 64 ];
    char icommand[ 9 ][ 64 ];
} MENU;

#define MAXMENU 32

MENU menus[ MAXMENU ];
int mennumb = 0;


/***************************************
 * Returns the number of a given menu name.
 ***************************************/

int
find_menu( const char * nnn )
{
    int i;

    for ( i = 0; i < mennumb; i++ )
        if ( strcmp( menus[ i ].name, nnn ) == 0 )
            return i;
    return -1;
}


/***************************************
 * Creates a new menu with name nnn
 ***************************************/

static void
create_menu( char nnn[ ] )
{
    if ( mennumb == MAXMENU - 1 )
        return;
    strcpy( menus[ mennumb ].name, nnn );
    menus[ mennumb ].numb = 0;
    mennumb++;
}


/***************************************
 * Adds an item to a menu
 ***************************************/

static void
addto_menu( char men[ ],
            char item[ ],
            char comm[ ] )
{
    int n = find_menu( men );

    if ( n < 0 )
    {
        create_menu( men );
        n = find_menu( men );
    }

    if ( menus[ n ].numb == 9 )
        return;

    strcpy( menus[ n ].iname[ menus[ n ].numb ], item );
    strcpy( menus[ n ].icommand[ menus[ n ].numb ], comm );
    menus[ n ].numb++;
}


/* Button to Item conversion and back. */

int b2n[ ][ 9 ] =
{
    { -1, -1, -1, -1,  0, -1, -1, -1, -1 },
    { -1, -1, -1,  0, -1,  1, -1, -1, -1 },
    {  0, -1, -1, -1,  1, -1, -1, -1,  2 },
    {  0, -1,  1, -1, -1, -1,  2, -1,  3 },
    {  0, -1,  1, -1,  2, -1,  3, -1,  4 },
    {  0, -1,  1,  2, -1,  3,  4, -1,  5 },
    {  0, -1,  1,  2,  3,  4,  5, -1,  6 },
    {  0,  1,  2,  3, -1,  4,  5,  6,  7 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8 }
};


int n2b[ ][ 9 ] =
{
    { 4, -1, -1, -1, -1, -1, -1, -1, -1 },
    { 3,  5, -1, -1, -1, -1, -1, -1, -1 },
    { 0,  4,  8, -1, -1, -1, -1, -1, -1 },
    { 0,  2,  6,  8, -1, -1, -1, -1, -1 },
    { 0,  2,  4,  6,  8, -1, -1, -1, -1 },
    { 0,  2,  3,  5,  6,  8, -1, -1, -1 },
    { 0,  2,  3,  4,  5,  6,  8, -1, -1 },
    { 0,  1,  2,  3,  5,  6,  7,  8, -1 },
    { 0,  1,  2,  3,  4,  5,  6,  7,  8 }
};


/***************************************
 * Transforms a button number to an item number when there are
 * maxnumb items in total. -1 if the button should not exist.
 ***************************************/

static int
but2numb( int bnumb,
          int maxnumb )
{
    return b2n[ maxnumb ][ bnumb ];
}


/***************************************
 * Transforms an item number to a button number when there are
 * maxnumb items in total. -1 if the item should not exist.
 ***************************************/

static int
numb2but( int inumb,
          int maxnumb )
{
    return n2b[ maxnumb ][ inumb ];
}


/* Pushing and Popping menus */

char stack[ 64 ][ 32 ];
int stsize = 0;

/***************************************
 * Pushes a menu to be visible
 ***************************************/

static void
push_menu( const char * nnn )
{
    int n,
        i,
        bn;
    int men = find_menu( nnn );

    /* make exceptions for B&W */

    FL_COLOR bc_more = fl_get_visual_depth( ) == 1 ? FL_COL1 : FL_INDIANRED;
    FL_COLOR bc_term = fl_get_visual_depth( ) == 1 ? FL_COL1 : FL_SLATEBLUE;

    if ( men < 0 )
        return;
    n = menus[ men ].numb;

    fl_freeze_form( form );

    for ( i = 0; i < 9; i++ )
        fl_hide_object( but[ i ] );

    for ( i = 0; i < n; i++ )
    {
        bn = numb2but( i, n - 1 );
        fl_show_object( but[ bn ] );
        fl_set_object_label( but[ bn ], menus[ men ].iname[ i ] );
        if ( menus[ men ].icommand[ i ][ 0 ] == '@' )
            fl_set_object_color( but[ bn ], bc_more, FL_RED );
        else
            fl_set_object_color( but[ bn], bc_term, FL_BLUE );
    }

    fl_unfreeze_form( form );
    strcpy( stack[ stsize ], nnn );
    stsize++;
}


/***************************************
 * Pops a menu
 ***************************************/

static void
pop_menu( void )
{
    if ( stsize <= 1 )
        return;

    stsize -= 2;
    push_menu( stack[ stsize ] );
}


/***************************************
 * The callback Routines
 ***************************************/

#if defined __cplusplus
extern "C"
#endif


/***************************************
 * handles a button push
 ***************************************/

void
dobut( FL_OBJECT * obj  FL_UNUSED_ARG,
       long        arg )
{
    int men = find_menu( stack[ stsize - 1 ] );
    int n = menus[ men ].numb;
    int bn = but2numb( ( int ) arg, n - 1 );

    if ( menus[ men ].icommand[ bn ][ 0 ] == '@' )
        push_menu( menus[ men ].icommand[ bn ] );
    else
    {
        char cmd[ 1024 ];
        char **vv;
        int c,
            i;

        vv = fl_get_cmdline_args( &c );
        strcpy( cmd, menus[ men ].icommand[ bn ] );
        for ( i = 1; i < c; i++ )
            strcat( strcat( cmd, " " ), vv[ i ] );

        fl_addto_command_log( "running " );
        fl_addto_command_log( cmd );
        fl_addto_command_log( "\n" );
        fl_deactivate_all_forms( );
        fl_exe_command( cmd, 1 );
        fl_activate_all_forms( );
    }
}


/***************************************
 * Go up a level in the menu tree
 ***************************************/

void
doback( FL_OBJECT * obj  FL_UNUSED_ARG,
        long        arg  FL_UNUSED_ARG )
{
    pop_menu( );
}


/***************************************
 * Exit the program
 ***************************************/

void
doexit( FL_OBJECT * obj  FL_UNUSED_ARG,
        long        arg  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void
showlog( FL_OBJECT * obj  FL_UNUSED_ARG,
         long        arg  FL_UNUSED_ARG )
{
    fl_show_command_log( FL_TRANSIENT );
}


/***************************************
 * Loads the menu file. Returns whether successful.
 ***************************************/

static int
load_the_menu( const char * fname )
{
    FILE *fin;
    char line[ 256 ],
         mname[ 64 ],
         iname[ 64 ],
         cname[ 64 ];
    int i,
        j;

    fin = fopen( fname, "r" );
    if ( fin == NULL )
    {
        fl_show_message( "ERROR", "",
                         "Cannot read the menu description file." );
        return 0;
    }

    while ( 1 )
    {
        if ( fgets( line, 256, fin ) == NULL)
            break;

        j = 0;
        i = 0;

        while ( line[ i ] == ' ' || line[ i ] == '\t' )
            i++;
        if ( line[ i ] == '\n' )
            continue;
        if ( line[ i ] == '#' )
            continue;
        while ( line[ i ] != ':' && line[ i ] != '\n' )
            mname[ j++ ] = line[ i++ ];
        mname[ j ] = '\0';
        if ( line[ i ] == ':' )
            i++;
        j = 0;
        while ( line[ i ] != ':' && line[ i ] != '\n' )
        {
            if ( line[ i ] == '\\' && line[ i + 1 ] == 'n' )
            {
                iname[ j++ ] = '\n';
                i += 2;
            }
            else
                iname[ j++ ] = line[ i++ ];
        }
        iname[ j ] = '\0';
        if ( line[ i ] == ':' )
            i++;
        j = 0;
        while ( line[ i ] != ':' && line[ i ] != '\n' )
            cname[ j++ ] = line[ i++ ];
        cname[ j ] = '\0';
        addto_menu( mname, iname, cname );
    }

    fclose( fin );
    return 1;
}


/***************************************
 ***************************************/

void
create_form_form( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 370, 450 );

    obj = fl_add_box( FL_UP_BOX, 0, 0, 370, 450, "" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );

    obj = fl_add_box( FL_FRAME_BOX, 20, 20, 330, 40, "Forms Demonstration" );
    fl_set_object_color( obj, FL_INDIANRED, FL_COL1 );
    fl_set_object_lsize( obj, FL_HUGE_SIZE );
    fl_set_object_lstyle( obj, FL_ENGRAVED_STYLE + FL_BOLD_STYLE );
    fl_set_object_lcolor( obj, FL_INDIANRED );

    obj = fl_add_box( FL_FRAME_BOX, 20, 70, 330, 330, "" );
    fl_set_object_color( obj, FL_INDIANRED, FL_COL1 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 190, 410, 110, 30, "Exit" );
    fl_set_object_callback( obj, doexit, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 80, 410, 110, 30, "Show Log" );
    fl_set_object_callback( obj, showlog, 0 );

    obj = fl_add_button( FL_HIDDEN_BUTTON, 20, 20, 330, 380, "Button" );
    fl_set_object_callback( obj, doback, 0 );

    but[ 0 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 40, 90, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 0 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 1 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 140, 90, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 1 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 2 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 240, 90, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 2 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 5 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 240, 190, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 5 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 4 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 140, 190, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 4 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 3 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 40, 190, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 3 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 6 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 40, 290, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 6 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 7 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 140, 290, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 7 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    but[ 8 ] = obj = fl_add_button( FL_NORMAL_BUTTON, 240, 290, 90, 90,
                                    "Button" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_callback( obj, dobut, 8 );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    fl_end_form( );
    fl_adjust_form_size( form );
}


/***************************************
 ***************************************/

static void
create_the_forms( void )
{
    create_form_form( );
    fl_set_form_dblbuffer( form, 1 );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
