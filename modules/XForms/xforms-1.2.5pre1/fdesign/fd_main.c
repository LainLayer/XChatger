/*
 * This file is part of XForms.
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
 * \file fd_main.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This is the main module of the Form Designer, a program that
 * helps you to design form in a fully interactive way. It
 * automatically generates the corresponding C-code.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd/ui_theforms.h"
#include "xpm/fd_logo.xpm"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined( __EMX__ ) || defined( WIN32 )
#define strcasecmp stricmp
#endif

#if defined __VMS && __VMS_VER < 70000000
extern int strcasecmp( const char *, const char * );
#endif


/***************************************
 * Info about the program
 ***************************************/

#define S( a )  #a
#define LIBVERSION( a, b ) S( a ) "." S( b )

static const char *fd_version[ ] =
{
    "fdesign (FORM Designer) " LIBVERSION( FL_VERSION, FL_REVISION ) "." FL_FIXLEVEL,
    "Copyright (c) 1996-2002 by T.C. Zhao and Mark Overmars",
    "GNU Lesser General Public License sinc 2002",
    NULL
};


/***************************************
 ***************************************/

static void
print_version( int die )
{
    const char **p = fd_version;

    for ( ; *p; p++ )
        fprintf( stderr, "%s\n", *p );

    if ( die )
        exit( 0 );
}


char xform_header[ 128 ] = "forms.h";
char glcanvas_header[ 128 ] = "glcanvas.h";
long main_window = 0;       /* The main screen window */
FL_Coord winw,
         winh;


/* Various options  of the program */

FD_Opt fdopt;
Conv convertor[ MAX_CONVERTOR + 1 ];

int fd_cntlborder;
int fd_bwidth;
int is_pasting;
int fd_trackgeometry = 1;
int fd_show_palette;
int fd_buttonLabelSize;
int fd_helpfontsize = 14;
int fd_align_fontsize = FL_TINY_SIZE;
int fd_type_fontsize = FL_TINY_SIZE;
int no_selection = 0;

GC fd_gc;
Colormap fd_colormap;
unsigned long fd_red,
              fd_black,
              fd_white,
              fd_col;
Display * fd_display;
int changed = FL_FALSE;             /* whether something has changed. */
char main_name[ MAX_VAR_LEN ];      /* name of the main calling routine */
char * loadedfile;


/***************************************
 * Lets the user add some object to the form
 ***************************************/

static void
add_something( void )
{
    FL_OBJECT *obj;
    double xx,
           yy,
           ww = 0.0,
           hh = 0.0;

    if ( ! cur_form )
        return;

    fl_winset( main_window );
    get_mouse_pos( &xx, &yy );
    scale_box( &xx, &yy, &ww, &hh );

    if ( ww < 5.0 || hh < 5.0 )
        return;

    obj = add_an_object( cur_class, -1, xx, yy, ww, hh );
    clear_selection( );
    addto_selection( obj );
    changed = FL_TRUE;

    /* Reset the object type selection */

    fl_deselect_browser( fd_control->objectbrowser );
    reset_pallette( );
    cur_class = -1;
}


/***************************************
 * Changes the main calling name.
 ***************************************/

void
mainname_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
             long        arg  FL_UNUSED_ARG )
{
    const char *s;

    if ( ! ( s = fl_show_input( "Main creation routine name:", main_name ) ) )
        return;

    if ( *s )
        strcpy( main_name, s );
    else
        strcpy( main_name, "create_the_forms" );

    changed = FL_TRUE;
}


/***************************************
 ***************************************/

static int
double_click( const XEvent * xev )
{
    static Time lasttime;
    static unsigned int lastbut;               
    static int lastx,
               lasty;
    int dblclk,
        x = xev->xbutton.x,
        y = xev->xbutton.y;

    dblclk =    xev->xbutton.button == lastbut
             && xev->xbutton.time - lasttime < FL_CLICK_TIMEOUT
             && lastx == x
             && lasty == y;

    lasttime = xev->xbutton.time;
    lastbut = xev->xbutton.button;
    lastx = x;
    lasty = y;

    return dblclk;
}


/***************************************
 * Handle mouse click inside the working window
 ***************************************/

static int
handle_click( XEvent * xev,
              void   * p  FL_UNUSED_ARG  )
{
    int dblclk = double_click( xev );

    /* If no form exists yet ask the user to create it */

    if ( ! cur_form )
    {
        addform_cb( NULL, 0 );
        return 0;
    }

    if ( no_selection )
        return 0;

    if ( dblclk )
    {
        if ( xev->xbutton.button == 3 )
            cut_selection( );
        else if ( xev->xbutton.button == 1 && cur_class < 0 )
            change_selection( );

        redraw_the_form( 0 );
        return 0;
    }

    if ( xev->xbutton.button == 1 && cur_class >= 0 )
    {
        XEvent ev;

        XNextEvent( fl_display, &ev );

        if ( ev.type == MotionNotify )
            add_something( );
    }
    else if ( xev->xbutton.button == 3 && cur_class >= 0 )
    {
        cur_class = -1;
        fl_deselect_browser( fd_control->objectbrowser );
        select_pallette_entry( cur_class );
    }
    else if ( is_pasting )
        /* empty */;
    else if (    within_selection( xev->xbutton.x, xev->xbutton.y )
              && xev->xbutton.button != 3 )
    {
        XEvent ev;

        XNextEvent( fl_display, &ev );
        if ( ev.type == MotionNotify )
            handle_move( xev );
        else if ( ev.type == ButtonRelease )
            handle_select( &ev );
    }
    else
        handle_select( xev );

    redraw_the_form( 0 );
    return 0;
}


/***************************************
 ***************************************/

static void
handle_keypress( const XKeyEvent * xev )
{
    KeySym keysym;
    char keybuf[ 128 ];
    int stp = get_snap_size( );
    int shift = ShiftIsDown( xev->state );

    XLookupString( ( XKeyEvent * ) xev, keybuf, sizeof keybuf, &keysym, 0 );

    if ( keysym >= XK_F1 && keysym <= XK_F12 )
        func_cb( 0, keysym - XK_F1 + 1 );
    else if ( IsRight( keysym ) )
        ( shift ? resize_selection : move_selection )( stp, 0 );
    else if ( IsLeft( keysym ) )
        ( shift ? resize_selection : move_selection )( -stp, 0 );
    else if ( IsUp( keysym ) )
        ( shift ? resize_selection : move_selection )( 0, -stp );
    else if ( IsDown( keysym ) )
        ( shift ? resize_selection : move_selection )( 0, stp );
    else if ( keysym == XK_Escape )
        exit_cb( 0, 0 );
    else if ( keysym == XK_t || keysym == XK_T )
        ( fd_test->test->visible ? stoptest_cb : test_cb )( 0, 0 );
    else if ( keysym == XK_s || keysym == XK_S )
        saveforms_as_cb( 0, 0 );
    else if ( IsTab( keysym ) )
        ( shift ? prev_selection : next_selection )( );
    else if ( keysym >= '0' && keysym <= '9' )
    {
        if ( ( stp = keysym - '0' ) == 0 )
            stp = 10;
        set_snap_size( stp, 1 );
    }
}


/***************************************
 * Process events on the main window. Since rubber band was implemented
 * badly, can't use buttonpress callback
 ***************************************/

static void
process_xevent( void )
{
    XEvent xev;

    fl_XNextEvent( &xev );
    fli_xevent_name( "fd_main", &xev );
    fl_winset( main_window );

    switch ( xev.type )
    {
        case KeyPress:
            handle_keypress( ( XKeyEvent * ) & xev );
            break;
    }
}


/***************************************
 * The main event handling loop.
 ***************************************/

static void
main_loop( void )
{
    FL_OBJECT *obj;
    char str[ 3 * MAX_VAR_LEN + 20 ],
         name[ MAX_VAR_LEN ];
    char cbname[ MAX_VAR_LEN ],
         argname[ MAX_VAR_LEN ];

    while ( 1 )
    {
        obj = fl_do_forms( );

        /* Check whether we're just testing a form */

        if ( thetestform != NULL && obj != FL_EVENT )
        {
            get_object_name( obj, name, cbname, argname );
            if ( ! *name )
                strcpy( name, "<noname>" );
            if ( ! *cbname )
                sprintf( str, "Called: %s( %s, %s );", cbname, name, argname );
            else
                sprintf( str, "Returned: %s", name );
            fl_addto_browser( fd_test->browser, str );
        }

        if ( obj == FL_EVENT )
            process_xevent( );
    }
}


#define DEFGeom       "320x250+150+420" /* working area geometry     */
#define DEFcntlGeom   "+150+1"          /* control panel position    */
#define DEFattribGeom "+210+25"         /* Attributes panel position */
#define DEFtestGeom   "-275+2"          /* Test panel position       */
#define DEFalignGeom  "-1+1"            /* align panel position       */
#define DEFhelpGeom   "-1+1"            /* Help panel position       */

static FL_CMD_OPT fd_cmdopt[ ] =
{
    { "-geometry",   "*geometry",       XrmoptionSepArg, NULL     },
    { "-border",     ".XForm.Border",   XrmoptionNoArg, "1"       },
    { "-convert",    ".convert",        XrmoptionNoArg, "1"       },
    { "-dir",        ".dir",            XrmoptionSepArg, NULL     },
    { "-unit",       "*unit",           XrmoptionSepArg, NULL     },
    { "-altformat",  "*altformat",      XrmoptionNoArg, "1"       },
    { "-I",          "*xformHeader",    XrmoptionSepArg, NULL     },
    { "-G",          "*glcanvasHeader", XrmoptionSepArg, NULL     },
    { "-main",       "*main",           XrmoptionNoArg, "1"       },
    { "-callback",   "*callback",       XrmoptionNoArg, "1"       },
    { "-lax",        "*lax",            XrmoptionNoArg, "1"       },
    { "-nocode",     "*nocode",         XrmoptionNoArg, "0"       },
    { "-version",    ".fdversion",      XrmoptionNoArg, "1"       },
    { "-compensate", ".compensate",     XrmoptionNoArg, "1"       },
    { "-ada",        ".language",       XrmoptionNoArg, "ada95"   },
    { "-ada95",      ".language",       XrmoptionNoArg, "ada95"   },
    { "-perl",       ".language",       XrmoptionNoArg, "perl"    },
    { "-python",     ".language",       XrmoptionNoArg, "python"  },
    { "-fortran",    ".language",       XrmoptionNoArg, "fortran" },
    { "-pascal",     ".language",       XrmoptionNoArg, "pascal"  },
    { "-scm",        ".language",       XrmoptionNoArg, "scm"     },
    { "-ps",         ".language",       XrmoptionNoArg, "ps"      },
    { "-filter",     ".filter",         XrmoptionSepArg, NULL     },
    { "-migrate",    ".migrate",        XrmoptionNoArg, "1"       },
    { "-help",       ".help",           XrmoptionNoArg, "1"       }
};

#define Ncopt ( sizeof fd_cmdopt / sizeof *fd_cmdopt )

/* resources */

#define NG     64
static char fdgeom[ NG ] = DEFGeom;
static char fdcntlgeom[ NG ] = DEFcntlGeom;
static char fdattribgeom[ NG ] = DEFattribGeom;
static char fdtestgeom[ NG ] = DEFtestGeom;
static char fdaligngeom[ NG ] = DEFalignGeom;
static char fdhelpgeom[ NG ] = DEFhelpGeom;
static char fd_attrib_col[ NG ];
static char fd_sunit[ 32 ];
static char fd_slanguage[ 32 ];
static char fd_sfilter[ 32 ];

static FL_resource fdres[ ] =
{
    { "formDesign.geometry", "Geometry", FL_STRING, fdgeom, 0, NG },
    { "workingArea.geometry", "Geometry", FL_STRING, fdgeom, 0, NG },
    { "control.geometry", "Control.Geometry", FL_STRING, fdcntlgeom, 0, NG },
    { "attributes.geometry", "Attributes.Geometry", FL_STRING, fdattribgeom,
      0, NG },
    { "attributes.background", "Attributes.Background", FL_STRING,
      fd_attrib_col, 0, NG },
    { "test.geometry", "Test.Geometry", FL_STRING, fdtestgeom, 0, NG },
    { "help.geometry", "Help.Geometry", FL_STRING, fdhelpgeom, 0, NG },
    { "align.geometry", "Align.Geometry", FL_STRING, fdaligngeom, 0, NG },
    { "control.border", "XForm.Border", FL_BOOL, &fd_cntlborder, "0", 0 },
    { "convert", "Convert", FL_BOOL, &fdopt.conv_only, "0", 0 },
    { "migrate", "Migrate", FL_BOOL, &fdopt.conv_only, "0", 0 },
    { "compensate", "Compensate", FL_BOOL, &fdopt.compensate, "0", 0 },
    { "unit", "Unit", FL_STRING, fd_sunit, "pixel", 30 },
    { "language", "Language", FL_STRING, fd_slanguage, "C", 30 },
    { "filter", "Filter", FL_STRING, fd_sfilter, 0, 30 },
    { "xformHeader", "XFormHeader", FL_STRING, xform_header, "forms.h", 128 },
    { "glcanvasHeader", "GLCanvasHeader", FL_STRING, glcanvas_header,
      "glcanvas.h", 128 },
    { "altformat", "AltFormat", FL_BOOL, &fdopt.altformat, "0", 0 },
    { "helpFontSize", "HelpFontSize", FL_INT, &fd_helpfontsize, "12", 0 },
    { "nocode", "NoCode", FL_BOOL, &fdopt.emit_code, "1", 0 },
    { "main", "Main", FL_BOOL, &fdopt.emit_main, "0", 0 },
    { "callback", "Callback", FL_BOOL, &fdopt.emit_cb, "0", 0 },
    { "lax", "Lax", FL_BOOL, &fdopt.lax, "0", 0 },
};

#define Nropt  ( sizeof fdres / sizeof *fdres )

char *helps[ ] =
{
    "-help                     this message",
    "-display host:dpy         display name",
    "-name appname             change app name",
    "-border                   add border to control panel",
    "-unit {mm|point|pixel|cp|cmm} unit of measure. Default pixel",
    "-nocode                   supress code generation",
    "-main                     emit main program template",
    "-callback                 emit callback stubs",
    "-altformat                select alternative output format",
    "-compensate               emit font/server compensation code",
    "-lax                      go easy on syntax checking",
    "-I headername             alternate header file (forms.h default)",
    "-G glcanvas headername    alternate glcanvas header file (glcanvas.h default)",
    "-convert file-list        convert .fd to code non-interactively",
    "-migrate file-list        convert & migrate .fd list non-interactively",
    "-dir destdir              output any generated files in destdir",
    "-geometry geom            initial working area geometry",
    0,
};


/***************************************
 ***************************************/

static void
usage( char * s,
       int    die )
{
    char **q = helps;
    Conv *cv = convertor;

    fprintf( stderr, "usage: %s: [options] [file.fd]\n", s );
    fprintf( stderr, "  where options are\n" );
    for ( ; *q; q++ )
        fprintf( stderr, "   %s\n", *q );

    fprintf( stderr, "  Language Options\n   " );
    for ( cv += 2; cv->lang_name; cv++ )
        fprintf( stderr, "-%s ", cv->lang_name );

    fprintf( stderr, "\n   -filter f       filter name" );
    fprintf( stderr, "\n\n See also the online Help for resources info\n" );

    if ( die )
        exit( 1 );
}


/***************************************
 ***************************************/

static int
lang_val( const char *s )
{
    int i;

    for ( i = 1; i < MAX_CONVERTOR; i++ )
        if (    strcasecmp( s, convertor[ i ].lang_name ) == 0
             || strncmp( s, convertor[ i ].lang_name, 3 ) == 0 )
            return i;

    return FD_C;
}


static int ignored_fake_configure;

/***************************************
 ***************************************/

static int
handle_configure( XEvent * xev,
                  void   * p  FL_UNUSED_ARG )
{
    /* Some window managers sends bogus configure events. Make a note of it */

    if ( xev->xconfigure.send_event )
        ignored_fake_configure =    winw != xev->xconfigure.width
                                 && winh != xev->xconfigure.height;
    else
    {
        winw = xev->xconfigure.width;
        winh = xev->xconfigure.height;

        if ( cur_form && ( cur_form->w > winw || cur_form->h > winh ) )
        {
            reshape_form_background( winw, winh );
            redraw_the_form( 1 );
        }

        if ( fd_resize->resize->visible )
        {
            fl_set_spinner_value( fd_resize->width,  winw );
            fl_set_spinner_value( fd_resize->height, winh );
        }

        changed = FL_TRUE;
    }

    return 1;
}


/***************************************
 ***************************************/

static int
handle_expose( XEvent * xev,
               void   * p  FL_UNUSED_ARG )
{
    if ( xev->xexpose.count == 0 )
    {
        M_warn( "FD_Expose", "" );

        /* If we have ignored a previous configure event, need the window
           size might not be correct. Re-read */

        if ( ignored_fake_configure )
            fl_get_winsize( main_window, &winw, &winh );

        /* Change form background size */

        if ( cur_form && ( cur_form->w != winw || cur_form->h != winh ) )
            reshape_form_background( winw, winh );

        redraw_the_form( 1 );
        ignored_fake_configure = 0;
        return 1;
    }

    return 0;
}


/***************************************
 * Need the ability to convert/help without requiring an X connection.
 ***************************************/

static void
pre_connect( int    argc,
             char * argv[ ] )
{
    int i,
        s;
    static char filter[ 128 ];

    for ( i = 1; i < argc && *argv[ i ] == '-'; i++ )
    {
        if ( strncmp( argv[ i ] + 1, "help", 1 ) == 0 )
            usage( argv[ 0 ], 1 );
        else if ( strncmp( argv[ i ] + 1, "version", 4 ) == 0 )
            print_version( 1 );
        else if ( strncmp( argv[ i ] + 1, "altformat", 3 ) == 0 )
            fdopt.altformat = 1;
        else if ( strncmp( argv[ i ] + 1, "callback", 3 ) == 0 )
            fdopt.emit_cb = 1;
        else if ( strncmp( argv[ i ] + 1, "compensate", 4 ) == 0 )
            fdopt.compensate = 1;
        else if ( strncmp( argv[ i ] + 1, "main", 3 ) == 0 )
            fdopt.emit_main = 1;
        else if ( strncmp( argv[ i ] + 1, "noc", 3 ) == 0 )
            fdopt.emit_code = 0;
        else if ( strncmp( argv[ i ] + 1, "unit", 4 ) == 0 && i + 1 < argc )
            fdopt.unit = unit_val( argv[ ++i ] );
        else if ( strncmp( argv[ i ] + 1, "filter", 4 ) == 0 && i + 1 < argc )
            strcpy( filter, argv[ ++i ] );
        else if ( strncmp( argv[ i ], "-I", 2 ) == 0 )
        {
            if ( argv[ i ][ 2 ] != '\0' )
                strcpy( xform_header, argv[ i ] + 2 );
            else if ( i + 1 < argc )
                strcpy( xform_header, argv[ ++i ] );
        }
        else if ( strcmp( argv[ i ], "-G" ) == 0 && i + 1 < argc )
            strcpy( glcanvas_header, argv[ ++i ] );
        else if ( strcmp( argv[ i ], "-bw" ) == 0 && i + 1 < argc )
            fd_bwidth = atoi( argv[ ++i ] );
        else if ( strncmp( argv[ i ] + 1, "convert", 1 ) == 0 )
        {
            fli_no_connection = 1;
            fli_internal_init( );
            fdopt.conv_only = 1;
        }
        else if ( strncmp( argv[ i ] + 1, "migrate", 1 ) == 0 )
        {
            fli_no_connection = 1;
            fli_internal_init( );
            fdopt.conv_only = 2;
        }
        else if ( strncmp( argv[ i ] + 1, "dir", 3 ) == 0 && i + 1 < argc )
        {
            fdopt.output_dir = malloc( strlen( argv[ ++i ] ) + 1 );
            strcpy( fdopt.output_dir, argv[ i ] );
        }
        else if ( strncmp( argv[ i ] + 1, "lang", 4 ) == 0 && i + 1 < argc )
            fdopt.language = lang_val( argv[ ++i ] );
        else
            fdopt.language = lang_val( argv[ i ] + 1 );
    }

    if ( fdopt.language < FD_C || fdopt.language > FD_EXP )
        fdopt.language = FD_C;

    if ( filter[ 0 ] )
        convertor[ fdopt.language ].extern_convertor = filter;

    if ( convertor[ fdopt.language ].init )
        convertor[ fdopt.language ].init( );

    /* No need to check for C syntax if not C program */

    if ( fdopt.language != FD_C )
        fdopt.lax = 1;

    if ( ! fdopt.conv_only )
        return;

    fli_set_app_name( argv[ 0 ], "Fdesign" );   /* resource routine needs it */
    fli_init_context( );
    create_the_forms( );
    init_classes( );

    fl_dpi = 96;

    if ( i > argc - 1 )
    {
        if ( fdopt.conv_only == 1 )
            fprintf( stderr, "'-convert' requires argument(s)\n" );
        else
            fprintf( stderr, "'-migrate' requires argument(s)\n" );

        usage( argv[ 0 ], 1 );
    }

    for ( s = i; s < argc; s++ )
    {
        reset_object_list( );

        if ( load_forms( FL_FALSE, argv[ s ] ) < 0 )
        {
            fprintf( stderr, "Unable to load '%s'\n", argv[ s ] );
            exit( 1 );
        }

        if ( ! save_forms( argv[ s ] ) )
        {
            fprintf( stderr, "Unable to convert '%s'\n", argv[ s ] );
            exit( 1 );
        }
    }

    exit( 0 );
}


/***************************************
 ***************************************/

static int
parse_geometry( const char   * gstr,
                int          * x,
                int          * y,
                unsigned int * w,
                unsigned int * h )
{
    int s;

    s = XParseGeometry( ( char * ) gstr, x, y, w, h );
    if ( s & XValue && s & XNegative )
        *x = fl_scrw - FL_abs( *x );
    if ( s & YValue && s & YNegative )
        *y = fl_scrh - FL_abs( *y );
    return s;
}

#include <signal.h>

/***************************************
 ***************************************/

static void
interrupted( int    s     FL_UNUSED_ARG,
             void * data  FL_UNUSED_ARG )
{
    exit_cb( 0, 0 );
}


/***************************************
 * Default action for delete window client message
 ***************************************/

static int
delete_handler( FL_FORM * form  FL_UNUSED_ARG,
                void    * data  FL_UNUSED_ARG )
{
    if (    changed 
         && fl_show_question( "Changes have not been saved\n"
                              "Save them now ?", 1 )
         && ! save_forms( NULL ) )
        return FL_IGNORE;

    exit( 0 );
    return 0;           /* shut up compiler */
}


/***************************************
 * Always output perl code in altformat
 ***************************************/

static void
perl_init( void )
{
    fdopt.altformat = 1;
}


/***************************************
 ***************************************/

static void
initialize( void )
{
    fdopt.conv_only = 0;
    fdopt.language = FD_C;
    fdopt.emit_code = 1;

    convertor[ FD_EXP ].lang_name = "exp";
    convertor[ MAX_CONVERTOR ].lang_name = NULL;

    convertor[ FD_C ].lang_name = "C";
    convertor[ FD_C ].convert = C_output;

    convertor[ FD_ADA95 ].lang_name = "ada";
    convertor[ FD_ADA95 ].extern_convertor = "flc2ada";
    convertor[ FD_ADA95 ].need_c_code = 1;

    convertor[ FD_PASCAL ].lang_name = "pascal";
    convertor[ FD_PASCAL ].extern_convertor = "fd2pascal";

    convertor[ FD_PS ].lang_name = "ps";
    convertor[ FD_PS ].extern_convertor = "fd2ps";

    convertor[ FD_PERL ].lang_name = "perl";
    convertor[ FD_PERL ].need_c_code = 1;
    convertor[ FD_PERL ].extern_convertor = "fd2perl";
    convertor[ FD_PERL ].init = perl_init;

    convertor[ FD_PYTHON ].lang_name = "python";
    convertor[ FD_PYTHON ].extern_convertor = "fd2python";

    convertor[ FD_FORTRAN ].lang_name = "fortran";
    convertor[ FD_FORTRAN ].extern_convertor = "fd2fortran";

    convertor[ FD_SCM ].lang_name = "scm";
    convertor[ FD_SCM ].extern_convertor = "fd2scm";
}


/***************************************
 ***************************************/

static int
ignore_close( FL_FORM *a  FL_UNUSED_ARG,
              void    *b  FL_UNUSED_ARG )
{
    return FL_IGNORE;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    unsigned int w = 0,
                 h = 0;
    int x = 0,
        y = 0,
        s,
        version,
        revision;
    FL_IOPT cntl;
    unsigned int mask;
    char *tmp = NULL;

    /* Before doing anything, check to make sure the library is made
       correctly */

    if ( FL_INCLUDE_VERSION != fl_library_version( &version, &revision ) )
    {
        fprintf( stderr, "Library and header mismatch\n" );
        fprintf( stderr, "  Header Version:%d.%d.%s\n",
                 FL_VERSION, FL_REVISION, FL_FIXLEVEL );
        fprintf( stderr, " Library version:%d.%d\n", version, revision );
    }

    initialize( );

    /* For conversion, version and usage help, we don't need a connection.
       pre_connect will exit in such circumstances. */

    pre_connect( argc, argv );

    /* Force fdesign to come up in default visual */

    cntl.vclass = FL_DefaultVisual;
    cntl.doubleBuffer = 0;
    cntl.browserFontSize = FL_NORMAL_FONT;
    mask = FL_PDVisual | FL_PDDouble | FL_PDBrowserFontSize;

    cntl.sharedColormap = 1;
    mask |= FL_PDSharedMap;

    fl_set_defaults( mask, &cntl );

    if ( ! ( fd_display = fl_initialize( &argc, argv, 0, fd_cmdopt, Ncopt ) ) )
        exit( 1 );

    fl_get_app_resources( fdres, Nropt );
    fl_add_signal_callback( SIGINT, interrupted, 0 );

    if ( argv[ 1 ] && argv[ 1 ][ 0 ] == '-' )
    {
        fprintf( stderr, " Unknown option: %s\n", argv[ 1 ] );
        usage( argv[ 0 ], 1 );
    }

    fli_cntl.coordUnit = FL_COORD_PIXEL;
    fdopt.unit = unit_val( fd_sunit );
    fdopt.language = lang_val( fd_slanguage );

    if ( *fd_sfilter )
        convertor[ fdopt.language ].extern_convertor = fd_sfilter;

    /* No need to check for C syntax if not C program */

    if ( fdopt.language != FD_C )
        fdopt.lax = 1;

    if ( convertor[ fdopt.language ].init )
        convertor[ fdopt.language ].init( );

    fd_bwidth = fli_cntl.borderWidth;
    M_warn( "fdesign", "UNIT=%s BW=%d", unit_name( fdopt.unit ), fd_bwidth );

    create_the_forms( );
    fl_set_atclose( delete_handler, 0 );

    /* Must suspend user requested button label font throughout fdesign and
       enable it only when testing */

    fd_buttonLabelSize = fli_cntl.buttonFontSize;
    fli_cntl.buttonFontSize = 0;

    /* Initialize stuff */

    init_classes( );

    fl_set_counter_bounds( fd_align->snapobj, 1.0, 500.0 );
    fl_set_counter_step( fd_align->snapobj, 1.0, 5.0 );
    fl_set_counter_value( fd_align->snapobj, 10.0 );
    fl_set_counter_precision( fd_align->snapobj, 0 );
    fl_set_form_atclose( fd_align->align, ignore_close, NULL );

    fl_set_spinner_bounds( fd_resize->width,  1, SHRT_MAX );
    fl_set_spinner_bounds( fd_resize->height, 1, SHRT_MAX );
    fl_set_form_atclose( fd_resize->resize, ignore_close, NULL );

    fl_set_form_atclose( fd_attrib->attrib, ignore_close, NULL );
    fl_set_form_atclose( fd_attrib->attrib, ignore_close, NULL );
    fl_set_form_atclose( fd_test->test, ignore_close, NULL );
    fl_set_form_atclose( fd_help->helpform, ignore_close, NULL );

    thetestform = NULL;
    strcpy( main_name, "create_the_forms" );

    /* Load files */

    /* If only one argument is given and the file does not exist, we can
       assume that the intention is to create a new file so we don't bother
       to try to load it */

    if (    argc >= 2
         && access( tmp = append_fd_suffix( argv[ argc - 1 ] ), R_OK ) == 0 )
    {
        for ( s = 1; s < argc; s++ )
            if ( load_forms( s == 1 ? FL_FALSE : FL_TRUE, argv[ s ] ) < 0 )
                break;
    }
    else
    {
        select_object_by_class( FL_BUTTON );
        select_pallette_entry( FL_BUTTON );
    }

    fli_safe_free( tmp );

    /* Do auto-naming for single file only */

    if ( argc == 2 )
        loadedfile = rel2abs( argv[ 1 ] );

    /* See if color change */

    if ( fd_attrib_col[ 0 ] )
    {
        long c = FL_FREE_COL1 - 10;

        fl_mapcolor_name( c, fd_attrib_col );
        modify_attrib_basic_color( c, c );
    }

    parse_geometry( fdcntlgeom, &x, &y, &w, &h );
    fl_set_form_position( fd_control->control, x, y );

    fl_set_app_mainform( fd_control->control );
    fli_set_form_icon_data( fd_control->control, fd_logo_pixels );
    fl_show_form( fd_control->control, FL_PLACE_GEOMETRY,
                 ( 1 || fd_cntlborder ) ? FL_FULLBORDER : FL_TRANSIENT,
                 "Control" );

    /* Other geometries */

    parse_geometry( fdattribgeom, &x, &y, &w, &h );
    fl_set_form_position( fd_attrib->attrib, x, y );

    parse_geometry( fdtestgeom, &x, &y, &w, &h );
    fl_set_form_position( fd_test->test, x, y );

    parse_geometry( fdaligngeom, &x, &y, &w, &h );
    fl_set_form_position( fd_align->align, x, y );

    parse_geometry( fdhelpgeom, &x, &y, &w, &h );
    fl_set_form_position( fd_help->helpform, x, y );

    s = parse_geometry( fdgeom, &x, &y, &w, &h );
    if ( s & XValue || s & YValue )
        fl_winposition( x, y );
    if ( s & WidthValue && s & HeightValue )
        fl_initial_winsize( w, h );

    /* If a form is already loaded, use that size */

    if ( cur_form )
    {
        y -= cur_form->h - h;
        w = cur_form->w;
        h = cur_form->h;
        fl_initial_wingeometry( x, y, w, h );
    }

    winw = w;
    winh = h;

    fd_colormap = fl_state[ fl_vmode ].colormap;
    fd_white = fl_get_flcolor( FL_WHITE );
    fd_red   = fl_get_flcolor( FL_RED );
    fd_black = fl_get_flcolor( FL_BLACK );
    fd_col   = fl_get_flcolor( FL_COL1 );

    main_window = fli_cmap_winopen( fl_root, fd_colormap, "Form Design" );

    fl_set_fselector_transient( 1 );

    fl_add_event_callback( main_window, Expose, handle_expose, 0 );
    fl_add_event_callback( main_window, ConfigureNotify, handle_configure, 0 );
    fl_add_event_callback( main_window, ButtonPress, handle_click, 0 );
    fl_addto_selected_xevent( main_window,
                              ButtonMotionMask | PointerMotionHintMask );
    fl_addto_selected_xevent( main_window, ButtonReleaseMask );

    redraw_the_form( 1 );

    /* GC is valid only after at least one window is created */

    fd_gc = fl_state[ fl_vmode ].gc[ 8 ];

    main_loop( );

    return 0;
}


/***************************************
 ***************************************/

void
set_snap_size( int n,
               int cb )
{
    fl_set_counter_value( fd_align->snapobj, n > 0 ? n : 5 );
    if ( cb )
        fl_call_object_callback( fd_align->snapobj );
}


/***************************************
 ***************************************/

int
get_snap_size( void )
{
    return 0.01 + fl_get_counter_value( fd_align->snapobj );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
