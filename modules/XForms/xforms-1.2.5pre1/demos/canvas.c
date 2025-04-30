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
 * Demo showing the interaction with a canvas object.
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars  (1997)
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>


/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * canvasform;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * canvas;
    FL_OBJECT * br;
    FL_OBJECT * keyboard;
    FL_OBJECT * mouse;
    FL_OBJECT * move;
    FL_OBJECT * misc;
} FD_canvasform;

FD_canvasform *fd_canvasform;

static GC canvasGC;

/***************************************
 ***************************************/

static int
canvas_expose( FL_OBJECT * ob  FL_UNUSED_ARG,
               Window      win,
               int         w,
               int         h,
               XEvent    * ev  FL_UNUSED_ARG,
               void      * d )
{
    FD_canvasform *ui = d;

    XFillRectangle( fl_get_display( ), win, canvasGC, 0, 0, w, h );
    fl_addto_browser( ui->br, "Expose" );
    return 0;
}


/***************************************
 ***************************************/

static int
canvas_key( FL_OBJECT * ob   FL_UNUSED_ARG,
            Window      win  FL_UNUSED_ARG,
            int         w    FL_UNUSED_ARG,
            int         h    FL_UNUSED_ARG,
            XEvent    * ev,
            void      * d )
{
    FD_canvasform *ui = d;
    char buf[ 128 ];
	KeySym *keysymT;
    int dummy;

	keysymT = XGetKeyboardMapping( fl_display, ev->xkey.keycode, 1, &dummy);
    sprintf( buf, "KeyPress: keysym=%ld", ( long ) keysymT[ 0 ] );
    XFree( keysymT );
    fl_addto_browser( ui->br, buf );
    return 0;
}


/***************************************
 ***************************************/

static int
canvas_but( FL_OBJECT * ob   FL_UNUSED_ARG,
            Window      win  FL_UNUSED_ARG,
            int         w    FL_UNUSED_ARG,
            int         h    FL_UNUSED_ARG,
            XEvent    * ev,
            void      * d )
{
    FD_canvasform *ui = d;
    char buf[ 128 ];

    sprintf( buf, "Button%s: %d", ev->type == ButtonPress? "Press" : "Release",
             ev->xbutton.button );
    fl_addto_browser( ui->br, buf );
    return 0;
}


/***************************************
 ***************************************/

static int
canvas_move( FL_OBJECT * ob   FL_UNUSED_ARG,
             Window      win  FL_UNUSED_ARG,
             int         w    FL_UNUSED_ARG,
             int         h    FL_UNUSED_ARG,
             XEvent    * ev,
             void      * d )
{
    FD_canvasform *ui = d;
    char buf[ 128 ];

    sprintf( buf, "Position: %d %d", ev->xmotion.x, ev->xmotion.y );
    fl_addto_browser( ui->br, buf );
    return 0;
}


/***************************************
 ***************************************/

static int
canvas_misc( FL_OBJECT * ob   FL_UNUSED_ARG,
             Window      win  FL_UNUSED_ARG,
             int         w    FL_UNUSED_ARG,
             int         h    FL_UNUSED_ARG,
             XEvent    * ev,
             void      * d )
{
    FD_canvasform *ui = d;
    fl_addto_browser( ui->br, ev->xcrossing.type == EnterNotify ?
                      "Enter canvas" : "Leave canvas" );
    return 0;
}


/***************************************
 ***************************************/

static void
init_canvas( FD_canvasform * fdui )
{
    fl_add_canvas_handler( fdui->canvas, Expose, canvas_expose, fdui );
    fl_add_canvas_handler( fdui->canvas, KeyPress, canvas_key, fdui );
    fl_add_canvas_handler( fdui->canvas, ButtonPress, canvas_but, fdui );
    fl_add_canvas_handler( fdui->canvas, ButtonRelease, canvas_but, fdui );
    fl_set_button( fdui->mouse, 1 );
    fl_set_button( fdui->keyboard, 1 );
    canvasGC = XCreateGC( fl_get_display( ),fl_state[ fl_vmode ].trailblazer,
                          0, 0 );
    XSetForeground( fl_get_display( ), canvasGC, fl_get_flcolor( FL_BLACK ) );
}


/* callbacks */

/***************************************
 ***************************************/

static void
sensitive_setting( FL_OBJECT * ob,
                   long        event )
{
    FL_HANDLE_CANVAS hc;
    int count = 1;
    int events[ 2 ] = { event, 0 };


    switch ( event )
    {
        case KeyPress:
            hc = canvas_key;
            break;

        case ButtonPress:
            hc = canvas_but;
            events[ 1 ] = ButtonRelease;
            count = 2;
            break;

        case EnterNotify:
            hc = canvas_misc;
            events[ 1 ] = LeaveNotify;
            count = 2;
            break;

        case MotionNotify:
            hc = canvas_move;
            break;

        default:
            return;
    }

    if ( fl_get_button( ob ) )
        while ( count > 0 )
            fl_add_canvas_handler( fd_canvasform->canvas, events[ --count ],
                                   hc, fd_canvasform );
    else
        while ( count > 0 )
            fl_remove_canvas_handler( fd_canvasform->canvas, events[ --count ],
                                      hc );
}


/***************************************
 ***************************************/

static void
disable_it( FL_OBJECT * ob,
            long        data  FL_UNUSED_ARG )
{
    if ( fl_get_button( ob ) )
        fl_deactivate_object( fd_canvasform->canvas );
    else
        fl_activate_object( fd_canvasform->canvas );
}


/***************************************
 ***************************************/

static void
hide_it( FL_OBJECT * ob,
         long        all  FL_UNUSED_ARG  )
{
    if ( fl_object_is_visible( fd_canvasform->canvas ) )
    {
        fl_hide_object( fd_canvasform->canvas );
        fl_set_object_label( ob, "ShowCanvas" );
    }
    else
    {
        fl_show_object( fd_canvasform->canvas );
        fl_set_object_label( ob, "HideCanvas" );
    }
}


/***************************************
 ***************************************/

static void
clear_list( FL_OBJECT * ob    FL_UNUSED_ARG,
            long        what  FL_UNUSED_ARG  )
{
    fl_clear_browser( fd_canvasform->br );
}


/***************************************
 ***************************************/

static FD_canvasform *
create_form_canvasform( void )
{
    FL_OBJECT *obj;
    FD_canvasform *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->canvasform = fl_bgn_form( FL_NO_BOX, 450, 280 );

    fl_add_box( FL_UP_BOX, 0, 0, 450, 280, "" );

    fdui->canvas = fl_add_canvas( FL_NORMAL_CANVAS, 20, 40, 155, 187, "" );

    fdui->br = fl_add_browser( FL_NORMAL_BROWSER, 188, 40, 152, 187, "" );

    obj = fl_add_text( FL_NORMAL_TEXT, 103, 10, 150, 20, "Canvas Events" );
    fl_set_object_lsize( obj, FL_MEDIUM_SIZE );
    fl_set_object_lalign( obj, FL_ALIGN_CENTER );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    fdui->keyboard = obj = fl_add_checkbutton( FL_PUSH_BUTTON, 345, 40, 76, 26,
                                               "Keyboard" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, sensitive_setting, KeyPress );

    fdui->mouse = obj = fl_add_checkbutton( FL_PUSH_BUTTON, 345, 70, 76, 26,
                                            "Buttons" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, sensitive_setting, ButtonPress );

    fdui->move = obj = fl_add_checkbutton( FL_PUSH_BUTTON, 345, 100, 74, 26,
                                           "Movements" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, sensitive_setting, MotionNotify );

    fdui->misc = obj = fl_add_checkbutton( FL_PUSH_BUTTON, 345, 130, 74, 26,
                                           "Enter\nLeave" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, sensitive_setting, EnterNotify );

    obj = fl_add_button( FL_PUSH_BUTTON, 30, 240, 90, 27, "Deactivate" );
    fl_set_object_callback( obj, disable_it, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 130, 240, 90, 27, "Hide canvas" );
    fl_set_object_callback( obj, hide_it, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 230, 240, 90, 27, "Clear" );
    fl_set_object_callback( obj, clear_list, 0 );

    fl_add_button( FL_NORMAL_BUTTON, 330, 240, 90, 27, "Done" );

    fl_end_form( );

    return fdui;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_canvasform = create_form_canvasform( );

    init_canvas( fd_canvasform );

    fl_show_form( fd_canvasform->canvasform,
                  FL_PLACE_FREE, FL_FULLBORDER, "canvasform" );

    fl_do_forms();

    fl_finish( );
    fl_free( fd_canvasform );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
