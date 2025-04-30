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
 * \file win.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 * To isolate dependencies of XForms on the window system, we provide
 * some system-neutual windowing services. It is expected that all
 * XForms internal windowing will be done using these.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"


/*********************************************************************
 *
 * Windowing support.
 * Geometry preference, opening/closing windows and geometry queries
 *
 * winclose is in appwin.c
 *
 ****************************************************************{****/

static XSetWindowAttributes st_xswa;
static XSizeHints           st_xsh;
static XWMHints             st_xwmh;
static unsigned int         st_wmask;
static int                  st_wmborder;
static unsigned int         bwidth = 0;

static int fli_winreparentxy( Window win,
                              Window new_parent,
                              int    x,
                              int    y );

extern FLI_WM_STUFF fli_wmstuff;       /* defined in flresource.c */


/*********************************************************************
 * Default window attributes. Subject to pref_winsize and its friends
 **********************************************************************/

void
fli_default_xswa( void )
{
    /* OwnerGrab is needed for pop-up to work correctly */

    st_xswa.event_mask =   ExposureMask
                         | KeyPressMask
                         | KeyReleaseMask
                         | ButtonPressMask
                         | ButtonReleaseMask
                         | OwnerGrabButtonMask
                         | EnterWindowMask
                         | LeaveWindowMask
                         | ButtonMotionMask
                         | PointerMotionMask
                         | PointerMotionHintMask
/*
                         | VisibilityChangeMask
                         | PropertyChangeMask
*/
                         | StructureNotifyMask;

    /* Add event mask flags required by the input method/context */

    if( fli_context->xic )
    {
        long int fevents;

        if ( ! XGetICValues( fli_context->xic, XNFilterEvents,
                             &fevents, NULL ) )
            st_xswa.event_mask |= fevents;
    }

    st_xswa.backing_store = fli_cntl.backingStore;
    st_wmask = CWEventMask | CWBackingStore;

    /* Border_pixel must be set for 24bit TrueColor displays */

    st_xswa.border_pixel  = 0;
    st_wmask             |= CWBorderPixel;
    st_xsh.flags          = 0;

    /* Default size */

    st_xsh.width = st_xsh.base_width   = 320;
    st_xsh.height = st_xsh.base_height = 200;

    /* Border */

    st_wmborder = FL_FULLBORDER;

    /* Keyboard focus. Need window manager's help  */

    st_xwmh.input         = True;
    st_xwmh.initial_state = NormalState;
    st_xwmh.flags         = InputHint | StateHint;
}


/************** Window sizes ******************{**/

/***************************************
 *  Open window with this size
 ***************************************/

void
fl_initial_winsize( FL_Coord w,
                    FL_Coord h )
{
    st_xsh.width   = st_xsh.base_width = w;
    st_xsh.height  = st_xsh.base_height = h;
    st_xsh.flags  |= USSize;
}


/***************************************
 ***************************************/

void
fl_initial_winstate( int state )
{
    st_xwmh.initial_state  = state;
    st_xwmh.flags         |= StateHint;
}


/***************************************
 ***************************************/

void
fl_winicon( Window win,
            Pixmap p,
            Pixmap m )
{
    XWMHints lxwmh,
             *xwmh;

    lxwmh.flags        = 0;
    xwmh               = win ? &lxwmh : &st_xwmh;
    xwmh->icon_pixmap  = p;
    xwmh->icon_mask    = m;
    xwmh->flags       |= IconPixmapHint | IconMaskHint;
    if ( win )
        XSetWMHints( flx->display, win, xwmh );
}


/***************************************
 * Open window with this size and KEEP it this size (if window manager
 * cooperates)
 ***************************************/

void
fl_winsize( FL_Coord w,
            FL_Coord h )
{
    fl_initial_winsize( w, h );

    /* Try to disable interactive resizing */

    st_xsh.min_width   = st_xsh.max_width  = w;
    st_xsh.min_height  = st_xsh.max_height = h;
    st_xsh.flags      |= PMinSize | PMaxSize;
}


/***************************************
 * Set a limit to the minimum size a window can take. Can be used
 * while a window is visible. If window is not given, we take the
 * request to mean a constraint for future windows.
 ***************************************/

void
fl_winminsize( Window   win,
               FL_Coord w,
               FL_Coord h )
{
    XSizeHints mxsh,
               *sh;

    /* Copy current constraints */

    mxsh            = st_xsh;
    mxsh.flags      = 0;
    sh              = win ? &mxsh : &st_xsh;

    sh->min_width   = w;
    sh->min_height  = h;
    sh->flags      |= PMinSize;
    if ( win )
        XSetWMNormalHints( flx->display, win, sh );
}


/***************************************
 ***************************************/

void
fl_winmaxsize( Window   win,
               FL_Coord w,
               FL_Coord h )
{
    XSizeHints mxsh,
               *sh;

    mxsh            = st_xsh;
    mxsh.flags      = 0;
    sh              = win ? &mxsh : &st_xsh;

    sh->max_width   = w;
    sh->max_height  = h;
    sh->flags      |= PMaxSize;
    if ( win )
        XSetWMNormalHints( flx->display, win, sh );
}


/***************************************
 ***************************************/

void
fl_winstepsize( Window   win,
                FL_Coord dx,
                FL_Coord dy )
{
    XSizeHints mxsh,
               *sh;

    /* Copy current constraints */

    mxsh            = st_xsh;
    mxsh.flags      = 0;
    sh              = win ? &mxsh : &st_xsh;

    sh->width_inc   = dx;
    sh->height_inc  = dy;
    sh->flags      |= PResizeInc;
    if ( win )
        XSetWMNormalHints( flx->display, win, sh );
}


/******* End of basic win size routines **********}***/


/******* Window position routines **************{***/


/***************************************
 ***************************************/

void
fl_winposition( FL_Coord x,
                FL_Coord y )
{
    st_xsh.x = x;
    st_xsh.y = y;
    st_xsh.flags |= fli_wmstuff.pos_request;
}


/****** End of window positioning routines ******}*/


/***** Window position and size **************{****/


/***************************************
 ***************************************/

void
fl_initial_wingeometry( FL_Coord x,
                        FL_Coord y,
                        FL_Coord w,
                        FL_Coord h )
{
    fl_winposition( x, y );
    fl_initial_winsize( w, h );
}


/***************************************
 ***************************************/

void
fl_wingeometry( FL_Coord x,
                FL_Coord y,
                FL_Coord w,
                FL_Coord h )
{
    fl_winposition( x, y );
    fl_winsize( w, h );
}

/***** End of geometry preference routine *******}**/

/***** Misc. windowing routines *****************{*/


/***************************************
 * Try to fix the aspect ration
 ***************************************/

void
fl_winaspect( Window   win,
              FL_Coord x,
              FL_Coord y )
{
    XSizeHints lxsh,
               *xsh;

    if ( x <= 0 || y <= 0 )
    {
        M_err( "fl_winaspect", "Bad aspect ratio" );
        return;
    }

    lxsh.flags         = 0;
    xsh                = win ? &lxsh : &st_xsh;

    xsh->flags        |= PAspect;
    xsh->min_aspect.x  = x;
    xsh->min_aspect.y  = y;
    xsh->max_aspect.x  = x;
    xsh->max_aspect.y  = y;

    xsh->base_width    = xsh->width  = x;
    xsh->base_height   = xsh->height = y;

    if ( xsh->base_width < 100 || xsh->base_height < 100 )
    {
        double fact = 100 / FL_max( x, y );

        xsh->base_width  *= fact;
        xsh->base_height *= fact;
    }

    if ( win )
        XSetWMNormalHints( flx->display, win, xsh );
}


/***************************************
 ***************************************/

void
fl_noborder( void )
{
    st_wmborder = FL_NOBORDER;
}


/***************************************
 ***************************************/

void
fl_transient( void )
{
    st_wmborder = FL_TRANSIENT;
}


/***************************************
 ***************************************/

void
fl_winmove( Window   win,
            FL_Coord dx,
            FL_Coord dy)
{
    if ( win )
        XMoveWindow( flx->display, win, dx, dy );
    else
        fl_winposition( dx, dy );
}


/***************************************
 ***************************************/

void
fl_winreshape( Window   win,
               FL_Coord dx,
               FL_Coord dy,
               FL_Coord w,
               FL_Coord h )
{
    if ( win )
        XMoveResizeWindow( flx->display, win, dx, dy, w, h );
    else
    {
        fl_winresize( win, w, h );
        fl_winmove( win, dx, dy );
    }
}


/***** End of misc. windowing routines **********}*/

/********* Window geometry query routines ********{*/


/***************************************
 ***************************************/

void
fl_get_winsize( Window     win,
                FL_Coord * w,
                FL_Coord * h )
{
    unsigned int ww,
                 hh,
                 bjunk,
                 djunk;
    int xx,
        yy;
    Window root;

    XGetGeometry( flx->display, win, &root, &xx, &yy, &ww, &hh,
                  &bjunk, &djunk );
    *w = ww;
    *h = hh;
}


/***************************************
 ***************************************/

void
fl_get_winorigin( Window     win,
                  FL_Coord * x,
                  FL_Coord * y )
{
    int xx,
        yy;
    unsigned int ww,
                 hh,
                 bw,
                 d;
    Window root;

    XGetGeometry( flx->display, win, &root, &xx, &yy, &ww, &hh, &bw, &d );
    XTranslateCoordinates( flx->display, win, root,
                           - ( int ) bw, - ( int ) bw, &xx, &yy, &root );
    *x = xx;
    *y = yy;
}


/***************************************
 ***************************************/

void
fl_get_wingeometry( Window     win,
                    FL_Coord * x,
                    FL_Coord * y,
                    FL_Coord * w,
                    FL_Coord * h )
{
    int xx,
        yy;
    unsigned int ww,
                 hh,
                 bw,
                 d;
    Window root;

    XGetGeometry( flx->display, win, &root, &xx, &yy, &ww, &hh, &bw, &d );
    XTranslateCoordinates( flx->display, win, root,
                           - ( int ) bw, - ( int ) bw, &xx, &yy, &root );
    *x = xx;
    *y = yy;
    *w = ww;
    *h = hh;
}


/***** End of window geometry query routines ********}*/

/******* Open window etc ***********************/


/***************************************
 * If one of the forms is destoryed we want to know about it
 * All window notices the Close window manager command
 ***************************************/

static void
setup_catch_destroy( Window win )
{
    static Atom atom_delete_win;
    static Atom atom_protocols;

    if ( ! atom_delete_win )
        atom_delete_win = XInternAtom( flx->display, "WM_DELETE_WINDOW", 0 );

    if ( ! atom_protocols )
        atom_protocols = XInternAtom( flx->display, "WM_PROTOCOLS", 0 );

    XChangeProperty( flx->display, win, atom_protocols, XA_ATOM, 32,
                     PropModeReplace, ( unsigned char * ) &atom_delete_win, 1 );
}


/***************************************
 * Waits until we know for sure the newly mapped window is visible
 ***************************************/

static void
wait_mapwin( Window win )
{
    XEvent xev;

    if ( ! ( st_xswa.event_mask & StructureNotifyMask ) )
    {
        M_err( "wait_mapwin", "XForms improperly initialized" );
        exit( 1 );
    }

    /* Wait for the window to become mapped */

    do
    {
        XWindowEvent( flx->display, win, StructureNotifyMask, &xev );
        fli_xevent_name( "waiting", &xev );
    } while ( xev.type != MapNotify );
}


/***************************************
 ***************************************/

static char *
fl_label_to_res_name( const char * label )
{
    static char res[ 54 ];

    fli_sstrcpy( res, label ? label : "", sizeof res );
    fli_nuke_all_non_alnum( res );
    if ( res[ 0 ] && isupper( ( unsigned char ) res[ 0 ] ) )
        res[ 0 ] = tolower( ( unsigned char ) res[ 0 ] );
    return res;
}


/***************************************
 ***************************************/

static char *
get_machine_name( Display * d )
{
    static char machine_name[ 256 ] = "";
    char *p;

    if ( machine_name[ 0 ] )
        return machine_name;

    if ( gethostname( machine_name, sizeof machine_name - 1 ) )
    {
        M_err( "get_machine_name", "Unable to get host name" );
        strcpy( machine_name, DisplayString( d ) );
        if ( ( p = strchr( machine_name, ':' ) ) )
            *p = '\0';
    }

    return machine_name;
}


/***************************************
 ***************************************/

void
fli_set_winproperty( Window       win,
                     unsigned int prop )
{
    char **argv;
    int argc;

    if ( prop & FLI_COMMAND_PROP )
    {
        argv = fl_get_cmdline_args( &argc );
        XSetCommand( flx->display, win, argv, argc );
    }
}


/***************************************
 ***************************************/

Window
fli_create_window( Window       parent,
                   Colormap     m,
                   const char * wname )
{
    Window win;
    XClassHint clh;
    char *tmp;
    XTextProperty xtpwname,
                  xtpmachine;
    char *label = fl_strdup( wname ? wname : "" );
    FL_FORM *mainform = fl_get_app_mainform( );

    st_xswa.colormap = m;
    st_wmask |= CWColormap;

    /* No decoration means unmanagered windows */

    if (    st_wmborder == FL_NOBORDER
         && ( st_xsh.flags & fli_wmstuff.pos_request)
                                                    == fli_wmstuff.pos_request )
    {
        /* Turning this on will make the window truely unmananged, might have
           problems with the input focus and colormaps */

        st_xswa.override_redirect = True;
        st_wmask |= CWOverrideRedirect;
    }

    /* MWM uses root window's cursor, don't want that */

    if ( ( st_wmask & CWCursor ) != CWCursor )
    {
        st_xswa.cursor = fli_get_cursor_byname( FL_DEFAULT_CURSOR );
        st_wmask |= CWCursor;
    }

    if ( st_wmborder != FL_FULLBORDER )
    {
        st_xswa.save_under = True;
        st_wmask |= CWSaveUnder;

    /* For small transient windows, we don't need backing store */

        if ( st_xsh.width < 200 || st_xsh.height < 200 )
            st_xswa.backing_store = NotUseful;
    }

    if ( mainform && mainform->window )
    {
        st_xwmh.flags |= WindowGroupHint;
        st_xwmh.window_group = mainform->window;
    }

#if FL_DEBUG >= ML_WARN
    fli_dump_state_info( fl_vmode, "fli_create_window" );
#endif

    win = XCreateWindow( flx->display, parent,
                         st_xsh.x, st_xsh.y, st_xsh.width, st_xsh.height,
                         bwidth, fli_depth( fl_vmode ), InputOutput,
                         fli_visual( fl_vmode ), st_wmask, &st_xswa );

    if ( fli_cntl.debug > 3 )
    {
        XFlush( flx->display );
        fprintf( stderr, "****CreateWin OK**** sleeping 1 seconds\n" );
        sleep( 1 );
    }

    clh.res_name = fl_label_to_res_name( label );
    clh.res_class = "XForm";

    /* Command property is set elsewhere */

    xtpwname.value = 0;
    XStringListToTextProperty( label ? &label : 0, 1, &xtpwname );

    XSetWMProperties( flx->display, win, &xtpwname, &xtpwname,
                      0, 0, &st_xsh, &st_xwmh, &clh );

    if ( xtpwname.value )
        XFree( xtpwname.value );

    xtpmachine.value = 0;
    tmp = get_machine_name( flx->display );

    if ( XStringListToTextProperty( &tmp, 1, &xtpmachine ) )
        XSetWMClientMachine( flx->display, win, &xtpmachine );

    if ( xtpmachine.value )
        XFree( xtpmachine.value );

    fli_create_gc( win );

    if ( st_wmborder == FL_TRANSIENT )
    {
        if ( mainform && mainform->window )
            XSetTransientForHint( flx->display, win, mainform->window );
        else
            XSetTransientForHint( flx->display, win, fl_root );
    }

    fl_free( label );

    return win;
}


/***************************************
 ***************************************/

Window
fli_cmap_winopen( Window       parent,
                 Colormap     m,
                 const char * label )
{
    Window win = fli_create_window( parent, m, label );
    return fl_winshow( win );
}


/***************************************
 ***************************************/

Window
fl_wincreate( const char * label )
{
    return fli_create_window( fl_root, fli_map( fl_vmode ), label) ;
}


/***************************************
 ***************************************/

Window
fl_winopen( const char * label )
{
    fli_init_colormap( fl_vmode );
    return fli_cmap_winopen( fl_root, fli_map( fl_vmode ), label );
}


/***************************************
 ***************************************/

Window
fl_winshow( Window win )
{
    XMapRaised( flx->display, win );

    /* Wait until the newly mapped window shows up */

    if ( st_xwmh.initial_state == NormalState )
        wait_mapwin( win );

    setup_catch_destroy( win );
    fl_winset( win );

    /* Re-initialize window defaults  */

    fli_default_xswa( );
    return win;
}


/***************************************
 ***************************************/

int
fli_winreparentxy( Window win,
                   Window new_parent,
                   int    x,
                   int    y )
{

    if ( ! win || ! new_parent )
        return -1;
    else
        return XReparentWindow( flx->display, win, new_parent, x, y );
}


/***************************************
 ***************************************/

int
fl_winreparent( Window win,
                Window new_parent )
{
    return fli_winreparentxy( win, new_parent, 0, 0 );
}


/***************************************
 ***************************************/

void
fl_winhide( Window win )
{
    if ( win )
        XUnmapWindow( flx->display, win );
}


/***************************************
 ***************************************/

void
fl_winbackground( Window         win,
                  unsigned long  bk )
{
    if ( win == 0 )
    {
        st_xswa.background_pixel = bk;
        st_wmask |= CWBackPixel;
    }
    else
    {
        XSetWindowBackground( flx->display, win, bk );
        XClearWindow( flx->display, win );
    }
}


/***************************************
 ***************************************/

void
fl_winset( Window win )
{
    flx->win = win;
}


/***************************************
 ***************************************/

Window
fl_winget( void )
{
    return flx->win;
}


/***************************************
 ***************************************/

int
fl_iconify( Window win )
{
    return XIconifyWindow( flx->display, win, flx->screen );
}


/***************************************
 * Inform window manager about window constraints: minsize, maxsize,
 * aspect ratio
 ***************************************/

void
fl_reset_winconstraints( Window win )
{
    if ( win )
        XSetWMNormalHints( flx->display, win, &st_xsh );
}


/***************************************
 ***************************************/

void
fl_winresize( Window   win,
              FL_Coord neww,
              FL_Coord newh )
{
    XSizeHints lxsh;
    long fields;
    FL_Coord curwh, curww;

    if ( ! win )
        return;

    /* If sizes are the same we don't have to do anything. Some window managers
       are too dumb to optimize this. */

    fl_get_winsize( win, &curww, &curwh );
    if ( curww == neww && curwh == newh )
        return;

    lxsh.flags = 0;
    fields = 0;

    if ( XGetWMNormalHints( flx->display, win, &lxsh, &fields ) )
    {
        lxsh.width   = lxsh.base_width  = neww;
        lxsh.height  = lxsh.base_height = newh;
        lxsh.flags  |= USSize;

        if ( lxsh.flags & PMinSize && lxsh.flags & PMaxSize )
        {
            if ( lxsh.min_width == lxsh.max_width )
                lxsh.min_width = lxsh.max_width = neww;
            if ( lxsh.min_height == lxsh.max_height )
                lxsh.min_height = lxsh.max_height = newh;
        }

        /* Reset any contraints */

        if ( lxsh.flags & PMinSize )
        {
            if ( lxsh.min_width > neww )
                lxsh.min_width = neww;
            if ( lxsh.min_height > newh )
                lxsh.min_height = newh;
        }

        if ( lxsh.flags & PMaxSize )
        {
            if ( lxsh.max_width < neww )
                lxsh.max_width = neww;
            if ( lxsh.max_height < newh )
                lxsh.max_height = newh;
        }

        XSetWMNormalHints( flx->display, win, &lxsh );
    }

    XResizeWindow( flx->display, win, neww, newh );
    XFlush( flx->display );
}


/***************************************
 * Check if a given window is valid. At the moment only used by
 * canvas. A dirty hack. *****TODO *****
 * If the main event loop is correct, we don't need to do this stuff
 ***************************************/

static int badwin;

static int
valid_win_handler( Display     * dpy  FL_UNUSED_ARG,
                   XErrorEvent * xev )
{
    if ( xev->error_code == BadWindow || xev->error_code == BadDrawable )
        badwin = 1;

    return 0;
}


/***************************************
 ***************************************/

int
fl_winisvalid( Window win )
{
    int ( * old )( Display *, XErrorEvent * );
    FL_Coord w,
             h;

    badwin = 0;
    old = XSetErrorHandler( valid_win_handler );
    fl_get_winsize( win, &w, &h );
    XSetErrorHandler( old );
    return ! badwin;
}


/***************************************
 ***************************************/

void
fl_wintitle( Window       win,
             const char * title )
{
    XTextProperty xtp;

    if ( ! win && ! title )
        return;

    xtp.value = 0;
    XStringListToTextProperty( ( char ** ) &title, 1, &xtp );
    XSetWMName( flx->display, win, &xtp );
    XSetWMIconName( flx->display, win, &xtp );
    if ( xtp.value )
        XFree( xtp.value );
}


/***************************************
 ***************************************/

void
fl_wintitle_f( Window       win,
               const char * fmt,
               ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_wintitle( win, buf );
    fl_free( buf );
}
    

/***************************************
 ***************************************/

void
fl_winicontitle( Window       win,
                 const char * title )
{
    XTextProperty xtp;

    if ( ! win || ! title )
        return;

    xtp.value = 0;
    XStringListToTextProperty( ( char ** ) &title, 1, &xtp );
    XSetWMIconName( flx->display, win, &xtp );
    if ( xtp.value )
        XFree( xtp.value );
}


/***************************************
 ***************************************/

void
fl_winicontitle_f( Window       win,
                   const char * fmt,
                   ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_winicontitle( win, buf );
    fl_free( buf );
}
    

/***************************************
 * Grab keyboard focus
 ***************************************/

void
fl_winfocus( Window win )
{
    XSetInputFocus( flx->display, win, RevertToParent, CurrentTime );

#if 0
    if ( fli_context->xic )
       XSetICValues( fli_context->xic,
                     XNClientWindow, win, XNFocusWindow, win, 0 );
#endif
}

/********* END of Windowing support ***}**/


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
