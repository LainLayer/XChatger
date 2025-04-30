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
 * \file appwin.c
 *.
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Manage application windows
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


/*****************************************************************
 * Application window management. Data structure is grossly wrong
 * ****TODO******
 **************************************************************{**/

/* some constant handlers */

static int
handle_mapping_notify( XEvent * xev,
                       void   * user_data  FL_UNUSED_ARG )
{
    XRefreshKeyboardMapping( ( XMappingEvent * ) xev );
    return 0;
}


/***************************************
 ***************************************/

static void
remove_app_win( FLI_WIN * appwin )
{
#if FL_DEBUG >= ML_DEBUG
    M_info( "remove_app_win", "deleting window %ld", appwin->win );
#endif

    if ( fli_app_win == appwin )
        fli_app_win = appwin->next;
    else
    {
        FLI_WIN *fwin = fli_app_win;

        while ( fwin && fwin->next != appwin )
            fwin = fwin->next;

        if ( fwin )
            fwin->next = fwin->next->next;
        else
        {
            M_err( "remove_app_win", "Invalid argument" );
            return;
        }
    }

    fl_free( appwin );
}


/***************************************
 * Given a window find the correct structure or create one
 ***************************************/

static FLI_WIN *
get_fl_win_struct( Window win )
{
    FLI_WIN *fwin = fli_app_win,
            *lwin = fli_app_win;
    size_t i;

    for ( ; fwin && fwin->win != win; lwin = fwin, fwin = fwin->next )
        /* empty */ ;

    /* If we found it we're done */

    if ( fwin )
        return fwin;

    /* Otherwise create a new structure and append it to the end */

#if FL_DEBUG >= ML_DEBUG
    M_info( "get_fl_win_struct", "Creating FLI_WIN struct for %ld", win );
#endif

    if ( ( fwin = fl_malloc( sizeof *fwin ) ) == NULL )
        return NULL;

    fwin->next = NULL;
    fwin->win = win;
    fwin->pre_emptive = NULL;
    fwin->pre_emptive_data = NULL;
    for ( i = 0; i < LASTEvent; i++ )
    {
        fwin->callback[  i ] = NULL;
        fwin->user_data[ i ] = NULL;
    }

    /* Default handlers */

    fwin->callback[ MappingNotify ] = handle_mapping_notify;

    fwin->default_callback = NULL;
    fwin->mask = 0;

    if ( ! fli_app_win )
        fli_app_win = fwin;
    else
        lwin->next = fwin;

    return fwin;
}


/***************************************
 ***************************************/

FL_APPEVENT_CB
fli_set_preemptive_callback( Window           win,
                             FL_APPEVENT_CB   pcb,
                             void           * data )
{
    FLI_WIN *fwin;
    FL_APPEVENT_CB old = NULL;

    if ( ! ( fwin = get_fl_win_struct( win ) ) )
    {
        M_err( "fli_set_preemptive_callback", "Memory allocation failure" );
        return NULL;
    }

    old = fwin->pre_emptive;

    fwin->pre_emptive      = pcb;
    fwin->pre_emptive_data = data;

    return old;
}


/***************************************
 * Add an event handler for a window
 ***************************************/

FL_APPEVENT_CB
fl_add_event_callback( Window           win,
                       int              ev,
                       FL_APPEVENT_CB   wincb,
                       void *           user_data )
{
    FLI_WIN *fwin;
    int i,
        nev;
    FL_APPEVENT_CB old = NULL;

    if ( ev < 0 || ev >= LASTEvent )
        return NULL;

    if ( ! ( fwin = get_fl_win_struct( win ) ) )
    {
        M_err( "fl_add_event_callback", "Memory allocation failure" );
        return NULL;
    }

    /* ev < KeyPress means all events */

    nev = ev;
    if ( ev < KeyPress )
    {
        ev = KeyPress;
        nev = LASTEvent - 1;
    }

    for ( i = ev; i <= nev; i++ )
    {
        old = fwin->callback[ i ];
        fwin->callback[ i ] = wincb;
        fwin->user_data[ i ] = user_data;
    }

    return old;
}


/***************************************
 * Removes one or all event callbacks for a window. Might be
 * called for a window for which no event callbacks have been
 * set, so handle also that case gracefully.
 ***************************************/

void
fl_remove_event_callback( Window win,
                          int    ev )
{
    FLI_WIN *fwin = fli_app_win;

    if ( ev < 0 || ev >= LASTEvent )
        return;

    while ( fwin && fwin->win != win )
        fwin = fwin->next;

    if ( ! fwin )
        return;

    if ( ev >= KeyPress )
    {
        fwin->callback[ ev ] = NULL;
        fwin->user_data[ ev ] = NULL;
    }
    else                         /* ev < KeyPress means all events */
        remove_app_win( fwin );
}


typedef struct
{
    int           event;
    unsigned long mask;
} EMS;

static EMS ems[ ] =
{
    { CirculateNotify,  StructureNotifyMask },
    { ConfigureNotify,  StructureNotifyMask },
    { DestroyNotify,    StructureNotifyMask },
    { CreateNotify,     StructureNotifyMask },
    { GravityNotify,    StructureNotifyMask },
    { MapNotify,        StructureNotifyMask },
    { ReparentNotify,   StructureNotifyMask },
    { UnmapNotify,      StructureNotifyMask },
    { CirculateRequest, SubstructureRedirectMask },
    { ConfigureRequest, SubstructureRedirectMask },
    { MapRequest,       SubstructureRedirectMask },
    { ResizeRequest,    ResizeRedirectMask },
    { Expose,           ExposureMask },
    { EnterNotify,      EnterWindowMask },
    { LeaveNotify,      LeaveWindowMask },
    { KeyPress,         KeyPressMask },
    { KeyRelease,       KeyReleaseMask} ,
    { ButtonPress,        ButtonPressMask
                     /* | OwnerGrabButtonMask */ },
    { ButtonRelease,      ButtonReleaseMask
                     /* | OwnerGrabButtonMask */ },
    { MotionNotify,       PointerMotionMask
                        | ButtonMotionMask
                        | PointerMotionHintMask },
    { FocusIn,          FocusChangeMask },
    { FocusOut,         FocusChangeMask },
    { KeymapNotify,     KeymapStateMask },
    { PropertyNotify,   PropertyChangeMask },
    { VisibilityNotify, VisibilityChangeMask },
    { ColormapNotify,   ColormapChangeMask },
 /* non-maskable events */
    { MappingNotify,    0 },
    { SelectionNotify,  0 },
    { SelectionRequest, 0 },
    { SelectionClear,   0 },
    { ClientMessage,    0 },
    { GraphicsExpose,   0 },
    { NoExpose,         0 }
};


/***************************************
 ***************************************/

unsigned long
fli_xevent_to_mask( int event )
{
    EMS *em = ems,
        *eme = ems + sizeof ems / sizeof *ems;

    for ( ; em < eme; em++ )
        if ( em->event == event )
            return em->mask;

    return 0;
}


/***************************************
 ***************************************/

void
fl_activate_event_callbacks( Window win )
{
    FLI_WIN *fwin = fli_app_win;
    int i;
    unsigned long mask;

    while ( fwin && fwin->win != win )
        fwin = fwin->next;

    if ( ! fwin )
    {
        M_err( "fl_activate_event_callbacks", "Unknown window %ld", win );
        return;
    }

    /* Solicit all registered events */

    for ( mask = i = 0; i < LASTEvent; i++ )
        if ( fwin->callback[ i ] )
            mask |= fli_xevent_to_mask( i );

    XSelectInput( flx->display, win, mask );
}


/***************************************
 ***************************************/

void
fl_winclose( Window win )
{
    XEvent xev;

    XUnmapWindow( flx->display, win );
    XDestroyWindow( flx->display, win );

    XSync( flx->display, 0 );

    while ( XCheckWindowEvent( flx->display, win, AllEventsMask, &xev ) )
        fli_xevent_name( "Eaten", &xev );

    fl_remove_event_callback( win, 0 );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
