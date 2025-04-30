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
 * \file clipboard.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1997-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Implementation of clipboard.  Event handling violates the ICCCM,
 *  but should work ok. Need server time from the mainloop.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


typedef struct {
    FL_OBJECT            * ob;          /* the object that stuff'ed cp  */
    FL_OBJECT            * req_ob;      /* the object that requested cp */
    Window                 window;
    Window                 req_window;
    long                   type,
                           size;
    FL_LOSE_SELECTION_CB   lose_callback;
    FL_SELECTION_CB        got_it_callback;
} ClipBoard;

static ClipBoard clipboard;

int ( * fli_handle_clipboard )( void * ) = NULL; /* also needed in handling.c */

static int handle_clipboard_event( void * );


/***************************************
 ***************************************/

int
fl_stuff_clipboard( FL_OBJECT            * ob,
                    long                   type  FL_UNUSED_ARG,
                    const void           * data,
                    long                   size,
                    FL_LOSE_SELECTION_CB   lose_callback )
{
    Window win = FL_ObjWin( ob );
    ClipBoard *cp = &clipboard;

    fli_handle_clipboard = handle_clipboard_event;

    if ( ! win )
    {
        M_err( "fl_stuff_clipboard", "Bad object %s", ob ? ob->label : "null" );
        return 0;
    }

    XSetSelectionOwner( flx->display, XA_PRIMARY, win, CurrentTime );

    /* Make sure we got it */

    if ( XGetSelectionOwner( flx->display, XA_PRIMARY ) != win )
    {
        M_err( "fl_stuff_clipboard", "Failed to get owner" );
        return 0;
    }

    /* Create structure that holds clipboard info */

    cp->window        = win;
    cp->ob            = ob;
    cp->size          = size;
    cp->lose_callback = lose_callback ? lose_callback : NULL;

    /* Cheap (and fast!) shot */

    XStoreBuffer( flx->display, data, size, 0 );
    return size;
}


static Atom clipboard_prop;
static Atom targets_prop;

/***************************************
 ***************************************/

int
fl_request_clipboard( FL_OBJECT       * ob,
                      long              type  FL_UNUSED_ARG,
                      FL_SELECTION_CB   got_it_callback )
{
    Window win;
    ClipBoard *cp = &clipboard;
    void *buf;
    int nb = 0;

    cp->req_ob = ob;

    if ( got_it_callback == NULL )
    {
        M_warn( "fl_request_clipboard", "Callback is NULL" );
        return -1;
    }

    if ( ! clipboard_prop )
    {
        clipboard_prop = XInternAtom( flx->display, "FL_CLIPBOARD", False );
        fli_handle_clipboard = handle_clipboard_event;
    }

    cp->got_it_callback = got_it_callback;
    cp->req_window      = FL_ObjWin( ob );

    win = XGetSelectionOwner( flx->display, XA_PRIMARY );

    if ( win == None )
    {
        XSetSelectionOwner( flx->display, XA_PRIMARY, cp->req_window,
                            CurrentTime );
        buf = XFetchBuffer( flx->display, &nb, 0 );
        cp->window = XGetSelectionOwner( flx->display, XA_PRIMARY );
        cp->ob = NULL;
        cp->size = nb;
        cp->got_it_callback( cp->req_ob, XA_STRING, buf, nb );
        XFree( buf );
    }
    else if ( win != cp->req_window )
    {
        /* We don't own it, request it */

        M_warn( "fl_request_clipboard", "Requesting selection from %ld", win );
        XConvertSelection( flx->display,
                           XA_PRIMARY, XA_STRING,
                           clipboard_prop,
                           cp->req_window, CurrentTime );
        nb = -1;
    }
    else if ( win == cp->req_window )
    {
        /* We own the buffer */

        buf = XFetchBuffer( flx->display, &nb, 0 );
        cp->got_it_callback( cp->req_ob, XA_STRING, buf, nb );
        XFree( buf );
    }

    return nb;
}


/***************************************
 * Returns a negative number if not known how to handle an event
 ***************************************/

static int
handle_clipboard_event( void * event )
{
    XSelectionRequestEvent *sreq = event;
    XEvent *xev = event;
    XSelectionEvent sev;
    ClipBoard *cp = &clipboard;
    char *s;
    int n;

    /* SelectionClear confirms loss of selection
       SelectionRequest indicates that another app wants to own selection
       SelectionNotify confirms that request of selection is ok */

    if ( ! targets_prop )
        targets_prop = XInternAtom( flx->display, "TARGETS", False );
    if ( ! clipboard_prop )
        clipboard_prop = XInternAtom( flx->display, "FL_CLIPBOARD", False );

    if ( ! cp->req_window && ! cp->window )
    {
        M_warn( "handle_clipboard_event", "InternalError" );
        return -1;
    }

    if ( xev->type == SelectionClear )
    {
        if ( cp->ob && cp->lose_callback )
            cp->lose_callback( cp->ob, cp->type );
        cp->ob     = NULL;
        cp->window = None;
    }
    else if ( xev->type == SelectionNotify && cp->req_ob )
    {
        /* Our request went through, go and get it */

        Atom ret_type;
        int ret_format;
        unsigned long ret_len = 0,
                      ret_after;
        unsigned char *ret = NULL;

        /* X guarantees 16K request size */

        long chunksize = fli_context->max_request_size,
             offset = 0;
        char *buf = NULL;
        int buflen = 0;

        /* Get the stuff. Repeat until we get all  */

        do
        {
            XGetWindowProperty( flx->display, xev->xselection.requestor,
                                xev->xselection.property, offset, chunksize,
                                False, xev->xselection.target, &ret_type,
                                &ret_format, &ret_len, &ret_after, &ret );

            if ( ret_len && ret )
            {
                if ( ret_after == 0 && ! buf )
                    cp->got_it_callback( cp->req_ob, ret_type, ret, ret_len );
                else
                {
                    buf = fl_realloc( buf, buflen + ret_len );
                    memcpy( buf + buflen, ret, ret_len );
                    buflen += ret_len;
                }

                XFree( ret );
                ret = NULL;
            }

            offset += ret_len * ret_format / 32;
            chunksize = ( ret_after + 3 ) / 4;

            if ( chunksize > fli_context->max_request_size )
                chunksize = fli_context->max_request_size;
        } while ( ret_after );

        if ( buflen )
        {
            cp->got_it_callback( cp->req_ob, ret_type, buf, buflen );
            fl_free( buf );
        }

        XDeleteProperty( flx->display, xev->xselection.requestor,
                         xev->xselection.property );
    }
    else if ( xev->type == SelectionRequest )
    {
        /* Someone wants our selection */

        M_warn( "handle_clipboard_event", "SelectionRequest" );

        if ( sreq->owner != cp->window )
        {
            M_err( "handle_clipboard_event", "Wrong owner" );
            return -1;
        }

        /* Set up the event to be sent to the requestor */

        sev.type      = SelectionNotify;
        sev.display   = sreq->display;
        sev.requestor = sreq->requestor;
        sev.selection = sreq->selection;
        sev.target    = sreq->target;
        sev.property  = None;
        sev.time      = sreq->time;

        if ( sreq->selection == XA_PRIMARY )
        {
            if ( sreq->target == XA_STRING )
            {
                s = XFetchBuffer( flx->display, &n, 0 );
                XChangeProperty( flx->display,
                                 sreq->requestor, sreq->property, sreq->target,
                                 8, PropModeReplace, (unsigned char *) s, n );
                sev.property = sreq->property;
                XFree( s );
            }
            else if ( sreq->target == targets_prop )   /* aixterm wants this */
            {
                Atom alist = XA_STRING;

                XChangeProperty( flx->display,
                                 sreq->requestor, sreq->property, XA_ATOM,
                                 32, PropModeReplace,
                                 ( unsigned char * ) &alist, 1 );
                sev.property = sreq->property;
            }
            else
            {
                /* If we have other types conversion routine should be
                   called here */

                M_warn( "handle_clipboard_event", "Received request with "
                        "unknown/not implemented XAtom target type: %d\n",
                        ( int ) sreq->target );
            }

            XSendEvent( flx->display, sreq->requestor, False, 0,
                        ( XEvent * ) & sev );
        }
        else
        {
            /* not XA_PRIMARY request */

            M_warn( "handle_clipboard_event", "Unknown selection request: %d",
                    sreq->selection );
            return -1;
        }
    }

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
