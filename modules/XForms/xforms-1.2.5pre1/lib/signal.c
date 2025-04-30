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
 * \file signal.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Simple minded quick&dirty signal handling.
 *
 *  Only permit a specific signal to have one handler
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <stdlib.h>
#include <signal.h>


void ( * fli_handle_signal )( void ) = NULL;   /* also needed in handling.c */


/***************************************
 ***************************************/

static void
handle_signal( void )
{
    FLI_SIGNAL_REC *rec = fli_context->signal_rec;

    for ( ; rec; rec = rec->next )
        while ( rec->caught )
        {
            rec->caught--;
            rec->callback( rec->signum, rec->data );
        }
}


#ifndef FL_WIN32
#define IsDangerous( s ) (    ( s ) == SIGBUS   \
                           || ( s ) == SIGSEGV  \
                           || ( s ) == SIGILL   \
                           || ( s ) == SIGFPE )
#else
#define IsDangerous( s )  0
#endif

static int sig_direct;


/***************************************
 ***************************************/

static RETSIGTYPE
default_signal_handler( int sig )
{
    fl_signal_caught( sig );

    /* if the signal is one of those that can cause infinite loops, handle it
       and then exit */

    if ( IsDangerous( sig ) )
    {
        handle_signal( );
        fprintf( stderr, "Can't continue upon receiving signal %d\n", sig );
        exit( sig );
    }

#ifndef RETSIGTYPE_IS_VOID
    return 0;
#endif
}


/***************************************
 ***************************************/

void
fl_add_signal_callback( int                 s,
                        FL_SIGNAL_HANDLER   cb,
                        void              * data )
{
    FLI_SIGNAL_REC *sig_rec,
                   *rec = fli_context->signal_rec;

    if ( ! fli_handle_signal )
        fli_handle_signal = handle_signal;

    while ( rec && rec->signum != s )
        rec = rec->next;

    if ( rec )
    {
        rec->callback = cb;
        rec->data = data;
    }
    else
    {
        sig_rec = fl_malloc( sizeof *sig_rec );
        sig_rec->next      = NULL;
        sig_rec->data      = data;
        sig_rec->callback  = cb;
        sig_rec->signum    = s;
        sig_rec->caught    = 0;

        if ( ! sig_direct )
        {
#if defined HAVE_SIGACTION
            struct sigaction sact;

            sact.sa_handler = default_signal_handler;
            sigemptyset( &sact.sa_mask );
            sact.sa_flags = 0;

            if ( sigaction( s, &sact, &sig_rec->old_sigact ) < 0 )
#else
            errno = 0;
            sig_rec->ocallback = signal( s, default_signal_handler );
            if ( sig_rec->ocallback == ( FLI_OSSIG_HANDLER ) - 1L || errno )
#endif
            {
                M_err( "fl_add_signal_callback", "Can't add handler for "
                       "signal %d", s );
                fl_free( sig_rec );
                return;
            }
        }

        if ( fli_context->signal_rec )
            sig_rec->next = fli_context->signal_rec;
        fli_context->signal_rec = sig_rec;
    }
}


/***************************************
 ***************************************/

void
fl_remove_signal_callback( int s )
{
    FLI_SIGNAL_REC *last,
                   *rec = fli_context->signal_rec;

    for ( last = rec; rec && rec->signum != s; last = rec, rec = rec->next )
        /* empty */ ;

    if ( ! rec )
    {
        M_err( "fl_remove_signal_callback", "No handler exists for signal %d",
               s );
        return;
    }

    if ( rec == fli_context->signal_rec )
        fli_context->signal_rec = rec->next;
    else
        last->next = rec->next;

    if ( ! sig_direct )
    {
#if defined HAVE_SIGACTION
        sigaction( s, &rec->old_sigact, NULL );
#else
        signal( s, rec->ocallback );
#endif
    }

    fli_safe_free( rec );
}


/***************************************
 ***************************************/

void
fl_signal_caught( int s )
{
    FLI_SIGNAL_REC *rec = fli_context->signal_rec;

    while ( rec && rec->signum != s )
        rec = rec->next;

    if ( ! rec )
    {
        M_err( "fl_signal_caught", "Caught bogus signal %d", s );
        return;
    }

    rec->caught++;

#if ! defined HAVE_SIGACTION
    if ( ! sig_direct && ! IsDangerous( s ) )
        signal( s, default_signal_handler );
#endif
}


/***************************************
 ***************************************/

void
fl_app_signal_direct( int y )
{
    if ( ! fli_handle_signal )
        fli_handle_signal = handle_signal;
    sig_direct = y;
}


/***************************************
 ***************************************/

void
fli_remove_all_signal_callbacks( void )
{
    while ( fli_context->signal_rec )
        fl_remove_signal_callback( fli_context->signal_rec->signum );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
