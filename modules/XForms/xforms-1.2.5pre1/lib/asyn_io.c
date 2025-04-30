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
 * \file asyn_io.c
 *.
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Handle input other than the X event queue. Mostly maintanance
 *  here. Actual input/output handling is triggered in the main loop
 *  via fli_watch_io().
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <sys/types.h>

#ifndef FL_WIN32
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef __sgi
#include <bstring.h>
#endif

#ifdef FL_WIN32
#include <X11/Xpoll.h>
#endif


static fd_set st_rfds,
              st_wfds,
              st_efds;

static void add_to_freelist( FLI_IO_REC * io );
static void clear_freelist( void );


/***************************************
 * Collect all the fd_sets so we don't do it inside the
 * critical select inner loop
 ***************************************/

static void
collect_fds( void )
{
    FLI_IO_REC *p;
    int nf = 0;

    /* Initialize the sets */

    FD_ZERO( &st_rfds );
    FD_ZERO( &st_wfds );
    FD_ZERO( &st_efds );

    /* Loop through all requested IOs */

    for ( p = fli_context->io_rec; p; p = p->next )
    {
        if ( p->source < 0 )
        {
            M_err( "collect_fds", "source < 0\n" );
            continue;
        }

        if ( p->mask & FL_READ )
            FD_SET( p->source, &st_rfds );
        if ( p->mask & FL_WRITE )
            FD_SET( p->source, &st_wfds );
        if ( p->mask & FL_EXCEPT )
            FD_SET( p->source, &st_efds );
        if ( nf < p->source + 1 )
            nf = p->source + 1;
    }

    fli_context->num_io = nf;
}


/***************************************
 * Register a callback function for file descriptor fd
 ***************************************/

void
fl_add_io_callback( int              fd,
                    unsigned int     mask,
                    FL_IO_CALLBACK   callback,
                    void           * data )
{
    FLI_IO_REC *io_rec;

    /* Create new record and make it the start of the list */

    io_rec = fl_malloc( sizeof *io_rec );

    io_rec->next     = fli_context->io_rec;
    io_rec->callback = callback;
    io_rec->data     = data;
    io_rec->source   = fd;
    io_rec->mask     = mask;

    fli_context->io_rec = io_rec;

    collect_fds( );
}


/***************************************
 ***************************************/

void
fl_remove_io_callback( int            fd,
                       unsigned       int mask,
                       FL_IO_CALLBACK cb )
{
    FLI_IO_REC *io,
               *previous_io = NULL;

    for ( io = fli_context->io_rec;
          io && ! ( io->source == fd && io->callback == cb && io->mask & mask );
          io = io->next )
        previous_io = io;

    if ( ! io )
    {
        M_err( "fl_remove_io_callback", "Non-existent handler for %d", fd );
        return;
    }

    /* If after removal the fd isn't to be checked anymore (i.e. mask == 0)
       remove it from global record */

    if ( ! ( io->mask &= ~ mask ) )
    {
        if ( previous_io )
            previous_io->next = io->next;
        else
            fli_context->io_rec = io->next;

        /* Caution: the following may look idiotic at first: simply getting
           rid of the structure for the callback would seem to be appropriate.
           But things get interesting if the callback gets removed from within
           the callback - then just removing it gets us into trouble since
           then fli_watch_io(), iterating over all IO callbacks still tries to
           to access the 'next' field and if the structure has been
           deallocated completely (instead of having been temporarily moved
           to somewhere else where it still can be accessed) it stumbles
           badly. That's also why fli_watch_io() calls clear_freelist() -
           it's the only place where it's known when the structure isn't
           needed anymore. */

        add_to_freelist( io );
    }

    collect_fds( );
}


/***************************************
 * Watch for activities using select or poll. Timeout is in milli-seconds.
 ***************************************/

void
fli_watch_io( FLI_IO_REC * io_rec,
              long         msec )
{
    fd_set rfds,
           wfds,
           efds;
    struct timeval timeout;
    FLI_IO_REC *p;
    int nf;

    clear_freelist( );

    if ( ! io_rec )
    {
        if ( msec > 0 )
            fl_msleep( msec );

        return;
    }

    timeout.tv_usec = 1000 * ( msec % 1000 );
    timeout.tv_sec  = msec / 1000;

    /* Initialize the sets */

    rfds = st_rfds;
    wfds = st_wfds;
    efds = st_efds;

    /* Now watch it. HP defines rfds to be ints. Althought compiler will
       bark, it is harmless. */

    nf = select( fli_context->num_io, &rfds, &wfds, &efds, &timeout );

    if ( nf < 0 )     /* something is wrong. */
    {
        if ( errno == EINTR )
            M_warn( "fli_watch_io", "select interrupted by signal" );

        /* select() on some platforms returns -1 with errno == 0 */

        else if ( errno != 0 )
            M_err( "fli_watch_io", fli_get_syserror_msg( ) );

        return;
    }

    /* Timeout expired */

    if ( nf == 0 )
        return;

    /* Handle it */

    for ( p = io_rec; p; p = p->next )
    {
        if ( ! p->callback || p->source < 0 || p->mask == 0 )
            continue;

        if ( p->mask & FL_READ && FD_ISSET( p->source, &rfds ) )
            p->callback( p->source, p->data );

        if ( p->mask & FL_WRITE && FD_ISSET( p->source, &wfds ) )
            p->callback( p->source, p->data );

        if ( p->mask & FL_EXCEPT && FD_ISSET( p->source, &efds ) )
            p->callback( p->source, p->data );
    }

    clear_freelist( );
}


/***************************************
 ***************************************/

int
fli_is_watched_io( int fd )
{
    FLI_IO_REC *p;

    for ( p = fli_context->io_rec; p; p = p->next )
        if ( p->source == fd && p->mask )
            return 1;

    return 0;
}


/***************************************
 ***************************************/

static struct free_list
{
    struct free_list * next;
    FLI_IO_REC       * io;
} *fl = NULL;

static void
add_to_freelist( FLI_IO_REC * io )
{
    struct free_list *cur;

    cur = malloc( sizeof *cur );
    cur->next = fl;
    cur->io   = io;

    fl = cur;
}


/***************************************
 ***************************************/

static void
clear_freelist( void )
{
    struct free_list *cur;

    while ( fl )
    {
        fl_free( fl->io );
        cur = fl;
        fl = fl->next;
        fl_free( cur );
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
