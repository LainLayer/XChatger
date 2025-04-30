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
 * \file timeout.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Check timeout
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>

long msec0 = 0;


/***************************************
 ***************************************/

int
fl_add_timeout( long                  msec,
                FL_TIMEOUT_CALLBACK   callback,
                void                * data )
{
    FLI_TIMEOUT_REC *rec;
    static int id = 1;

    rec = fl_malloc( sizeof *rec );
    fl_gettime( &rec->start_sec, &rec->start_usec );

    rec->id         = id;
    rec->ms_to_wait = FL_max( msec, 0 );
    rec->callback   = callback;
    rec->data       = data;
    rec->prev       = NULL;

    /* Make it the start of the (doubly) linked list */

    rec->next = fli_context->timeout_rec;
    if ( fli_context->timeout_rec )
        fli_context->timeout_rec->prev = rec;
    fli_context->timeout_rec = rec;

    /* Deal with wrap around of IDs- rather unlikely to happen but if it does
       it's not a 100% safe way to do it, we can only bet on the chance that
       the timeouts with the re-used numbers have expired a long time ago... */

    if ( id++ <= 0 )
        id = 1;

    return rec->id;
}


/***************************************
 * Internal function for remving a timeout - remove
 * it from the (doubly) linked list and free memory
 ***************************************/

static void
remove_timeout( FLI_TIMEOUT_REC * rec )
{
    if ( rec == fli_context->timeout_rec )
    {
        fli_context->timeout_rec = rec->next;
        if ( rec->next )
            fli_context->timeout_rec->prev = NULL;
    }
    else
    {
        rec->prev->next = rec->next;
        if ( rec->next )
            rec->next->prev = rec->prev;
    }

    fl_free( rec );
}


/***************************************
 * Public function for removing a timeout
 ***************************************/

void
fl_remove_timeout( int id )
{
    FLI_TIMEOUT_REC *rec = fli_context->timeout_rec;

    while ( rec && rec->id != id )
        rec = rec->next;

    if ( rec )
        remove_timeout( rec );
    else
        M_err( "fl_remove_timeout", "ID %d not found", id );
}


/***************************************
 * Function that periodically gets called to deal with expired
 * timeouts, invoking their handlers and removing them. Via the
 * argument the time until the next timeout expires gets returned
 * (if this is earlier than the original value).
 ***************************************/

void
fli_handle_timeouts( long * msec )
{
    FLI_TIMEOUT_REC *rec,
                    *next;
    long sec = 0,
         usec,
         elapsed,
         diff;

    if ( ! fli_context->timeout_rec )
        return;

    fl_gettime( &sec, &usec );

    /* Loop over all candidates, dealing with those that expired and
       removing them, while also keeping looking for the time the next
       one is going to expire */

    for ( rec = fli_context->timeout_rec; rec; rec = next )
    {
        next = rec->next;

        elapsed =   1000 * ( sec - rec->start_sec )
                  + ( usec - rec->start_usec ) / 1000;
        diff = rec->ms_to_wait - elapsed;

        if ( diff <= 0 )
        {
            if ( rec->callback )
            {
                rec->callback( rec->id, rec->data );
                fl_gettime( &sec, &usec );
            }

            remove_timeout( rec );
        }
        else
            *msec = FL_min( *msec, diff );
    }
}


/***************************************
 ***************************************/

void
fli_remove_all_timeouts( void )
{
    while ( fli_context->timeout_rec )
        fl_remove_timeout( fli_context->timeout_rec->id );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
