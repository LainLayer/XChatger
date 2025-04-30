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


/*
 *  This file is part of the XForms library package.
 *  Copyright (c) 1993, 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Use one of the builtin image reader and an external filter to
 *  add new supported format.
 *
 *  TODO: add signal handling to make sure the temp files are deleted.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include "private/flsnprintf.h"
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef FL_WIN32
#include <process.h>
#include <io.h>
#include <X11/Xw32defs.h>
#endif


/***************************************
 ***************************************/

static char *
get_tmpf( char * obuf )
{
    static int k,
               seq;
    static char buf[ 15 ][ 256 ];
    int fd = -1,
        tries = 0;
    char *name;

    k = ( k + 1 ) % 15;
    name = obuf ? obuf : buf[ k ];

    do
    {
        if ( ( fd = mkstemp( name ) ) >= 0 )
            /* empty */ ;
        else
        {
            fli_snprintf( buf[ k ], sizeof buf[ k ],
                          "%s/.FL%03d_%d.tmp", "/tmp", seq++,
                          ( int ) getpid( ) );
            name = buf[ k ];

            /* create the file now in exclusive mode (for security) */

            fd = open( name, O_RDWR | O_CREAT | O_EXCL, S_IREAD | S_IWRITE );
        }

        tries++;
    } while ( fd < 0 && tries < 30 );

    if ( fd >= 0 )
    {
        close( fd );
        return name;
    }

    return 0;
}


/***************************************
 ***************************************/

int
flimage_description_via_filter( FL_IMAGE     * im,
                                char * const * cmds,
                                const char   * what,
                                int verbose )
{
    char cmd[ 1024 ],
         *tmpf;
    char * const *q = cmds;
    int status = 0,
        n;

    if ( ! ( tmpf = get_tmpf( 0 ) ) )
    {
        im->error_message( im, "can't get tmpfile!" );
        return -1;
    }

    do
    {
        fli_snprintf( cmd, sizeof cmd - 12, *q, im->infile, tmpf );
        if ( verbose )
            fprintf( stderr, "executing %s\n", cmd );
        else
            strcat( cmd, " 2>/dev/null" );
        status = system( cmd );
    } while ( status && *++q );

    if ( status )
    {
        M_err( "", "%s failed", cmd );
        return -1;
    }

    /* first check if the converted image is something we can handle */

    if ( ! ( n = flimage_is_supported( tmpf ) ) )
    {
        im->error_message( im, "unknown filtered output" );
        remove( tmpf );
        return -1;
    }

    im->visual_cue( im, what );

    /* now we're really ok */

    fclose( im->fpin );
    im->fpin = fopen( tmpf, "rb" );
    strcpy( cmd, im->infile );
    strcpy( im->infile, tmpf );

    /* if verbose, delay the file deletion in case we want to look at it */

    --n;
    if ( verbose )
        fprintf( stderr, " reading %s via %s\n",
                 ( ( FLIMAGE_IO * ) im->image_io )->short_name,
                 flimage_io[ n ].short_name );

    if ( strcmp( im->fmt_name, "gzip" ) == 0 )
        im->fmt_name = flimage_io[ n ].short_name;

    im->image_io = flimage_io + n;
    im->type = flimage_io[ n ].type;

    flimage_io[ n ].identify( im->fpin );   /* advance file position */
    status = flimage_io[ n ].read_description( im );

    remove( tmpf );

    strcpy( im->infile, cmd );

    return status;
}


/**********************************************************************
 * write via external filters
 **********************************************************************/

/* Given several formats, say ppm, pgm, and pbm, check if the image
 * type is the same as one of the requested. If yes, return the IO struct
 * else return the first match. Therefore,
 * caller should place the formats in decreasing order of generality,
 * i.e., ppm, pgm, pbm, never pbm, pgm, ppm.
 */

static FLIMAGE_IO *
best_format( FL_IMAGE     * im,
             char * const   formats[ ] )
{
    FLIMAGE_IO *io = flimage_io;
    char *const *fmts = formats;
    FLIMAGE_IO *first = 0,
               *best_sofar = 0;
    int found;

    for ( ; *fmts; fmts++ )
    {
        for ( io = flimage_io, found = 0; ! found && io->formal_name; io++ )
            found =    strcasecmp( io->formal_name, *fmts ) == 0
                    || strcasecmp( io->short_name,  *fmts ) == 0;

        if ( found )
        {
            io--;
            best_sofar = ( im->type & io->type ) ? io : 0;
            if ( ! first )
                first = best_sofar;
        }
        else
            fprintf( stderr, "bad format name: %s\n", *fmts );
    }

    return best_sofar ? best_sofar : first;
}


/***************************************
 ***************************************/

int
flimage_write_via_filter( FL_IMAGE     * im,
                          char * const * cmds,            /* shell commands */
                          char *const    formats[ ],      /* formats */
                          int            verbose )
{
    char *tmpf;
    char ofile[ 256 ],
         cmd[ 1024 ];
    char * const *shellcmd;
    FLIMAGE_IO *io;
    int err,
        status;

    /* check if we can handle the type */

    if ( ! ( io = best_format( im, formats ) ) )
    {
        fprintf( stderr, "can't find format handler\n" );
        return -1;
    }

    if ( ! ( io->type & im->type ) )
        flimage_convert( im, io->type, 256 );

    tmpf = get_tmpf( 0 );
    strcpy( ofile, im->outfile );
    strcpy( im->outfile, tmpf );

    if ( ! ( im->fpout = fopen( im->outfile, "wb" ) ) )
    {
        fprintf( stderr, "can't open %s\n", tmpf );
        remove( tmpf );
        return -1;
    }

    /* skip the pre_write step */

    err = io->write_image( im ) < 0;
    fclose( im->fpout );
    if ( verbose )
        fprintf( stderr, "Done writing %s (%s) \n",
                 im->outfile, io->short_name );

    /* now we have the intermediate image ready, generate the shell cmd */

    for ( shellcmd = cmds, status = ! err; status && *shellcmd; shellcmd++ )
    {
        fli_snprintf( cmd, sizeof cmd, *shellcmd, tmpf, ofile );
        if ( ! verbose )
            strcat( cmd, " 2>/dev/null" );
        else
            fprintf( stderr, "executing %s\n", cmd );
        status = system( cmd );
    }

    remove( tmpf );
    strcpy( im->outfile, ofile );

    if ( status )
        fprintf( stderr, "%s failed\n", cmd );

    return status ? -1 : 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
