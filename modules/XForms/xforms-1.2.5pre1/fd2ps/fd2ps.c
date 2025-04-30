/*
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file fd2ps.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 * Read in a form defination file (.fd) and write an EPS output
 * for inclusion in a document
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include "include/forms.h"
#include "fd2ps.h"
#include "global.h"
#include <sys/stat.h>

static int parse_command_line( int argc, char * argv[ ] );
static void usage( const char *, int );
static void fd2ps_init( void );


static char *helpmsg[ ] =
{
    "-h        this help",
    "-dpi f    specifies the pixel/length conversion",
    "-gray     requests grayscale output",
    "-l        requests landscape output",
    "-p        requests portrait output",
    "-bw n     sets object border width",
    "-eps      requests Encapsulated PostScript",
    "-G f      specifies gamma",
    "-verbose  specifies verbose output",
    "-version  prints version info and exits",
    "-paper s  specifies paper name  (A4 etc). Use all for a list",
    "-pw f     specifies paper width  (in inches)",
    "-ph f     specifies paper height  (in inches)",
    0
};


/***************************************
 ***************************************/

static void
usage( const char * cmd,
       int          die )
{
    char **q = helpmsg;

    fprintf( stderr, "Usage: %s [options] infile.[fd] [outfile]\n", cmd );
    fprintf( stderr, " where options are\n" );

    for ( ; *q; q++ )
        fprintf( stderr, "    %s\n", *q );

    fprintf( stderr, "    -rgb file specifies the path to rgb.txt. "
             "Default is %s\n", psinfo.rgbfile );

    if ( die )
        exit( 1 );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    int n;
    char outname[ 512 ],
         inname[ 512 ],
         *p;
    FILE *fp;

    fd2ps_init( );
    n = parse_command_line( argc, argv );

    strcpy( inname, argv[ n ] );
    if ( ! strstr( inname, ".fd" ) )
        strcat( inname, ".fd" );

    if ( n < argc - 1 )
        strcpy( outname, argv[ ++n ] );
    else
    {
        strcpy( outname, inname );
        if ( ( p = strrchr( outname, '.' ) ) )
            *p = '\0';
        strcat( outname, psinfo.eps ? ".eps" : ".ps" );
    }

    /* before opening the output file, check the existence of input */

    if ( ! ( fp = fopen( inname, "r" ) ) )
    {
        perror( inname );
        exit( 1 );
    }
    fclose( fp );

    if ( strcmp( outname, "-" ) == 0 )
        flps->fp = stdout;
    else if ( ! ( flps->fp = fopen( outname, "w" ) ) )
    {
        fprintf( stderr, "Can't open %s for output\n", outname );
        exit( 1 );
    }

    load_form_definition( inname );
    return 0;
}


/***************************************
 * Overall default configuration
 ***************************************/

static void
fd2ps_init( void )
{
    char *env;
    struct stat statbuf;

    psinfo.xdpi = psinfo.ydpi = 85;
    psinfo.paper_name = "Letter";
    get_paper_size( psinfo.paper_name, &psinfo.paper_w, &psinfo.paper_h );
    psinfo.bw = 1;
    psinfo.verbose = 0;
    psinfo.colorps = 1;
    psinfo.eps = 0;
    psinfo.gamma = 1.0;
    psinfo.page = 1;
    psinfo.xscale = psinfo.yscale = 1.0;
    psinfo.pack = 1;
    psinfo.landscape = -1;  /* auto */
    psinfo.fp = stdout;

    psinfo.rgbfile = "/usr/lib/X11/rgb.txt";
    if ( stat( psinfo.rgbfile, &statbuf ) < 0 )
        psinfo.rgbfile = "/usr/share/X11/rgb.txt";

    psinfo.xpmtops_direct = 1;
    flps = &psinfo;

    /* Check if enviornment variable paper is defined */

    if ( ( env = getenv( "PAPER" ) ) )
    {
        get_paper_size( env, &psinfo.paper_w, &psinfo.paper_h );
        psinfo.paper_name = env;
    }

    if ( ( env = getenv( "RGBFile" ) ) )
        psinfo.rgbfile = env;
}


/***************************************
 ***************************************/

static int
parse_command_line( int    argc,
                    char * argv[ ] )
{
    int i;
    float ftmp;

    for ( i = 1; i < argc && *argv[ i ] == '-'; i++ )
    {
        if ( strcmp( argv[ i ], "-bw" ) == 0 && i + 1 < argc )
            psinfo.user_bw = atoi( argv[ ++i ] );
        else if ( strcmp( argv[ i ], "-dpi" ) == 0 && i + 1 < argc )
        {
            ftmp = atof( argv[ ++i ] );
            psinfo.xdpi = psinfo.ydpi = ftmp;
        }
        else if ( strncmp( argv[ i ], "-verb", 5 ) == 0 )
            psinfo.verbose = 1;
        else if ( strcmp( argv[ i ], "-eps" ) == 0 )
            psinfo.eps = 1;
        else if ( strncmp( argv[ i ], "-vers", 5 ) == 0 )
            print_version( 1 );
        else if ( strncmp( argv[ i ], "-h", 2 ) == 0 )
            usage( argv[ 0 ], 1 );
        else if ( strcmp( argv[ i ], "-pw" ) == 0 && i + 1 < argc )
        {
            psinfo.paper_w = atof( argv[ ++i ] );
            psinfo.paper_name = 0;
        }
        else if ( strcmp( argv[ i ], "-ph" ) == 0 && i + 1 < argc )
        {
            psinfo.paper_h = atof( argv[ ++i ] );
            psinfo.paper_name = 0;
        }
        else if ( strcmp( argv[ i ], "-G" ) == 0 && i + 1 < argc )
            psinfo.gamma = atof( argv[ ++i ] );
        else if ( strcmp( argv[ i ], "-l" ) == 0 )
            psinfo.landscape = 1;
        else if ( strcmp( argv[ i ], "-p" ) == 0 )
        psinfo.landscape = 0;
        else if ( strcmp( argv[ i ], "-color" ) == 0 )
            psinfo.colorps = 1;
        else if ( strcmp( argv[ i ], "-pack" ) == 0 )
            psinfo.pack = !psinfo.pack;
        else if (    strcmp( argv[ i ], "-gray" ) == 0
                  || strcmp( argv[ i ], "-grey" ) == 0 )
            psinfo.colorps = 0;
        else if ( strcmp( argv[ i ], "-rgb" ) == 0 && i + 1 < argc )
            psinfo.rgbfile = fl_strdup( argv[ ++i ] );
        else if ( strcmp( argv[ i ], "-paper" ) == 0 && i + 1 < argc )
        {
            if ( strcmp( argv[ ++i ], "all" ) == 0 )
            {
                fprintf( stderr, " The following paper names are known\n" );
                list_papers( "\t" );
                exit( 0 );
            }

            get_paper_size( argv[ i ], &psinfo.paper_w, &psinfo.paper_h );
            psinfo.paper_name = argv[ i ];
        }
        else
        {
            usage( argv[ 0 ], 0 );
            fprintf( stderr, "Unknown Option %s\n", argv[ i ] );
            exit( 1 );
        }
    }

    if ( i == argc )
        usage( argv[ 0 ], 1 );

    /* limited validation */

    if ( psinfo.paper_h <= 1 || psinfo.paper_w <= 1 )
    {
        fprintf( stderr, "%s: incorrect paper size (%.1fX%.1f)\n",
                 argv[ 0 ], psinfo.paper_w, psinfo.paper_h );
        exit( 0 );
    }

    if ( psinfo.xdpi < 50 || psinfo.xdpi > 300 )
    {
        fprintf( stderr, "%s: unusual DPI value %.1f\n",
                 argv[ 0 ], psinfo.xdpi );
    }

    if ( psinfo.gamma != 1.0 )
        apply_gamma( psinfo.gamma );

    return i;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
