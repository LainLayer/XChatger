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
 * \file readxpm.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 * read an XPM file. Only handles XPM3 files.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fd2ps.h"

/*#define DEBUG */

enum
{
    CMAP,
    GMAP,
    MMAP,
    G4MAP,
    SMAP
};

#define NMAPS   5

static char *keys[ ] = { "c", "g", "m", "g4", "s" };
static int lookup_rgb( const char *,
                       int        *,
                       int        *,
                       int        * );



/***************************************
 ***************************************/

#ifdef DEBUG
static void
dump_map( char      * name,
          fd2psCMAP * m,
          int         ncol )
{
    int i;

    for ( i = 0; i < ncol; i++ )
        fprintf( stderr, "%s: %s %s (%d %d %d)\n", name, m[ i ].key,
                 m[ i ].name, m[ i ].red, m[ i ].green, m[ i ].blue);
}
#endif


/***************************************
 ***************************************/

static short *
read_xpm( const char  * file,
          int         * w,
          int         * h,
          int         * ncol,
          fd2psCMAP  ** maps,
          int         * set )
{
    char buf[ 2048 ],
         val[ 64 ],
         *head,
         key[ 16 ],
         ckey[ 8 ];
    int char_per_pixel, signature = 0;
    int x, y, icol, c, n, i, match;
    fd2psCMAP *map = 0;
    int r = 0,
        g = 0,
        b = 0;
    short *pixels, *p;
    FILE *fp;

    if ( ! ( fp = fopen( file, "r" ) ) )
    {
        fprintf( stderr, "unable to open xpm file %s\n", file );
        return 0;
    }

    while ( ! signature && fgets( buf, sizeof buf, fp ) )
    {
        if ( strstr( buf, "XPM" ) && strstr( buf, "/*" ) )
            signature = 1;
    }

    if ( ! signature )
    {
        fprintf( stderr, "%s does not seem to be an XPM3 file\n", file );
        return 0;
    }

    while ( ( c = getc( fp ) ) != EOF && c != '"' )
        /* empty */ ;

    if ( fscanf( fp, "%d %d %d %d", w, h, ncol, &char_per_pixel ) != 4 )
    {
        fprintf( stderr, "can't determine xpm size\n" );
        return 0;
    }

    while ( getc(fp) != '\n' )
        /* empty */ ;
    
    /* We only handle 1, 2, or 3 char_per_pixel due to colormap limit */

    if ( char_per_pixel > 3 || char_per_pixel <= 0 )
    {
        fprintf( stderr, "can't handle char_per_pixel: %d\n", char_per_pixel );
        return 0;
    }

#ifdef DEBUG
    fprintf( stderr, "xpm: w=%d h=%d ncol=%d cpp=%d\n",
             *w, *h, *ncol, char_per_pixel );
#endif

    memset( set, 0, sizeof *set * NMAPS );

    for ( i = 0; i < NMAPS; i++ )
        maps[ i ] = malloc( *ncol * sizeof **maps );

    /* Read the colormap. We handle color, grayscale mono only */

    for ( icol = 0; icol < *ncol; icol++ )
    {
        /* Skip comments if any */

        while ( fgets( buf, sizeof buf, fp ) && strncmp( buf, "/*", 2 ) == 0 )
            /* empty */ ;

        if ( ( head = strchr( buf, '"' ) ) == 0 )
        {
            fprintf( stderr, "bad color line:%s", buf );
            return 0;
        }
        else
            head++;

        strncpy( key, head, char_per_pixel );
        key[ char_per_pixel ] = '\0';
        head += char_per_pixel + 1;

    loop:
        sscanf( head, " %7s %63s %n", ckey, val, &n );
        if ( val[ strlen( val ) - 1 ] == '"')
            val[ strlen( val ) - 1 ] = '\0';
        if ( val[ strlen( val ) - 1 ] == ',' )
            val[ strlen( val ) - 2 ] = '\0';
        head += n;

        /* Find the color code. We do not handle s currently */

        for ( match = i = 0; i < NMAPS; i++ )
            if ( strcmp( ckey, keys[ i ] ) == 0 )
            {
                match = 1;
                map = maps[ i ];
                set[ i ] = 1;
            }

        if ( map != maps[ SMAP ] )
            lookup_rgb( val, &r, &g, &b );

        if ( ! match )
        {
            fprintf( stderr, "colormode %s not handled\n", ckey );
            map = 0;
        }

        if ( map )
        {
            strcpy( map[ icol ].key,  key );
            strcpy( map[ icol ].name, val );
            map[ icol ].red   = r;
            map[ icol ].green = g;
            map[ icol ].blue  = b;
        }

        if ( *head != '\n' && *head != '\0' && *head != ',' && *head != '"' )
            goto loop;
    }

#ifdef DEBUG
    if ( set[ CMAP ] )
        dump_map( "CMAP", maps[ CMAP ], *ncol );
    if ( set[ GMAP ] )
        dump_map( "GMAP", maps[ GMAP ], *ncol );
    if ( set[ G4MAP ] )
        dump_map( "G4MAP", maps[ G4MAP ], *ncol );
    if ( set[ MMAP ] )
        dump_map( "MMAP", maps[ MMAP ], *ncol );
#endif

    /* Read the pixels */

    map = maps[ CMAP ];
    p = pixels = malloc( *w * *h * sizeof *pixels );
    for ( y = 0; y < *h; y++ )
    {
        while ( fgets( buf, sizeof buf, fp ) && strncmp( buf, "/*", 2 ) == 0 )
            /* e,pty */ ;

        head = strchr( buf, '"' );
        for ( x = 0; x < *w; x++ )
        {
            for ( i = 0; i < char_per_pixel; i++ )
                key[ i ] = *++head;
            key[ char_per_pixel ] = '\0';

            /* Search colormap for pixel value */

            for ( match = icol = 0; ! match && icol < *ncol; icol++ )
            {
                if ( strcmp(map[ icol ].key, key ) == 0 )
                {
                    match = 1;
                    *p++ = icol;
                }
            }

            if ( ! match )
            {
                fprintf( stderr, "pixel %s unknown\n", key );
                *p++ = 0;
            }
        }
    }

    return pixels;
}


/***************************************
 * read the standard RGB file and get rid of the spaces in color names
 * return 1 for success.
 ***************************************/

static int
read_entry( FILE * fp,
            int  * r,
            int  * g,
            int  * b,
            char * name )
{
    int n;
    char buf[ 512 ],
         *p;

    if ( ! fgets( buf, sizeof buf, fp ) )
        return 0;

    while ( buf[ 0 ] == '!' )
        if ( fgets( buf, sizeof buf, fp ) )
            return 0;

    if ( sscanf( buf, " %d %d %d %n", r, g, b, &n ) != 3 )
        return 0;

    p = buf + n;

    /* Remove all spaces */

    while ( *p )
    {
        if ( *p != ' ' && *p != '\n' )
            *name++ = *p;
        p++;
    }

    *name = '\0';

    return ! feof( fp ) && ! ferror( fp );
}



/***************************************
 ***************************************/

#define MAXDBSIZE  1024

static int
lookup_rgb( const char * name,
            int        * red,
            int        * green,
            int        * blue )
{
    static fd2psCMAP *predef, *end;
    fd2psCMAP *db;
    int match;
    FILE *fp;
    char lname[ 64 ];
    static char hexv[ 128 ];

    if ( ! predef )
    {
        long ccol, lcol = -1;
        int r, g, b;

        for ( r = 0; r < 10; r++ )
            hexv[ r + '0' ] = r;

        for ( r = 10; r <= 15; r++ )
        {
            hexv[ r - 10 + 'a' ] = r;
            hexv[ r - 10 + 'A' ] = r;
        }

        db = predef = malloc( MAXDBSIZE * sizeof *predef );

        if ( ! ( fp = fopen( flps->rgbfile, "r" ) ) )
        {
            fprintf( stderr, "can't find RGB database %s\n", flps->rgbfile );
            fprintf( stderr, "Alternative files will be tried\n" );
        }

        /* Try some alternative before giving up */

        if ( ! fp )
            fp = fopen( "/usr/local/lib/X11/rgb.txt", "r" );

        if ( ! fp )
            fp = fopen( "/etc/X11/rgb.txt", "r" );

#if defined sun || defined __sun__
        if ( ! fp )
            fp = fopen( "/usr/openwin/lib/rgb.txt", "r" );
#endif

#if defined __EMX__
        if ( ! fp )
            fp = fopen( "/XFree86/lib/X11/rgb.txt", "r" );
#endif

#if defined __VMS
        if ( ! fp )
            fp = fopen( "SYS$MANAGER:DECW$RGB.DAT", "r" );
#endif

        if ( ! fp )
        {
            fprintf( stderr, "no suitable rgb.txt files found\n" );
            return -1;
        }

        end = predef + MAXDBSIZE;

        while ( db < end && read_entry( fp, &r, &g, &b, db->name ) )
        {
            db->red   = r;
            db->green = g;
            db->blue  = b;
            ccol = ( r << 16 ) + ( g << 8 ) + b;

            if ( ccol != lcol || strcasecmp( lname, db->name ) )
            {
                strcpy( lname, db->name );
                lcol = ccol;
                db++;
            }
        }
        fclose( fp );
    }

    /* Search for special cases: numerical and None */

    if ( strcasecmp( name, "None" ) == 0 )
        *red = *green = *blue = -1;
    else if ( *name == '#' )
    {
        if ( ( match = strlen( name ) ) == 7 )    /* #rrggbb */
        {
            *red   =   ( hexv[ ( int ) name[ 1 ] ] << 4 )
                     +   hexv[ ( int ) name[ 2 ] ];
            *green =   ( hexv[ ( int ) name[ 3 ] ] << 4 )
                     +   hexv[ ( int ) name[ 4 ] ];
            *blue  =   ( hexv[ ( int ) name[ 5 ] ] << 4 )
                     +   hexv[ ( int ) name[ 6 ] ];
        }
        else if ( match == 13 )   /* #rrrrggggbbbb */
        {
            *red   =   ( hexv[ ( int ) name[  1 ] ] << 12 )
                     + ( hexv[ ( int ) name[  2 ] ] <<  8 )
                     + ( hexv[ ( int ) name[  3 ] ] <<  4 )
                     +   hexv[ ( int ) name[  4 ] ];
            *green =   ( hexv[ ( int ) name[  5 ] ] << 12 )
                     + ( hexv [( int ) name[  6 ] ] <<  8 )
                     + ( hexv[ ( int ) name[  7 ] ] <<  4 )
                     +   hexv[ ( int ) name[  8 ] ];
            *blue  =   ( hexv[ ( int ) name[  9 ] ] << 12 )
                     + ( hexv[ ( int ) name[ 10 ] ] <<  8 )
                     + ( hexv[ ( int ) name[ 11 ] ] <<  4 )
                     +   hexv[ ( int ) name[ 12 ] ];

            *red   = ( *red   * 255L ) / 65535L;
            *green = ( *green * 255L ) / 65535L;
            *blue  = ( *blue  * 255L ) / 65535L;
        }
        else if ( match == 4 )
        {
            *red   = ( hexv[ ( int ) name[ 1 ] ] * 255 ) / 15;
            *green = ( hexv[ ( int ) name[ 2 ] ] * 255 ) / 15;
            *blue  = ( hexv[ ( int ) name[ 3 ] ] * 255 ) / 15;
        }
        else
            fprintf( stderr, "can't handle color %s\n", name );
    }
    else
    {
        /* Search the pre-defined colorname database */

        for ( match = 0, db = predef;
              ! match && db < predef + MAXDBSIZE; db++ )
        {
            if ( strcasecmp(name, db->name ) == 0 )
            {
                match = 1;
                *red   = db->red;
                *green = db->green;
                *blue  = db->blue;
            }
        }

        if ( ! match )
            fprintf( stderr, "colorname %s not found\n", name );
    }

    return 0;
}


/***************************************
 ***************************************/

int
xpmtops_direct( const char * file,
                int          xo,
                int          yo,
                long         tran )
{
    short *pixels;
    fd2psCMAP *maps[ NMAPS ], *map;
    int set[ NMAPS ];
    int ncols, w, h, i, r, g, b;

    if ( ! ( pixels = read_xpm( file, &w, &h, &ncols, maps, set ) ) )
        return -1;

#ifdef DEBUG
    {
        int x, y;
        short *p;

        fprintf( stderr, "xmapfile: w=%d h=%d ncol=%d\n", w, h, ncols );

        for ( p = pixels, y = 0; y < h; y++ )
        {
            for ( x = 0; x < w; x++ )
                fprintf( stderr, "%1d", *p++ );
            fprintf(stderr, "\n" );
        }
    }
#endif

    /* Make sure we get a usable colormap */

    if ( set[ CMAP ] + set[ GMAP ] + set[ G4MAP ] + set[ MMAP ] == 0 )
    {
        fprintf( stderr, "no usable colormap found\n" );
        return -1;
    }

    if ( set[ CMAP ] )
        map = maps[ CMAP ];
    else if ( set[ GMAP ])
        map = maps[ GMAP ];
    else if ( set[ G4MAP ] )
        map = maps[ G4MAP ];
    else
        map = maps[ MMAP ];

    /* If gray scale, graymap has priority */

    if ( ! flps->colorps && set[ GMAP ] )
        map = maps[ GMAP ];

    /* Fix transparency */

    fl_query_imap( tran, &r, &g, &b );
    for ( i = 0; i < ncols; i++ )
    {
        if ( map[ i ].red < 0 )
        {
            map[ i ].red   = r;
            map[ i ].green = g;
            map[ i ].blue  = b;
        }
    }

    /* Start outputting */

    ps_verbatim( "\n%% Start of pixmap file %s {\n", file );
    ps_output( "gsave\n" );
    ps_output( "%d %d translate\n", xo, yo );

    ( flps->colorps ? image2colorps : image2grayps )( pixels, w, h, map,
                                                      ncols, 0 );

    ps_verbatim( "\ngrestore %%}\n" );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
