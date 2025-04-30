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
 *  along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/*
 *  This file is part of the XForms library package.
 *  Copyright (c) 1993, 1998-2002  By T.C. Zhao
 *  All rights reserved.
 *
 *  Read and write XPM3 files.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include <stdlib.h>
#include <ctype.h>

#define XPM_DEBUG 0

typedef struct
{
    int r,
        g,
        b,
        a;
    char key[ 4 ];      /* char keys. max 3 */
} XPMMap;


#define NMAPS 4

/* don't handle SMAP */

enum
{
    CMAP,
    GMAP,
    G4MAP,
    MMAP
};

typedef struct
{
    XPMMap map[ NMAPS ][ FLIMAGE_MAXLUT ];  /* only deal with c and g map */
    int    char_per_pix;
    int    available_maps[ NMAPS ];
} SPEC;


static char * get_xpm_pixel_name( char str[ ] );


/***************************************
 ***************************************/

static int
XPM_identify( FILE * fp )
{
    char buf[ 128 ];
    int sig,
        i;

    /* demand the signature be present in the first 3 lines */

    for ( i = sig = 0; i < 3 && ! sig && fgets( buf, 127, fp ); i++ )
    {
        buf[ 127 ] = '\0';
        sig = strstr( buf, "XPM" ) && strstr( buf, "/*" );
    }

    return sig ? 1 : -1;
}


/***************************************
 ***************************************/

static int
XPM_description( FL_IMAGE * im )
{
    int c,
        ncol;
    SPEC *sp = fl_calloc( 1, sizeof *sp );
    FILE *fp = im->fpin;

    im->io_spec = sp;

    while ( ( c = getc( fp ) ) && c != '"' )
        /* empty */ ;

    if ( fscanf( fp, "%d %d %d %d", &im->w, &im->h, &ncol,
                 &sp->char_per_pix ) != 4 )
    {
        im->error_message( im, "Can't get xpm description" );
        return -1;
    }

    if ( sp->char_per_pix <= 0 || ncol <= 0 )
    {
        im->error_message( im, "bad xpm description" );
        return -1;
    }

    if ( sp->char_per_pix > 3 || ncol > 256 )
    {
        im->error_message( im, "can't handle this xpm" );
        return -1;
    }

    while ( getc( fp ) != '\n' )
        /* empty */ ;

    im->type = FL_IMAGE_CI;
    im->map_len = ncol;

    return 0;
}


/***************************************
 ***************************************/

static int
XPM_load( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;
    FILE *fp = im->fpin;
    char *buf,
         key[ 32 ],
         val[ 32 ],
         ckey[ 8 ],
         *head,
         *p;
    int i,
        done,
        icol,
        n,
        match,
        r,
        g,
        b,
        x,
        y,
        buflen,
        mapi,
        len;
    XPMMap *map;

    buflen = ( im->w + 5 ) * sp->char_per_pix;

    /* If comments longer than 256 chars on a single line, this
       may not work right */

    if ( buflen < 256 )
        buflen = 256;

    buf = fl_malloc( buflen );

    /* Read the colormap */

    for ( icol = 0; icol < im->map_len; icol++ )
    {
        while ( fgets( buf, buflen, fp ) && strncmp( buf, "/*", 2 ) == 0 )
        {
            while ( strstr( buf, "*/" ) == NULL )
                if ( fgets( buf, buflen, fp ) == NULL )
                {
                    fl_free( buf );
                    flimage_error( im, "Failure to read xpm file" );
                    return -1;
                }
        }

        if ( ( head = strchr( buf, '"' ) ) == 0 )
        {
            fl_free( buf );
            flimage_error( im, "Bad ColorLine: %s", buf );
            return -1;
        }

        head++;

        /* The colormap line is char  [mapkey  color]* */

        strncpy( key, head, sp->char_per_pix );
        key[ sp->char_per_pix ] = '\0';
        head += sp->char_per_pix + 1;

        done = 0;
        while ( ! done )
        {
            if ( ( done =
                      ( sscanf( head, "%7s %31s %n", ckey, val, &n ) < 2 ) ) )
                break;

            head += n;

            /* Find the color code. We do not handle s currently */

            if ( ckey[ 0 ] == 'c' )
                mapi = CMAP;
            else if ( ckey[ 0 ] == 'g' && ckey[ 1 ] == '\0' )
                mapi = GMAP;
            else if ( ckey[ 0 ] == 'g' && ckey[ 1 ] == '4' )
                mapi = G4MAP;
            else if ( ckey[ 0 ] == 'm' )
                mapi = MMAP;
            else
                mapi = -1;

            /* Ignore the unhandled colormap types */

            if ( mapi >= 0 )
            {
                map = sp->map[ mapi ];
                sp->available_maps[ mapi ] = 1;
#if 1
                for ( len = strlen( val ), p = val + len - 1;
                      p > val && ( *p == ',' || *p == '"' ); p-- )
                    *p = '\0';
#endif
                strcpy( map[ icol ].key, key );

                if ( fl_lookup_RGBcolor( val, &r, &g, &b ) != -1 )
                {
                    map[ icol ].r = r;
                    map[ icol ].g = g;
                    map[ icol ].b = b;
                }
                else
                    map[ icol ].r = map[ icol ].g = map[ icol ].b = -1;
            }
        }
    }

    if ( sp->available_maps[ CMAP ] )
        map = sp->map[ CMAP ];
    else if ( sp->available_maps[ GMAP ] )
        map = sp->map[ GMAP ];
    else if ( sp->available_maps[ G4MAP  ])
        map = sp->map[ G4MAP ];
    else if ( sp->available_maps[ MMAP ] )
        map = sp->map[ MMAP ];
    else
    {
        im->error_message( im, "Can't handle XPM colormap" );
        fl_free( buf );
        return -1;
    }

    /* Copy local colormap to FLIMAGE colormap */

    for ( i = 0; i < im->map_len; i++ )
    {
        if ( map[ i ].r < 0 || map[ i ].g < 0 )
        {
            map[ i ].r = 1;
            map[ i ].g = 2;
            map[ i ].b = 3;
            map[ i ].a = 0;
            im->tran_index = i;
            im->tran_rgb = FL_PACK4( map[ i ].r, map[ i ].g, map[ i ].b,
                                     map[ i ].a );
        }

        im->red_lut[   i ] = map[ i ].r;
        im->green_lut[ i ] = map[ i ].g;
        im->blue_lut[  i ] = map[ i ].b;
    }

#if XPM_DEBUG
    fprintf( stderr, "MAP: %d entries\n", im->map_len );
    for ( i = 0; i < im->map_len; i++ )
        fprintf( stderr, "i=%d key=%s r=%3d g=%3d b=%3d\n",
                 i, map[ i ].key, map[ i ].r, map[ i ].g, map[ i ].b );
#endif

    /* read pixels */

    for ( y = 0; y < im->h; y++, im->completed++ )
    {
        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, "xpm" );

        while ( fgets( buf, buflen, fp ) && strncmp( buf, "/*", 2 ) == 0 )
            /* empty */ ;

        if ( ! ( head = strchr( buf, '"' ) ) )
        {
            fprintf( stderr, "something is wrong: %s\n", buf );
            exit( 1 );
        }

        for ( x = 0; x < im->w; x++ )
        {
            for ( i = 0; i < sp->char_per_pix; i++ )
                key[ i ] = *++head;
            key[ sp->char_per_pix ] = '\0';

            for ( match = i = 0; ! match && i < im->map_len; i++ )
                if ( ( match = (    key[ 0 ] == map[ i ].key[ 0 ]
                                 && key[ 1 ] == map[ i ].key[ 1 ]
                                 && strcmp( key, map[ i ].key ) == 0 ) ) )
                    im->ci[ y ][ x ] = i;

            if ( ! match )
            {
                im->error_message( im, "Bad pixel" );
                im->ci[ y ][ x ] = 0;
            }
        }
    }

    fl_free( buf );

    return 0;
}


/* this is enough for about 2000 colors */

static char token[ ] = ".+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN$%&!";


/***************************************
 * Only write colormaped images
 ***************************************/

static int
XPM_dump( FL_IMAGE * im )
{
    int cpp,
        i,
        j,
        k,
        x,
        y,
        buflen;
    FILE *fp = im->fpout;
    int len = strlen( token ),
        packed,
        gray;
    char name[ 512 ],
         *p,
         *buf;
    XPMMap map[ 256 ];
    unsigned short *ci;

    /* get a correct pixel name */

    p = get_xpm_pixel_name( strcpy( name, im->outfile ) );
    cpp = 1 + ( im->map_len > len );
    fprintf( fp, "/* XPM */\nstatic char *%s[] = {\n", p );
    fprintf( fp, "\"%d %d %d %d\",\n", im->w, im->h, im->map_len, cpp );

    /* generate tokens on the fly (len*(len-1) possibilities */

    for ( i = k = 0; k < im->map_len && i < len; i++ )
    {
        for ( j = i + 1; k < im->map_len && j < len; j++, k++ )
        {
            map[ k ].key[ 0] = token[ j ];
            map[ k ].key[ 1] = token[ i ];
            map[ k ].key[ cpp ] = '\0';
        }
    }

    for ( i = 0; i < im->map_len; i++ )
    {
        map[ i ].r = im->red_lut[   i ];
        map[ i ].g = im->green_lut[ i ];
        map[ i ].b = im->blue_lut[  i ];

        packed = FL_PACK( map[ i ].r, map[ i ].g, map[ i ].b );
        gray = 100 * FL_RGB2GRAY(map[ i ].r, map[ i ].g, map[ i ].g ) / 255.0
               + 0.5;

        if ( packed == im->tran_rgb || i == im->tran_index )
        {
            strcpy( map[ i ].key, cpp == 1 ? " " : "  " );
            fprintf( fp, "\"%s  c None   g None \", \n", map[ i ].key );
        }
        else
        {
            fprintf( fp, "\"%s  c #%02x%02x%02x   g grey%d \",\n",
                     map[ i ].key, map[ i ].r, map[ i ].g, map[ i ].b, gray );
        }
    }

    /* now pixels */

    buf = fl_malloc( cpp * ( im->w + 5 ) * sizeof *buf );

    for ( buflen = y = 0; y < im->h; y++, im->completed++ )
    {
        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, "writing xpm" );

        buf[ 0 ] = '"';
        buf[ buflen + 1 ] = '\0';
        ci = im->ci[ y ];

        /* we never write cpp > 2 */

        if ( cpp == 1 )
        {
            for ( x = 0; x < im->w; x++ )
                buf[ buflen++ ] = map[ ci[ x ] ].key[ 0 ];
        }
        else
        {
            for ( x = 0; x < im->w; x++ )
            {
                buf[ buflen++ ] = map[ ci[ x ] ].key[ 0 ];
                buf[ buflen++ ] = map[ ci[ x ] ].key[ 1 ];
            }
        }

        buf[ buflen ] = '\0';

        if ( i < im->h - 1 )
            fprintf( fp, "%s\",\n", buf );
        else
            fprintf( fp, "%s\"\n", buf );
    }

    /* { */

    fprintf( fp, "};\n" );
    fl_free( buf );

    return 0;
}


/***************************************
 ***************************************/

static char *
get_xpm_pixel_name( char * str )
{
    char *name,
         *q,
         *p;

    if ( ! ( name = strrchr( str, '/' ) ) )
         name = str;

    /* get rid of extension */

    if ( ( q = strchr( name, '.' ) ) )
        *q = '\0';

    /* make sure it's a legal C name */

    if ( ! isalpha( ( unsigned char ) *name ) )
        *name = 'A';

    for ( p = name + 1; *p; p++ )
        if ( ! isalnum( ( unsigned char ) *p ) && *p != '_' )
            *p = '_';

    return name;
}


/***************************************
 ***************************************/

void
flimage_enable_xpm( void )
{
    flimage_add_format( "XPM format", "xpm", "xpm",
                        FL_IMAGE_CI,
                        XPM_identify, XPM_description,
                        XPM_load, XPM_dump );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
