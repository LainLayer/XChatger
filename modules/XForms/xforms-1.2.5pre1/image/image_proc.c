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
 *   simple image processing routines
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


static void * get_submatrix( void *,
                             int,
                             int,
                             int,
                             int,
                             int,
                             int,
                             unsigned int );

static void * make_submatrix( void *,
                              int,
                              int,
                              int,
                              int,
                              int,
                              int,
                              unsigned int );


/********************************************************************
 *  general pixel transformation
 ********************************************************************/

int
flimage_transform_pixels( FL_IMAGE * im,
                          int      * red,
                          int      * green,
                          int      * blue )
{
    int i,
        j;
    FL_PCTYPE *r,
              *g,
              *b;
    SubImage *sub;

    if ( ! im || im->w <= 0 )
        return -1;

    flimage_convert( im, FL_IMAGE_RGB, 0 );
    flimage_invalidate_pixels( im );

    if ( ! ( sub = flimage_get_subimage( im, 1 ) ) )
        return -1;

    im->total = sub->h;
    im->visual_cue( im,"Transforming" );
    for ( i = 0; i < sub->h; i++ )
    {
        r = ( ( FL_PCTYPE ** ) sub->mat[ 0 ] )[ i ];
        g = ( ( FL_PCTYPE ** ) sub->mat[ 1 ] )[ i ];
        b = ( ( FL_PCTYPE ** ) sub->mat[ 2 ] )[ i ];

        if ( ! ( i & FLIMAGE_REPFREQ ) )
        {
            im->completed = i;
            im->visual_cue( im,"Transforming" );
        }

        for ( j = 0; j < sub->w; j++ )
        {
            r[ j ] = red[   r[ j ] ];
            g[ j ] = green[ g[ j ] ];
            b[ j ] = blue[  b[ j ] ];
        }
    }

    im->completed = sub->h;
    im->visual_cue( im,"Transforming" );

    if ( im->subw )
    {
        fl_free_matrix( sub->mat[ 0 ] );
        fl_free_matrix( sub->mat[ 1 ] );
        fl_free_matrix( sub->mat[ 2 ] );
    }

    im->modified = 1;
    return 0;
}


/********************************************************************
 * tint.
 ******************************************************************{*/

int
flimage_tint( FL_IMAGE     * im,
              unsigned int   packed,
              double         opacity )
{
    float r = FL_GETR( packed ) * opacity + 0.001;
    float g = FL_GETG( packed ) * opacity + 0.001;
    float b = FL_GETB( packed ) * opacity + 0.001;
    float trans = 1 - opacity,
          tmp;
    int i;

    if ( ! im || im->w <= 0 )
        return -1;

    if ( flimage_get_linearlut( im ) < 0 )
        return -1;

    for ( i = 0; i < im->map_len; i++ )
    {
        tmp = i * trans;
        im->llut[ 0 ][ i ] = tmp + r;
        im->llut[ 1 ][ i ] = tmp + g;
        im->llut[ 2 ][ i ] = tmp + b;
    }

    return flimage_transform_pixels( im, im->llut[ 0 ],
                                     im->llut[ 1 ], im->llut[ 2 ]);
}


/* get a subimage of the image. if parameter make is true,
   we fake a matrix so processing is done in place
 */

#define MAX_RETBUF  6       /* hack to be limited re-entrent */

SubImage *
flimage_get_subimage( FL_IMAGE * im,
                      int        make )
{
    static SubImage subimage[ MAX_RETBUF ];
    static int buf;
    SubImage *sub = subimage + buf;
    void * ( * submat )( void *, int, int, int, int, int, int, unsigned int );

    submat = make ? make_submatrix : get_submatrix;
    im->subx = FL_clamp( im->subx, 0, im->w - 1 );
    im->suby = FL_clamp( im->suby, 0, im->h - 1 );

    sub->comp = FL_IsGray( im->type) ? 1 : 3;
    sub->mat[ 0 ] = sub->mat[ 1 ] = sub->mat[ 2 ] = NULL;

    if ( im->subw < 0 || im->subh < 0 )
        im->subw = im->subh = 0;

    if ( im->subx + im->subw > im->w )
        im->subw = im->subh = 0;

    if ( im->suby + im->subh > im->h )
        im->subw = im->subh = 0;

    if ( im->subw == 0 )
    {
        sub->w = im->w;
        sub->h = im->h;
        if ( sub->comp == 1 )
            sub->mat[ 0 ] = im->gray;
        else
        {
            sub->mat[ 0 ] = im->red;
            sub->mat[ 1 ] = im->green;
            sub->mat[ 2 ] = im->blue;
        }
    }
    else
    {
        int err;

        sub->w = im->subw;
        sub->h = im->subh;

        if ( sub->comp == 3 )
        {
            err = ! ( sub->mat[ 0 ] = submat( im->red, im->h, im->w,
                                              im->suby, im->subx, im->subh,
                                              im->subw,
                                              sizeof **im->red ) );
            err = err || ! ( sub->mat[ 1 ] = submat( im->green, im->h, im->w,
                                                     im->suby, im->subx,
                                                     im->subh, im->subw,
                                                     sizeof **im->red ) );
            err = err || ! ( sub->mat[ 2 ] = submat( im->blue, im->h, im->w,
                                                     im->suby, im->subx,
                                                     im->subh, im->subw,
                                                     sizeof **im->blue ) );
        }
        else
            err = ! ( sub->mat[ 0 ] = submat( im->gray, im->h, im->w,
                                              im->suby, im->subx, im->subh,
                                              im->subw,
                                              sizeof **im->gray ) );

        if ( err )
        {
            im->error_message( im, "Failed to get working memory" );
            fl_free_matrix( sub->mat[ 0 ]);
            fl_free_matrix( sub->mat[ 1 ]);
            fl_free_matrix( sub->mat[ 2 ] );
            return NULL;
    }
    }

    buf = ( buf + 1 ) % MAX_RETBUF;

    return sub;
}


/**********************************************************************
 * Simple matrix operations
 **********************************************************************/

/* grab a piece of a matrix without copying */

static void *
make_submatrix( void         * in,
                int            rows,
                int            cols,
                int            r1,
                int            c1,
                int            rs,
                int            cs,
                unsigned int   esize )
{
    int i;
    unsigned int offset = c1 * esize;
    char **subm;
    char **mat = in;

    if (r1 < 0 || c1 < 0 || (r1 + rs - 1) >= rows || (c1 + cs - 1) >= cols)
    {
        M_err("make_submatrix", "Bad arguments");
        return 0;
    }

    if (    mat[ -1 ] != ( char * ) FL_GET_MATRIX
         && mat[ -1 ] != ( char * ) FL_MAKE_MATRIX )
    {
        M_err( "make_submatrix", "input is not a matrix" );
        return NULL;
    }

    subm = fl_malloc( ( rs + 1 ) * sizeof(void *));

    subm[ 0 ] = ( char * ) FL_MAKE_MATRIX;
    for ( i = 1; i <= rs; i++ )
        subm[ i ] = mat[ r1 + i - 1 ] + offset;
    return subm + 1;
}


/* grab a piece of a matrix */

static void *
get_submatrix( void         * in,
               int            rows,
               int            cols,
               int            r1,
               int            c1,
               int            rs,
               int            cs,
               unsigned int   esize )
{
    int i;
    unsigned int offset = c1 * esize,
                 size = cs * esize;
    char **subm;
    char **mat = in;

    if ( r1 < 0 || c1 < 0 || r1 + rs - 1 >= rows || c1 + cs - 1 >= cols )
    {
        M_err("get_submatrix", "Bad arguments");
        return 0;
    }

    if (    mat[ -1 ] != ( char * ) FL_GET_MATRIX
         && mat[ -1 ] != ( char * ) FL_MAKE_MATRIX )
    {
        M_err( "get_submatrix", "input is not a matrix" );
        return NULL;
    }

    subm = fl_get_matrix( rows, cols, esize );
    for ( i = 0; i < rs; i++ )
        memcpy( subm[ i ], mat[ r1 + i ] + offset, size );

    return subm;
}


/***********************************************************************
 * Histogram equalization
 ***********************************************************************/

static int
get_histogram(FL_IMAGE * im)
{
    unsigned int *rhist,
                 *ghist,
                 *bhist,
                 *grhist;
    unsigned int size = ( FL_PCMAX + 3 ) * sizeof **im->hist;

    if ( ! im->hist[ 0 ] )
    {
        im->hist[ 0 ] = fl_malloc( size );
        im->hist[ 1 ] = fl_malloc( size );
        im->hist[ 2 ] = fl_malloc( size );
        im->hist[ 3 ] = fl_malloc( size );
    }

    memset( rhist  = im->hist[ 0 ], 0, size );
    memset( ghist  = im->hist[ 1 ], 0, size );
    memset( bhist  = im->hist[ 2 ], 0, size );
    memset( grhist = im->hist[ 3 ], 0, size );

    if ( im->type == FL_IMAGE_RGB )
    {
        int g,
            n;

        for ( n = im->w * im->h; --n >= 0; )
        {
            if ( ++rhist[ im->red[ 0 ][ n ] ] == 0 )
                rhist[ im->red[ 0 ][ n ] ]--;
            if ( ++ghist[ im->green[ 0 ][ n ] ] == 0 )
                ghist[ im->green[ 0 ][ n ] ]--;
            if ( ++bhist[ im->blue[ 0 ][ n ] ] == 0 )
                bhist[ im->blue[ 0 ][ n ] ]--;
            g = FL_RGB2GRAY( im->red[ 0 ][ n ],
                             im->green[ 0 ][ n ],
                             im->blue[ 0 ][ n ] );
            if ( ++grhist[ g ] == 0 )
                grhist[ g ]--;
        }
    }
    else if ( im->type == FL_IMAGE_GRAY )
    {
        int n;

        for ( n = im->w * im->h; --n >= 0; )
        {
            if ( ++grhist[ im->gray[ 0 ][ n ] ] == 0 )
                grhist[ im->gray[ 0 ][ n ] ]--;
        }
    }
    else if ( im->type == FL_IMAGE_CI )
    {
        unsigned short *ci = im->ci[ 0 ];
        int g;

        for ( ci = im->ci[ 0 ] + im->w * im->h; --ci >= im->ci[ 0 ]; )
        {
            if ( ++rhist[ im->red_lut[ *ci ] ] )
                rhist[ im->red_lut[ *ci ] ]--;
            if ( ++ghist[ im->green_lut[ *ci ] ] )
                ghist[ im->green_lut[ *ci ] ]--;
            if ( ++bhist[ im->blue_lut[ *ci ] ] )
                bhist[ im->blue_lut[ *ci ] ]--;
            g = FL_RGB2GRAY( im->red_lut[   *ci ],
                             im->green_lut[ *ci ],
                             im->blue_lut[  *ci ] );
            if ( ++grhist[ g ] == 0 )
                grhist[ g ]--;
        }
    }
    else
    {
        im->error_message( im, "histogram: unhandled" );
        return -1;
    }

    return 0;
}


int
flimage_enhance( FL_IMAGE * im,
                 int        delta  FL_UNUSED_ARG )
{
    long sum[ FL_PCMAX + 2 ];
    int i,
        n;

    if (im->type == FL_IMAGE_CI)
        flimage_convert(im, FL_IMAGE_RGB, 0);
    else if (im->type == FL_IMAGE_MONO)
        flimage_convert(im, FL_IMAGE_GRAY, 0);

    get_histogram( im );
    memset( sum, 0, sizeof sum );
    sum[ 0 ] = im->hist[ 3 ][ 0 ];

    for ( i = 1; i <= FL_PCMAX; i++ )
        sum[ i ] = sum[ i - 1 ] + im->hist[ 3 ][ i ];

    for ( i = 0; i <= FL_PCMAX; i++ )
        sum[ i ] *= ( FL_PCMAX - 0.999f ) / ( im->w * im->h );

    if (im->type == FL_IMAGE_RGB)
        for (n = im->w * im->h; --n >= 0;)
        {
            im->red[0][n] = sum[im->red[0][n]];
            im->green[0][n] = sum[im->green[0][n]];
            im->blue[0][n] = sum[im->blue[0][n]];
        }
    else if (im->type == FL_IMAGE_GRAY)
        for (n = im->w * im->h; --n >= 0;)
            im->gray[0][n] = sum[im->gray[0][n]];
    else
        fprintf(stderr, "image_enhance: unhandled");

    im->modified = 1;
    return 0;
}


int
flimage_get_closest_color_from_map( FL_IMAGE     * im,
                                    unsigned int   col )
{
    int r = FL_GETR( col ),
        g = FL_GETG( col ),
        b = FL_GETB( col );
    int mindiff = 0x7fffffff,
        diff;
    int dr,
        dg,
        db,
        k,
        i;

    for ( k = i = 0; i < im->map_len; i++ )
    {
        dr = r - im->red_lut[ i ];
        dg = g - im->green_lut[ i ];
        db = b - im->blue_lut[ i ];

        diff = 3 * dr * dr + 4 * dg * dg + 2 * db * db;

        if (mindiff > diff)
        {
            mindiff = diff;
            k = i;
        }
    }

    return k;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
