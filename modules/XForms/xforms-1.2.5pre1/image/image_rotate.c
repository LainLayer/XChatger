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
 *  Copyright (c) 1993, 1998-2002 By  T.C. Zhao
 *  All rights reserved.
 *
 *      Image rotation
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include <stdlib.h>
#include <math.h>

#ifndef M_PI
#define M_PI   3.1415926
#endif


static void *rotate_matrix( void *,
                            int,
                            int,
                            int,
                            size_t );


/***************************************
 * rotation angle is one-tenth of a degree
 ***************************************/

int
flimage_rotate( FL_IMAGE * im,
                int        deg,
                int        subp )
{
    int nw,
        nh;
    float mat[ 2 ][ 2 ];
    void *r,
         *g = 0,
         *b = 0;

    /* normalize the angle to within (0,360) */

    while ( deg < 0 )
        deg += 3600;
    while ( deg >= 3600 )
        deg -= 3600;

    if ( deg == 0 || deg == 3600 )
        return 0;

    /* handle special cases TODO */

    if ( deg % 900 == 0 )
    {
        deg /= 10;
        if ( im->type == FL_IMAGE_RGB )
        {
            r = rotate_matrix( im->red,   im->h, im->w, deg,
                               sizeof **im->red );
            g = rotate_matrix( im->green, im->h, im->w, deg,
                               sizeof **im->green );
            b = rotate_matrix( im->blue,  im->h, im->w, deg,
                               sizeof **im->blue );
        }
        else if ( im->type == FL_IMAGE_GRAY )
            r = rotate_matrix( im->gray, im->h, im->w, deg, sizeof **im->gray );
        else if ( im->type == FL_IMAGE_CI )
            r = rotate_matrix( im->ci, im->h, im->w, deg, sizeof **im->ci );
        else
        {
            M_err( "flimage_rotate", "InternalError: unsupported image "
                   "type\n" );
            return -1;
        }

        if ( deg % 180 == 0 )
        {
            nw = im->w;
            nh = im->h;
        }
        else
        {
            nw = im->h;
            nh = im->w;
        }

        if ( ! r )
            return -1;
    
        flimage_replace_image( im, nw, nh, r, g, b );

        return 0;
    }

    /* three shear is slightly faster , but with general transform,
     * we save a lot of code */

    mat[ 0 ][ 0 ] = mat[ 1 ][ 1 ] = cos( deg * M_PI / 1800.0 );
    mat[ 0 ][ 1 ] = sin( deg * M_PI / 1800.0 );
    mat[ 1 ][ 0 ] = -mat[ 0 ][ 1 ];

    nw = nh = 0;

    if ( flimage_warp(im, mat, nw, nh, subp) >= 0 )
    {
        im->completed = im->h;
        im->visual_cue( im, "Rotation Done" );
        return 0;
    }
    else
        return -1;
}


static int flip_matrix( void *,
                        int,
                        int,
                        int,
                        int );


/***************************************
 ***************************************/

int
flimage_flip( FL_IMAGE * im,
              int        axis )
{
    int err = 0;

    if ( im->type == FL_IMAGE_RGB )
        err =    flip_matrix( im->red,   im->h, im->w, 1, axis ) < 0
              || flip_matrix( im->green, im->h, im->w, 1, axis ) < 0
              || flip_matrix( im->blue,  im->h, im->w, 1, axis ) < 0;
    else if (FL_IsGray(im->type))
        err = flip_matrix( im->gray, im->h, im->w, 2, axis ) < 0;
    else
        err = flip_matrix( im->ci, im->h, im->w, 2, axis ) < 0;

    if ( ! err )
        im->modified = 1;

    return err ? -1 : 0;
}


/* low level matrix stuff */

#define flip_col( type, matrix, rows, cols )                           \
      do  {                                                            \
         type **mm = matrix,                                           \
               *t,                                                     \
               *h,                                                     \
                tmp;                                                   \
         int    j;                                                     \
         for ( j = 0; j < rows; j++ )                                  \
            for( t = ( h = mm[ j ] ) + cols - 1; t > h; t--, h++ )     \
            {                                                          \
               tmp = *h;                                               \
               *h = *t;                                                \
               *t = tmp;                                               \
            }                                                          \
      } while ( 0 )



/***************************************
 * flip a matrix. Mirror about the x or y
 ***************************************/

static int
flip_matrix( void * matrix,
             int    rows,
             int    cols,
             int    esize,
             int    what )
{
    if ( what == 'c' || what == 'x' )   /* flip columns */
    {
        if ( esize == 2 )
            flip_col( unsigned short, matrix, rows, cols );
        else
            flip_col( unsigned char, matrix, rows, cols );
    }
    else
    {
        int i,
            is = rows / 2;
        size_t size = esize * cols;
        unsigned char *tmp,
                      **mm = matrix;

        if ( ! ( tmp = fl_malloc( size ) ) )
            return -1;

        /* if we only flip the pointers, this will be faster, but then, the
           1-d property is violated */

        for ( i = 0; i < is; i++ )
        {
            memcpy( tmp, mm[ i ], size );
            memcpy( mm[ i ], mm[ rows - 1 - i ], size );
            memcpy( mm[ rows - 1 - i ], tmp, size );
        }

        fl_free( tmp );
    }

    return 0;
}


/* special angles: +-90, +-180 */
/***************************************************************
 * rotate a matrix by 90, or -90 or multiples of it
 * Rotate 180 can be implented as two 90 rotations, but current
 * code is faster.
 *
 * NOTE: input dimension is the diemsnion of the matrix to be
 *       rotated. caller must take care of the rotated dimensions
 **************************************************************/

/*  Rotate 90 degrees */

#define DO_M90( type, out, in )                      \
    do {                                             \
        type  *p= ( ( type ** ) out )[ 0 ],          \
             **o= in;                                \
        int i,                                       \
            j;                                       \
        for ( j = 0; j < col; j++ )                  \
        {                                            \
            for ( i = row - 1; i >= 0; i-- )         \
                *p++ = o[ i ][ j ];                  \
        }                                            \
    } while ( 0 )

/*  Rotate -90 degrees */

#define DO_90( type, out, in )                       \
    do {                                             \
        type  *p= ( ( type ** ) out )[ 0 ],          \
             **o= in;                                \
        int i,                                       \
            j;                                       \
        for ( j = col - 1; j >= 0; j-- )             \
        {                                            \
            for ( i = 0; i < row; i++ )              \
                *p++ = o[ i ][ j ];                  \
        }                                            \
    } while ( 0 )

#define DO_180( ty, out, in )                               \
    do {                                                    \
        ty *p= ( ( ty ** ) out )[ 0 ],                      \
           *o= ( ( ty ** ) in  )[ 0 ];                      \
        ty *os;                                             \
        for ( os= o + col * row-1 ; os > o; *p++ = *os-- )  \
            /* empty */ ;                                   \
    } while( 0 )



/***************************************
 ***************************************/

static void *
rotate_matrix( void * m,
               int    row,
               int    col,
               int    deg,
               size_t e )
{
    int nrow = row,
        ncol = col;
    void *mm;

    /* Coerce angle to be +/- 360 */

    deg %= 360;

    /* Now coerce it into +/- 180. */

    if ( abs( deg ) > 180 )
    {
        if ( deg < 0 )
            deg += 360;
        else
            deg -= 360;
    }

    if ( deg == 90 || deg == -90 )
    {
        nrow = col;
        ncol = row;
    }

    if ( ! ( mm = fl_get_matrix( nrow, ncol, e ) ) )
        return 0;

    if ( deg == 90 )
    {
        if ( e == 2 )
            DO_90( unsigned short, mm, m );
        else
            DO_90( unsigned char, mm, m );
    }
    else if ( deg == -90 )
    {
        if ( e == 2 )
            DO_M90( unsigned short, mm, m );
        else
            DO_M90( unsigned char, mm, m );
    }
    else if ( deg == 180 || deg == -180 )
    {
        if ( e == 2 )
            DO_180( unsigned short, mm, m );
        else
            DO_180( unsigned char, mm, m );
    }
    else
    {
        M_err( "RotateMatrix", "InternalError: bad special angle\n" );
        return 0;
    }

    return mm;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
