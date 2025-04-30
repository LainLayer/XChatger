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
 *  Copyright (c) 1996-2001  T.C. Zhao
 *  All rights reserved.
 *
 *  Headers used internally by image support
 */

#ifndef FLIMAGE_INT_H_
#define FLIMAGE_INT_H_

#include "ulib.h"

#define fli_safe_free( p )   do {                   \
                                 if ( p )           \
                                 {                  \
                                     fl_free( p );  \
                                     p = NULL;      \
                                 }                  \
                             } while( 0 )

typedef struct flimageIO {
    const char          * formal_name;
    const char          * short_name;
    const char          * signature;
    const char          * extension;
    int                   type;
    FLIMAGE_Identify      identify;
    FLIMAGE_Description   read_description;
    FLIMAGE_Read_Pixels   read_pixels;
    FLIMAGE_Write_Image   write_image;
    int annotation;
} FLIMAGE_IO;

typedef struct {
    int    w,
           h;
    int    type;
    void * pixels;
} FLIMAGE_BUFFER;

/* Subimage for convolve etc */

typedef struct {
    int    w,
           h;
    void * mat[ 3 ];
    int    comp;                   /* number of components */
} SubImage;

SubImage * flimage_get_subimage( FL_IMAGE * im,
                                 int make );


#define FL_IsGray( t )        ( t == FL_IMAGE_GRAY || t == FL_IMAGE_GRAY16 )
#define FL_IsCI( t )          ( t == FL_IMAGE_CI   || t == FL_IMAGE_MONO )
#define FLIMAGE_MAXLUT        ( 1 << FL_LUTBITS )

extern FLIMAGE_IO *flimage_io;

typedef int ( * FLIMAGE_QUANTIZE_RGB )( unsigned char **,
                                        unsigned char **,
                                        unsigned char **,
                                        int,
                                        int,
                                        int,
                                        unsigned short **,
                                        int *,
                                        int *,
                                        int *,
                                        int *,
                                        FL_IMAGE * );

typedef int ( * FLIMAGE_QUANTIZE_PACKED )( unsigned int   **,
                                           int,
                                           int,
                                           int,
                                           unsigned short **,
                                           int *,
                                           int *,
                                           int *,
                                           int *,
                                           FL_IMAGE * );

extern FLIMAGE_QUANTIZE_RGB flimage_quantize_rgb;

extern FLIMAGE_QUANTIZE_PACKED flimage_quantize_packed;

void flimage_replace_image( FL_IMAGE *,
                            int,
                            int,
                            void *,
                            void *,
                            void * );

int flimage_transform( FL_IMAGE *,
                       int,
                       int,
                       float m[ ][ 2 ],
                       float *shift,
                       unsigned int,
                       int subp );

int flimage_getmem( FL_IMAGE * );

void flimage_freemem( FL_IMAGE * );

void flimage_add_comments( FL_IMAGE *,
                           const char *,
                           int );

int j2pass_quantize_rgb( unsigned char **,
                         unsigned char **,
                         unsigned char **,
                         int,
                         int,
                         int,
                         unsigned short **,
                         int *,
                         int *,
                         int *,
                         int *,
                            FL_IMAGE * );

int j2pass_quantize_packed( unsigned int **,
                            int,
                            int,
                            int,
                            unsigned short **,
                            int *,
                            int *,
                            int *,
                            int *,
                            FL_IMAGE * );

/* These numbers can be anything, but should be less than < 128 and may not
   equal 0 */

enum {
    FL_GET_MATRIX = 100,
    FL_MAKE_MATRIX
};

void flimage_enable_gzip( void );

void flimage_invalidate_pixels( FL_IMAGE * );

int flimage_get_closest_color_from_map( FL_IMAGE *,
                                        unsigned int );

int flimage_replace_pixel( FL_IMAGE *,
                           unsigned int,
                           unsigned int );

void flimage_free_gray( FL_IMAGE * );

void flimage_free_ci( FL_IMAGE * );

void flimage_free_rgb( FL_IMAGE * );

void pack_bits( unsigned char *,
                unsigned short *,
                int );

void unpack_bits( unsigned short *,
                  unsigned char *,
                  int );

void flimage_error( FL_IMAGE *,
                    const char *,
                    ... );

void flimage_enable_genesis( void );

int fl_spline_int_interpolate( const int *,
                               const int *,
                               int,
                               int,
                               int * );

unsigned int fl_value_to_bits( unsigned int val );

int flimage_get_linearlut( FL_IMAGE * );

void flimage_free_linearlut( FL_IMAGE * );

FLIMAGE_IO *flimage_find_imageIO( const char * );

void flimage_display_markers( FL_IMAGE * );

unsigned long flimage_color_to_pixel( FL_IMAGE *,
                                      int,
                                      int,
                                      int,
                                      int * );

int flimage_write_annotation( FL_IMAGE * );

int flimage_read_annotation( FL_IMAGE * );

int flimage_swapbuffer( FL_IMAGE * );

FL_IMAGE *flimage_dup_( FL_IMAGE *,
                        int );

int flimage_to_ximage( FL_IMAGE *,
                       FL_WINDOW,
                       XWindowAttributes * );

#if ! defined( SEEK_SET )
#define SEEK_SET 0
#endif
#if ! defined( SEEK_CUR )
#define SEEK_CUR 1
#endif
#if ! defined( SEEK_END )
#define SEEK_END 2
#endif

#endif      /* FLIMAGE_INT_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
