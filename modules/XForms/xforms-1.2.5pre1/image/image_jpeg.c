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
 *  Copyright (c) 1993, 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  JFIF file IO support.
 *  Based mostly on Independent JPEG Groups' example code.
 *
 *  Except for a couple of output control parameters, there are no
 *  static variables.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/* jpeglib.h includes jconfig.h which has a old-style definition of
 * HAVE_STDLIB_H. This breaks compilation with compilers like IBM's
 * xlc. */

#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif

#include "jpeglib.h"
#include "jerror.h"
#include <setjmp.h>

/* For some reason, jpeg 6.1 does not work well */

#if JPEG_LIB_VERSION < 62
#error does not work well with jpeg lib v6.a
#endif

/* options supported by jpeg reader/writer */

static int do_quantization = 0;
static int quality_factor = 75;
static int smoothing_factor = 0;


/***************************************
 ***************************************/

void
flimage_jpeg_output_options( FLIMAGE_JPEG_OPTION * op )
{
    quality_factor = op->quality;
    smoothing_factor = op->smoothing;
}


static unsigned int jpeg_getc( j_decompress_ptr cinfo );


/***************************************
 ***************************************/

static int
JPEG_identify( FILE * fp )
{
    char buf[ 128 ];
    int cnt;
    int i;

    cnt = fread( buf, 1, 128, fp );
    rewind( fp );
    if ( cnt < 3 )
        return 0;

    /* Clive Stubbings.
     * Test for a JPEG SOI code (0xff, 0xd8) followed by the start of
     * APP0 segement (0xff).
     * A 'raw' JPEG will not have the JFIF (JPEG file interchange format)
     * header but is still readable
     */
 
    if ( ! strncmp( buf, "\xff\xd8\xff", 3 ) )
         return 1;

    for ( i = 0; i < cnt - 3 && buf[ i ] != 'J'; i++ )
        /* empty */ ;

    return i < cnt - 3 && ! strncmp( buf + i, "JFIF", 4 );
}


/* cinfo->client_data member only exists in V6B, have to stuff image into
   error handler. Yuck! */

typedef struct
{
    struct jpeg_error_mgr         pub;
    jmp_buf                       jmp_buffer;
    struct jpeg_decompress_struct dinfo;
    struct jpeg_compress_struct   cinfo;
    FL_IMAGE *image;
} SPEC;


/***************************************
 ***************************************/

static void
error_exit( j_common_ptr cinfo )
{
    SPEC *spec = ( SPEC * ) cinfo->err;
    static char buf[ 1024 ];

    cinfo->err->format_message( cinfo, buf );
    spec->image->error_message( spec->image, buf );
    longjmp( spec->jmp_buffer, 1 );
}


/***************************************
 ***************************************/

static boolean
gather_comments( j_decompress_ptr cinfo )
{
    SPEC *spec = ( SPEC * ) cinfo->err;
    FL_IMAGE *image = spec->image;
    int length,
        ch;
    char *s;

    length  = jpeg_getc( cinfo ) << 8;
    length += jpeg_getc( cinfo ) - 2;

    image->comments = fl_realloc( image->comments, length + 1 );

    image->comments[ length ] = '\0';
    image->comments_len = length;

    for ( s = image->comments; --length >= 0; )
    {
        ch = jpeg_getc( cinfo );
        *s++ = ch;
    }

    return FL_TRUE;
}


/***************************************
 ***************************************/

static boolean
gather_text( j_decompress_ptr cinfo )
{
    SPEC *spec = ( SPEC * ) cinfo->err;
    FL_IMAGE *image = spec->image;
    int length,
        ch;
    char *s;

    length = jpeg_getc( cinfo ) << 8;
    length += jpeg_getc( cinfo ) - 2;

    if ( image->comments )
        image->comments = fl_realloc( image->comments, length + 1 );
    else
        image->comments = fl_malloc( length + 1 );

    image->comments[ length ] = '\0';
    image->comments_len = length;


    for ( s = image->comments; --length >= 0; )
    {
        ch = jpeg_getc( cinfo );
        *s++ = ch;
    }

    if ( image->comments[ image->comments_len - 1 ] == '\n' )
        image->comments[ image->comments_len - 1 ] = ' ';

    return FL_TRUE;
}


/***************************************
 ***************************************/

static int
JPEG_description( FL_IMAGE * im )
{
    SPEC *spec = fl_malloc( sizeof *spec );
    struct jpeg_decompress_struct *cinfo;

    cinfo = &spec->dinfo;
    cinfo->err = jpeg_std_error( &spec->pub );
    spec->pub.error_exit = error_exit;
    spec->image = im;
    im->io_spec = spec;

    jpeg_create_decompress( cinfo );
    jpeg_set_marker_processor( cinfo, JPEG_COM, gather_comments );
    jpeg_set_marker_processor( cinfo, JPEG_APP0 + 12, gather_text );

    jpeg_stdio_src( cinfo, im->fpin );
    jpeg_read_header( cinfo, FL_TRUE );

    /* decompressison options such as quantization here */
    if (do_quantization)
    {
        cinfo->desired_number_of_colors = 215;
        cinfo->quantize_colors = FL_TRUE;
        cinfo->enable_2pass_quant = FL_TRUE;
        cinfo->two_pass_quantize = FL_TRUE;
        cinfo->dither_mode = JDITHER_FS;
    }

    jpeg_start_decompress( cinfo );

    im->w = cinfo->output_width;
    im->h = cinfo->output_height;
    im->map_len = cinfo->desired_number_of_colors;

    if ( cinfo->out_color_space == JCS_GRAYSCALE )
        im->type = FL_IMAGE_GRAY;
    else if ( cinfo->out_color_space == JCS_RGB )
        im->type = cinfo->output_components == 3 ? FL_IMAGE_RGB : FL_IMAGE_CI;
    else
    {
        im->error_message( im, "unhandled colorspace" );
        return -1;
    }

    im->original_type = im->type;
    return 0;
}


/***************************************
 ***************************************/

static int
JPEG_read_pixels( FL_IMAGE * im )
{
    SPEC *spec = im->io_spec;
    struct jpeg_decompress_struct *cinfo = &spec->dinfo;
    int i,
        j,
        stride,
        err;
    JSAMPARRAY buf;
    unsigned short *gray,
                   *ci;

    if ( setjmp( spec->jmp_buffer ) )
    {
        jpeg_destroy_decompress( cinfo );
        /* keep what we'be got */
        return ( im->completed > im->w / 2 ) ? 1 : -1;
    }

    err = 0;
    stride = cinfo->output_width * cinfo->output_components;

    buf = cinfo->mem->alloc_sarray( ( j_common_ptr ) cinfo, JPOOL_IMAGE,
                                    stride, 1 /* cinfo->rec_outbuf_height */ );

    while ( cinfo->output_scanline < cinfo->output_height && ! err )
    {
        jpeg_read_scanlines( cinfo, buf, 1 /* cinfo->rec_out_height  */ );

        if ( ! ( cinfo->output_scanline & FLIMAGE_REPFREQ ) )
        {
            im->completed = cinfo->output_scanline;
            im->visual_cue( im, "Reading JPEG" );
        }

        if ( im->type == FL_IMAGE_RGB )
        {
            for ( i = j = 0; i < ( int ) cinfo->output_width; i++, j += 3 )
            {
                im->red[   cinfo->output_scanline - 1 ][ i ] =
                                                             buf[ 0 ][ j ];
                im->green[ cinfo->output_scanline - 1 ][ i ] =
                                                             buf[ 0 ][ j + 1 ];
                im->blue[  cinfo->output_scanline - 1 ][ i ] =
                                                             buf[ 0 ][ j + 2 ];
            }
        }
        else if ( im->type == FL_IMAGE_CI )
        {
            im->map_len = cinfo->actual_number_of_colors;
            for ( i = 0; i < cinfo->actual_number_of_colors; i++ )
            {
                im->red_lut[   i ] = cinfo->colormap[ 0 ][ i ];
                im->green_lut[ i ] = cinfo->colormap[ 1 ][ i ];
                im->blue_lut[  i ] = cinfo->colormap[ 2 ][ i ];
            }

            ci = im->ci[ cinfo->output_scanline - 1 ];
            for ( i = 0; i < ( int ) cinfo->output_width; i++ )
                ci[ i ] = buf[ 0 ][ i ];
        }
        else if ( im->type == FL_IMAGE_GRAY )
        {
            gray = im->gray[ cinfo->output_scanline - 1 ];
            for ( i = j = 0; i < im->w; i++ )
                gray[ i ] = buf[ 0 ][ i ];
        }
        else
        {
            flimage_error( im, "%s: unknown color space", im->infile );
            err = 1;
        }
    }

    jpeg_finish_decompress( cinfo );
    jpeg_destroy_decompress( cinfo );

    return im->completed > im->h / 3 ? 1 : -1;
}


/***************************************
 ***************************************/

static int
JPEG_write( FL_IMAGE * im )
{
    SPEC *spec = fl_calloc( 1, sizeof *spec );
    struct jpeg_compress_struct *cinfo;
/*    JSAMPROW rowptr[ 1 ]; */
    JSAMPARRAY rowptr;
    unsigned char *buf;
    int i;

    cinfo = &spec->cinfo;
    cinfo->err = jpeg_std_error( &spec->pub );
    spec->pub.error_exit = error_exit;

    if ( setjmp( spec->jmp_buffer ) )
    {
        jpeg_destroy_compress( cinfo );
        fl_free( spec );
        return -1;
    }

    jpeg_create_compress( cinfo );
    jpeg_stdio_dest( cinfo, im->fpout );

    cinfo->image_width = im->w;
    cinfo->image_height = im->h;

    if ( im->type == FL_IMAGE_RGB )
    {
        cinfo->input_components = 3;
        cinfo->in_color_space = JCS_RGB;
    }
    else if ( im->type == FL_IMAGE_GRAY )
    {
        cinfo->input_components = 1;
        cinfo->in_color_space = JCS_GRAYSCALE;
    }

    jpeg_set_defaults( cinfo );
    jpeg_set_quality( cinfo, quality_factor, FL_TRUE );
    cinfo->smoothing_factor = smoothing_factor;

    jpeg_start_compress( cinfo, FL_TRUE );

    if ( im->comments )
        jpeg_write_marker( cinfo, JPEG_COM, (void *) im->comments,
                           im->comments_len );

    rowptr = cinfo->mem->alloc_sarray( ( j_common_ptr ) cinfo, JPOOL_IMAGE,
                                       cinfo->input_components * im->w, 1 );

    while ( cinfo->next_scanline < cinfo->image_height )
    {
        if ( ! ( cinfo->next_scanline & FLIMAGE_REPFREQ ) )
        {
            im->completed = cinfo->next_scanline;
            im->visual_cue( im, "Writing JPEG " );
        }

        for ( buf = rowptr[ 0 ], i = 0; i < im->w; i++ )
        {
            if ( cinfo->input_components == 3 )
            {
                *buf++ = im->red[   cinfo->next_scanline ][ i ];
                *buf++ = im->green[ cinfo->next_scanline ][ i ];
                *buf++ = im->blue[  cinfo->next_scanline ][ i ];
            }
            else
                *buf++ =
                        ( unsigned char ) im->gray[ cinfo->next_scanline ][ i ];
        }

        jpeg_write_scanlines( cinfo, rowptr, 1 );
    }

    jpeg_finish_compress( cinfo );
    fflush( im->fpout );

    jpeg_destroy_compress( cinfo );
    fl_free( spec );

    return 1;
}


/***************************************
 ***************************************/

static unsigned int
jpeg_getc( j_decompress_ptr cinfo )
{
    struct jpeg_source_mgr *datasrc = cinfo->src;

    if (datasrc->bytes_in_buffer == 0)
    {

    if (!datasrc->fill_input_buffer(cinfo))
        ERREXIT(cinfo, JERR_CANT_SUSPEND);
    }

    datasrc->bytes_in_buffer--;

    return GETJOCTET(*datasrc->next_input_byte++);
}


/***************************************
 ***************************************/

void
flimage_enable_jpeg( void )
{
    flimage_add_format( "JPEG/JFIF format", "jpeg", "jpg",
                        FL_IMAGE_RGB | FL_IMAGE_GRAY,
                        JPEG_identify,
                        JPEG_description,
                        JPEG_read_pixels,
                        JPEG_write );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
