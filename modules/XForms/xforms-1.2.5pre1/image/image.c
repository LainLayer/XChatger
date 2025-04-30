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
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *   Public API for image file IO
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "flimage.h"
#include "flimage_int.h"
#include "private/flsnprintf.h"
#include <stdlib.h>
#include <stdarg.h>

static int visual_cue( FL_IMAGE *,
                       const char * );
static void error_message( FL_IMAGE *,
                           const char * );

static int nimage;
static FLIMAGE_SETUP current_setup;

#define MaxImageFileNameLen  260

FLIMAGE_IO *flimage_io;
FLIMAGE_QUANTIZE_RGB flimage_quantize_rgb;
FLIMAGE_QUANTIZE_PACKED flimage_quantize_packed;

static int ppm_added,
           gzip_added;

static void add_default_formats( void );


/*********************************************************************
 *****************************************************************{**/

static void
null_op( FL_IMAGE * im  FL_UNUSED_ARG )
{
}


/*********************************************************************
 * Setup and image structure creation
 *****************************************************************{**/

void
flimage_setup( FLIMAGE_SETUP * setup )
{
    current_setup = *setup;

    if ( setup->max_frames == 0 )
        current_setup.max_frames = 30;
    if ( setup->delay > 2000 )
        current_setup.delay = 2000;

    add_default_formats( );
}


/***************************************
 ***************************************/

static void
init_setup( void )
{
    if ( current_setup.max_frames || current_setup.delay )
        return;

    current_setup.max_frames = 30;
    current_setup.delay = 50;
}


/***************************************
 ***************************************/

FL_IMAGE *
flimage_alloc( void )
{
    FL_IMAGE *image = fl_calloc( 1, sizeof *image );

    init_setup( );

    add_default_formats( );

    image->setup = &current_setup;
    image->visual_cue = current_setup.visual_cue;
    image->error_message = current_setup.error_message;
    image->gray_maxval = 255;
    image->ci_maxval = 255;
    image->tran_index = -1;
    image->tran_rgb = -1;
    image->app_background = -1;
    image->app_data = current_setup.app_data;
    image->total_frames = 1;
    image->xdist_scale = image->ydist_scale = 1.0;
    image->pscale = 1.0;
    image->display = flimage_display;
    image->xdisplay = current_setup.xdisplay;
    image->infile = fl_malloc( MaxImageFileNameLen * sizeof *image->infile );
    image->outfile = fl_malloc( MaxImageFileNameLen * sizeof *image->outfile );
    image->infile[0] = image->outfile[ 0 ] = '\0';

    if ( ! image->xdisplay )
        image->xdisplay = fl_display;

    /* initialize the quantizer */

    if ( ! flimage_quantize_rgb )
    {
        flimage_quantize_rgb = j2pass_quantize_rgb;
        flimage_quantize_packed = j2pass_quantize_packed;
    }

    /* make sure visual_cue and error_message are ok */

    if ( ! image->visual_cue )
        image->visual_cue = visual_cue;

    if ( ! image->error_message )
        image->error_message = error_message;

    /* annotation stuff */

    image->display_markers = null_op;
    image->free_markers = null_op;
    image->display_text = null_op;
    image->free_text = null_op;

    return image;
}


/*************************************************************************
 * Image identification
 *************************************************************************/

/* it's important that this routine be silient. is_supported calls this */

static FL_IMAGE *
identify_image( const char *file )
{
    FILE *fp;
    FLIMAGE_IO *io;
    FL_IMAGE *image = NULL;

    if ( ! file || ! *file )
        return NULL;

    if ( ! ( fp = fopen( file, "rb" ) ) )
    {
        fprintf( stderr, "Can't open %s\n", file );
        return NULL;
    }

    if ( ! ppm_added )
        add_default_formats( );

    for ( io = flimage_io; io->formal_name; io++ )
    {
        if ( io->identify( fp ) > 0 )
        {
            image = flimage_alloc( );
            image->image_io = io;
            image->original_type = io->type;
            image->fpin = fp;
            strncpy( image->infile, file, MaxImageFileNameLen - 5 );
            image->infile[ MaxImageFileNameLen - 5 ] = '\0';
            return image;
        }

        rewind( fp );
    }

    fclose( fp );
    return NULL;
}


/***************************************
 * Check if the file is an image file. Should never bitch
 ***************************************/

int
flimage_is_supported( const char * file )
{
    FILE *fp;
    FLIMAGE_IO *io;
    int n;

    if ( ! file || ! *file || ! ( fp = fopen( file, "rb" ) ) )
        return 0;

    if ( ! ppm_added )
        add_default_formats( );

    for ( n = 0, io = flimage_io; io->formal_name; io++, n++ )
    {
        if ( io->identify( fp ) > 0 )
        {
            fclose( fp );
            return n + 1;
        }
        else
            rewind( fp );
    }

    fclose( fp );

    return 0;
}


/*********************************************************************
 * Basic image file open routines
 ********************************************************************/


FL_IMAGE *
flimage_open( const char * file )
{
    FL_IMAGE *im = identify_image( file );

    if ( ! im )
        M_err( "OpenImage", "%s: Unknown image format", file ? file : "null" );

    return im;
}


/***************************************
 ***************************************/

int
flimage_close( FL_IMAGE * im )
{
    int status = 0;

    if ( ! im )
        return -1;

    if ( im->fpin )
        status = fclose( im->fpin );

    if ( im->fpout )
        status = fclose( im->fpout );

    im->fpin = NULL;
    im->fpout = NULL;

    return status;
}


/************************************************************************
 * Input routines
 **********************************************************************{*/

FL_IMAGE *
flimage_read( FL_IMAGE * im )
{
    FL_IMAGE *image = im;
    FLIMAGE_IO *io;
    int error = 0;
    char buf[ 256 ];

    if ( ! im || ! im->fpin )
        return NULL;

    io = image->image_io;
    if ( ! io->read_description || ! io->read_pixels )
        return NULL;

    /* Copy some default info */

    image->type = io->type;
    image->fmt_name = io->short_name;

    image->foffset = ftell( image->fpin );

    if ( ( error = ( io->read_description( image ) < 0 ) ) )
        return NULL;

    /* image_io can change between description and read_pixels for
       io_filter'ed image */

    io = image->image_io;

    if ( ( error = ( flimage_getmem( image ) < 0 ) ) )
    {
        im->error_message( im, "ImageGetMem:Failed to allocate memory" );
        flimage_freemem( im );
        return NULL;
    }

    image->completed = 0;
    image->total = im->h;
    image->error_message( image, "" );
    error = error || ( io->read_pixels( image ) < 0 );
    image->completed = im->total;
    sprintf( buf, "Done Reading %s", image->fmt_name );
    image->visual_cue( image, error ? "Error Reading" : buf );

    image->original_type = image->type;
    image->available_type = image->type;
    image->modified = 1;

    if ( error )
    {
        flimage_freemem( image );
        image = NULL;
    }

    return image;
}


/***************************************
 * turn a random frame into next frame
 ***************************************/

static int
default_next_frame( FL_IMAGE * im )
{
    return im->random_frame( im, im->current_frame );
}


/***************************************
 ***************************************/

FL_IMAGE *
flimage_load( const char * file )
{
    FL_IMAGE *image,
             *im;
    int err,
        tc,
        total_frames = 1;
    char buf[ 256 ];

    add_default_formats( );

    if ( ( image = flimage_open( file ) ) )
    {
        if ( ! ( im = flimage_read( image ) ) )
        {
            flimage_free( image );
            image = NULL;
        }
        else
            image = im;
    }

    if ( ! image )
        return image;

    /* transparency */

    tc = image->tran_index;
    if ( FL_IsCI( image->type ) && tc >= 0 && tc < image->map_len )
        image->tran_rgb = FL_PACK3( image->red_lut[ tc ],
                                    image->green_lut[ tc ],
                                    image->blue_lut[ tc ] );

    /* Create a next_frame function on the fly if possible */

    if ( ! image->next_frame && image->random_frame )
        image->next_frame = default_next_frame;

    if ( ! image->more || ! image->next_frame )
    {
        if ( ( ( FLIMAGE_IO * ) image->image_io )->annotation )
            flimage_read_annotation( image );
        flimage_close( image );
        fli_safe_free( image->io_spec );
        image->spec_size = 0;
        image->display = flimage_sdisplay;
        return image;
    }

    image->current_frame = 1;

    /* We have multi-frames */

    err = 0;
    im = image;

    while (    ! err
            && im->more
            && im->more > im->completed
            && im->current_frame < current_setup.max_frames )
    {
        if ( ! ( err = ! ( im->next = flimage_dup_( im, 0 ) ) ) )
        {
            im = im->next;
            im->current_frame++;
        }
        sprintf( buf, "Done image %d of %d",
                 im->current_frame, current_setup.max_frames );
        im->visual_cue( im, buf );
        err = err || ( im->next_frame( im ) < 0 );
        total_frames += ! err;
    }

    flimage_close( image );

    image->completed = im->total;
    sprintf( buf, "Done Reading multi-frame %s", image->fmt_name );
    image->visual_cue( image, err ? "Error Reading" : buf );

    /* multi frame cleanup */

    if ( image->cleanup )
        image->cleanup( image );

    /* update the number of frames */

    image->total_frames = total_frames;
    return image;
}


/**********************************************************************
 * Output routines
 *********************************************************************/

static void convert_type( FL_IMAGE *,
                          FLIMAGE_IO * );

int
flimage_dump( FL_IMAGE   * image,
              const char * filename,
              const char * fmt )
{
    FLIMAGE_IO *io = flimage_io;
    char buf[ 256 ], *p;
    FILE *fp;
    int status = -1,
        otype;
    FL_IMAGE *tmpimage;

    if ( ! image || image->type == FL_IMAGE_NONE )
    {
        fprintf( stderr, "WriteImage: invalid or null image\n" );
        return -1;
    }

    if ( ! fmt || ! *fmt )
        fmt = image->fmt_name;

    for ( ; io->formal_name; io++ )
    {
        if (    (    strcasecmp( io->formal_name, fmt ) == 0
                  || strcasecmp( io->short_name,  fmt ) == 0
                  || strcasecmp( io->extension,   fmt ) == 0 )
             && io->write_image )
        {
            strncpy( image->outfile, filename, MaxImageFileNameLen - 5 );
            image->outfile[ MaxImageFileNameLen - 5 ] = '\0';

            /* change extension */

            if ( ! image->setup->no_auto_extension )
            {
                if ( ( p = strrchr( image->outfile, '.' ) ) )
                    *p = '\0';
                strcat( strcat( image->outfile, "." ), io->extension );
            }

            if ( ! ( fp = fopen( image->outfile, "wb" ) ) )
            {
                flimage_error( image, "can't open %s", image->outfile );
                return -1;
            }

            image->fpout = fp;
            otype = image->type;

            for ( tmpimage = image; tmpimage; tmpimage = tmpimage->next )
                convert_type( tmpimage, io );

            if ( image->pre_write && image->pre_write( image ) < 0 )
            {
                flimage_close( image );
                return FL_CANCEL;
            }

            image->completed = 0;
            image->total = image->h;
            status = io->write_image( image );

            if ( status >= 0 && image->post_write )
                image->post_write( image );
            image->type = otype;

            if ( io->annotation )
                flimage_write_annotation( image );

            flimage_close( image );

            image->completed = image->total;
            fli_snprintf( buf, sizeof buf,
                          "Done Writing %s(%s)", image->outfile, fmt );
            image->visual_cue( image, buf );
            return status;
        }
    }

    flimage_error( image, "don't know how to write %s", fmt );
    return -1;
}


/***************************************
 * Convert the image to a type the output routine can handle
 ***************************************/

static void
convert_type( FL_IMAGE   * im,
              FLIMAGE_IO * io )
{
    const int types[ ] = { FL_IMAGE_RGB,
                           FL_IMAGE_PACKED,
                           FL_IMAGE_CI,
                           FL_IMAGE_GRAY,
                           FL_IMAGE_MONO };
    int ntypes = sizeof types / sizeof *types;
    int i,
        done;

    /* if the output routine can handle the current image type, do nothing */

    if ( ( im->type & io->type ) )
        return;

    /* must force the conversion */

    im->force_convert = 1;

    if ( im->type == FL_IMAGE_CI || im->type == FL_IMAGE_RGB )
    {
        for ( i = done = 0; !done && i < ntypes; i++ )
        {
            if ( ( done = io->type & types[ i ] ) )
                flimage_convert( im, types[ i ], 256 );
        }
    }
    else if ( im->type == FL_IMAGE_GRAY || im->type == FL_IMAGE_MONO )
    {
        if ( io->type & FL_IMAGE_CI )
            flimage_convert( im, FL_IMAGE_CI, 256 );
        else
        {
            for ( i = done = 0; !done && i < ntypes; i++ )
            {
                if ( ( done = io->type & types[ i ] ))
                    flimage_convert( im, types[ i ], 256 );
            }
        }
    }
    else if ( im->type == FL_IMAGE_GRAY16 )
    {
        if ( io->type & FL_IMAGE_GRAY )
            flimage_convert( im, FL_IMAGE_GRAY, 0 );
        else
        {
            for ( i = done = 0; !done && i < ntypes; i++ )
            {
                if ( ( done = io->type & types[ i ] ) )
                    flimage_convert( im, types[ i ], 256 );
            }
        }
    }
    else
    {
        M_err( "Output", "InternalError: unhandled image type: %s",
               flimage_type_name( im->type ) );
        im->force_convert = 0;
    }
}


/***********************************************************************/


/***********************************************************************
 *  Memory related routines
 ***********************************************************************/

void
flimage_free( FL_IMAGE * image )
{
    FL_IMAGE *im,
             *imnext;

    for ( im = image; im; im = imnext)
    {
        flimage_freemem( im );
        if ( im == image )
            flimage_close( im );
        imnext = im->next;
        fli_safe_free( im->infile );
        fli_safe_free( im->outfile );
        im->next = NULL;
        fl_free( im );
    }
}


/***************************************
 ***************************************/

int
flimage_get_linearlut( FL_IMAGE * im )
{
    if ( ! im->map_len )
    {
        im->map_len = FL_PCMAX + 1;
        flimage_getcolormap( im );
    }

    if ( im->map_len > im->llut_len )
    {
        fli_safe_free( im->llut[ 0 ] );
        fli_safe_free( im->llut[ 1 ] );
        fli_safe_free( im->llut[ 2 ] );
    }

    if ( ! im->llut[ 0 ] )
    {
        im->llut[ 0 ] = fl_malloc( im->map_len * sizeof **im->llut );
        im->llut[ 1 ] = fl_malloc( im->map_len * sizeof **im->llut );
        im->llut[ 2 ] = fl_malloc( im->map_len * sizeof **im->llut );
    }

    if ( ! im->llut[ 2 ] )
    {
        fli_safe_free( im->llut[ 0 ] );
        fli_safe_free( im->llut[ 1 ]);
        return -1;
    }

    im->llut_len = im->map_len;
    return 0;
}


/***************************************
 ***************************************/

void
flimage_free_linearlut( FL_IMAGE * im )
{
    fli_safe_free( im->llut[ 0 ] );
    fli_safe_free( im->llut[ 1 ] );
    fli_safe_free( im->llut[ 2 ] );

    im->llut_len = 0;
}


/***************************************
 ***************************************/

int
flimage_getmem( FL_IMAGE * im )
{
    int nomap,
        err = 0,
        same_size;
    unsigned int esize;

    if ( ! im || ! im->w || ! im->h )
        return -1;

    same_size = im->w == im->matc && im->h == im->matr;

    switch ( im->type )
    {
        case FL_IMAGE_CI:
        case FL_IMAGE_MONO:
            if ( ( nomap = ( im->map_len <= 0 ) ) )
                im->map_len = 2;

            if ( flimage_getcolormap( im ) < 0 )
            {
                flimage_error( im, "can't alloc colormap" );
                return -1;
            }

            if ( im->type == FL_IMAGE_MONO && nomap )
            {
                im->red_lut[ 0 ] = im->green_lut[ 0 ] = im->blue_lut[ 0 ] =
                                                                       FL_PCMAX;
                im->red_lut[ 1 ] = im->green_lut[ 1 ] = im->blue_lut[ 1 ] = 0;
            }

            if ( ! same_size || ! im->ci )
            {
                if ( im->ci )
                    fl_free_matrix( im->ci );
                err = ! ( im->ci = fl_get_matrix( im->h, im->w,
                                                  sizeof **im->ci ) );
            }
            break;

        case FL_IMAGE_GRAY:
        case FL_IMAGE_GRAY16:
            flimage_getcolormap( im );
            if ( ! same_size || ! im->gray )
            {
                if ( im->gray )
                    fl_free_matrix( im->gray );
                err = ! ( im->gray = fl_get_matrix( im->h, im->w,
                                                    sizeof **im->gray ) );
            }

            if ( ! err && ( ! im->wlut || im->gray_maxval > im->wlut_len ) )
            {
                fli_safe_free( im->wlut );
                if ( ( im->wlut_len = im->gray_maxval + 1 ) < 256 )
                    im->wlut_len = 256;
                err = ! ( im->wlut = fl_malloc( im->wlut_len
                                                * sizeof *im->wlut ) );
            }
            break;

        case FL_IMAGE_PACKED:
            if ( ! same_size || ! im->packed )
            {
                if ( im->packed )
                    fl_free_matrix( im->packed );
                err = ! ( im->packed = fl_get_matrix( im->h, im->w,
                                                      sizeof **im->packed ) );
            }
            break;

        case FL_IMAGE_RGB:
            /* it's possible for some image format to be RGB yet  * have a
               redundant colormap in it (xwd for example) */

            flimage_getcolormap( im );
            if ( ! same_size || ! im->red )
            {
                if ( im->red )
                {
                    fl_free_matrix( im->red );
                    fl_free_matrix( im->green );
                    fl_free_matrix( im->blue );
                    fl_free_matrix( im->alpha );
                }

                esize = sizeof **im->red;

                err =    ! ( im->red   = fl_get_matrix( im->h, im->w, esize ) )
                      || ! ( im->green = fl_get_matrix( im->h, im->w, esize ) )
                      || ! ( im->blue  = fl_get_matrix( im->h, im->w, esize ) )
                      || ! ( im->alpha = fl_get_matrix( im->h, im->w, esize ) );

                if ( err )
                {
                    fl_free_matrix( im->red );
                    fl_free_matrix( im->green );
                    fl_free_matrix( im->blue );
                    fl_free_matrix( im->alpha );
                    im->red = NULL;
                }
                else
                {
                    im->rgba[ 0 ] = im->red;
                    im->rgba[ 1 ] = im->green;
                    im->rgba[ 2 ] = im->blue;
                    im->rgba[ 3 ] = im->alpha;
                }

            }
            break;

        default:
            return -1;
    }

    im->matr = im->h;
    im->matc = im->w;

    return err ? -1 : 0;
}


/***************************************
 ***************************************/

int
flimage_getcolormap( FL_IMAGE * im )
{
    int len = im->map_len;

    if ( len <= 0 )
        return -1;

    if ( len > FLIMAGE_MAXLUT )
        len = im->map_len = FLIMAGE_MAXLUT;

    im->red_lut   = fl_realloc( im->red_lut,   len * sizeof *im->red_lut   );
    im->green_lut = fl_realloc( im->green_lut, len * sizeof *im->green_lut );
    im->blue_lut  = fl_realloc( im->blue_lut,  len * sizeof *im->blue_lut  );
    im->alpha_lut = fl_realloc( im->alpha_lut, len * sizeof *im->alpha_lut );

    if ( ! im->alpha_lut )
    {
        fli_safe_free( im->red_lut );
        fli_safe_free( im->green_lut );
        fli_safe_free( im->blue_lut );
        return -1;
    }

    im->lut[ 0 ] = im->red_lut;
    im->lut[ 1 ] = im->green_lut;
    im->lut[ 2 ] = im->blue_lut;
    im->lut[ 3 ] = im->alpha_lut;

    if ( im->map_len > im->wlut_len && FL_IsGray( im->type ) )
    {
        im->wlut = fl_realloc( im->wlut, im->map_len * sizeof *im->wlut );
        if ( ! im->wlut )
        {
            im->wlut_len = 0;
            return -1;
        }

        im->wlut_len = im->map_len;
    }

    return 0;
}


/***************************************
 * Before we modify the current image, need to invalidate/free all
 * other types
 ***************************************/

void
flimage_invalidate_pixels( FL_IMAGE * im )
{
    if ( ! FL_IsGray( im->type ) )
    {
        fl_free_matrix( im->gray );
        im->gray = NULL;
    }

    if ( ! FL_IsCI( im->type ) )
    {
        fl_free_matrix( im->ci );
        im->ci = NULL;
    }

    if ( im->type != FL_IMAGE_PACKED )
    {
        fl_free_matrix( im->packed );
        im->packed = NULL;
    }

    if ( im->type != FL_IMAGE_RGB )
    {
        fl_free_matrix( im->red );
        fl_free_matrix( im->green );
        fl_free_matrix( im->blue );
        fl_free_matrix( im->alpha );
        im->red = im->green = im->blue = im->alpha = NULL;
    }

    im->available_type = im->type;
}


/***************************************
 * Free all allocated memory associated with the image
 ***************************************/

void
flimage_freemem( FL_IMAGE * image )
{

    if ( ! image || ! image->w || ! image->h )
        return;

    if ( image->ci )
    {
        fl_free_matrix( image->ci );
        image->ci = NULL;
    }

    fli_safe_free( image->wlut );
    image->wlut_len = 0;

    if ( image->gray )
    {
        fl_free_matrix( image->gray );
        image->gray = NULL;
    }

    if ( image->packed )
    {
        fl_free_matrix( image->packed );
        image->packed = NULL;
    }

    if ( image->red )
    {
        fl_free_matrix( image->red );
        fl_free_matrix( image->green );
        fl_free_matrix( image->blue );
        fl_free_matrix( image->alpha );
        image->red = image->green = image->blue = image->alpha = NULL;
    }

    if ( image->map_len > 0 && image->red_lut )
    {
        fl_free( image->red_lut );
        fl_free( image->green_lut );
        fl_free( image->blue_lut );
        fl_free( image->alpha_lut );
        image->red_lut = image->green_lut = image->blue_lut = NULL;
        image->map_len = 0;
    }

    fli_safe_free( image->comments );
    image->comments_len = 0;

    image->free_text( image );
    image->free_markers( image );
    flimage_free_linearlut( image );

    if ( image->pixmap )
    {
        XFreePixmap( image->xdisplay, image->pixmap );
        image->pixmap = None;
        image->pixmap_depth = 0;
    }

    if ( image->ximage )
    {
        XDestroyImage( ( XImage * ) image->ximage );
        image->ximage = NULL;
    }

    if ( image->gc )
    {
        XFreeGC( image->xdisplay, image->gc );
        image->gc = None;
    }

    if ( image->textgc )
    {
        XFreeGC( image->xdisplay, image->textgc );
        image->textgc = None;
    }

    if ( image->markergc )
    {
        XFreeGC( image->xdisplay, image->markergc );
        image->markergc = None;
    }

    if ( image->pixels )
    {
        fl_free_matrix( image->pixels );
        image->pixels = NULL;
    }

    fli_safe_free( image->io_spec );
    image->spec_size = 0;

    fli_safe_free( image->info );

    image->w = image->h = 0;
    image->matr = image->matc = 0;
    image->type = FL_IMAGE_NONE;
    image->available_type = FL_IMAGE_NONE;
}


/***************************************
 ***************************************/

int
flimage_add_format( const char          * formal_name,
                    const char          * short_name,
                    const char          * extension,
                    int                   type,
                    FLIMAGE_Identify      identify,
                    FLIMAGE_Description   description,
                    FLIMAGE_Read_Pixels   read_pixels,
                    FLIMAGE_Write_Image   write_image )
{
    int i, k;
    FLIMAGE_IO *thisIO;

    if ( ! formal_name || ! *formal_name || ! short_name || ! *short_name )
        return -1;

    ppm_added = ppm_added || ( extension && strcmp( "ppm", extension ) == 0 );
    gzip_added = gzip_added || ( extension && strcmp("gz", extension ) == 0 );

    if ( type <= 0 || type > FL_IMAGE_FLEX )
        return -1;

    if ( ! description || ! read_pixels || ! identify )
        description = read_pixels = 0;

    if ( flimage_io == 0 )
    {
        nimage = 1;     /* sentinel */
        flimage_io = fl_calloc( 3, sizeof *flimage_io );
    }
    else
        flimage_io = fl_realloc( flimage_io,
                                 ( nimage + 2 ) * sizeof *flimage_io );

    k = nimage;

    /* find out if the image format is already installed. Replace if yes */

    for ( i = 0; flimage_io[ i ].formal_name; i++ )
    {
        if (    strcmp( flimage_io[ i ].formal_name, formal_name ) == 0
             && strcmp( flimage_io[ i ].short_name, short_name ) == 0 )
        {
            M_err( "flimage_add_format",
                   "%s already supported. Replaced", short_name );
            k = i + 1;
        }
    }

    thisIO = flimage_io + k - 1;

    thisIO->formal_name = formal_name;
    thisIO->short_name = short_name;
    thisIO->extension = extension ? extension : short_name;
    thisIO->type = type;
    thisIO->identify = identify;
    thisIO->read_description = description;
    thisIO->read_pixels = read_pixels;
    thisIO->write_image = write_image;
    thisIO->annotation = 0;

    nimage += k == nimage;

    if ( ! strcmp( short_name, "ppm" ) || ! strcmp( short_name, "pgm" ) )
        thisIO->annotation = 1;

    /* sentinel */

    ( ++thisIO )->formal_name = NULL;

    return k;
}


/***************************************
 ***************************************/

void
flimage_set_annotation_support( int in,
                                int flag )
{
     --in;

     if ( in < 0 || in >= nimage )
         return;
     flimage_io[ in ].annotation = flag != 0;
}


#define VN( a )  {a,#a}
static FLI_VN_PAIR types[ ] =
{
    VN( FL_IMAGE_NONE   ),
    VN( FL_IMAGE_CI     ),
    VN( FL_IMAGE_MONO   ),
    VN( FL_IMAGE_RGB    ),
    VN( FL_IMAGE_PACKED ),
    VN( FL_IMAGE_GRAY   ),
    VN( FL_IMAGE_GRAY16 ),
    VN( FL_IMAGE_FLEX   ),
    { -1, NULL }
};


/***************************************
 ***************************************/

const char *
flimage_type_name( int type )
{
    return fli_get_vn_name( types, type );
}


/***************************************
 ***************************************/

int
flimage_get_number_of_formats( void )
{
    add_default_formats( );
    return nimage - 1;
}


/***************************************
 ***************************************/

#define MaxInfoBuffer 6

const FLIMAGE_FORMAT_INFO *
flimage_get_format_info( int n )
{
    static FLIMAGE_FORMAT_INFO fmt_return[ MaxInfoBuffer ];
    static int k;
    FLIMAGE_IO *io;
    FLIMAGE_FORMAT_INFO *fmtinfo;

    add_default_formats( );

    if ( n <= 0 || n > nimage )
        return 0;

    fmtinfo = fmt_return + k++ % MaxInfoBuffer;
    n--;
    io = flimage_io + n;

    fmtinfo->formal_name = io->formal_name;
    fmtinfo->short_name = io->short_name;
    fmtinfo->extension = io->extension;
    fmtinfo->type = io->type;
    fmtinfo->annotation = io->annotation;
    fmtinfo->read_write =   ( io->write_image ? FLIMAGE_WRITABLE : 0 )
                          | ( io->read_pixels ? FLIMAGE_READABLE : 0 );

    return fmtinfo;
}


/***************************************
 ***************************************/

void
flimage_replace_image( FL_IMAGE * im,
                       int        w,
                       int        h,
                       void     * r,
                       void     * g,
                       void     * b )
{
    /* If we replace an image, all old backingstore pixels are invalid.
       Free all images */

    flimage_invalidate_pixels( im );

    im->w = w;
    im->h = h;

    if ( im->type == FL_IMAGE_RGB )
    {
        fl_free_matrix( im->red );
        fl_free_matrix( im->green );
        fl_free_matrix( im->blue );
        fl_free_matrix( im->alpha );
        im->red = r;
        im->green = g;
        im->blue = b;

        /* Dont' have to preserve the alpha. remember to doc it */

        im->alpha = fl_get_matrix( h, w, sizeof **im->alpha );
    }
    else if ( FL_IsCI( im->type ) )
    {
        fl_free_matrix( im->ci );
        im->ci = r;
    }
    else if ( FL_IsGray( im->type ) )
    {
        fl_free_matrix( im->gray );
        im->gray = r;
    }
    else
    {
        M_err( "flimage_replace_image", "InternalError: bad type=%s",
               flimage_type_name( im->type ) );
        return;
    }

    im->matr = h;
    im->matc = w;

    im->total = im->h;

    /* invalidate subimage settings if any */

    im->sx = im->sy = im->sw = im->sh = 0;
    im->modified = 1;
}


/***************************************
 ***************************************/

void
flimage_add_comments( FL_IMAGE   * im,
                      const char * s,
                      int          len )
{
    /* Null entry clears comments */

    if ( ! s || len <= 0 )
    {
        fli_safe_free( im->comments );
        im->comments_len = 0;
        return;
    }

    im->comments = fl_realloc( im->comments, im->comments_len + len + 1 );
    strcpy( im->comments + im->comments_len, s );
    im->comments_len += len;
}


/***************************************
 ***************************************/

int
flimage_windowlevel( FL_IMAGE * im,
                     int        level,
                     int        width)
{
    if ( ! im || im->type != FL_IMAGE_GRAY16 )
        return -1;

    im->modified = im->level != level || im->wwidth != width;

    if ( im->modified )
    {
        im->level = level > im->gray_maxval ? im->gray_maxval : level;
        im->wwidth = width;
    }

    return im->modified;
}


/***************************************
 ***************************************/

static int
visual_cue( FL_IMAGE   * im,
            const char * s )
{
    if ( im->completed < 0 )
    {
        /* don't know how long */

        fprintf( stderr, "\r%s", s );
    }
    else if ( im->completed >= 0 && im->completed != im->total )
    {
        fprintf( stderr, "\r%s %3.0f%%(%d of %d)                  ",
                 s, 100.0 * im->completed / ( im->total - 1.0 ),
                 im->completed, im->h );
    }
    else if ( im->completed == im->total )
        fprintf( stderr, "\n%s 100%%(%d of %d)\n", s, im->total, im->total );

    return 0;
}


/***************************************
 ***************************************/

static void
copy_pixels( FL_IMAGE * dim,
             FL_IMAGE * sim )
{
    unsigned int size;

    flimage_getmem( dim );

    switch ( sim->type )
    {
        case FLIMAGE_RGB:
            size = sim->w * sim->h * sizeof **sim->red;
            memcpy( dim->red[ 0 ],   sim->red[ 0 ],   size );
            memcpy( dim->green[ 0 ], sim->green[ 0 ], size );
            memcpy( dim->blue[ 0 ],  sim->blue[ 0 ],  size );
            memcpy( dim->alpha[0 ],  sim->alpha[ 0 ], size );
            break;

        case FLIMAGE_CI:
        case FLIMAGE_MONO:
            size = sim->w * sim->h * sizeof **sim->ci;
            memcpy( dim->ci[ 0 ], sim->ci[ 0 ], size );
            break;

        case FLIMAGE_GRAY:
        case FLIMAGE_GRAY16:
            size = sim->w * sim->h * sizeof **sim->gray;
            memcpy( dim->gray[ 0 ], sim->gray[ 0 ], size );
            break;

        default:
            M_err( "copy_pixel", "Bad type: %d", sim->type );
            break;
    }
}


/***************************************
 ***************************************/

FL_IMAGE *
flimage_dup( FL_IMAGE * sim )
{
    if ( ! sim || ! sim->w || sim->type == FLIMAGE_NONE )
        return NULL;

    return flimage_dup_( sim, 1 );
}


/***************************************
 * duplicate an image, with or without the pixels
 ***************************************/

FL_IMAGE *
flimage_dup_( FL_IMAGE * sim,
              int        pix )
{
    FL_IMAGE *im = flimage_alloc( );
    unsigned int mapsize = sim->map_len * sizeof *sim->red_lut;
    char *infile,
         *outfile;

    if ( ! im )
    {
        flimage_error( sim,"malloc() failed in image_dup()" );
        return 0;
    }

    infile = im->infile;
    outfile = im->outfile;

    memcpy( im, sim, sizeof *im );

    /* reset all pointers */

    im->red = im->green = im->blue = im->alpha = NULL;
    im->red_lut = im->green_lut = im->blue_lut = im->alpha_lut = NULL;
    im->gray = NULL;
    im->ci = NULL;
    im->red16 = im->green16 = im->blue16 = im->alpha16 = NULL;
    im->packed = NULL;
    im->wlut = NULL;
    im->llut[ 0 ] = im->llut[ 1 ] = im->llut[ 2 ] = NULL;
    im->extra_io_info = NULL;
    im->info = NULL;

    flimage_getmem( im );

    im->available_type = im->type;
    im->next = NULL;
    strcpy( im->infile = infile, sim->infile );
    strcpy( im->outfile = outfile, sim->outfile );

    /* copy pixels if requested */

    if ( pix )
        copy_pixels( im, sim );

    if ( mapsize )
    {
        if ( flimage_getcolormap( im ) < 0 )
        {
            flimage_error( im, "Can't alloc colormap" );
            return 0;
        }

        memcpy( im->red_lut,   sim->red_lut,   mapsize );
        memcpy( im->green_lut, sim->green_lut, mapsize );
        memcpy( im->blue_lut,  sim->blue_lut,  mapsize );
        memcpy( im->alpha_lut, sim->alpha_lut, mapsize );
    }

    im->io_spec = NULL;
    if ( sim->spec_size && sim->io_spec )
    {
        im->io_spec = fl_malloc( sim->spec_size );
        memcpy( im->io_spec, sim->io_spec, sim->spec_size );
    }

    /* Reset stuff that's on a per-image basis */

    im->depth = 0;
    im->vclass = 0;
    im->display_type = 0;
    im->ximage = 0;
    im->visual = 0;
    im->pixels = 0;
    im->pixmap = None;
    im->ximage = NULL;
    im->info = 0;
    im->win = None;
    im->gc = im->textgc = im->markergc = None;
    im->text = NULL;
    im->ntext = 0;
    im->marker = 0;
    im->nmarkers = 0;
    im->comments = NULL;
    im->comments_len = 0;

    return im;
}


/***************************************
 ***************************************/

static void
error_message( FL_IMAGE   * im  FL_UNUSED_ARG,
               const char * s )
{
    if ( s && *s )
        M_err( 0, s );
}


/***************************************
 * A short cut for error message generating
 ***************************************/

void
flimage_error( FL_IMAGE   * im,
               const char * fmt,
               ... )
{
    va_list args;
    char buf[ 1024 ];

    buf[ 0 ] = '\0';
    if ( fmt && *fmt )
    {
        va_start( args, fmt );
        fli_vsnprintf( buf, sizeof buf, fmt, args );
        va_end( args );
    }

    im->error_message( im, buf );
}


/***************************************
 ***************************************/

void
flimage_free_rgb( FL_IMAGE * im )
{
    fl_free_matrix( im->red );
    fl_free_matrix( im->green );
    fl_free_matrix( im->blue );
    fl_free_matrix( im->alpha );
    im->red = im->green = im->blue = im->alpha = NULL;
    im->available_type &= ~FL_IMAGE_RGB;
}


/***************************************
 ***************************************/

void
flimage_free_ci( FL_IMAGE * im )
{
    fl_free_matrix( im->ci );
    im->ci = NULL;
    im->available_type = ~ FL_IMAGE_CI;
}


/***************************************
 ***************************************/

void
flimage_free_gray( FL_IMAGE * im )
{
    fl_free_matrix( im->gray );
    im->gray = NULL;
    im->available_type = ~FL_IMAGE_GRAY;
}


/***************************************
 * unpack packed bits into color indeces (0 or 1). len is the length
 * of packed bytes
 ***************************************/

void
unpack_bits( unsigned short * out,
             unsigned char  * in,
             int              len )
{
    unsigned int mask = 0x80;

    for ( ; --len >= 0; out++, mask >>= 1 )
    {
        if ( ! mask )
        {
            in++;
            mask = 0x80;
        }
        *out = ( *in & mask ) != 0;
    }
}


/***************************************
 * pack color index (0 or 1 ) into bytes. len is number of indeces
 ***************************************/

void
pack_bits( unsigned char  * out,
           unsigned short * in,
           int              len)
{
    int k = 0,
        bit = 0;

    for ( k = bit = 0; --len >= 0; in++ )
    {
        k = ( k << 1 ) | *in;
        if ( ++bit == 8 )
        {
            *out++ = k;
            k = bit = 0;
        }
    }

    /* left overs */

    if ( bit )
    {
        k <<= 8 - bit;
        *out++ = k;
    }
}


/***************************************
 * Default supported image formats
 ***************************************/

static void
add_default_formats( void )
{
    if ( ! ppm_added )
    {
        flimage_enable_pnm( );
        flimage_enable_genesis( );
    }

    if ( ! gzip_added )
        flimage_enable_gzip( );
}


/***************************************
 * Given a format, find the corresponding io handler
 ***************************************/

FLIMAGE_IO *
flimage_find_imageIO( const char *fmt )
{
    FLIMAGE_IO *io = flimage_io;

    for ( ; io && io->formal_name; io++ )
    {
        if (    ! strcmp( io->formal_name, fmt )
             || ! strcmp( io->short_name, fmt )
             || ! strcmp( io->extension, fmt ) )
            return io;
    }

    return NULL;
}


/***************************************
 * Annoation IO
 ***************************************/

static int
write_marker( FLIMAGE_MARKER * m,
              FILE           * fp )
{
    int r,
        g,
        b;

    fprintf( fp, "%s %d %d %d %d %d %d %d %d", m->name, m->x, m->y,
             m->w, m->h, m->fill, m->angle, m->thickness, m->style );
    FL_UNPACK( m->color, r, g, b );
    fprintf( fp, " %d %d %d", r, g, b );
    FL_UNPACK( m->bcolor, r, g, b );
    fprintf( fp, " %d %d %d\n", r, g, b );

    return 0;
}


/***************************************
 ***************************************/

static int
read_marker( FLIMAGE_MARKER * m,
             FILE           * fp )
{
    char buf[ 128 ];
    static char name[ 64 ];
    int r,
        g,
        b,
        br,
        bg,
        bb;

    if ( fgets( buf, sizeof buf - 1, fp ) )
        buf[ sizeof buf - 1 ] = '\0';
    else
        return -1;

    if ( sscanf( buf, "%63s %d %d %d %d %d %d %d %d %d %d %d %d %d %d", name,
                 &m->x, &m->y, &m->w, &m->h, &m->fill, &m->angle, &m->thickness,
                 &m->style, &r, &g, &b, &br, &bg, &bb ) == 15 )
    {
        m->name = name;
        m->color = FL_PACK( r, g, b );
        m->bcolor = FL_PACK( br, bg, bb );
        return 0;
    }

    return -1;
}


#define LB '('
#define RB ')'

static FLI_VN_PAIR fonts_vn[ ] =
{
    { FL_NORMAL_STYLE,          "Helvetica"              },
    { FL_ITALIC_STYLE,          "Helvetica-Oblique"      },
    { FL_BOLD_STYLE,            "Helvetica-Bold"         },
    { FL_BOLDITALIC_STYLE,      " Helvetica-BoldOblique" },

    { FL_FIXED_STYLE,           "Courier"                },
    { FL_FIXEDBOLD_STYLE,       "Courier-Bold"           },
    { FL_FIXEDITALIC_STYLE,     "Courier-Oblique"        },
    { FL_FIXEDBOLDITALIC_STYLE, "Courier-BoldOblique"    },

    { FL_TIMES_STYLE,           "Times-Roman"            },
    { FL_TIMESBOLD_STYLE,       "Times-Bold"             },
    { FL_TIMESITALIC_STYLE,     "Times-Oblique"          },
    { FL_TIMESBOLDITALIC_STYLE, "Times-BoldOblique"      },

    { FL_SYMBOL_STYLE,          "Symbol"                 },

    { FL_SHADOW_STYLE,          "Shadow"                 },
    { FL_ENGRAVED_STYLE,        "Engraved"               },
    { FL_ENGRAVED_STYLE,        "Enbossed"               },

    { -1,                       NULL                     }    /* sentinel */
};


/***************************************
 ***************************************/

static const char *
get_font_style( int fstyle )
{
    static char retbuf[ 128 ];
    const char *font_spstyle = "normal";
    int spstyle = fstyle / FL_SHADOW_STYLE;
    int style = fstyle % FL_SHADOW_STYLE;

    strcpy( retbuf, fli_get_vn_name( fonts_vn, style ) );
    if ( spstyle )
        font_spstyle = fli_get_vn_name( fonts_vn, spstyle * FL_SHADOW_STYLE );
    return strcat( strcat( retbuf, " " ), font_spstyle );
}


static FLI_VN_PAIR align_vn[ ] =
{
    { FL_ALIGN_CENTER,       "center"      },
    { FL_ALIGN_TOP,          "top"         },
    { FL_ALIGN_LEFT,         "left"        },
    { FL_ALIGN_RIGHT,        "right"       },
    { FL_ALIGN_LEFT_TOP,     "lefttop"     },
    { FL_ALIGN_RIGHT_TOP,    "righttop"    },
    { FL_ALIGN_LEFT_BOTTOM,  "leftbottom"  },
    { FL_ALIGN_RIGHT_BOTTOM, "rightbottom" },
    { -1,                    NULL          }      /* sentinel */
};


/***************************************
 ***************************************/

static void
write_text( FLIMAGE_TEXT * t,
            FILE         * fp )
{
    int r,
        g,
        b;
    char *p;

    /* output string. */

    putc( LB, fp );
    for ( p = t->str; p && *p; p++ )
    {
        if ( *p == RB )
            putc( '\\', fp );
        putc( *p, fp );
    }
    putc( RB, fp );

    fprintf( fp, " %s %d %d %d %s %d %d", get_font_style( t->style ), t->size,
             t->x, t->y, fli_get_vn_name( align_vn, t->align ), t->angle,
             t->nobk );
    FL_UNPACK( t->color, r, g, b );
    fprintf( fp, " %d %d %d", r, g, b );
    FL_UNPACK( t->bcolor, r, g, b );
    fprintf( fp, " %d %d %d\n", r, g, b );
}


/***************************************
 ***************************************/

static int
read_text( FLIMAGE_TEXT * t,
           FILE *         fp )
{
    char buf[ 1024 ],
         fnt[ 64 ],
         style[ 64 ],
         align[ 64 ];
    static char name[ 512 ];
    int r,
        g,
        b,
        br,
        bg,
        bb;
    char *p  = buf + 1,
         *s  = name,
         *ss = name + sizeof name - 1;

    if ( fgets( buf, sizeof buf - 1, fp ) )
        buf[ sizeof buf - 1 ] = '\0';
    else
        buf[ 0 ] = '\0';

    for ( ; s < ss && *p && ( *p != ')' || *( p - 1 ) == '\\' ); p++ )
        *s++ = *p;
    *s = '\0';

    if ( sscanf( p + 1, "%63s %63s %d %d %d %63s %d %d %d %d %d %d %d %d",
                 fnt, style, &t->size, &t->x, &t->y, align, &t->angle, &t->nobk,
                 &r, &g, &b, &br, &bg, &bb ) == 14 )
    {
        t->str = name;
        t->len = s - name;
        t->style = fli_get_vn_value( fonts_vn, fnt );
        t->style |= fli_get_vn_value( fonts_vn, style );
        t->align = fli_get_vn_value( align_vn, align );
        t->color = FL_PACK( r, g, b );
        t->bcolor = FL_PACK( br, bg, bb );

        return 0;
    }

    return -1;
}


/***************************************
 ***************************************/

static int
skip_line( FILE * fp )
{
    int c;

    if ( ( c = getc( fp ) ) == '#' )
    {
        while ( ( c = getc( fp ) ) != '\n' && c != EOF )
            /* empty */ ;
    }
    else
        ungetc( c, fp );

    return c == '#' && c != EOF;
}


/***************************************
 ***************************************/

#define TEXTVERSION           1
#define MARKERVERSION         1

int
flimage_write_annotation( FL_IMAGE * im )
{
    FILE *fp;
    int i;
    FLIMAGE_MARKER *m;
    FLIMAGE_TEXT *t;

    if ( !im || im->type == FL_IMAGE_NONE )
        return -1;

    fp = im->fpout;

    /* Write markers first */

    if ( im->nmarkers )
    {
        fprintf( fp, "\n###markers %d %d\n", im->nmarkers, MARKERVERSION );
        fprintf( fp, "# name x y w h fill angle thick style r g b r g b\n" );
        m = im->marker;
        for ( i = 0; i < im->nmarkers; i++, m++ )
            write_marker( m, fp );
    }

    if ( im->ntext )
    {
        fprintf( fp, "###text %d %d\n", im->ntext, TEXTVERSION );
        fprintf( fp, "# (s) font style size x y align angle nobk "
                 "r g b r g b\n" );
        t = im->text;
        for ( i = 0; i < im->ntext; i++, t++ )
            write_text( t, fp );
    }

    return 0;
}


/***************************************
 ***************************************/

int
flimage_read_annotation( FL_IMAGE * im )
{
    FILE *fp;
    FLIMAGE_MARKER m;
    FLIMAGE_TEXT t;
    int c,
        done,
        v,
        nmarkers,
        i,
        ntext;
    char buf[ 1024 ];

    if ( ! im || im->type == FL_IMAGE_NONE )
        return -1;

    fp = im->fpin;

    /* Load the markers */

    for ( done = 0; ! done; /* empty */ )
    {
        while ( ( c = getc( fp ) ) != EOF && c != '#' )
            /* empty */ ;
        done = c == EOF;

        if ( fgets( buf, sizeof buf - 1, fp ) )
            buf[ sizeof buf - 1 ] = '\0';
        else
            buf[ 0 ] = '\0';

        if ( strstr( buf, "#marker" ) )
        {
            sscanf( buf, "%*s %d %d", &nmarkers, &v );
            if ( v > MARKERVERSION )
                M_err( "ReadMarker", "wrong version" );
            for ( i = 0; i < nmarkers; i++ )
            {
                while ( skip_line( fp ) )
                    /* empty */ ;
                if ( read_marker( &m, fp ) >= 0 )
                    flimage_add_marker_struct( im, &m );
            }
        }

        if ( strstr( buf, "#text" ) )
        {
            sscanf( buf, "%*s %d %d", &ntext, &v );
            if ( v > TEXTVERSION )
                M_err( "ReadText", "wrong version" );
            for ( i = 0; i < ntext; i++ )
            {
                while ( skip_line( fp ) )
                    /* empty */ ;
                if ( read_text( &t, fp) >= 0 )
                    flimage_add_text_struct( im, &t );
            }
            done = 1;
        }
    }

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
