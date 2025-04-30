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
 *  Copyright (c) 1998-2002  By T.C. Zhao
 *  All rights reserved.
 *
 *  but genesis format. Eventually dicom will
 *  be supported
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"

#define IMG_MAGIC       0x494d4746

typedef struct
{
    int magic;
    int hdr_len;
    int width;
    int height;
    int depth;
    int compress;
    int windoww;
    int windowl;
} SPEC;


/***************************************
 ***************************************/

static int
GENESIS_identify( FILE * fp )
{
    char buf[ 4 ];

    if ( fread( buf, 1, 4, fp ) == 4 )
        return 0;
    rewind( fp );
    return ! strncmp( buf, "IMGF", 4 );
}


/***************************************
 ***************************************/

static int
GENESIS_description( FL_IMAGE * im )
{
    SPEC *sp = fl_calloc( 1, sizeof *sp );
    FILE *fp = im->fpin;

    im->io_spec = sp;
    im->spec_size = sizeof *sp;

    rewind( fp );
    sp->magic    = fli_fget4MSBF( fp );
    sp->hdr_len  = fli_fget4MSBF( fp );
    sp->width    = fli_fget4MSBF( fp );
    sp->height   = fli_fget4MSBF( fp );
    sp->depth    = fli_fget4MSBF( fp );
    sp->compress = fli_fget4MSBF( fp );
    sp->windoww  = fli_fget4MSBF( fp );
    sp->windowl  = fli_fget4MSBF( fp );

    if ( sp->depth < 8 || sp->compress != 1 )
        return -1;

    im->type = sp->depth == 8 ? FL_IMAGE_GRAY : FL_IMAGE_GRAY16;
    im->gray_maxval = ( 1 << sp->depth ) - 1;
    im->w = sp->width;
    im->h = sp->height;

    return 0;
}


/***************************************
 * convert MSBF
 ***************************************/

static void
convert_msbf( unsigned short * pixels,
              int              npixels )
{
    unsigned short *p = pixels,
                   *ps = p + npixels;
    unsigned char *c = ( unsigned char * ) p;

    for ( ; p < ps; p++, c += 2 )
        *p = ( c[ 0 ] << 8 ) | c[ 1 ];
}


/***************************************
 ***************************************/

static int
GENESIS_load( FL_IMAGE * im )
{
    FILE *fp = im->fpin;
    SPEC *sp = im->io_spec;

    fseek( fp, sp->hdr_len, SEEK_SET );
    if ( fread( im->gray[ 0 ], sp->depth / 8, im->w * im->h, fp )
                                                 != ( size_t ) im->w * im->h )
        convert_msbf( im->gray[ 0 ], im->w * im->h );

    return 0;
}


/***************************************
 ***************************************/

void
flimage_enable_genesis( void )
{
    flimage_add_format( "GE Genesis", "genesis", "ge",
                        FL_IMAGE_GRAY16 | FL_IMAGE_GRAY,
                        GENESIS_identify,
                        GENESIS_description,
                        GENESIS_load,
                        0 );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
