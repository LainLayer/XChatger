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
 *  Copyright (c) 2000-2002  By T.C. Zhao
 *
 *  TIFF file reader/writer for some tiff files. It is not possible to
 *  develop a tiff reader to handle all possible valid tiffs.
 *
 *  could use some optimization
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "ulib.h"
#include "flimage.h"
#include "flimage_int.h"

#if defined __sun__ && ! defined SYSV 
int fgetc( FILE *stream );
int fputc( int c, FILE *stream );
#endif

#define TIFF_DEBUG    0

static int get_image_info_from_ifd( FL_IMAGE * im );

typedef int ( * ReadIT )( FILE * );

typedef int ( * WriteIT )( int, FILE * );

typedef struct
{
    int    tag_value;
    char * tag_name;
    int    type;
    int  * value;
    int    count;
    int    offset;
    char * svalue;
} TIFFTag;


static TIFFTag *find_tag( int );

typedef struct
{
    int endian;
    int ifd_offset;     /* next ifd location. 0 indicates end */
    int spp;            /* samples per pixel                  */
    int bps[ 4 ];       /* bits per sample                    */
    int curr_pos;       /* current writing location           */
    int next_pos;       /* next   writing location           */
    int ( * read2bytes ) ( FILE * );
    int ( * read4bytes ) ( FILE * );
    int ( * write2bytes ) ( int, FILE * );
    int ( * write4bytes ) ( int, FILE * );
    FL_IMAGE *image;
    ReadIT readit[ 15 ];
    WriteIT writeit[ 15 ];
    int strip_size;     /* strip size in bytes */
    int rowsPerStrip;       /* preferred  */
    int nstrips;
    int *stripOffsets;
    int *stripByteCount;
    int offset_offset;
    int bytecount_offset;
    int max_tags;
} SPEC;

static void initialize_tiff_io( SPEC *,
                                int );

/***************************************
 ***************************************/

static int
TIFF_identify( FILE * fp )
{
    char buf[ 4 ];

    if ( fread( buf, 1, 4, fp ) != 4 )
        return 0;
    rewind( fp );
    return ! strncmp( buf, "II", 2 ) || ! strncmp( buf, "MM", 2 );
}


static int read_tiff_ifd( FILE * fp,
                          SPEC * sp );


/***************************************
 ***************************************/

static int
TIFF_description( FL_IMAGE * im )
{
    FILE *fp = im->fpin;
    SPEC *sp = fl_malloc( sizeof *sp );
    char buf[ 4 ];

    im->io_spec = sp;
    im->spec_size = sizeof *sp;
    sp->image = im;

    if ( fread( buf, 1, 4, fp ) != 4 )
    {
        flimage_error( im, "Failure to read TIFF file" );
        fl_free( sp );
        im->io_spec = NULL;
        im->spec_size = 0;
        return -1;
    }

    sp->endian = buf[ 0 ] == 'M' ? MSBFirst : LSBFirst;

    initialize_tiff_io( sp, sp->endian );

    sp->ifd_offset = sp->read4bytes( fp );

    if ( ! sp->ifd_offset )
    {
        flimage_error( im, "Invalid TIFF: no IFD" );
        fl_free( sp );
        im->io_spec = NULL;
        im->spec_size = 0;
        return -1;
    }

    read_tiff_ifd( fp, sp );

    if ( get_image_info_from_ifd( im ) < 0 )
    {
        fl_free( sp );
        im->io_spec = NULL;
        im->spec_size = 0;
        return -1;
    }

    return 0;
}


static int read_pixels( FL_IMAGE * im );
static int TIFF_next( FL_IMAGE * );
static int load_tiff_colormap( FL_IMAGE * );


/***************************************
 ***************************************/

static int
TIFF_readpixels( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;

    load_tiff_colormap( im );

    if ( sp->ifd_offset )
        im->next_frame = TIFF_next;
    else
        im->next_frame = 0;

    im->more = sp->ifd_offset != 0;

    return read_pixels(im);
}


/***************************************
 ***************************************/

static int
TIFF_next( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;

    read_tiff_ifd( im->fpin, sp );

    if ( get_image_info_from_ifd( im ) < 0 )
    {
        flimage_error( im, "Can't get image info" );
        M_err( "Next", "Can't get image info" );
        return -1;
    }

    flimage_getmem( im );

    return TIFF_readpixels( im );
}


static int write_ifd( FL_IMAGE *,
                      SPEC * );
static int write_pixels( FL_IMAGE *,
                         SPEC * );


/***************************************
 ***************************************/

static int
machine_endian( void )
{
    static unsigned short a = 0x1234;
    static unsigned char *c = ( unsigned char * ) &a;

    return c[ 0 ] == 0x12 ? MSBFirst : LSBFirst;
}


#define MaxStripSize 32767       /* max strip size */


/***************************************
 ***************************************/

static int
TIFF_write( FL_IMAGE * image )
{
    FILE *fp = image->fpout;
    FL_IMAGE *im = image;
    int err,
        t;
    SPEC *sp;

    /* we do not touch im->io_spec. Use this local copy */

    sp = fl_calloc( 1, sizeof *sp );

    t = ( im->w * im->h ) / ( im->type == FL_IMAGE_MONO ? 8 : 1 );

    /* We always write StripByteCount at offset. Need to make
       sure we'll have more than one strips */

    if ( t <= MaxStripSize )
         sp->strip_size = ( t + 1 ) / 2;
    else
         sp->strip_size = MaxStripSize;

    sp->endian = machine_endian( );

    initialize_tiff_io( sp, sp->endian );

    fwrite( sp->endian == LSBFirst ? "II" : "MM", 1, 2, fp );
    sp->write2bytes( 42, fp );
    sp->next_pos = 4;
    sp->max_tags = 15;
    sp->write4bytes( sp->next_pos += 4, fp );   /* ifd location */

    for ( err = 0; ! err && im; im = im->next )
    {
        sp->curr_pos = sp->next_pos;
        sp->next_pos += sp->max_tags * 12;
        im->fpout = image->fpout;
        fseek( fp, sp->curr_pos, SEEK_SET );
        err =    write_ifd( im, sp ) < 0
              || write_pixels( im, sp ) < 0;

        /* update the IFD location */

        fseek( fp, sp->ifd_offset, SEEK_SET );
        sp->write4bytes( im->next ? sp->next_pos : 0, fp );
    }

    fl_free( sp->stripByteCount );
    fl_free( sp->stripOffsets );
    fl_free( sp );

    return 0;
}


/***************************************
 ***************************************/

void
flimage_enable_tiff(void)
{
    flimage_add_format( "Tag Image File Format", "tiff", "tif",
                        FL_IMAGE_FLEX,
                        TIFF_identify,
                        TIFF_description,
                        TIFF_readpixels,
                        TIFF_write);
}


/*************************************************************************
 * TIFF tags
 *************************************************************************/

static int junkBuffer;

#define NV(a,t)  {a,#a,t,&junkBuffer,0,0,0}

#define SubFileType       254
#define ReduceImage          1
#define    Page                 2
#define    Mask                 4
#define ImageWidth        256
#define ImageHeight       257
#define BitsPerSample     258
#define Compression       259
#define   Uncompressed          1
#define   LZW                   5
#define   JPEG                  6
#define   PackBits              32773
#define PhotometricI      262
#define   PhotoBW0White         0
#define   PhotoBW0Black         1
#define   PhotoRGB              2
#define   PhotoPalette          3
#define   PhotoTransMask        4
#define   PhotoCMYK             5
#define   PhotoYCbCr            6
#define DocumentName      269
#define Description       270
#define StripOffsets      273
#define Orientation       274
#define TopLeft                1
#define TopRight               2
#define RightTop               6
#define SamplesPerPixel   277
#define RowsPerStrip      278
#define StripByteCount    279
#define MinSampleValue    280
#define MaxSampleValue    281
#define PlannarConfig     284
#define   RGBRGB              1
#define   RRGGBB              2
#define GrayResponse      291
#define ColorResponse     301
#define ColorMap          320

/* tiff support types   */

enum
{
    kUByte    = 1,
    ASCII     = 2,
    kUShort   = 3,
    kULong    = 4,
    RATIONAL  = 5,
    SBYTE     = 6,
    kShort    = 8,
    kLong     = 9,
    SRATIONAL = 10,
    kFloat    = 11,
    kDouble   = 12
};

/* type is used for writing only */

TIFFTag interestedTags[ ] =
{
    NV( ImageWidth,      kUShort ),
    NV( ImageHeight,     kUShort ),
    NV( BitsPerSample,   kUShort ),
    NV( Compression,     kUShort ),
    NV( SamplesPerPixel, kUShort ),
    NV( PhotometricI,    kUShort ),
    NV( DocumentName,    ASCII   ),
    NV( Description,     ASCII   ),
    NV( StripOffsets,    kULong  ),
    NV( Orientation,     kUShort ),
    NV( RowsPerStrip,    kULong  ),
    NV( StripByteCount,  kULong  ),
    NV( MinSampleValue,  kUShort ),
    NV( MaxSampleValue,  kUShort ),
    NV( PlannarConfig,   kUShort ),
    NV( GrayResponse,    kUShort ),
    NV( ColorResponse,   kUShort ),
    NV( ColorMap,        kUShort ),
    /* sentinel */

    NV( 0,               kShort  )
};

static TIFFTag *

/***************************************
 ***************************************/

find_tag( int val )
{
    TIFFTag *tag;

    /* if tags are more than about 20, binary search may be better */

    for ( tag = interestedTags; tag->tag_value && tag->tag_value != val; tag++ )
        /* empty */ ;

    return tag->tag_value ? tag : 0;    /* &stag; */
}


/***************************************
 * convert tag value to image value
 ***************************************/

static int
get_image_info_from_ifd( FL_IMAGE * im )
{
    TIFFTag *tag;
    SPEC *sp = im->io_spec;
    int i;

    if ( ! ( tag = find_tag( ImageWidth ) ) )
    {
        flimage_error( im, "Bad ImageWidth tag" );
        return -1;
    }
    im->w = tag->value[ 0 ];

    if ( ! ( tag = find_tag( ImageHeight ) ) )
    {
        flimage_error( im, "Bad ImageLength tag" );
        return -1; 
    }
    im->h = tag->value[ 0 ];

    if ( im->w <= 0 || im->h <= 0 )
    {
        fprintf( stderr, "bad image dimension: %d %d\n", im->w, im->h );
        return -1;
    }

    if ( ! ( sp->spp = find_tag( SamplesPerPixel )->value[ 0 ] ) )
        sp->spp = 1;

    tag = find_tag( BitsPerSample );

    for ( i = 0; i < sp->spp; i++ )
    {
        if ( ( sp->bps[ i ] = tag->value[ i ] ) <= 0 )
        {
            flimage_error( im, "bad bps: %d\n", sp->bps[ i ] );
            return -1;
        }
    }

    tag = find_tag( PhotometricI );

    switch ( tag->value[ 0 ] )
    {
        case PhotoBW0White :
        case PhotoBW0Black :
            im->type = sp->bps[ 0 ] == 1 ? FL_IMAGE_MONO :
                       ( sp->bps[ 0 ] <= 8 ? FL_IMAGE_GRAY : FL_IMAGE_GRAY16 );
            break;

        case PhotoRGB :
            im->type = FL_IMAGE_RGB;
            break;

        case PhotoPalette :
            im->type = FL_IMAGE_CI;
            if ( ( im->map_len = find_tag( ColorMap )->count / 3 ) <= 0 )
            {
                flimage_error( im, "Colormap is missing for PhotoPalette" );
                return -1;
            }
            break;

        default:
            flimage_error( im, "Unhandled photometricI %d\n", 0 );
            break;
    }

    if ( im->type == FL_IMAGE_GRAY16 && ( tag = find_tag( MaxSampleValue ) ) )
        im->gray_maxval = tag->value[ 0 ];
    else
        im->gray_maxval = ( 1 << sp->bps[ 0 ] ) - 1;

    return 0;
}

static int typeSize[ 13 ];


/***************************************
 * this need to be called everytime to avoid re-entrant problems
 ***************************************/

static void
initialize_tiff_io( SPEC * sp,
                    int    endian )
{
    if ( ! typeSize[ kUByte ] )
    {
        /* initialize the typeSize                       */

        typeSize[ kUByte ] = typeSize[ SBYTE ] = 1;
        typeSize[ ASCII ] = 1;
        typeSize[ kShort ] = typeSize[ kUShort ] = 2;
        typeSize[ kLong ] = typeSize[ kULong ] = 4;
        typeSize[ RATIONAL ] = typeSize[ SRATIONAL ] = 8;
        typeSize[ kFloat ] = 4;
        typeSize[ kDouble ] = 8;
    }

    /* initialize the functions that reads various types */

    sp->readit[ kUByte ] = sp->readit[SBYTE] = fgetc;
    sp->writeit[ kUByte ] = sp->writeit[SBYTE] = fputc;
    sp->readit[ ASCII ] = fgetc;
    sp->writeit[ ASCII ] = fputc;

    sp->readit[ kShort ] = endian == MSBFirst ? fli_fget2MSBF : fli_fget2LSBF;
    sp->readit[ kUShort ] = endian == MSBFirst ? fli_fget2MSBF : fli_fget2LSBF;
    sp->writeit[ kUShort ] = endian == MSBFirst ? fli_fput2MSBF : fli_fput2LSBF;
    sp->writeit[ kShort ] = endian == MSBFirst ? fli_fput2MSBF : fli_fput2LSBF;

    sp->readit[ kULong ] = endian == MSBFirst ? fli_fget4MSBF : fli_fget4LSBF;
    sp->readit[ kLong ] = endian == MSBFirst ? fli_fget4MSBF : fli_fget4LSBF;
    sp->writeit[ kULong ] = endian == MSBFirst ? fli_fput4MSBF : fli_fput4LSBF;
    sp->writeit[ kLong ] = endian == MSBFirst ? fli_fput4MSBF : fli_fput4LSBF;

    sp->read2bytes = sp->readit[ kShort ];
    sp->read4bytes = sp->readit[ kLong ];
    sp->write2bytes = sp->writeit[ kShort ];
    sp->write4bytes = sp->writeit[ kLong ];
}


/***************************************
 ***************************************/

static void
read_tag( FILE * fp,
          long   offset,
          SPEC * sp )
{
    int tag_val,
        count,
        type,
        nbyte;
    TIFFTag *tag;

    fseek( fp, offset, SEEK_SET );

    tag_val = sp->read2bytes( fp );
    if ( ! ( tag = find_tag( tag_val ) ) )
    {
#if TIFF_DEBUG
        fprintf( stderr, "Unsupported tag 0x%x(%d)\n", tag_val, tag_val );
#endif
        return;
    }

    tag->type = type = sp->read2bytes( fp );
    tag->count = count = sp->read4bytes( fp );

    if (    type < 0
         || type > kDouble
         || ( nbyte = count * typeSize[ type ] ) <= 0 )
    {
        flimage_error( sp->image, "BadType (%d) or count (%d)\n", type, count );
        M_err( "ReadTag", "BadType (%d) or count (%d)\n", type, count );
        return;
    }

    if ( tag->value && tag->value != &junkBuffer )
        fl_free( tag->value );

    if ( ! ( tag->value = fl_malloc( sizeof *tag->value * tag->count ) ) )
    {
        flimage_error( sp->image, "Can't allocate %d tag value buffer",
                       tag->count );
        return;
    }

    if ( nbyte > 4 )
    {
        tag->offset = sp->read4bytes( fp );
        tag->value[ 0 ] = tag->offset;
        fseek( fp, tag->offset, SEEK_SET );
    }

    /* We read the colormap seperately */

    if ( tag->tag_value != ColorMap )
    {
        int i;

        for ( i = 0; i < count; i++)
            tag->value[ i ] = ( sp->readit[ type ] )( fp );
    }
}


/***************************************
 ***************************************/

static int
read_tiff_ifd( FILE * fp,
               SPEC * sp )
{
    int num_tags,
        offset,
        i;
    TIFFTag *tag;

    fseek( fp, sp->ifd_offset, SEEK_SET );

    num_tags = sp->read2bytes( fp );

    for ( offset = sp->ifd_offset + 2, i = 0; i < num_tags; i++ )
    {
        read_tag( fp, offset, sp );
        offset += 12;
    }

    fseek( fp, sp->ifd_offset + num_tags * 12 + 2, SEEK_SET );
    sp->ifd_offset = sp->read4bytes( fp );

    /* validate the tags (sort of) */

    if ( ! ( tag = find_tag( BitsPerSample ) )->count )
        return -1;

    if (    tag->value[ 0 ] != 1
         && tag->value[ 0 ] !=  2
         && tag->value[ 0 ] !=  4
         && tag->value[ 0 ] !=  8
         && tag->value[ 0 ] != 16 )
    {
        M_err( "ReadIFD", "Unsupported bitsPerSample %d", tag->value[ 0 ] );
        return -1;
    }

#if TIFF_DEBUG
    for ( tag = interestedTags; tag->tag_value; tag++ )
    {
        if ( tag->count )
            fprintf( stderr, "%s\t count=%2d\t val=%d\n",
                     tag->tag_name, tag->count,
                     tag->value ? tag->value[ 0 ] : 0 );
    }
    fprintf( stderr, "nextIFD at %d\n", sp->ifd_offset );
#endif

    return 0;
}


/***************************************
 * parameter endian is the endian the input data is in
 ***************************************/

static unsigned short *
convert2( unsigned short * sbuf,
          int              nbytes,
          int              endian )
{
    int nshort = nbytes / 2,
        i,
        j;
    unsigned char *buf = ( unsigned char * ) sbuf;

    if ( nbytes & 1 )
    {
        fprintf( stderr, "Error: Bad ByteCount %d\n", nbytes );
        return sbuf;
    }

    if ( endian == machine_endian( ) )
        return sbuf;

    if ( endian == MSBFirst )
    {
        for ( i = j = 0; i < nshort; i++, j += 2 )
            sbuf[ i ] = ( buf[ j ] << 8 ) | buf[ j + 1 ];
    }
    else
    {
        for ( i = j = 0; i < nshort; i++, j += 2 )
            sbuf[ i ] = buf[ j ] | ( buf[ j + 1 ] << 8 );
    }

    return sbuf;
}



/***************************************
 ***************************************/

static int
read_pixels( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;
    int nstrips,
        val,
        err,
        i,
        j,
        strip,
        row,
        bytecount;
    TIFFTag *tag,
            *bytecountTag,
            *rowsPerStripTag;
    unsigned char *tmpbuffer,
                  *tmp;
    int compress,
        rps,
        bpl;
    unsigned short *sbuf;
    FILE *fp = im->fpin;

    rowsPerStripTag = find_tag( RowsPerStrip );

    if ( ( val = rowsPerStripTag->value[ 0 ] ) <= 0 )
    {
        flimage_error( im, "Bad RowsPerStrip tag" );
        return -1;
    }

    if (    ( compress = find_tag( Compression )->value[ 0 ] )
         && compress != Uncompressed )
    {
        flimage_error( im, "can't handled compressed TIF" );
        return -1;
    }

    nstrips = ( im->h + val - 1 ) / val;
    bytecountTag = find_tag( StripByteCount );

    if ( nstrips != bytecountTag->count )
    {
        flimage_error( im, "Inconsistent in number of strips" );
        return -1;
    }

    bpl = ( im->w * sp->spp * find_tag( BitsPerSample )->value[ 0 ] + 7 ) / 8;
    rps = rowsPerStripTag->value[ 0 ];
    tag = find_tag( StripOffsets );

    if ( ! ( tmpbuffer = fl_malloc( bytecountTag->value[ 0 ] + 4 ) ) )
    {
        flimage_error( im, "Can't allocate strip buffer (%d bytes)",
                       bytecountTag->value[ 0 ] );
        return -1;
    }

    for ( row = strip = err = 0; !err && strip < nstrips; strip++ )
    {
#if TIFF_DEBUG
        fprintf( stderr, "strip%d at %d\n", strip, tag->value[ strip ] );
#endif
        fseek( fp, tag->value[strip], SEEK_SET );

        bytecount = bytecountTag->value[ strip ];

        if ( ( err = ( fread( tmpbuffer, 1, bytecount, fp ) == 0 ) ) )
            M_err( "ReadStrip", "Error reading ByteCount" );

        /* TODO: de-compress the tmpbuffer */

        tmp = tmpbuffer;
        if ( sp->spp == 1 )
        {
            if ( sp->bps[ 0 ] == 8 )
            {
                unsigned short **ctmp = FL_IsCI( im->type ) ? im->ci : im->gray;

                for ( i = 0; row < im->h && i < rps; i++, row++ )
                {
                    for ( j = 0; j < im->w; j++ )
                        ctmp[ row ][ j ] = tmp[ j ];
                    tmp += im->w;
                }
            }
            else if ( sp->bps[ 0 ] > 8 )
            {
                unsigned short **ctmp = FL_IsCI( im->type ) ? im->ci : im->gray;

                /* TIFF SPEC did not define 16 bps, and seems libtiff always
                   uses MSB. */

                sbuf = convert2( ( void * ) tmp, bytecount,
                                 MSBFirst /* sp->endian */ );

                for ( i = 0; row < im->h && i < rps; i++, row++ )
                {
                    memcpy( ctmp[ row ], sbuf, bpl );
                    sbuf += im->w;
                }
            }
            else if ( sp->bps[ 0 ] == 4 )
            {
                for ( i = 0; row < im->h && i < rps; i++, row++, tmp += bpl )
                {
                    for ( j = 0; j < im->w - 1; tmp++ )
                    {
                        im->ci[ row ][ j++ ] = ( *tmp >> 4 ) & 0x0f;
                        im->ci[ row ][ j++ ] = *tmp & 0x0f;
                    }

                    im->ci[ row ][ j++ ] = ( *tmp >> 4 ) & 0x0f;

                    if ( j < im->w )
                        im->ci[ row ][ j ] = *tmp & 0x0f;
                }
            }
            else if ( sp->bps[0] == 1 )
            {
                for ( i = 0; row < im->h && i < rps; i++, row++, tmp += bpl )
                    unpack_bits( im->ci[ row ], tmp, im->w );
            }
            else
            {
                M_err( "ReadStrip", "Unhandled bpp=%d\n", sp->bps[ 0 ] );
                return -1;
            }
        }
        else if ( sp->spp == 3 || sp->spp == 4 )
        {
            int config = find_tag( PlannarConfig )->value[ 0 ];

            if ( sp->bps[ 0 ] == 8 )
            {
                if ( config == RGBRGB )
                {
                    for ( i = 0; row < im->h && i < rps; i++, row++ )
                    {
                        for ( j = 0; j < im->w; j++, tmp += sp->spp )
                        {
                            im->red[   row ][ j ] = *tmp;
                            im->green[ row ][ j ] = *( tmp + 1 );
                            im->blue[  row ][ j ] = *( tmp + 2 );
                        }
                    }
                }
                else if ( config == RRGGBB )
                {
                    for ( i = 0; row < im->h && i < rps; i++, row++ )
                    {
                        for ( j = 0; j < im->w; j++, tmp++ )
                            im->red[ row ][ j ] = *tmp;

                        for ( j = 0; j < im->w; j++, tmp++ ) ;
                        im->green[ row ][ j ] = *tmp;

                        for ( j = 0; j < im->w; j++, tmp++ )
                            im->blue[ row ][ j ] = *tmp;
                    }
                }
                else
                {
                    M_err( "ReadRGB", "Unknown PlannarConfig %d", config );
                    return -1;
                }
            }
            else
            {
                flimage_error( im, "Unsupported bps=%d", sp->bps[ 0 ] );
                return -1;
            }
        }
        else
        {
            flimage_error( im, "spp=%d unsupported", sp->spp );
            return -1;
        }
    }

    fl_free( tmpbuffer );

    if ( find_tag(BitsPerSample)->value[ 0 ] == 1 )
    {
        int b = find_tag( PhotometricI )->value[0] != PhotoBW0Black;
        im->red_lut[ b ] = im->green_lut[ b ] = im->blue_lut[ b ] = 0;
        im->red_lut[ ! b ] = im->green_lut[ ! b ] = im->blue_lut[ ! b ] =
                                                                      FL_PCMAX;
    }

    /* TODO: post-processing gamma, color/gray response etc */

    if ( err )
        flimage_error( im, "ErrorReading" );

    return err ? -1 : 0;
}


/***************************************
 ***************************************/

static int
load_tiff_colormap( FL_IMAGE * im )
{
    FILE *fp = im->fpin;
    TIFFTag *tag = find_tag( ColorMap );
    SPEC *sp = im->io_spec;

    if ( ! tag->count )
        return 0;

    if ( im->map_len != tag->count / 3 )
    {
        flimage_error( im, "Bad Colormap" );
        return -1;
    }

    if ( im->map_len > 0 )
    {
        int i;

        fseek( fp, tag->offset, SEEK_SET );

        for ( i = 0; i < im->map_len; i++ )
            im->red_lut[ i ] = sp->readit[ kUShort ]( fp ) >> 8;

        for ( i = 0; i < im->map_len; i++ )
            im->green_lut[ i ] = sp->readit[ kUShort ]( fp ) >> 8;

        for ( i = 0; i < im->map_len; i++ )
            im->blue_lut[ i ] = sp->readit[ kUShort ]( fp ) >> 8;
    }

    return 0;
}


/***************************************
 ***************************************/

static void
write_tiff_colormap( FL_IMAGE * im,
                     SPEC     * sp,
                     int        len )
{
    FILE *fp = im->fpout;
    int i;

    sp->write2bytes( ColorMap, fp );
    sp->write2bytes( kUShort, fp );
    sp->write4bytes( len * 3, fp );
    sp->write4bytes( sp->next_pos, fp );
    fseek( fp, sp->next_pos, SEEK_SET );

    /* red */

    for ( i = 0; i < im->map_len; i++ )
        sp->write2bytes( im->red_lut[ i ] << 8 | 0xff, fp );

    for ( ; i < len; i++ )
        sp->write2bytes( 0, fp );

    /* green */

    for ( i = 0; i < im->map_len; i++ )
        sp->write2bytes( im->green_lut[ i ] << 8 | 0xff, fp );

    for ( ; i < len; i++ )
        sp->write2bytes( 0, fp );

    /* blue */

    for ( i = 0; i < im->map_len; i++ )
        sp->write2bytes( im->blue_lut[ i ] << 8 | 0xff, fp );

    for ( ; i < len; i++ )
        sp->write2bytes( 0, fp );
}



/***************************************
 ***************************************/

static void
write_tag( FILE * fp,
           SPEC * sp,
           int    tag_val,
           int    count,
           int  * value,
           int  * n )
{
    TIFFTag *tag;
    int i;

    tag = find_tag( tag_val );
    sp->write2bytes( tag_val, fp );
    sp->write2bytes( tag->type, fp );
    sp->write4bytes( count, fp );

    if ( typeSize[ tag->type ] * count > 4 )
    {
        sp->write4bytes( sp->next_pos, fp );
        fseek( fp, sp->next_pos, SEEK_SET );

        if ( tag->type == ASCII || tag->type == SBYTE || tag->type == kUByte )
        {
            char *p = ( char * ) value;

            for ( i = 0; i < count; i++ )
                sp->writeit[ tag->type ]( p[ i ], fp );
        }
        else
            for ( i = 0; i < count; i++ )
                sp->writeit[ tag->type ]( value[ i ], fp );

        sp->next_pos += count * typeSize[ tag->type ];
    }
    else
        for ( i = 0; i < count; i++ )
            sp->writeit[ tag->type ]( value[ i ], fp );

    ( *n )++;

    /* tag is always 12bytes long */

    fseek( fp, sp->curr_pos += 12, SEEK_SET );
}


/***************************************
 ***************************************/

static int
write_ifd( FL_IMAGE * im,
           SPEC     * sp )
{
    FILE *fp = im->fpout;
    int num_tags,
        itag,
        nstrips,
        bpl;
    int compression = Uncompressed,
                      photometric;
    int plannarConfig = RGBRGB,
        orientation = TopLeft;
    char doc[ 256 ],
         *p;
    static const char *desc = "TIFF by XForms V1.0.91";
    int minval = -1,
        maxval = -1;

    num_tags = 13;
    sp->spp = 1;

    /* strip path info */

    if ( ! *strcpy( doc,
                    ( p = strrchr( im->outfile, '/' ) ) ? p + 1 : im->outfile ) )
        num_tags--;

    if ( im->type == FL_IMAGE_CI )
    {
        num_tags++;
        sp->bps[ 0 ] = 8;
        photometric = PhotoPalette;
    }
    else if ( im->type == FL_IMAGE_MONO )
    {
        sp->bps[ 0 ] = 1;
        photometric = im->red_lut[ 0 ] > im->red_lut[ 1 ] ?
                      PhotoBW0White : PhotoBW0Black;
    }
    else if ( im->type == FL_IMAGE_GRAY || im->type == FL_IMAGE_GRAY16 )
    {
        num_tags += im->type == FL_IMAGE_GRAY ? 0 : 2;
        sp->bps[ 0 ] = im->type == FL_IMAGE_GRAY ? 8 : 16;
        minval = 0;
        maxval = im->gray_maxval;
        photometric = PhotoBW0Black;
    }
    else if ( im->type == FL_IMAGE_RGB )
    {
        sp->bps[ 0 ] = sp->bps[ 1 ] = sp->bps[ 2 ] = 8;
        sp->spp = 3;
        photometric = PhotoRGB;
    }

    bpl = ( im->w * sp->spp * sp->bps[ 0 ] + 7 ) / 8;
    sp->rowsPerStrip = sp->strip_size / bpl;
    nstrips = ( im->h + sp->rowsPerStrip - 1 ) / sp->rowsPerStrip;

    if ( sp->nstrips < nstrips )
    {
        sp->stripOffsets = fl_calloc( sizeof( int ), nstrips );
        sp->stripByteCount = fl_calloc( sizeof( int ), nstrips );
    }
    sp->nstrips = nstrips;

    /* write the tags */

    if ( num_tags > sp->max_tags )
    {
        M_err( "WriteTIFFIFD", "InternalError: run out of tag space" );
        return -1;
    }

    sp->write2bytes( num_tags, fp );
    sp->curr_pos += 2;

    itag = 0;
    write_tag( fp, sp, ImageWidth, 1, &im->w, &itag );
    write_tag( fp, sp, ImageHeight, 1, &im->h, &itag );
    write_tag( fp, sp, BitsPerSample, sp->spp, sp->bps, &itag );
    write_tag( fp, sp, Compression, 1, &compression, &itag );
    write_tag( fp, sp, PhotometricI, 1, &photometric, &itag );

    if ( doc[ 0 ] )
        write_tag( fp, sp, DocumentName, strlen( doc ), ( int * ) doc, &itag );

    write_tag( fp, sp, Description, strlen(desc), (int *) desc, &itag );
    sp->offset_offset = sp->next_pos;

    write_tag( fp, sp, StripOffsets, nstrips, sp->stripOffsets, &itag );
    write_tag( fp, sp, Orientation, 1, &orientation, &itag );
    write_tag( fp, sp, SamplesPerPixel, 1, &sp->spp, &itag );
    write_tag( fp, sp, RowsPerStrip, 1, &sp->rowsPerStrip, &itag );

    sp->bytecount_offset = sp->next_pos;
    write_tag( fp, sp, StripByteCount, nstrips, sp->stripByteCount, &itag );

    if ( im->type == FL_IMAGE_GRAY16 )
    {
        write_tag( fp, sp, MinSampleValue, 1, &minval, &itag );
        write_tag( fp, sp, MaxSampleValue, 1, &maxval, &itag );
    }

    write_tag( fp, sp, PlannarConfig, 1, &plannarConfig, &itag );

    if ( im->type == FL_IMAGE_CI )
    {
        itag++;

        /* we always write 8bit palette image */

        write_tiff_colormap( im, sp, 256 );
        sp->next_pos += 256 * 3 * typeSize[ kShort ];
        fseek( fp, sp->curr_pos += 12, SEEK_SET );
    }

    if ( itag != num_tags )
    {
        M_err( "WriteTIFFIFD", "wrong number of tags. wrote %d expect %d",
               itag, num_tags );
        return -1;
    }

    /* we do not know where next IFD is at, but need to reserve space */

    sp->ifd_offset = sp->curr_pos;
    sp->write4bytes( 0, fp );
    sp->curr_pos += sp->curr_pos;

    return ( feof( fp ) || ferror( fp ) ) ? -1 : 0;
}


/***************************************
 ***************************************/

static int
write_pixels( FL_IMAGE * im,
              SPEC     * sp )
{
    FILE *fp = im->fpout;
    int row,
        i,
        j,
        k,
        err,
        eof,
        strip;
    int bytesPerRow;
    unsigned char *tmpbuf;

    fseek( fp, 0, SEEK_END );
    eof = ftell( fp );

    bytesPerRow = ( im->w * sp->spp * sp->bps[ 0 ] + 7 ) / 8;

    for ( i = 0; i < sp->nstrips; i++ )
    {
        sp->stripByteCount[ i ] = sp->rowsPerStrip * bytesPerRow;
        sp->stripOffsets[ i ]   = eof + i * sp->stripByteCount[ i ];
    }

    /* fix up the last strip, otherwise we need to pad the output */

    sp->stripByteCount[ sp->nstrips - 1 ] =
                  bytesPerRow
                * ( im->h - sp->rowsPerStrip * ( sp->nstrips - 1 ) );

    fseek( fp, sp->offset_offset, SEEK_SET );

    for ( i = 0; i < sp->nstrips; i++ )
        sp->write4bytes( sp->stripOffsets[ i ], fp );

    /* if compression, we won't know the bytecount until after writing */

    fseek( fp, sp->bytecount_offset, SEEK_SET );

    for ( i = 0; i < sp->nstrips; i++ )
        sp->write4bytes( sp->stripByteCount[i], fp );

    if ( ! ( tmpbuf = fl_malloc( bytesPerRow + 4 ) ) )
    {
        flimage_error( im, "Can't allocate buffer (%d bytes)", bytesPerRow );
        return -1;
    }

    for ( row = strip = err = 0; !err && strip < sp->nstrips; strip++ )
    {
        fseek( fp, sp->stripOffsets[ strip ], SEEK_SET );

        if ( im->type == FL_IMAGE_CI )
        {
            for ( j = 0; row < im->h && j < sp->rowsPerStrip; j++, row++ )
            {
                for ( k = 0; k < im->w; k++ )
                    tmpbuf[ k ] = im->ci[ row ][ k];

                err =
                 fwrite( tmpbuf, 1, bytesPerRow, fp ) != ( size_t ) bytesPerRow;
            }
        }
        else if ( im->type == FL_IMAGE_GRAY )
        {
            for ( j = 0; row < im->h && j < sp->rowsPerStrip; j++, row++ )
            {
                for ( k = 0; k < im->w; k++ )
                    tmpbuf[ k ] = im->gray[ row ][ k ];
                err =
                 fwrite( tmpbuf, 1, bytesPerRow, fp ) != ( size_t ) bytesPerRow;
            }
        }
        else if ( im->type == FL_IMAGE_GRAY16 )
        {
            for ( j = 0; row < im->h && j < sp->rowsPerStrip; j++, row++ )
            {
                /* tiff spec 6.0 did not define 16 bits samples. libtiff
                   seems to use MSB always for this. We do the same */

                for ( k = 0; k < im->w; k++ )
                    fli_fput2MSBF( im->gray[row][k], fp );

                /* sp->write2bytes(im->gray[row][k], fp); */
            }
        }
        else if ( im->type == FL_IMAGE_MONO )
        {
            for ( j = 0; row < im->h && j < sp->rowsPerStrip; j++, row++ )
            {
                pack_bits( tmpbuf, im->ci[row], im->w );
                err = fwrite( tmpbuf, 1, bytesPerRow, fp )
                                                 != ( size_t ) bytesPerRow;
            }
        }
        else if ( im->type == FL_IMAGE_RGB )
        {
            /* always write RGBRGB */

            for ( j = 0; row < im->h && j < sp->rowsPerStrip; j++, row++ )
            {
                for ( k = 0; k < im->w; k++ )
                {
                    tmpbuf[ 0 ] = im->red[   row ][ k ];
                    tmpbuf[ 1 ] = im->green[ row ][ k ];
                    tmpbuf[ 2 ] = im->blue[  row ][ k ];
                    err = fwrite( tmpbuf, 1, 3, fp ) != 3;
                }
            }
        }
        else
        {
            flimage_error( im, "unhandled type: %s",
                           flimage_type_name( im->type ) );
            return -1;
        }
    }

    fl_free( tmpbuf );
    fseek( fp, 0, SEEK_END );
    sp->next_pos = ftell( fp );

    return err ? -1 : 0;
}


/***************************************
 ***************************************/

#if 0
static int
PackBitsDecode( char * input,
                char * output,
                int    inlen,
                int    outlen )
{
    int b,
        n;

    for ( n = 0; n < outlen; )
    {
        b = *input;
        if ( b >= 128 )
            b -= 256;

        if ( b == -128 )
            ;

        if (b < 0)
        {
            b = -b + 1;
            input++;
        }
    }
}
#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
