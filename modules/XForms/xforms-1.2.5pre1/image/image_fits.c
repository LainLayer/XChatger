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
 *  Copyright (c) 1993, 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *   NASA/OST Flexble Image Transport Sysmtem suport.
 *   Basic FITS (principle HUD)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"
#include "ulib.h"
#include <stdlib.h>
#include <string.h>


#define FITS_DEBUG         0

/* number of bits of gray image to generate for float/double FITS */

static unsigned int fits_bit = 12;


/***************************************
 ***************************************/

int
flimage_set_fits_bits( int bits )
{
    int old = fits_bit;

    if ( bits > 0 && bits < 16 )
    {
        fits_bit = bits;
        return old;
    }

	return - old;
}


static int dogray = 1;              /* how to do fits        */
static float nan_replace = 0.0;     /* what to do about NaNs  */
static float blank_replace = 0.0;   /* what to do about NaNs  */
static int little_endian = -1;

#define RECORD_LEN    2880

typedef double FLOAT64;

typedef float FLOAT32;

typedef union
{
    FLOAT32 val;
    unsigned char uc[ 4 ];
} FLOAT_UNION;

#define ISNAN( n, p ) ( ( p = n ), ( p != n ) )


/***************************************
 ***************************************/

static int
FITS_identify( FILE * fp )
{
    char buf[ 6 ];

    if ( fread( buf, 1, 6, fp ) != 6 )
        return 0;
    rewind( fp );
    return ! strncmp( buf, "SIMPLE", 6 );
}


#define MAXDIM     4
#define MAXLEN    73

typedef struct
{
    double bzero;                       /* convert from data to physical   */
    double bscale;                      /* convert from data to physical   */
    double dmin;                        /* mininum physical quantity       */
    double dmax;                        /* maximum physical quantity       */
    double offset;                      /* scale data directly to pixel    */
    double scale;                       /* scale data directly to pixel    */
    double cdelta[ MAXDIM ];
    int    simple;                      /* only deal simple (basic) fits   */
    int    xtension;                    /* if have extension               */
    int    bpp;                         /* pixel size/array data size      */
    int    ndim;                        /* number of dimensions in array   */
    int    gcount;
    int    pcount;
    int    blank;
    int    has_blank;
    int    nframe;
    int    dim[ MAXDIM ];               /* dimensions                      */
    char   label[ MAXDIM ][ MAXLEN ];   /* name of each dimension          */
    char   bunit[ MAXLEN ];             /* unit name of the quantities     */
    char   xtname[ MAXLEN ];            /* if and what extension           */
} SPEC;

#define bad_hdu( h )  ( ! h->simple || ( h->ndim == 0 && ! h->xtname[ 0 ] ) )
#define Bad_bpp( p )  ( p != 8 && p != 16 && abs( p ) != 32 && p != - 64 )
#define bad_dim( h )  (    h->ndim < 0                                       \
                        || ( h->ndim>MAXDIM && h->dim[ MAXDIM - 1 ] != 1 ) )


/***************************************
 ***************************************/

static void
detect_endian( void )
{
    FLOAT_UNION U;

    U.val = 1.0;
    little_endian = ( U.uc[ 3 ] == 0x3f );
}


/***************************************
 ***************************************/

static void
init_fits( SPEC * sp )
{
    if ( little_endian < 0 )
    detect_endian( );

    sp->bpp = sp->ndim = -1;
    sp->bscale = 1.0;
    sp->gcount = sp->pcount = 1;
    sp->nframe = 1;
}



/***************************************
 ***************************************/

static char **
FITS_header_info( const void * p )
{
    const SPEC *h = p;
    static char hbuf[ 15 ][ 80 ];
    static char *buf[ 15 ];
    int i,
        j;

    for ( i = 0; i < 15; i++ )
        buf[ i ] = hbuf[ i ];

    i = 0;
    sprintf( buf[ i++ ], "SIMPLE\t= %c", h->simple == 1 ? 'Y' : 'N' );
    sprintf( buf[ i++ ], "NAXIS\t= %d", h->ndim);

    for ( j = 0; j < h->ndim; j++ )
        sprintf( buf[ i++ ], "   NAXIS%d=%d\t%s", j + 1, h->dim[ j ],
                 h->label[j] ? h->label[ j ] : "" );

    sprintf( buf[ i++ ], "PSIZE\t= %d", h->bpp );
    sprintf( buf[ i++ ], "BSCALE\t= %g", h->bscale );
    sprintf( buf[ i++ ], "BZERO\t= %g", h->bzero );
    sprintf( buf[ i++ ], "DMIN\t= %g", h->dmin );
    sprintf( buf[ i++ ], "DMAX\t= %g", h->dmax );
    sprintf( buf[ i++ ], "BUNIT\t=%s", h->bunit );
    sprintf( buf[ i++ ], "BLANK\t=%d", h->blank );

    buf[ i ] = 0;

    return buf;
}


/***************************************
 ***************************************/

static void
generate_fits_header_info( FL_IMAGE * im )
{
    SPEC *h = im->io_spec;
    char **q;

    if ( ! ( im->info = fl_malloc( 1024 ) ) )
        return;

    for ( im->info[ 0 ] = '\0', q = FITS_header_info( h ); *q; q++ )
        strcat( strcat( im->info, *q ),"\n" );
}


#if FITS_DEBUG

static int verbose = 4;


/***************************************
 ***************************************/

static void
echo_FITS_header( SPEC * h )
{
    char **q;

    if ( verbose <= ML_INFO1 )
        return;

    for ( q = FITS_header_info( h ); *q; q++ )
        fprintf( stderr, "%s\n", *q );
}

#endif


static int parse_fits_header( FILE *,
                              SPEC *,
                              FL_IMAGE * );

#define LBSIZE     12
#define LBFONT     0        /* default courier */
#define LBCOL      0        /* black           */

static int FITS_next( FL_IMAGE * );


/***************************************
 ***************************************/

static int
FITS_description( FL_IMAGE * im )
{
    SPEC *sp = fl_calloc( 1, sizeof *sp );

    init_fits( sp );
    im->io_spec = sp;
    im->spec_size = sizeof *sp;

    if ( parse_fits_header( im->fpin, sp, im ) < 0 )
        return -1;

    if ( feof( im->fpin ) )
        return -1;

    /* sanity check */

    if ( ! sp->simple || bad_dim( sp ) )
    {
        flimage_error( im, "FITS: %s unsupported type--%sSIMPLE, NAXIS=%d",
                       im->infile, sp->simple ? "" : "Not ", sp->ndim );
        return -1;
    }

    if ( Bad_bpp( sp->bpp ) )
    {
        flimage_error( im, "FITS:%s unsupported pixelsize %d",
                       im->infile, sp->bpp );
        return -1;
    }

    if ( sp->ndim == 0 )
    {
        flimage_error( im, "FITS: unsupported %s",
                       sp->xtname[ 0 ] ? sp->xtname : "null image" );
        return -1;
    }

    /* now we have something to work with */

    im->w = sp->dim[ 0 ];
    im->h = sp->dim[ 1 ] ? sp->dim[ 1 ] : 1;    /* handle 1-dim data */

    if ( dogray )
    {
        if ( FL_abs( sp->bpp ) > 8 )
        {
            im->type = FL_IMAGE_GRAY16;
            im->gray_maxval = ( 1 << fits_bit ) - 1;
        }
        else
        {
            im->type = FL_IMAGE_GRAY;
            im->gray_maxval = ( 1 << 8 ) - 1;
        }
    }
    else
    {
        int i;

        /* fake a graymap */

        im->type = FL_IMAGE_CI;
        im->map_len = 256;
        flimage_getcolormap( im );

        for ( i = 0; i < 256; i++ )
            im->red_lut[ i ] = im->green_lut[ i ] = im->blue_lut[ i ] = i;
    }

    im->more = sp->ndim > 2 && sp->dim[ 2 ] > 1;
    im->next_frame = FITS_next;

    /* label the axis if available */

    if ( sp->label[ 0 ][ 0 ] )
    {
        flimage_add_text( im, sp->label[ 0 ], strlen( sp->label[ 0 ] ),
                          LBFONT, LBSIZE,
                          FL_PACK(FL_PCMAX, FL_PCMAX, 0),
                          FL_PACK(0, FL_PCMAX, FL_PCMAX),
                          1, im->w / 3, im->h + LBSIZE, 0);
#if 0
        img_add_mark( im, "Arrow", 5, -5, 54, 85, 2, 0, 0 );
#endif
    }

    if ( sp->label[ 1 ][ 0 ] )
    {
        flimage_add_text( im, sp->label[ 1 ], strlen( sp->label[ 1 ] ),
                          LBFONT, LBSIZE,
                          FL_PACK(FL_PCMAX, FL_PCMAX, 0),
                          FL_PACK(0, FL_PCMAX, FL_PCMAX),
                          1, im->w + 4, im->h / 2, 90 );
#if 0
        img_add_mark( im, "Arrow", -5, 5, 54, 85, 2, 900, 0 );
#endif
    }

    return 0;
}

/********************************************************************
 * Read fits header for keyword and value pairs. more lenient than
 * the standard demands
 ********************************************************************/

static char *comments[ ] =
{
    "AUTHOR",
    "COMMENTS",
    "OBJECT",
    "DATE",
    "DATE_OBS",
    "INSTRUME",
    "TELESCOP",
    "ORIGIN",
     NULL };


/***************************************
 ***************************************/

static int
is_comments( const char * key )
{
    char **q = comments;

    while ( *q )
        if ( strcmp( key, *q++ ) == 0 )
            return 1;

    return 0;
}


/***************************************
 ***************************************/

static int
parse_fits_header( FILE     * fp,
                   SPEC     * h,
                   FL_IMAGE * im )
{
    char buf[ 90 ],
         key[ 90 ],
         val[ 90 ];
    int done,
        i;

 doextension:
    done = 0;
    do
    {
        key[ 0 ] = buf[ 0 ] = val[ 0 ] = '\0';

        /* each rec is 80 characters long */

        if ( ! fgets( buf, 81, fp ) )
            buf[ 0 ] = '\0';
        buf[ 79 ] = '\n';
        buf[ 80 ] = '\0';
        sscanf( buf, "%[A-Z0-9]%*[ =]%s", key, val );
        fli_space_de( val );
        if ( key[ 0 ] )
            flimage_add_comments( im, buf, 80 );

#if FITS_DEBUG
        M_err( "FITS", "key=%s_\t\t val=%s_", key, val );
#endif

        if ( strcmp( key, "SIMPLE" ) == 0 )
            h->simple = val[ 0 ] == 'T';
        else if ( strcmp(key, "BITPIX" ) == 0 )
            h->bpp = atoi( val );
        else if ( strcmp( key, "NAXIS" ) == 0 )
            h->ndim = atoi( val );
        else if ( strcmp( key, "BUNIT" ) == 0 )
            strcpy( h->bunit, val );
        else if ( strcmp( key, "BSCALE" ) == 0 )
            h->bscale = atof( val );
        else if ( strcmp( key, "BZERO" ) == 0 )
            h->bzero = atof( val );
        else if ( strcmp( key, "DATAMIN" ) == 0 )
            h->dmin = atof( val );
        else if ( strcmp( key, "DATAMAX" ) == 0 )
            h->dmax = atof( val );
        else if ( strcmp( key, "PCOUNT" ) == 0 )
            h->pcount = atoi( val );
        else if ( strcmp( key, "GCOUNT" ) == 0 )
            h->gcount = atoi( val );
        else if ( strcmp( key, "BLANK" ) == 0 )
        {
            h->blank = atoi( val );
            h->has_blank = 1;
        }
        else if ( strcmp(key, "XTENSION" ) == 0 )
            strcpy( h->xtname, val );
        else if (strcmp( key, "EXTEND" ) == 0 )
            h->xtension = val[ 0 ] == 'T';
        else if ( strncmp( buf, "END ", 4 ) == 0 )
            done = 1;
        else if ( is_comments( key ) )
            flimage_add_comments( im, buf, 80 );

        for ( i = 1; i <= MAXDIM; i++ )
        {
            sprintf( buf, "NAXIS%d", i );
            if ( strcmp(buf, key ) == 0 )
                h->dim[ i - 1 ] = atoi( val );

            sprintf( buf, "CTYPE%d", i );
            if ( strcmp( buf, key ) == 0 )
                strcpy( h->label[ i - 1 ], fli_space_de( val ) );

            sprintf( buf, "TTYPE%d", i );
            if ( strcmp( buf, key ) == 0 )
                strcpy( h->label[ i - 1 ], fli_space_de( val ) );

            sprintf( buf, "CDELT%d", i );
            if (strcmp( buf, key ) == 0 )
                h->cdelta[ i - 1 ] = atoi( val );
        }
    } while ( ! feof( fp ) && ! done );

    /* skip padding */

    while ( ( i = getc( fp ) ) == ' ' || i == '\n' )
        /* empty */ ;

    if ( i != EOF )
        ungetc( i, fp );

    /* if empty data array && extension, try to do the extension */

    if ( ! feof( fp ) && h->ndim == 0 && h->xtension && ! h->xtname[ 0 ] )
        goto doextension;

    /* keep trying, until we get an extension we can handle */

    if ( ! feof( fp ) && h->xtname[ 0 ] && ! strcmp( h->xtname, "'IMAGE") == 0 )
    {
        long curpos = ftell( fp );
        int total;

        for ( total = 1, i = 0; i < h->ndim; i++ )
            total *= h->dim[ i ];
        total = ( total * h->bpp ) / 8;

        /* round */

        total = ( ( total + RECORD_LEN - 1 ) / RECORD_LEN ) * RECORD_LEN;
        fseek( fp, curpos + total, SEEK_SET );

        goto doextension;
    }

    if ( strcmp( h->xtname, "'IMAGE" ) == 0 )
    {
        im->visual_cue( im, "Found IMAGE extension" );
        flimage_add_comments( im, "IMAGE EXTENSION", 16 );
    }

#if FITS_DEBUG
    echo_FITS_header( h );
#endif

    if( im->setup->header_info )
        generate_fits_header_info( im );

    return 0;
}


#define SWAP4( i, o )     do {                   \
                              o[ 0 ] = i[ 3 ];   \
                              o[ 1 ] = i[ 2 ];   \
                              o[ 2 ] = i[ 1 ];   \
                              o[ 3 ] = i[ 0 ];   \
                          } while( 0 )

#define SWAP8( i, o )     do {                   \
                              o[ 0 ] = i[ 7 ];   \
                              o[ 1 ] = i[ 6 ];   \
                              o[ 2 ] = i[ 5 ];   \
                              o[ 3 ] = i[ 4 ];   \
                              o[ 4 ] = i[ 3 ];   \
                              o[ 5 ] = i[ 2 ];   \
                              o[ 6 ] = i[ 1 ];   \
                              o[ 7 ] = i[ 0 ];   \
                          } while ( 0 )


/***************************************
 * Assuming IEEE-745 floating point native
 ***************************************/

static int
FITS_load( FL_IMAGE * im )
{
    unsigned short *ci = FL_IsGray( im->type ) ? im->gray[ 0 ] : im->ci[ 0 ];
    SPEC *sp = im->io_spec;
    FLOAT64  offset,
             scale,
             dmin,
             dmax,
            *dval,
             tmp64;
    FILE *fp = im->fpin;
    int  i,
         j,
         n,
         k,
         byte_per_pix,
         has_minmax,
        *ival,
         err;
    unsigned char *c,
                   uc[ 8 ];
    short *sval;
    FLOAT32 *fval,
             tmp32;
    void **vals;

    dmin = 1.0e30;
    dmax = -1.0e30;
    has_minmax = sp->dmax != sp->dmin;

#if FITS_DEBUG
    M_err( "fits_load", "sp->dmax=%g sp->dmin=%g", sp->dmax, sp->dmin );
#endif

    /* read the data */

    byte_per_pix = FL_abs( sp->bpp ) / 8;
    if ( ! ( vals = fl_get_matrix( im->h, im->w, byte_per_pix ) ) )
    {
        im->error_message( im, "Can't get memory for FITS" );
        return -1;
    }

    for ( err = 0, i = im->h - 1; !err && i >= 0; i--, im->completed++ )
    {
        if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            im->visual_cue( im, "Reading FITS" );

        k = im->h - 1 - i;

        if ( ( err = ( fread( c = vals[ k ], byte_per_pix, im->w, fp ) !=
                                                          ( size_t ) im->w ) ) )
            im->error_message( im, "Error reading FITS" );

        /* now do data conversion to MSBF order */

        switch ( sp->bpp )
        {
            case 32 :
                for ( ival = vals[k], j = 0; j < im->w; j++, c += 4 )
                {
                    ival[ j ] =   ( c[ 0 ] << 24 )
                                | ( c[ 1 ] << 16 )
                                | ( c[ 2 ] <<  8 )
                                | c[ 3 ];

                    if ( sp->has_blank && ival[ j ] == sp->blank )
                        ival[ j ] = blank_replace;
                }

                if ( ! has_minmax )
                {
                    for ( j = 0; j < im->w; j++ )
                        if ( ival[ j ] < dmin )
                            dmin = ival[ j ];
                        else if ( ival[ j ] > dmax )
                            dmax = ival[ j ];
                }
                break;

            case 16 :
                for ( sval = vals[ k ], j = 0; j < im->w; j++, c += 2 )
                {
                    sval[ j ] = ( c[ 0 ] << 8 ) | c[ 1 ];
                    if ( sp->has_blank && sval[ j ] == sp->blank )
                        sval[ j ] = blank_replace;
                }

                if ( ! has_minmax )
                {
                    for ( j = 0; j < im->w; j++ )
                        if ( sval[ j ] < dmin )
                            dmin = sval[ j ];
                        else if ( sval[ j ] > dmax )
                            dmax = sval[ j ];
                }
                break;

            case 8 :
                if ( ! has_minmax )
                {
                    for ( j = 0; j < im->w; j++ )
                        if ( c[ j ] < dmin )
                            dmin = c[ j ];
                        else if ( c[ j ] > dmax )
                            dmax = c[ j ];
                }
                break;

            case -32 :
                for ( fval = vals[ k ], j = 0; j < im->w; j++, c += 4 )
                {
                    if ( little_endian )
                    {
                        /* Using
                            fval[ j ] = * ( FLOAT32 * ) uc;
                           results in type-punning warning, so instead: */
                        memcpy( fval + j, uc, 4 );
                    }

                    if ( ISNAN( fval[ j ], tmp32 ) )
                        fval[ j ] = nan_replace;
                }

                if ( ! has_minmax )
                {
                    for ( j = 0; j < im->w; j++ )
                        if ( fval[ j ] < dmin )
                            dmin = fval[ j ];
                        else if ( fval[ j ] > dmax )
                            dmax = fval[ j ];
                }
                break;

            case -64 :
                for ( dval = vals[ k ], j = 0; j < im->w; j++, c += 8 )
                {
                    if ( little_endian )
                    {
                        SWAP8( c, uc );
                        /* Using
                            dval[ j ] = * ( FLOAT64 * ) uc;
                           results in type-punning warning, so instead: */
                        memcpy( dval + j, uc, 8 );
                    }

                    if ( ISNAN( dval[ j ], tmp64 ) )
                        dval[ j ] = nan_replace;
                }

                if ( ! has_minmax )
                {
                    for ( j = 0; j < im->w; j++ )
                        if ( dval[ j ] < dmin )
                            dmin = dval[ j ];
                        else if ( dval[ j ] > dmax )
                            dmax = dval[ j ];
                }
                break;
        }
    }

    if ( ! has_minmax )
    {
        sp->dmin = sp->bzero + dmin * sp->bscale;
        sp->dmax = sp->bzero + dmax * sp->bscale;
    }

    /* now the overall offset and scale for physical data */

    scale = im->gray_maxval / ( sp->dmax - sp->dmin );
    offset = -sp->dmin * scale;

    /* figure in the raw to physcal transform */

    offset = offset + sp->bzero * scale;
    scale = sp->bscale * scale;

    /* reverse transform */

    im->poffset = -offset / scale;
    im->pscale = 1.0 / scale;
    im->pmin = sp->dmin;
    im->pmax = sp->dmax;
    im->xdist_scale = sp->cdelta[ 0 ];
    im->ydist_scale = sp->cdelta[ 1 ];

    /* remap data into pixels */

    if ( sp->bpp == 8 )
        for ( c = vals[ 0 ], n = im->w * im->h; --n > 0; )
            ci[ n ] = offset + c[ n ] * scale;
    else if ( sp->bpp == 16 )
        for ( sval = vals[ 0 ], n = im->w * im->h; --n > 0; )
            ci[ n ] = offset + sval[ n ] * scale;
    else if ( sp->bpp == 32 )
        for ( ival = vals[ 0 ], n = im->w * im->h; --n > 0; )
            ci[ n ] = offset + ival[ n ] * scale;
    else if ( sp->bpp == -32 )
        for ( fval = vals[ 0 ], n = im->w * im->h; --n > 0; )
            ci[ n ] = offset + fval[ n ] * scale;
    else if ( sp->bpp == -64 )
        for ( dval = vals[ 0 ], n = im->w * im->h; --n > 0; )
            ci[ n ] = offset + dval[ n ] * scale;

    fl_free_matrix( vals );

    return im->completed >= im->h / 2 ? 1 : -1;
}


/***************************************
 ***************************************/

static void
dump_space( FILE * fp,
            int n )
{
    while ( --n >= 0 )
    putc( ' ', fp );
}


/***************************************
 ***************************************/

static int
FITS_dump( FL_IMAGE * im )
{
    FILE *fp = im->fpout;
    unsigned short *ras;
    int n = 0,
        bits;

    bits = im->type == FL_IMAGE_GRAY ? 8 : 16;
    ras = im->gray[ 0 ];

    /* write a brief header */

    dump_space( fp, 80 - fprintf( fp, "SIMPLE  = T " ) );
    dump_space( fp, 80 - fprintf( fp, "BITPIX  = %d ", bits ) );
    dump_space( fp, 80 - fprintf( fp, "NAXIS   = 2" ) );
    dump_space( fp, 80 - fprintf( fp, "NAXIS1  = %d", im->w ) );
    dump_space( fp, 80 - fprintf( fp, "NAXIS2  = %d", im->h ) );
    dump_space( fp, 80 - fprintf( fp, "END "));
    dump_space( fp, RECORD_LEN - 80 * 6 );

    if ( bits == 8 )
        for ( n = im->w * im->h; --n >= 0; ras++ )
            putc( *ras & 0xff, fp );
    else
        for ( n = im->w * im->h; --n >= 0; ras++ )
            fli_fput2MSBF( *ras, fp );

    return fflush( fp );
}


/***************************************
 ***************************************/

static int
FITS_next( FL_IMAGE * im )
{
    int status;
    SPEC *sp = im->io_spec;

    sp->nframe++;

#if FITS_DEBUG
    M_err( "FITS_next", "loading %d ", sp->nframe );
#endif

    status = FITS_load( im );
    im->more = status >= 0 && ! ( feof( im->fpin ) || ferror( im->fpin ) );
    im->more = im->more && sp->nframe < sp->dim[ 2 ];
    return status;
}


/***************************************
 ***************************************/

void
flimage_enable_fits( void )
{
    flimage_add_format( "NASA/NOST FITS", "fits", "fits",
                        FL_IMAGE_GRAY | FL_IMAGE_GRAY16,
                        FITS_identify,
                        FITS_description,
                        FITS_load,
                        FITS_dump );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
