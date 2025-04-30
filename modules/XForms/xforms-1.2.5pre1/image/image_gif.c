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
 *  Copyright (c) 1993, 1998-2002  By T.C. Zhao
 *  All rights reserved.
 *
 * BUGS: delay & input not handled
 *
 * "The Graphics Interchange Format(c) is the Copyright property of
 *  CompuServ Incorporated. GIF(sm) is a Service Mark property of
 *  CompuServ Incorporated.
 *
 *   Signature
 *   screen descriptor
 *   global map
 *   image descriptor   --- 1
 *   raster             --- 2
 *   terminator
 *
 *  1 & 2 can be repeated.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"

#define IMAGESEP      0x2C  /* ',' */


/***************************************
 ***************************************/

static int
GIF_identify( FILE * fp )
{
    char buf[ 6 ];

    if ( fread( buf, 1, 6, fp ) != 6 )
        return 0;
    rewind( fp );
    return ! strncmp( buf, "GIFa", 4 );
}


static int read_descriptor_block( FL_IMAGE * im );
static int skip_extension( FILE * fp,
                           FL_IMAGE * );
static void read_map( FL_IMAGE * );


/* plain text extension */

typedef struct
{
    char str[ 512 ];
    int  x,
         y;
    int cw,
        ch;
    int tw,
        th;
    int tran;
    int bc,
        tc;
} GIFTEXT;

/* graphics control extension */

typedef struct
{
    int tran;
    int delay;
    int input;
    int tran_col;
} GIFGCNTL;

#define MAXGIFTEXT 5

typedef struct
{
    int      interlace;
    int      lsx,
             lsy;
    int      bkcolor;
    int      aspect;
    int      cur_total;
    int      globalmap;
    GIFGCNTL gc;
    int      ctext;
    GIFTEXT  giftext[ MAXGIFTEXT ];
} SPEC;

static int GIF_next( FL_IMAGE * );


/***************************************
 ***************************************/

static int
GIF_description( FL_IMAGE * im )
{
    unsigned char buf[ 15 ];
    FILE *fp = im->fpin;
    SPEC *sp = fl_calloc( 1, sizeof *sp );

    im->io_spec = sp;
    im->spec_size = sizeof *sp;

    im->next_frame = GIF_next;
    sp->gc.tran = 0;

    /* identify should've already checked signature. */

    if (    fread( buf, 1, 6, fp ) != 6
         || fread( buf, 1, 7, fp ) != 7 )
    {
        flimage_error( im, "%s: error while reading gif file", im->infile );
        return -1;
    }

    sp->lsx = buf[ 0 ] + ( buf[ 1 ] << 8 );
    sp->lsy = buf[ 2 ] + ( buf[ 3 ] << 8 );

    sp->globalmap = buf[ 4 ] & 0x80;
    im->map_len = 1 << ( 1 + ( buf[ 4 ] & 0x07 ) );
    flimage_getcolormap( im );
    sp->bkcolor = buf[ 5 ];
    sp->aspect = buf[ 6 ] ?
                 ( int ) ( 1000.0 * ( buf[ 6 ] + 15 ) / 64.0 ) : 1000;

    /* err= buf[4] & 0x08; */

    if ( sp->globalmap )
        read_map( im );

    return read_descriptor_block( im );
}


/***************************************
 ***************************************/

static void
read_map( FL_IMAGE * im )
{
    int i;

    for ( i = 0; i < im->map_len; i++ )
    {
        im->red_lut[   i ] = getc( im->fpin );
        im->green_lut[ i ] = getc( im->fpin );
        im->blue_lut[  i ] = getc( im->fpin );
    }
}


/***************************************
 ***************************************/

static void
write_map( FL_IMAGE * im,
           int        n )
{
    int i;

    for ( i = 0; i < im->map_len; i++ )
    {
        putc( im->red_lut[   i ], im->fpout );
        putc( im->green_lut[ i ], im->fpout );
        putc( im->blue_lut[  i ], im->fpout );
    }

    for ( ; i < n; i++ )
    {
        putc( 0, im->fpout );
        putc( 0, im->fpout );
        putc( 0, im->fpout );
    }
}


/***************************************
 ***************************************/

static void
generate_header_info( FL_IMAGE *im )
{
   SPEC *sp = im->io_spec;
   char buf[ 128 ];

   if ( ! im->info && ! ( im->info = fl_malloc( 1024 ) ) )
       return;

   sprintf( im->info, "Size=(%d x %d)\n", im->w, im->h );
   sprintf( buf,"Colors=%d\nGlobalmap=%d\n", im->map_len, sp->globalmap );
   strcat( im->info,buf );
   sprintf( buf,"Aspect=%d\nInterlace=%d\n", sp->aspect, sp->interlace );
   strcat( im->info, buf );
   sprintf( buf,"Offset=(%d %d)\n", im->wx, im->wy );
   strcat( im->info, buf );
}


/***************************************
 ***************************************/

static int
read_descriptor_block( FL_IMAGE * im )
{
    int local_map,
        inbyte;
    FILE *fp = im->fpin;
    SPEC *sp = im->io_spec;

    /* Read the extension if any, and do nothing about it until get the image
       separator */

    if ( skip_extension( fp, im ) != IMAGESEP )
    {
        flimage_error( im, "%s: no separator or BadBlockMarker", im->infile );
        return -1;
    }

    /* offset relative to lsx and lsy */

    im->wx = fli_fget2LSBF( fp );
    im->wy = fli_fget2LSBF( fp );

    /* True image size */

    im->w = fli_fget2LSBF( fp );
    im->h = fli_fget2LSBF( fp );

    if ( sp->lsx < im->w || sp->lsy < im->h )
    {
        M_info( "", "Bad screen description. LX=%d W=%d LY=%d H=%d",
                sp->lsx, im->w, sp->lsy, im->h );
        sp->lsx = im->w;
        sp->lsy = im->h;
    }

    inbyte = getc( fp );
    sp->interlace = ( inbyte & 0x40 ) != 0;
    local_map = ( inbyte & 0x80 );

    if ( ! sp->globalmap && !local_map )
    {
        M_err( "GIFDescriptor", "%s: No ColorMap", im->infile );
        /* return -1; *//* might want to continue */
    }

    /* If local map, replace the global map */

    if ( local_map )
    {
        local_map = ( inbyte & 0x07 ) + 1;
        im->map_len = 1 << local_map;
        flimage_getcolormap( im );
        read_map( im );
    }

    /* Handle transparency */

    if ( sp->gc.tran && sp->gc.tran_col < im->map_len )
        im->tran_index = sp->gc.tran_col;

    if ( im->setup->header_info )
        generate_header_info( im );

    return 0;
}


#define Badfread( a, b, c, d )    ( fread( a, b, c, d ) != ( c ) )
#define Badfwrite( a, b, c, d )   ( fwrite( a, b, c, d ) != ( c ) )


/***************************************
 ***************************************/

static void
convert_gif_text( FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;
    GIFTEXT *p = sp->giftext,
            *ps = p + sp->ctext;
    unsigned int tcol,
                 bcol;
    int x,
        y;
    int fsize;

    while ( p < ps )
    {
        int tc = p->tc,
            bc = p->bc;

        if ( ! p->str[ 0 ] )
            continue;

        /* gif text size is given in pixels, convert to point. 1pixel = 0.75pt
           for a typical screen */

        if ( ( fsize = ( int ) ( FL_min( p->cw, p->ch ) * 0.75 ) ) < 6 )
            fsize = 6;
        else if ( fsize > 24 )
            fsize = 24;

        /* convert text position to image based */

        x = p->x - im->wx;
        y = p->y - im->wy;

        tcol = FL_PACK3( im->red_lut[ tc ], im->green_lut[ tc ],
                         im->blue_lut[ tc ] );
        bcol = FL_PACK3( im->red_lut[ bc ], im->green_lut[ bc ],
                         im->blue_lut[ bc ] );

        flimage_add_text( im, p->str, strlen( p->str ), 0, fsize, tcol, bcol,
                          ! p->tran, x, y, 0 );
        p++;
    }
}


/******************* local functions ******************/

static int readextension( FILE *,
                          FL_IMAGE * );
static int next_lineno( int,
                        int,
                        int );
static int process_lzw_code( FL_IMAGE *,
                             int );
static void outputline( FL_IMAGE *,
                        unsigned char * );


/****************** decoder variables ******************/

static const unsigned int gif_codemask[ ] =
{
    0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f,
    0x003f, 0x007f, 0x00ff, 0x01ff, 0x03ff, 0x07ff, 0x0fff
};


/***************************************
 * ouptut line simply copies one scanline at a time to the master
 * image structure, taking into account the possibility of
 * interlacing
 ***************************************/

static void
outputline( FL_IMAGE      * im,
            unsigned char * line )
{
    unsigned short *po;
    unsigned char *pi = line;
    SPEC *sp = im->io_spec;
    static int lines;
    int k;

    if ( sp->cur_total == 0 )   /* first entry */
        lines = 0;

    /* figure out the real row  number if interlace */

    k = next_lineno( lines, im->h, sp->interlace );

    sp->cur_total += im->w;

    /* stop to avoid buffer overrun if k is bad */

    if ( k >= im->h )
        return;

    for ( po = im->ci[ k ], line += im->w; pi < line; )
        *po++ = *pi++;

    im->completed = ++lines;
    if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
        im->visual_cue( im, "Reading GIF" );
}


/***************************************
 * Get a single data block
 ***************************************/

static int
getblock( FILE * fp,
          char * buf )
{
    int count;

    if ( ( count = getc( fp ) ) != EOF && count != 0 )
        count = fread( buf, 1, count, fp );
    return count;
}


#define EXTENSION     0x21  /* '!'  introducer  */
#define GIFEXT_PT     0x01  /* plain text       */
#define GIFEXT_APP    0xFF  /* application      */
#define GIFEXT_GC     0xF9  /* graphics control */
#define GIFEXT_COM    0xFE  /* comment          */
#define TRAILER       0x3b


/***************************************
 *  As long as we are not doing the extension, print it out to stderr
 ***************************************/

static int
readextension( FILE     * fp,
               FL_IMAGE * im )
{
    SPEC *sp = im->io_spec;
    int count = 0,
        label;
    char buf[ 258 ];
    const char *f = "GIF_ext";
    GIFTEXT *t = sp->giftext + sp->ctext;

    label = getc( fp );

    switch ( label )
    {
        case GIFEXT_PT :        /* plain text extension */
            M_info( 0, "%s: PlainText Extension", im->infile );
            if ( getc( fp ) != 12 )
            {
                flimage_error( im, "%s: bad PlainText extension", im->infile );
                return EOF;
            }

            t->x  = fli_fget2LSBF( fp );    /* left wrt left edge of ls  */
            t->y  = fli_fget2LSBF( fp );
            t->tw = fli_fget2LSBF( fp );    /* total width  */
            t->th = fli_fget2LSBF( fp );    /* total width  */
            t->cw = fgetc( fp );    /* cell width   */
            t->ch = fgetc( fp );    /* cell height  */
            t->tc = fgetc( fp );    /* text color   */
            t->bc = fgetc( fp );    /* bk color     */
            t->tran = sp->gc.tran;

            t->str[ 0 ] = '\0';
            while ( ( count = getblock( fp, buf ) ) != 0 && count != EOF )
            {
                buf[ count ] = '\0';
                M_info( 0, buf );
                if ( strlen( t->str ) + count > sizeof t->str )
                    count = sizeof t->str - strlen( t->str ) - 1;
                strncat( t->str, buf, count );
            }
            sp->ctext++;
            break;

        case GIFEXT_COM :       /* a comment extension */
            M_info( 0, "%s:Comment Extension", im->infile );
            while ( ( count = getblock( fp, buf ) ) != 0 && count != EOF )
            {
                buf[ count ] = '\0';
                flimage_add_comments( im, buf, count );
            }
            break;

        case GIFEXT_GC :        /* graphics control     */
            M_info( 0, "%s:GraphicsControl extension", im->infile );
            while ( ( count = getblock( fp, buf ) ) != 0 && count != EOF )
            {
                sp->gc.tran = buf[ 0 ] & 1;
                sp->gc.input = buf[ 0 ] & 2;
                sp->gc.delay = 10 * ( buf[ 0 ] + ( buf[ 1 ] << 8 ) );
                if ( sp->gc.tran )
                    sp->gc.tran_col = buf[ 3 ];
            }
            break;

        case GIFEXT_APP :       /* application extension */
            M_info( 0, "%s:ApplicationExtension", im->infile );
            if ( getc( fp ) != 11 ) /* block length */
                M_warn( "GifExt", "wrong block length" );
            if ( fread( buf, 1, 8, fp ) != 8 )
                return EOF;
            buf[ 8 ] = '\0';
            M_info( 0, buf );
            if ( fread( buf, 1, 3, fp ) != 3 )
                return EOF;
            while ( ( count = getblock( fp, buf ) ) != 0 && count != EOF )
            {
                buf[ count ] = '\0';
                M_info( 0, buf );
            }
            break;

        default :
            M_err( f, "%s: Bogus extension byte 0x%02x", im->infile, label );
            break;
    }

    return count;
}


/***************************************
 ***************************************/

static int
skip_extension( FILE     * fp,
                FL_IMAGE * im )
{
    int pchar,
        err = 0;

    while ( ! err && ( pchar = getc( fp ) ) != EOF && pchar != IMAGESEP )
    {
        switch ( pchar )
        {
            case '\0' :
            case TRAILER :
                break;

            case EXTENSION :
                err = readextension( fp, im );
                break;

            default :
                M_warn( "GIFextension", "%s: Bogus byte 0x%02x",
                        im->infile, pchar );
                return EOF;
        }
    }

    return err ? EOF : pchar;
}


#define LZW_INIT          9000


static int bpp,
           ClearCode,
           EOFCode,
           CodeSize;

#include <ctype.h>

static unsigned char * lhead,
                     *lbuf,
                     *stackp;   /* local buffers */


/***************************************
 ***************************************/

static int
GIF_load( FL_IMAGE * im )
{
    int bits = 0,
        err,
        count,
        code = -1;
    unsigned int datum = 0;
    unsigned char *ch,
                  buf[ 257 ];
    SPEC *sp = im->io_spec;
    const char *func = "GIFReadPix";
    FILE *fp = im->fpin;

    sp->ctext = 0;

    CodeSize = getc( fp );
    if ( CodeSize > 8 || CodeSize < 2 )
    {
        flimage_error( im, "Load: Bad CodeSize %d(%s)", CodeSize, im->infile );
        return -1;
    }

    /* initialize the decompressor */

    err = sp->cur_total = 0;
    process_lzw_code( im, LZW_INIT );

    while ( ! err && ( count = getc( fp ) ) != EOF && count > 0 )
    {
        err = Badfread( buf, 1, ( size_t )count, fp );
        for ( ch = buf; count-- > 0; ch++ )
        {
            datum += *ch << bits;
            bits += 8;
            while ( bits >= CodeSize && ! err )
            {
                code = datum & gif_codemask[ CodeSize ];
                datum >>= CodeSize;
                bits -= CodeSize;
                err = code == EOFCode || process_lzw_code( im, code );
            }
        }

        /* EOFcode is not exactly an errr */

        if ( err && code == EOFCode )
            err = 0;

        if ( code != EOFCode && sp->cur_total > (long) im->w * im->h )
        {
            flimage_error( im, "%s: Raster full before EOI", im->infile );
            err = 1;
        }
    }

    if ( ! err )
    {
        if ( ( code = getc( fp ) ) == EXTENSION )
        {
            ungetc( code, fp );
            while (    ( code = skip_extension( fp, im ) ) != EOF
                    && code != IMAGESEP )
                /* empty */ ;
        }

        if ( code == IMAGESEP )
        {
            im->more = 1;
            ungetc( IMAGESEP, fp );
        }
        else if (    code != EOF
                  && fread( buf, 1, 50, fp )
                  && getc( fp ) != EOF )
        {
            M_info( func, "%s: Garbage(> 50bytes) at end", im->infile );
        }
    }

    count = sp->cur_total / im->w;

    /* final check: get pixels that are decoded but yet to be output */

    if ( count < im->h )
    {
        int leftover;
        leftover = lbuf - lhead;

        M_warn( func, "total %ld should be %d", sp->cur_total + leftover,
                im->w * im->h );

        if ( leftover )
            outputline( im, lhead );
    }

    /* if more than 1/4 image is read, return positive value so that driver
       will try to display it.  */

    convert_gif_text( im );

    return count >= im->h / 4 ? count : -1;
}


/***************************************
 * process_lzw_code - Process a compression code.  "clear" resets the
 * code table. Otherwise make a new code table entry, and output the
 * bytes associated with the code.
 *
 * Based on gifpaste by Kipp Hickman @ Silicon Graphics
 ***************************************/

#define OUTPIX( c )    ( *lbuf++ = ( c ) )
#define MC_SIZE        4097


/***************************************
 * if we've got more than one scanline, output
 ***************************************/

static void
flush_buffer( FL_IMAGE * im )
{
    int incode;

    incode = lbuf - lhead;

    if ( incode >= im->w )
    {
        int i;

        lbuf = lhead;

        while ( incode >= im->w )
        {
            outputline( im, lbuf );
            incode -= im->w;
            lbuf += im->w;
        }

        /* copy the left over */

        for ( i = 0; i < incode; i++ )
            lhead[ i ] = *lbuf++;
        lbuf = lhead + incode;
    }
}


/***************************************
 ***************************************/

static int
process_lzw_code( FL_IMAGE * im,
                  int        code )
{
    int incode;
    static unsigned char firstchar;
    static unsigned char stack[ MC_SIZE ];
    static int avail,
               oldcode;
    static unsigned char suffix[ MC_SIZE ];
    static unsigned short prefix[ MC_SIZE ];

    if ( code == LZW_INIT )
    {
        lbuf = lhead = fl_realloc( lhead, im->w + 1 + 4096 );

        bpp = CodeSize;
        ClearCode = 1 << bpp;
        EOFCode = ClearCode + 1;
        CodeSize = bpp + 1;

        for ( incode = ClearCode; --incode >= 0; )
        {
            *( suffix + incode ) = incode;
            *( prefix + incode ) = 0;
        }

        avail = ClearCode + 2;
        oldcode = -1;
        stackp = stack;
        return lbuf ? 0 : -1;
    }

    if ( code == ClearCode )
    {
        CodeSize = bpp + 1;
        avail = ClearCode + 2;
        oldcode = -1;
        return 0;
    }

    /* this is possible only if the image file is corrupt */

    if ( code > avail || code < 0 )
    {
        flimage_error( im, "GIFLZW(%s): Bad code 0x%04x", im->infile, code );
        return -1;
    }

    if ( oldcode == -1 )
    {
        OUTPIX( suffix[ code ] );
        firstchar = oldcode = code;

        /* Clive Stubbings.
         * There is the posibility of an image with just alternate
         * single code bytes and resets. I know thats really dumb,
         * but I found one and it took a long time to work out why
         * it crashed...
         * So flush the buffer before it overuns. */

        flush_buffer( im );
        return 0;
    }

    incode = code;
    if ( code == avail )
    {               /* the first code is always < avail */
        *stackp++ = firstchar;
        code = oldcode;
    }

    while ( code > ClearCode )
    {
        *stackp++ = suffix[ code ];
        code = prefix[ code ];
    }

    if ( avail >= 4096 )
    {
        flimage_error( im, "GIFLZW(%s): BadBlock--TableFull", im->infile );
        return -1;
    }

    *stackp++ = firstchar = suffix[ code ];
    prefix[ avail ] = oldcode;
    suffix[ avail ] = firstchar;

    avail++;
    if ( ( avail & gif_codemask[ CodeSize ] ) == 0 && avail < 4096 )
        CodeSize++;

    oldcode = incode;

    do
    {
        OUTPIX( *--stackp );
    }
    while ( stackp > stack );

    /* if we've got more than one scanline, output */

    flush_buffer( im );

    return 0;
}


/***************************************
 ***************************************/

static int
GIF_next( FL_IMAGE * im )
{
    int ow = im->w,
        oh = im->h;
    int ret;

    read_descriptor_block( im );

    /* It would seem from the doc that it is possible new image could be
       larger than last one */

    if ( ow != im->w || oh != im->h )
        flimage_getmem( im );

#if 0
    del_text( );
#endif

    im->more = 0;       /* gif_load will do turn it on if more */
    im->modified = 1;

    ret = GIF_load( im );

    return ret;
}

/******************* END of DECODER ****************************}*****/


/***************************************
 * Given GIF sequence no. i, starting from 0, figure out the image
 * sequence number. If interlaced, the sequence will be independent
 * of i, sort of a bug, but for this application, it is perfectly ok.
 ***************************************/

static int
next_lineno( int i,
             int h,
             int interlace )
{
    static const int steps[ 5 ] = { 8, 8, 4, 2, 0 };
    static const int start[ 5 ] = { 0, 4, 2, 1, 0 };
    static int pass,
               sofar,
               current;
    int line;

    /* init for each image */

    if ( i == 0 )
        pass = sofar = current = 0;

    line = i;           /* unless interlace */

    if ( interlace )
    {
        line = current;
        if ( ( current += steps[pass] ) >= h )
            current = start[ ++pass ];
    }

    sofar++;

    return line;
}


/********************************************************************
 * GIF encoding routine.
 * Original code
 ********************************************************************/

/************************************************************
 * Write image to a disk file in GIF format.
 ************************************************************/

/* current char, cchar, must be of signed type, and code and prefix must be
 * at least 12 bits long. */

typedef struct strspace_
{
    struct strspace_ * next;            /* link          */
    int                code;            /* emit code     */
    int                cchar;           /* current char */
} Strtab;

typedef struct
{
    int prefix,
        cchar,
        code;
} WorkStr;

#define  MAXTABL  4097

static Strtab *strtab[ MAXTABL ],
               strspace[ MAXTABL ];


/**************************************************************
 * Check if current string is already in the string table
 **************************************************************/

static int
in_table( WorkStr * cstr )
{
    Strtab *p = strtab[ cstr->prefix ];

    for ( ; p && p->cchar != cstr->cchar; p = p->next )
        /* empty */ ;

    return p ? p->code : -1;
}

#define USE_TAB_FUNC


/*
 * A macro and function are supplied to insert a string into the
 * string table.
 */

#ifdef USE_TAB_FUNC

/***************************************
 ***************************************/

static void
addto_table( WorkStr * cstr,
             int       code )
{
    Strtab *p = &strspace[ code ];

    p->code = code;
    p->cchar = cstr->cchar;
    p->next = strtab[ cstr->prefix ];
    strtab[ cstr->prefix ] = p;
}

#else

#define  addto_table(cstr, ccode )                         \
    do {                                                   \
        Strtab *p = &strspace[ ccode ];                    \
        p->code = ccode;                                   \
        p->cchar = cstr->cchar;                            \
        p->next = strtab[ cstr->prefix ];                  \
        strtab[ cstr->prefix ] = p;                        \
   } while( 0 )
#endif


static void output_lzw_code( unsigned int,
                             FILE * );
static void init_table( int,
                        FILE * );
#if 0
static unsigned short * get_scan_line( FL_IMAGE *,
                                       int );
#endif

static int interlace;


/***************************************
 ***************************************/

void
flimage_gif_output_options( int inter )
{
    interlace = inter;
}


/***************************************
 * for now, only write max 255 chars
 ***************************************/

static void
write_gif_comments( FILE       * fp,
                    const char * str )
{
    char s[ 256 ];
    const char *p = str;
    int len,
        k = strlen( str );

    for ( len = 0; p < str + k; p += len )
    {
        strncpy( s, p, 255 );
        s[ 255 ] = '\0';
        len = strlen( s );
        putc( EXTENSION, fp );
        fputc( GIFEXT_COM, fp );
        putc( len, fp );
        fwrite( s, 1, len, fp );
        putc( 0, fp );
    }
}


/***************************************
 ***************************************/

static int
write_descriptor( FL_IMAGE * im )
{
    unsigned char buf[ 10 ];
    FILE *ffp = im->fpout;

    if ( im->app_background >= 0 )
    {
        int tran = flimage_get_closest_color_from_map( im, im->app_background );

        buf[ 0 ] = GIFEXT_GC;
        buf[ 1 ] = 4;       /* count */
        buf[ 2 ] = 0x1;
        buf[ 3 ] = 0;
        buf[ 4 ] = 0;
        buf[ 5 ] = tran;
        buf[ 6 ] = 0;       /* end of block */
        putc( EXTENSION, ffp );
        fwrite( buf, 1, 7, ffp );
    }

    /* image descriptions  */

    buf[ 0 ] = IMAGESEP;
    buf[ 1 ] = buf[ 2 ] = buf[ 3 ] = buf[ 4 ] = 0;  /* offsets         */
    if ( Badfwrite( buf, 1, 5, ffp ) )
        return -1;

    /* raster dimensions */

    fli_fput2LSBF( im->w, ffp );
    fli_fput2LSBF( im->h, ffp );

    /* local_gifmap, interlace, etc. only set interlace if requested */

    putc( interlace ? 0x40 : 0, ffp );
    return 0;
}


/***************************************
 * write the image description
 ***************************************/

static int
write_desc( FL_IMAGE * im,
            FILE     * ffp )
{
    int packed;

    /* get bits per pixel first */

    bpp = 0;
    while ( im->map_len > 1 << bpp )
        bpp++;

    if ( bpp < 1 || bpp > 8 )
    {
        M_err( "GIF_dump", "%s: Bad bpp=%d", im->outfile, bpp );
        bpp = 1;
    }

    if ( Badfwrite("GIF89a", 1, 6, ffp ) )
    {
        M_err( "GIF_dump", im->outfile );
        return -1;
    }

    /* always write the same logical screen/image size  */

    fli_fput2LSBF( im->w, ffp );
    fli_fput2LSBF( im->h, ffp );

    packed =   0x80                  /* always output global map */
             + ( ( bpp - 1 ) << 4 )  /* cr. does not mean much   */
             + ( bpp - 1 );          /* bits_per_pixel-1         */
    putc( packed, ffp );
    putc( 0, ffp );
    putc( 0, ffp );     /* bk color and aspect ratio */

    /* global color map.  Entries must be 2^N */

    write_map( im, 1 << bpp );

    if ( im->comments )
        write_gif_comments( ffp, im->comments );

    return 0;
}


/*******************************************************************
 * The encoder
 *******************************************************************/

/***************************************
 ***************************************/

static int
write_pixels( FL_IMAGE * im )
{
    int j, code,
        ccode;
    unsigned short *scan,
                   *ss;
    WorkStr *cstr;
    int colors;
    WorkStr workstring;
    FILE *fp = im->fpout;

    /* IMPORTANT: number of colors handed to this routine might not be 2^n,
       need to make it so to fool the encoder (colors-1 need to be full bits) */

    colors = 1 << bpp;

    /* min bpp by definition is no smaller than 2 */

    if ( bpp < 2 )
        bpp = 2;        /* initial codesize */
    putc( bpp, fp );

    ClearCode = 1 << bpp;   /* set clear and end codes */
    EOFCode = ClearCode + 1;
    CodeSize = bpp + 1;     /* start encoding */

    init_table( colors, fp );   /* initialize the LZW tables */
    cstr = &workstring;
    ccode = EOFCode + 1;
    cstr->prefix = -1;

    /* start raster stream. Old way of doing things, that is as soon as we
       get 4095, a clearcode is emitted. */

    for ( j = 0; j < im->h; j++ )
    {
        scan = im->ci[ next_lineno( j, im->h, interlace ) ];

        for ( ss = scan + im->w; scan < ss; scan++ )
        {
            cstr->cchar = *scan & ( colors - 1 );
            if ( cstr->prefix >= 0 )
            {
                if ( ( code = in_table( cstr ) ) >= 0 )
                    cstr->prefix = code;
                else
                {
                    addto_table( cstr, ccode );
                    output_lzw_code( cstr->prefix, fp );
                    cstr->prefix = cstr->cchar;

                    if ( ccode >= 1 << CodeSize )
                        CodeSize++;
                    ccode++;

                    if ( ccode >= 4096 )
                    {
                        output_lzw_code( cstr->prefix, fp );
                        init_table( colors, fp );
                        ccode = EOFCode + 1;
                        cstr->prefix = -1;
                    }
                }
            }
            else
            {           /* root entry */
                cstr->prefix = cstr->code = cstr->cchar;
            }
        }
    }

    output_lzw_code( cstr->prefix, fp );
    output_lzw_code( EOFCode, fp );
    putc( 0, fp );      /* end block  */

    return fflush( fp );
}


/***************************************
 ***************************************/

static int
GIF_write( FL_IMAGE * sim )
{
    int err = 0;
    FL_IMAGE *im;
    
    if ( write_desc( sim, sim->fpout ) < 0 )
        return -1;

    for ( err = 0, im = sim; !err && im; im = im->next )
    {
        im->fpout = sim->fpout;
        err = write_descriptor( im ) < 0 || write_pixels( im ) < 0;
        if ( im != sim )
            im->fpout = 0;
    }

    putc( ';', sim->fpout );    /* end stream */
    fflush( sim->fpout );

    return err ? -1 : 0;
}


/***************************************
 ***************************************/

static void
init_table( int    rootlen,
            FILE * fp )
{
    int i;
    Strtab *sp = strspace;

    output_lzw_code( ClearCode, fp );

    CodeSize = bpp + 1;

    for ( i = 0; i < rootlen; i++, sp++ )
    {
        sp->next = 0;
        sp->code = i;
        sp->cchar = -1;
        strtab[ i ] = sp;
    }

    for ( ; i < MAXTABL; i++, sp++ )
        strtab[ i ] = sp->next = 0;
}


/*******************************************************************
 * Packing and output an LZW code(bpp+1 to 12 bits long).
 *
 * Note: accum must be at least 19 bits long. accum and bits must be
 * re-initialized when EOFCode is written out.
 *******************************************************************/

static void
output_lzw_code( unsigned int   code,
                 FILE         * fp )
{
    static unsigned int bytes,
                        bits;
    static unsigned char bbuf[ 255 + 3 ];
    static unsigned long accum;
    unsigned char *ch;

    accum &= gif_codemask[ bits ];
    accum |= code << bits;
    bits += CodeSize;

    ch = bbuf + bytes;
    bytes += bits >> 3;

    while ( bits >= 8 )
    {
        bits -= 8;
        *ch++ = ( unsigned char ) ( accum & 255 );
        accum >>= 8;
    }

    if ( bytes >= 254 || ( int ) code == EOFCode )
    {
        if ( ( int ) code == EOFCode && bits )
        {
            *ch = ( unsigned char ) ( accum & 255 );
            bytes++;
            bits = accum = 0;
        }

        putc(bytes, fp);
        fwrite( bbuf, 1, bytes, fp );
        bytes = 0;
    }
}


/***************************************
 ***************************************/

void
flimage_enable_gif( void )
{
    flimage_add_format( "CompuServ GIF", "gif", "gif",
                        FL_IMAGE_CI,
                        GIF_identify,
                        GIF_description,
                        GIF_load,
                        GIF_write);
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
