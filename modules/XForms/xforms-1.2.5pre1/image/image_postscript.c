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
 *  PostScript support.
 *
 * Do we want to integrate the stuff from ps_core.c, ps_draw.c and
 * postscript.c to consolidate ps support ?
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "flimage.h"
#include "flimage_int.h"
#include "private/flsnprintf.h"

#ifndef FLPS_H
#include "flps.h"
#endif

#include "private/pflps.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

typedef FLPSInfo SPEC;


/***************************************
 ***************************************/

FLPS_CONTROL *
flimage_ps_options( void )
{
    static SPEC *sp;

    if ( ! sp )
    {
        sp = fl_calloc( 1, sizeof *sp );
        sp->orientation = FLPS_AUTO;
        sp->paper_w = 8.5;
        sp->paper_h = 11.0;
        sp->auto_fit = 1;
        sp->xdpi = sp->ydpi = fl_dpi;
        sp->printer_dpi = 300;
        sp->vm = sp->hm = 0.3;
        sp->xscale = sp->yscale = 1.0;
        sp->tmpdir = "/tmp";
        sp->gamma = 1.0;
        sp->verbose = 0;
        sp->comment = 0;
        sp->pack = 0;
        sp->lastr = -1;
        sp->ps_color = 1;
        /* cache */
        sp->cur_color = FLIMAGE_BADCOLOR;
        sp->cur_style = sp->cur_size = sp->cur_lw = -1;
    }

    return ( FLPS_CONTROL * ) sp;
}


/***************************************
 ***************************************/

static int
PS_identify( FILE * fp )
{
    char buf[ 2 ];

    if ( fread( buf, 1, 2, fp ) != 2 )
        return 0;
    rewind( fp );
    return ! strncmp( buf, "%!", 2 );
}


/***************************************
 * this is a fake to get past the driver
 ***************************************/

static int
PS_description( FL_IMAGE * im )
{
    im->extra_io_info = fl_malloc( sizeof( SPEC ) );
    memcpy( im->extra_io_info, flimage_ps_options( ), sizeof( SPEC ) );
    im->w = im->h = 1;
    im->type = FL_IMAGE_RGB;
    return 0;
}


#define GS_DEVICE   "ppmraw"
#define FL_FILE     "ppm"
#define GS_OPTION   "-q -DNOPAUSE"


/***************************************
 ***************************************/

static const char *
file_tail( char *s )
{
    char *p = strrchr( s, '/' );
    return p ? ( p + 1 ) : s;
}


/***************************************
 * load a specific page
 ***************************************/

static int
load_page( FL_IMAGE * im,
           int        pageNo )
{
    char name[ 1024 ],
         tmpf[ 1024 ];
    SPEC *sp = im->extra_io_info;
    FLIMAGE_IO *fileIO;
    int status, n;

    fli_snprintf( name, sizeof name, "%s/%s_%d",
                  sp->tmpdir, sp->prefix, pageNo );

    if ( sp->verbose )
        M_err( "LoadPage", "loading %s", name );

    if ( ! ( n = flimage_is_supported( name ) ) )
    {
        M_err( "LoadPage", "internal error. %s unknown", name );
        return -1;
    }

    fclose( im->fpin );
    im->fpin = fopen( name, "rb" );
    strcpy( tmpf, im->infile );
    strcpy( im->infile, name );

    im->completed = pageNo;
    im->visual_cue( im, "Loading PostScript" );

    /* re-direct the io handling */

    im->image_io = fileIO = &flimage_io[ n - 1 ];
    im->type = fileIO->type;

    fileIO->identify( im->fpin );

    if ( ( status = fileIO->read_description( im ) ) >= 0 )
        status = flimage_getmem( im );

    if ( status >= 0 )
        status = fileIO->read_pixels( im );

    strcpy( im->infile, tmpf );
    return status;
}


/***************************************
 * delete all temporary files
 ***************************************/

static void
PS_cleanup( FL_IMAGE * im )
{
    int i,
        n = im->total_frames >= 1 ? im->total_frames : 1;
    SPEC *sp = im->extra_io_info;
    char name[ 1024 ];

    if ( ! sp )
        return;

    for ( i = 1; i <= n; i++ )
    {
        fli_snprintf( name, sizeof name, "%s/%s_%d", sp->tmpdir,
                      sp->prefix, i );
        if ( sp->verbose )
            M_err( "Cleanup", "deleting %s", name );
        remove( name );
    }

    fl_free( sp->prefix );
    fl_free( sp );
    im->extra_io_info = NULL;
}


/***************************************
 ***************************************/

static int
PS_read_pixels( FL_IMAGE * im )
{
    char cmd[ 1024 ];
    int npages,
        status;
    SPEC *sp = im->extra_io_info;
    const FL_Dirlist *dirlist,
                     *dls,
                     *dl;
    char prefix[ 1024 ];
    int old_sort;

    /* the tmp file pattern will be /tmp/gs_$InputFile_$pid_pageNO */

    fli_snprintf( prefix, sizeof prefix,
                  "gs_%s_%d", file_tail( im->infile ), ( int ) fli_getpid( ) );

    sp->prefix = strdup( prefix );

    if ( sp->verbose )
        M_err( "LoadPS", "prefix=%s", sp->prefix );

    fli_snprintf( cmd, sizeof cmd,
                  "gs -sDEVICE=%s %s -r%dx%d -sOutputFile=%s/%s_%%d -- %s %s",
                  GS_DEVICE, GS_OPTION, (int) sp->xdpi, ( int ) sp->ydpi,
                  sp->tmpdir, sp->prefix, im->infile,
                  sp->first_page_only ?
                  "/showpage { systemdict begin showpage quit end} def" : "" );

    if ( sp->verbose )
        M_err( "LoadPS", "executing %s\n", cmd );
    else
        strcat( cmd, " 2 > /dev/null" );

    im->completed = -1;     /* indicate infinite/unknown */
    im->visual_cue( im, "Converting PS ..." );

    if ( ( status = system( cmd ) ) )
    {
        M_err( "ReadPS", " status=%d", status );
        flimage_error( im, "ReadPS failed. Status=%d", status );
        return -1;
    }

    im->completed = 1;
    im->visual_cue( im, "Loading PostScript" );

    /* we really do not need the current image stuff */

    flimage_freemem( im );

    /* find out how many pages we have. Turn off sorting, much faster */

    old_sort = fl_set_dirlist_sort( FL_NONE );
    dl = fl_get_dirlist( sp->tmpdir, strcat( prefix, "_*" ), &npages, 1 );
    fl_set_dirlist_sort( old_sort );

    if ( ! ( dirlist = dl ) )
    {
        PS_cleanup( im );
        return -1;
    }

    /* remove directories from the list */

    for ( dls = dl + npages; dl < dls; dl++ )
        if ( dl->type == FT_DIR )
            npages--;

    fl_free_dirlist( dirlist );

    if ( sp->verbose )
        M_err( "LoadPS", "Total %d pages", npages );

    if ( npages <= 0 )
    {
        PS_cleanup( im );
        flimage_error( im, "LoadPS: no page written!" );
        im->more = 0;
        return -1;
    }

    im->total_frames = npages;

    if ( ! sp->first_page_only )
    {
        im->more = npages > 1;
        im->random_frame = load_page;
        im->cleanup = PS_cleanup;
    }

    im->total = im->total_frames;

    /* construct the filename and load it */

    status = load_page( im, 1 );

    /* need to cleanup the file if single page. For multipage, the driver
       will cleanup */

    if ( ! im->more || status < 0 )
        PS_cleanup( im );

    return status;
}


/***************************************************************************
 * Output routine
 **************************************************************************/

/***************************************
 ***************************************/

static void
PS_push( void )
{
    flps_output( "gsave\n" );
}


/***************************************
 ***************************************/

static void
PS_pop( void )
{
    flps_output( "grestore\n" );
}


/***************************************
 ***************************************/

static void
PS_trailer( SPEC *sp )
{
    PS_pop( );
    flps_output( 0 );
    fputs( "%%Trailer\n", sp->fp );
}


/***************************************
 ***************************************/

static int
auto_scale( float pagew,
            float pageh,
            float w,
            float h,
            int   landscape )
{
    int i = 0;

    if (    ( ! landscape && ( pagew < w || pageh < h ) )
         || ( landscape && ( pagew < h || pageh < w ) ) )
    {
        float sx,
              sy;

        if ( ! landscape )
        {
            sx = ( pagew - 2.0 ) / w;
            sy = ( pageh - 2.0 ) / h;
        }
        else
        {
            sx = ( pagew - 2.0 ) / h;
            sy = ( pageh - 2.0 ) / w;
        }
        
        i = 100.0 * FL_min( sx, sy );
    }

    return i;
}


/***************************************
 ***************************************/

static void
PS_start_image( FL_IMAGE * im  FL_UNUSED_ARG )
{
    PS_push( );
}


/***************************************
 ***************************************/

static void
PS_end_image( FL_IMAGE * im  FL_UNUSED_ARG )
{
    PS_pop( );
}


#define LEFT    '('
#define RIGHT   ')'

static void PS_annotation_init( FL_IMAGE * );
static void PS_annotation( FL_IMAGE * im );

/***************************************
 ***************************************/

static void
PS_write_header( FL_IMAGE * im )
{
    FILE *fp = im->fpout;
    SPEC *sp = im->extra_io_info;
    float pagew = sp->paper_w - 2.0 * sp->hm;
    float pageh = sp->paper_h - 2.0 * sp->vm;
    float hm = sp->hm,
          vm = sp->vm;
    float s2px,
          s2py;
    float xscale = sp->xscale,
          yscale = sp->yscale;
    int xo,
        yo;
    int w = im->w,
        h = im->h;
    int orientation;
    int rescale;

    sp->fp = fp;

    /* check the size and orientation */

    pagew *= 72.0;
    pageh *= 72.0;
    hm *= 72.0;
    vm *= 72.0;

    sp->s2px = s2px = 72.0 / sp->xdpi;
    sp->s2py = s2py = 72.0 / sp->ydpi;
    w *= xscale * s2px;
    h *= yscale * s2py;

    if ( ( orientation = sp->orientation ) == FLPS_AUTO )
    {
        /* pick the orientation so even margin results */

        int plm,
            pbm,
            llm,
            lbm;

        plm = ( pagew - w ) / 2;
        pbm = ( pageh - h ) / 2;
        llm = ( pagew - h ) / 2;
        lbm = ( pageh - w ) / 2;
        orientation = ( FL_abs( lbm - llm ) < FL_abs( pbm - plm ) ) ?
                        FLPS_LANDSCAPE : FLPS_PORTRAIT;
    }

    sp->landscape = orientation == FLPS_LANDSCAPE;

    /* always make the image fit on the page */

    if (    ( rescale = auto_scale( pagew, pageh, w, h, sp->landscape ) )
         && sp->auto_fit)
    {
        xscale *= rescale * 0.01;
        yscale *= rescale * 0.01;
        w *= rescale * 0.01;
        h *= rescale * 0.01;
    }

    /* update */

    sp->final_xscale = xscale;
    sp->final_yscale = yscale;

    /* get the origin of the system. For BoundingBox only. Actual PS output
       computes these on the fly */

    xo = hm + ( pagew - ( sp->landscape ? h : w ) ) * 0.5;
    yo = vm + ( pageh - ( sp->landscape ? w : h ) ) * 0.5;

    xo -= ( sp->landscape ? sp->miscb : sp->miscl ) * xscale * s2px;
    yo -= ( sp->landscape ? sp->miscl : sp->miscb ) * xscale * s2py;

    w += ( sp->miscr + sp->miscl ) * xscale * s2px;
    h += ( sp->misct + sp->miscb ) * yscale * s2py;

    /* write header */

    flps_emit_header( file_tail( im->infile ), im->total_frames,
                      xo - 1, yo - 1, xo + w + 1, yo + h + 1 );

    /* Prolog. Basic defines. */

    fputs( "/inch { 72 mul } def /D {def} def /BD {bind def} def\n", fp );
    fputs( "% Beginning of modifiable parameters\n", fp );
    fprintf( fp, "/pagew {%.2g inch} BD\t%% page width\n", sp->paper_w );
    fprintf( fp, "/pageh {%.2g inch} BD \t%% page height\n", sp->paper_h );
    fprintf( fp, "/lm {%.2g inch} BD \t%% Left margin\n", sp->hm );
    fprintf( fp, "/bm {%.2g inch} BD \t%% Bottom margin\n", sp->vm );
    fprintf( fp, "/xscale %g D /yscale %g D\t %% DPIScale %g SizeScale %g\n",
             s2px * xscale, s2py * yscale,
             (s2px + s2py) * 0.5, rescale * 0.01 );
    fputs( "% End of modifiable parameters\n", fp );

    fprintf( fp, "/pw { pagew lm 2 mul sub } BD \t%% writable width\n" );
    fprintf( fp, "/ph { pageh bm 2 mul sub } BD \t%% writable height\n" );

    /* instead of emitting numbers, the actual calculation is output so that
     * both scale and margin can be adjusted in PS */

    flps_output( "/xo pw xscale div %d sub 2 div def\n",
                 sp->landscape ? im->h : im->w );
    flps_output( "/yo ph yscale div %d sub 2 div def\n",
                 sp->landscape ? im->w : im->h );

    PS_annotation_init( im );

    flps_output( 0 );
    fputs( "%%EndProlog\n", fp );

    if ( sp->comment )
        fprintf( sp->fp, "%%OverallStateSave{\n" );

    PS_push( );

    /* honor the margin request */

    flps_output( "lm bm translate\n" );
}


static const char *hexdigits = "0123456789abcdef";

#define OutPixel( c )                                 \
          do {                                        \
               putc( hexdigits[ ( c ) >> 4 ], fp );   \
               putc( hexdigits[ ( c ) & 15 ], fp );   \
          } while ( 0 )


/***************************************
 * pixel data only
 ***************************************/

static int
PS_write_pixels( FL_IMAGE * im )
{
    FILE *fp = im->fpout;
    int ok = 1,
        j,
        k;

    im->total = im->h;
    im->completed = 0;

    if ( FL_IsRGB( im ) )
    {
        unsigned char *pc,
                      *ss;

        im->visual_cue( im, "Writing ColorPS" );
        for ( j = 0, k = 1; ok && j < im->h; j++, im->completed++ )
        {
            for ( pc = im->red[ j ], ss = pc + im->w; pc < ss; pc++, k++ )
            {
                OutPixel( *pc );
                if ( k % 37 == 0 )
                    putc( '\n', fp );
            }
            for ( pc = im->green[ j ], ss = pc + im->w; pc < ss; pc++, k++ )
            {
                OutPixel( *pc );
                if ( k % 37 == 0 )
                    putc( '\n', fp );
            }
            for ( pc = im->blue[ j ], ss = pc + im->w; pc < ss; pc++, k++ )
            {
                OutPixel( *pc );
                if ( k % 37 == 0 )
                    putc( '\n', fp );
            }

            if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            {
                im->visual_cue( im, "Writing PS" );
                ok = ! ferror( fp );
            }
        }
    }
    else
    {
        unsigned short *pc,
                       *ss;
        unsigned char g;

        im->visual_cue( im, "Writing GrayPS" );
        for ( j = 0, k = 1; ok && j < im->h; j++, im->completed++ )
        {
            for ( pc = im->gray[ j ], ss = pc + im->w; pc < ss; pc++, k++ )
            {
                g = *pc & 0xff;
                OutPixel( g );
                if ( k % 37 == 0 )
                    putc( '\n', fp );
            }
            if ( ! ( im->completed & FLIMAGE_REPFREQ ) )
            {
                im->visual_cue( im, "Writing PS" );
                ok = ! ferror( fp );
            }
        }
    }

    putc( '\n', fp );

    return ok ? 1 : -1;
}


/***************************************
 ***************************************/

static void
make_raster_command( FL_IMAGE * im,
                     char       pscmd[ ] )
{
    int rgb = FL_IsRGB( im );

    sprintf( pscmd, "StartRaster" );

    if ( ! rgb )
    {
        flps_output( "/graystring %d string def\n", im->w );
        flps_output( "/%s\n", pscmd );
        flps_output( "  {%d %d %d [ %d 0 0 -%d 0 %d]\n",
                     im->w, im->h, FL_PCBITS, im->w, im->h, im->h );
        flps_output( "  {currentfile graystring readhexstring pop}\n" );
        flps_output( "  imag`e\n} bind def\n" );
    }
    else
    {
        flps_output( "/redstring %d string def\n", im->w );
        flps_output( "/grnstring %d string def\n", im->w );
        flps_output( "/blustring %d string def\n", im->w );
        flps_output( "/%s\n", pscmd );
        flps_output( "  {%d %d %d [ %d 0 0 -%d 0 %d]\n",
                    im->w, im->h, FL_PCBITS, im->w, im->h, im->h );
        flps_output( "  {currentfile redstring readhexstring pop}\n" );
        flps_output( "  {currentfile grnstring readhexstring pop}\n" );
        flps_output( "  {currentfile blustring readhexstring pop}\n" );
        flps_output( "  true 3 colorimage\n} bind def\n");
    }
}


/***************************************
 ***************************************/

static int
PS_write_image( FL_IMAGE * sim )
{
    SPEC *sp = sim->extra_io_info;
    char pscmd[ 512 ];
    FL_IMAGE *im = sim;
    int err,
        npage;

    if ( ! sp )
    {
        sp = sim->extra_io_info = fl_calloc( 1, sizeof *sp );
        memcpy( sp, flimage_ps_options( ), sizeof *sp );
    }

    sp->fp = sim->fpout;

    flps_switch_flps( sp );
    PS_write_header( sim );

    fprintf( sp->fp, sp->comment ? " %%StartOfMultiImage {\n" : "" );
    PS_push( );

    for ( err = 0, npage = 1, im = sim; !err && im; im = im->next, npage++ )
    {
        im->fpout = sim->fpout;
        flps_output( 0 );
        fprintf( im->fpout, "%%%%Page: %d %d\n", npage, sim->total_frames );

        /* the origin of the image (xo,yo) and annotation */

        flps_output( "xscale yscale scale xo yo translate\n" );

        if ( sp->landscape )
        {
            flps_output( "%d %d translate\n", sim->h, 0 );
            flps_output( " 90 rotate\n" );
        }

        PS_start_image( im );
        make_raster_command( im, pscmd );
        flps_output( "%d %d scale %s\n", im->w, im->h, pscmd );
        flps_output( 0 );
        err = PS_write_pixels( im ) < 0;
        PS_end_image( im );
        PS_annotation( im );
        flps_output( "showpage\n" );
    }

    if ( sp->comment )
        fprintf (sp->fp, " %%EndOfMultiImage}\n" );

    PS_pop( );

    PS_trailer( sp );
    fflush( sim->fpout );

    flps_reset_cache( );
    flps_restore_flps( );

    fl_free( sim->extra_io_info );
    sim->extra_io_info = 0;

    return err ? -1 : 1;
}


void
flimage_enable_ps( void )
{
    flimage_add_format( "PostScript", "ps", "ps",
                        FL_IMAGE_RGB | FL_IMAGE_GRAY,
                        PS_identify, PS_description,
                        PS_read_pixels, PS_write_image );
}


/***************************************
 * Marker output
 *  M-moveto  LT-lineto L
 ***************************************/

#define MBUFLEN 10

static void
PS_annotation_init( FL_IMAGE * im )
{
    const char *mbuf[ MBUFLEN ];
    FLIMAGE_MARKER *m;

    if ( ! im->nmarkers && !im->ntext )
        return;

    flps_output( "/M {moveto} BD /G {setgray} BD /RGB {setrgbcolor} BD\n" );
    flps_output( "/LT {lineto} BD /L {M LT} BD /S {stroke} BD /F {fill} BD\n" );
    flps_output( "/L {M LT} BD /S {stroke} BD /F {fill} BD\n" );
    flps_output( "/LW {setlinewidth} BD /C {closepath} BD\n" );

    memset( mbuf, 0, MBUFLEN );

    if ( im->nmarkers )
    {
        int i, k;

        flps_output( "%%marker defs: t w h angle xo yo\n" );
        flps_output( 0 );
        flps_output( "/DTD {[5 4 1 4] 0 setdash} BD\n" );       /* dot-dash */
        flps_output( "/DT {[1 3] 0 setdash} BD\n" );            /* dot   */
        flps_output( "/LD {[8 5] 0 setdash} BD\n" );            /* long dash */
        flps_output( "/DS {[4 4] 0 setdash} BD\n" );            /* dash */
        flps_output( "/SL {[] 0 setdash} BD\n" );               /* solid */
        flps_output( "/NP {newpath} BD\n" );                    /* solid */

        flps_output( "/BM {gsave} D /EM {grestore} D\n" );
        flps_output( "/MK {newpath translate rotate scale LW} BD\n" );

        /* define primitives (-1 to +1) */

        for ( k = 0, m = im->marker, i = 0; i < im->nmarkers; i++, m++ )
        {
            int j, out;

            for ( j = out = 0; ! out && j < MBUFLEN; j++ )
                out = m->name == mbuf[ j ];

            if ( ! out )
            {
                mbuf[ k++ ] = m->name;
                flps_output( "/%s {%s %s} D\n", m->name, "MK", m->psdraw );
            }
        }
    }

    if ( im->ntext )
    {
        /* do we want to scale the font ? */

        flps_output( "/point {xscale yscale add 2 div div} BD\n" );
        flps_output( "/SetFont {findfont exch scalefont setfont} BD\n" );
        flps_output( "/CP {currentpoint} BD /SW {stringwidth} BD\n" );
        flps_output( "/Lshow {show} BD\n" );
        flps_output( "/Cshow {dup SW pop -2 div 0 rmoveto show} BD\n" );
        flps_output( "/Rshow {dup SW pop neg 0 rmoveto show} BD\n" );
    }
}


/***************************************
 ***************************************/

#if 0
static void
switch_to_ISOLatin1( FILE * fp )
{
    /***** usage: newfontname oldfontname SwitchISO ******/

    flps_output( 0 );
    flps_output( "% Switch to ISOLatin1 to get special characters" );
    flps_output( 0 );
    flps_output( "/languagelevel where\n" );
    flps_output( "   {pop languagelevel} {1} ifelse\n" );
    flps_output( "   2 lt {/BitEncoding /StandardEncoding load def}\n" );
    flps_output( "        {/BitEncoding /ISOLatin1Encoding load def}\n" );
    flps_output( "   ifelse\n" );
    flps_output( "/SwitchToISO {\n" );
    flps_output( "   findfont dup length\n   dict begin {1 index /FID ne {def} "
                 "{pop pop} ifelse} forall\n" );
    flps_output( "   /Encoding BitEncoding def " );
    flps_output( " currentdict end\n   definefont pop\n} bind def\n" );
}
#endif


/***************************************
 ***************************************/

static void
PS_annotation( FL_IMAGE * im )
{
    FLIMAGE_MARKER *m = im->marker;
    FLIMAGE_TEXT *t = im->text;
    int r,
        g,
        b,
        i,
        thickness;
    SPEC *sp = im->extra_io_info;

    for ( i = 0; i < im->nmarkers; i++, m++ )
    {
        thickness = m->thickness + (m->thickness == 0);
        FL_UNPACK( m->color, r, g, b );
        flps_rgbcolor( r, g, b );
        flps_linestyle( m->style );
        flps_output( "BM %.3g %g %g %g %d %d %s",
                     2.0 * thickness / ( m->w + m->h ), 0.5 * m->w,
                     0.5 * m->h, m->angle * 0.1, m->x, im->h - m->y, m->name );
        flps_output( " %c EM\n", "SF"[ m->fill ] );
    }

    /* we make use of the ps_text.c */

    sp->isRGBColor = 1;
    for ( i = 0; i < im->ntext; i++, t++ )
    {
        sp->rotation = t->angle;
        flps_draw_text( t->align, t->x - 1, im->h - t->y - 1, 2, 2,
                        t->color, t->style, t->size, t->str );
    }

    sp->rotation = 0;
    sp->isRGBColor = 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
