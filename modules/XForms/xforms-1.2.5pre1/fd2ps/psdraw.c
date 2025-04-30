/*
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file psdraw.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 * Some primitive drawing routines is PS
 *
 *  (x,y) (w,h) passed to all drawing functions are relative
 *  to PS coordinate system and the unit is point.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd2ps.h"
#include "flinternal.h"
#include <ctype.h>

static float cur_lwx = 1, cur_lwy = 1;


/***************************************
 ***************************************/

void
ps_log( const char *s )
{
    fprintf( flps->fp, "%%%s", s );
}

#include <stdarg.h>


/***************************************
 ***************************************/

void
ps_output( const char * fmt,
           ... )
{
    va_list args;
    char buf[ 2048 ],
         *q;
    int lastc = flps->lastc;

    va_start( args, fmt );
    vsprintf( buf, fmt, args );
    va_end( args );

    if ( ! flps->pack )
        fprintf( flps->fp, "%s", buf );
    else
    {
        flps->literal = 0;

        for ( q = buf; *q; q++ )
        {
            if ( *q == '\n' )
                *q = ' ';

            if ( *q == '(' )
                flps->literal = 1;
            else if ( *q == ')' )
                flps->literal = 0;

            if ( lastc == ' ' && *q == ' ' && flps->literal )
                continue;

            if ( *q == ' ' && flps->len == 0 )
                continue;

            if ( *q == ' ' && flps->len >= 69 )
            {
                putc( '\n', flps->fp );
                flps->len = 0;
            }
            else
            {
                lastc = *q;
                flps->len++;
                putc( *q, flps->fp );
            }
        }

        flps->lastc = lastc;
    }
}


/***************************************
 ***************************************/

void
ps_set_clipping( int x,
                 int y,
                 int w,
                 int h )
{
    ps_output( "gsave newpath %d %d %d %d rectclip\n", x, y, w, h );
}


/***************************************
 ***************************************/

void
ps_unset_clipping( void )
{
    ps_output( "grestore\n" );
    ps_invalidate_color_cache( );
}


/***************************************
 ***************************************/

void
ps_verbatim( const char * fmt,
             ... )
{
    va_list args;

    va_start( args, fmt );
    vfprintf( flps->fp, fmt, args );
    va_end( args );
}


/***************************************
 ***************************************/

void
ps_set_linewidth( float lwx,
                  float lwy )
{
    ps_output( "gsave %.2g %.2g LW\n", cur_lwx = lwx, cur_lwy = lwy );
}


/***************************************
 ***************************************/

void
ps_get_linewidth( float * lwx,
                  float * lwy )
{
    *lwx = cur_lwx;
    *lwy = cur_lwy;
}


/***************************************
 ***************************************/

void
ps_reset_linewidth( void )
{
    ps_output( "grestore\n" );
    ps_invalidate_color_cache( );
}


/* define FAST_POLY to get faster PS polygon at the expense of
 * larger PS output
 */


/* #define FAST_POLY  */

/********************************************************************
 * Basic drawing routines
 *
 *  Always need to code for different devices
 *
 *****************************************************************{**/


/***************************************
 * Draw a line in abs coordinate system
 ***************************************/

void
ps_line( float x1,
         float y1,
         float x2,
         float y2,
         long  col )
{
    ps_color( col );
    ps_output( "%.1f %.1f %.1f %.1f L S\n", x2, y2, x1, y1 );
}


/***************************************
 ***************************************/

void
ps_lines( Point * xp,
          int     n,
          long    col )
{
    Point *xps = xp + n;
    int cnt = 1;

    ps_color( col );

    for ( ; xp < xps; xp++, cnt++ )
    {
        ps_output( "%.1f %.1f ", ( double ) xp->x, ( double ) xp->y );
        if ( cnt % 6 == 0 )
            ps_output( "\n" );
    }

    ps_output( "%d linesa\n", n );
}


/***************************************
 ***************************************/

void
ps_poly( int     fill,
         Point * xp,
         int     n,
         long    col )
{
    Point *xps = xp + n;
    int cnt = 1;

    ps_color( col );

    for ( ; xp < xps; xp++, cnt++ )
    {
        ps_output( "%.1f %.1f ", ( double ) xp->x, ( double ) xp->y );
        if ( cnt % 6 == 0 )
            ps_output( "\n" );
    }

    ps_output( "%d P %c\n", n, "SF"[ fill ? 1 : 0 ] );
}


/***************************************
 ***************************************/

void
ps_rectangle( int   fill,
              float x,
              float y,
              float w,
              float h,
              long  col )
{
    ps_color( col );
    ps_output( "%.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f 4 P",
               x, y, x, y + h - 1, x + w - 1, y + h - 1, x + w - 1, y );
    ps_output( " %c\n", "SF"[ fill ? 1 : 0 ] );
}


/***************************************
 * rectangle with rounded corners
 ***************************************/

#define RS 16

/*
 * 0.0, 0.034074, 0.1339746, 0.292893, 0.5, 0.741181, 1.0
 */

static float offset[ ] =
{
    0.0, 0.07612, 0.29289, 0.61732, 1.0
};

#define RN   ( sizeof offset / sizeof *offset )


/***************************************
 ***************************************/

static int
compute_rounded_corners( FL_Coord   x,
                         FL_Coord   y,
                         FL_Coord   w,
                         FL_Coord   h,
                         Point    * point)
{
    Point *xp;
    size_t i, n;
    float rsx, rsy, xf, yf;

    rsx = rsy = 0.42 * FL_min( w, h );

    if ( rsx > RS )
        rsx = rsy = RS;

    for ( xp = point, n = i = 0; i < RN; i++, n++, xp++ )
    {
        xf = x + offset[ RN - i - 1 ] * rsx;
        yf = y + offset[ i ] * rsy;
        xp->x = FL_nint( xf );
        xp->y = FL_nint( yf );
    }

    for ( i = 0; i < RN; i++, n++, xp++ )
    {
        xf = x + offset[ i ] * rsx;
        yf = y + h - 1.0 - offset[ RN - i - 1 ] * rsy;
        xp->x = FL_nint( xf );
        xp->y = FL_nint( yf );
    }

    for ( i = 0; i < RN; i++, n++, xp++ )
    {
        xf = x + w - 1.0 - offset[ RN - i - 1 ] * rsx;
        yf = y + h - 1.0 - offset[ i ] * rsy;
        xp->x = FL_nint( xf );
        xp->y = FL_nint( yf );
    }

    for ( i = 0; i < RN; i++, n++, xp++ )
    {
        xf = x + w - 1.0 - offset[ i ] * rsx;
        yf = y + offset[ RN - i - 1 ] * rsy;
        xp->x = FL_nint( xf );
        xp->y = FL_nint( yf );
    }

    return n;
}


#define AddVertex( p, xp, yp ) do{ p->x = xp; p->y = yp; p++; } while( 0 )


/***************************************
 ***************************************/

void
ps_roundrectangle( int   fill,
                   float x,
                   float y,
                   float w,
                   float h,
                   long  col )
{
    Point point[ 5 * RN ];
    int n;

    n = compute_rounded_corners( x, y, w, h, point );
    ps_poly( fill, point, n, col );
}


#define ps_rbox ps_roundrectangle


/***************************************
 ***************************************/

void
ps_oval( int   fill,
         float x,
         float y,
         float w,
         float h,
         long  col )
{
    ps_pieslice( fill, x, y, w, h, 0.0, 3600.0, col );
}


/***************************************
 ***************************************/

void
ps_circ( int   fill,
         float x,
         float y,
         float r,
         long  col )
{
    ps_color( col );
    ps_output( "newpath %.1f %.1f %.1f 0 360 arc %c\n", x, y, r,
               "SF"[ fill ? 1 : 0 ] );
}


/***************************************
 * draw an circular arc, optionally filled. Angle t1 and t2 are in one-tenth of
 * a degree
 ***************************************/

void
ps_arc( int   fill,
        float x,
        float y,
        float r,
        int  t1,
        int   t2,
        long  col )
{
    ps_color( col );
    ps_output( "newpath %.1f %.1f %.1f %.1f %.1f arc %c\n",
               x, y, r, t1 * 0.1, t2 * 0.1, "SF"[ fill ? 1 : 0 ] );
}


/***************************************
 * only fill does a pie slice
 ***************************************/

void
ps_pieslice( int   fill,
             float x,
             float y,
             float w,
             float h,
             int   t1,
             int   t2,
             long  col )
{
    float sx = 1.0,
          sy = ( float ) h / w;

    ps_color( col );
    ps_output( "gsave newpath %.1f %.1f translate %.1f %.1f scale\n",
               x + 0.5 * w, y + 0.5 * h, sx, sy );
    if ( ! fill )
        ps_output( "0 0 %.1f %.1f %.1f arc S grestore\n",
                   w * 0.5, t1 * 0.1, t2 * 0.1 );
    else
        ps_output( "0 0 M 0 0 %.1f %.1f %.1f arc C F grestore\n",
                   w * 0.5, t1 * 0.1, t2 * 0.1 );

    ps_invalidate_color_cache( );
}


/************ End of basic drawing routines ********}******/

/*****************************************************************
 *  Some high level drawing routines
 *************************************************************{***/

/***************************************
 ***************************************/

static void
ps_roundedbox( int   style,
               float x,
               float y,
               float w,
               float h,
               long  col,
               int   bw )
{
    Point point[ 5 * RN + 2 ];
    int n,
        lw = FL_abs( bw ),
        lw2 = lw / 2;

    n = compute_rounded_corners( x + lw2, y + lw2, w - lw, h - lw, point );
    ps_poly( 1, point, n, col );

    ps_set_linewidth( lw, lw );

    if ( style == FL_ROUNDED3D_UPBOX )
    {
        ps_lines( point, 2 * RN, FL_TOP_BCOL );
        ps_lines( point + 2 * RN - 3, RN + 1, FL_TOP_BCOL );
        ps_lines( point + 3 * RN - 4, RN + 2, FL_BOTTOM_BCOL );
        point[ n ] = point[ 0 ];
        ps_lines( point + n - 3, 4, FL_BOTTOM_BCOL );
    }
    else
    {
        ps_lines( point, 2 * RN, FL_BOTTOM_BCOL );
        ps_lines( point + 2 * RN - 3, RN + 1, FL_BOTTOM_BCOL );
        ps_lines( point + 3 * RN - 4, RN + 2, FL_LEFT_BCOL );
        point[ n ] = point[ 0 ];
        ps_lines( point + n - 3, 4, FL_TOP_BCOL );
    }

    ps_reset_linewidth( );
}


/***************************************
 ***************************************/

static void
ps_ovalbox( int   style,
            float x,
            float y,
            float w,
            float h,
            long  col,
            int   bw )
{
    int lw = FL_abs( bw ),
        cr = lw / 2;
    int extra = 1 + ( lw > 3 );
    int xx,
        yy,
        ww,
        hh;

    x += cr;
    y += cr;
    w -= 2 * cr;
    h -= 2 * cr;

    xx = x + extra;
    yy = y + extra;
    ww = w - 2 * extra;
    hh = h - 2 * extra;

    ps_pieslice( 1, x, y, w, h, 0, 3600, col );

    /* this should be replaced by a loop. Faking it with line thickness looks
       bad when w != h */

    if ( style == FL_OVAL3D_UPBOX )
    {
        ps_set_linewidth( bw, bw );

        ps_pieslice( 0, x, y, w, h, 450, 2250, FL_TOP_BCOL );
        ps_pieslice( 0, x, y, w, h, 0, 450, FL_BOTTOM_BCOL );
        ps_pieslice( 0, x, y, w, h, 2250, 3600, FL_BOTTOM_BCOL );
    }
    else if ( style == FL_OVAL3D_FRAMEBOX )
    {
        ps_set_linewidth( 0.9, 0.9 );

        ps_pieslice( 0, x, y, w, h, 450, 2250, FL_BOTTOM_BCOL );
        ps_pieslice( 0, xx, yy, ww, hh, 450, 2250, FL_LEFT_BCOL );
        ps_pieslice( 0, xx, yy, ww, hh, 0, 450, FL_BOTTOM_BCOL );
        ps_pieslice( 0, x, y, w, h, 0, 450, FL_LEFT_BCOL );
        ps_pieslice( 0, xx, yy, ww, hh, 2250, 3600, FL_BOTTOM_BCOL );
        ps_pieslice( 0, x, y, w, h, 2250, 3600, FL_LEFT_BCOL );
    }
    else if ( style == FL_OVAL3D_EMBOSSEDBOX )
    {
        ps_set_linewidth( 0.9, 0.9 );

        ps_pieslice( 0, x, y, w, h, 450, 2250, FL_LEFT_BCOL );
        ps_pieslice( 0, xx, yy, ww, hh, 450, 2250, FL_BOTTOM_BCOL );
        ps_pieslice( 0, xx, yy, ww, hh, 0, 450, FL_LEFT_BCOL );
        ps_pieslice( 0, x, y, w, h, 0, 450, FL_BOTTOM_BCOL );
        ps_pieslice( 0, xx, yy, ww, hh, 2250, 3600, FL_LEFT_BCOL );
        ps_pieslice( 0, x, y, w, h, 2250, 3600, FL_BOTTOM_BCOL );
    }
    else
    {
        ps_set_linewidth( bw, bw );

        ps_pieslice( 0, x, y, w, h, 450, 2250, FL_BOTTOM_BCOL );
        ps_pieslice( 0, x, y, w, h, 0, 450, FL_TOP_BCOL );
        ps_pieslice( 0, x, y, w, h, 2250, 3600, FL_TOP_BCOL );
    }

    ps_reset_linewidth( );
}


#define vv2(x1, y1, x2, y2) AddVertex(xp,x1,y1); AddVertex(xp, x2,y2);
#define vv3(x1, y1, x2, y2, x3, y3) vv2(x1,y1,x2,y2); AddVertex(xp,x3,y3)

#define Corner 4


/***************************************
 ***************************************/

static void
ps_foldertab_box( int   style,
                  float x,
                  float y,
                  float w,
                  float h,
                  long  col,
                  float bw )
{
    float ctr, right, top;
    Point vert[10], *xp;
    int border = ( bw > 0 ),
        i;
    float absbw = FL_abs( bw );
    float C = Corner;

    ctr = absbw / 2;
    x += ctr;
    y += ctr;
    w -= 2 * absbw;
    h -= 2 * absbw;

    right = x + w - 1;
    top = y + h - 1;
    xp = vert;

    switch ( style )
    {
        case FL_TOPTAB_UPBOX :
            vv3( x, y, x, top - C, x + C, top );
            vv2( x + C, top, right - C, top );
            vv3( right - C, top, right, top - C, right, y );
            ps_poly( 1, vert, 8, col );
            ps_set_linewidth( absbw, absbw );
            ps_lines( vert, 3, FL_LEFT_BCOL );
            ps_lines( vert + 3, 2, FL_TOP_BCOL );
            ps_lines( vert + 5, 3, FL_BOTTOM_BCOL );
            ps_reset_linewidth( );
            if ( border )
                for ( i = 0; i < 8; i++ )
                {
                    if ( vert[ i ].x > x + w / 2 )
                        vert[ i ].x += ctr;
                    else
                        vert[ i ].x -= ctr + 1;
                    if ( vert[ i ].y > y + h / 2 )
                        vert[ i ].y += ctr;
                }
            break;

        case FL_SELECTED_TOPTAB_UPBOX :
            vv3( x, y - absbw, x, top - C, x + C, top );
            vv2( x + C, top, right - C, top );
            vv3( right - C, top, right, top - C, right, y - absbw );
            ps_poly( 1, vert, 8, col );
            ps_set_linewidth( absbw, absbw );
            ps_lines( vert, 3, FL_LEFT_BCOL );
            ps_lines( vert + 3, 2, FL_TOP_BCOL );
            ps_lines( vert + 5, 3, FL_BOTTOM_BCOL );
            ps_reset_linewidth( );
            break;

        default:
            break;
    }
}


#define ShrinkBox(x,y,w,h,d) do {x+=d; y+=d; w-=2*d; h-=2*d;} while(0)


/***************************************
 ***************************************/

void
ps_draw_tbox( int   style,
              float x,
              float y,
              float w,
              float h,
              long  col,
              float bw )
{
    Point point[ 8 ],
          *fp;
    float absbw = FL_abs( bw );
    float halfbw = absbw / 2;
    float xc = x + w / 2,
          yc = y + h / 2;

    if ( psinfo.verbose )
        ps_verbatim( "%%TBOX %d: %.1f %.1f %.1f %.1f\n", style, x, y, w, h );

    fp = point;

    switch ( style )
    {
        case FLI_TRIANGLE_UPBOX8 :
            AddVertex(fp, xc, y + h - absbw);
            AddVertex(fp, x + w - bw, y + absbw);
            AddVertex(fp, x + bw, y + bw);
            ps_poly(1, point, 3, col);

            ps_set_linewidth(absbw, absbw);
            ShrinkBox(x, y, w, h, halfbw);
            ps_line(x, y, xc, y + h - 1, FL_LEFT_BCOL);
            ps_line(xc, y + h - 1, x + w - 1, y, FL_RIGHT_BCOL);
            ps_line(x + w - 1, y, x, y, FL_BOTTOM_BCOL);
            ps_reset_linewidth();
            break;

        case FLI_TRIANGLE_UPBOX2 :
            AddVertex(fp, xc, y + absbw);
            AddVertex(fp, xc, y + h - absbw);
            AddVertex(fp, x + w - absbw, y + h - absbw);
            ps_poly(1, point, 3, col);

            ps_set_linewidth(absbw, absbw);
            ShrinkBox(x, y, w, h, halfbw);
            ps_line(xc, y, x, y + h - 1, FL_LEFT_BCOL);
            ps_line(x, y + h - 1, x + w - 1, y + h - 1, FL_TOP_BCOL);
            ps_line(x + w - 1, y + h - 1, xc, y, FL_RIGHT_BCOL);
            ps_reset_linewidth();
            break;

        case FLI_TRIANGLE_UPBOX6:
            AddVertex(fp, x + bw, y + h - bw);
            AddVertex(fp, x + w - bw, yc);
            AddVertex(fp, x + bw, y + bw);
            ps_poly(1, point, 3, col);
            ps_set_linewidth(absbw, absbw);
            ShrinkBox(x, y, w, h, halfbw);
            ps_line(x, y + h - 1, x + w - 1, yc, FL_RIGHT_BCOL);
            ps_line(x + w - 1, yc, x, y, FL_BOTTOM_BCOL);
            ps_line(x, y, x, y + h - 1, FL_LEFT_BCOL);
            ps_reset_linewidth();
            break;

        case FLI_TRIANGLE_UPBOX4:
            AddVertex(fp, x + bw, yc);
            AddVertex(fp, x + w - bw, y + h - bw);
            AddVertex(fp, x + w - bw, y);
            ps_poly(1, point, 3, col);

            ps_set_linewidth(absbw, absbw);
            ShrinkBox(x, y, w, h, halfbw);
            ps_line(x, yc, x + w - 1, y + h - 1, FL_TOP_BCOL);
            ps_line(x + w - 1, y + h - 1, x + w - 1, y, FL_RIGHT_BCOL);
            ps_line(x + w - 1, y, x, yc, FL_BOTTOM_BCOL);
            ps_reset_linewidth();
            break;
    }
}


/***************************************
 ***************************************/

void
ps_draw_box( int   style,
             float x,
             float y,
             float w,
             float h,
             long  col,
             float bw_in )
{
    int border, B;
    Point xpoint[ 8 ], *xp;
    int bw = bw_in;

    if ( ! ( border = ( bw > 0 ) ) )
        bw = -bw;

    B = border;
    xp = xpoint;

    if ( psinfo.verbose )
        ps_verbatim( "%%BOX %d: %.1f %.1f %.1f %.1f\n", style, x, y, w, h );

    switch (style)
    {
        case FL_NO_BOX:
            break;

        case FL_UP_BOX:
            ps_rectf(x + bw, y + bw, w - 2 * bw, h - 2 * bw, col);

            ps_rectf(x + B, y, w - 2 * B, bw + 1, FL_BOTTOM_BCOL);
            ps_rectf(x + B, y + h - 1 - bw, w - 2 * B, bw + 1, FL_TOP_BCOL);

            /* left */

            AddVertex(xp, x + B, y + B);
            AddVertex(xp, x + B, y + h - 1 - B);
            AddVertex(xp, x + bw + B, y + h - 1 - bw - B);
            AddVertex(xp, x + bw + B, y + bw + B);
            ps_poly(1, xpoint, 4, FL_LEFT_BCOL);

            xp = xpoint;
            AddVertex(xp, x + w - 1, y);
            AddVertex(xp, x + w - 1, y + h - 1);
            AddVertex(xp, x + w - 1 - bw, y + h - 1 - bw);
            AddVertex(xp, x + w - 1 - bw, y + bw);
            ps_poly(1, xpoint, 4, FL_RIGHT_BCOL);

            if (border)
                ps_rect(x, y, w, h, FL_BLACK);
            break;

        case FL_DOWN_BOX:
            ps_rectf(x, y, w, h, col);
            ps_rectf(x, y + h - bw, w, bw, FL_BOTTOM_BCOL);
            ps_rectf(x, y, w, bw, FL_TOP_BCOL);

            AddVertex(xp, x, y);
            AddVertex(xp, x, y + h - 1);
            AddVertex(xp, x + bw - 1, y + h - bw);
            AddVertex(xp, x + bw - 1, y + bw - 1);
            ps_poly(1, xpoint, 4, FL_RIGHT_BCOL);

            /* right */

            xp = xpoint;
            AddVertex(xp, x + w - 1, y);
            AddVertex(xp, x + w - 1, y + h - 1);
#if 0
            AddVertex(xp, x + w - 1 - bw, y + h - bw);
            AddVertex(xp, x + w - 1 - bw, y + bw - 1);
#else
            AddVertex(xp, x + w - bw, y + h - bw);
            AddVertex(xp, x + w - bw, y + bw - 1);
#endif
            ps_poly(1, xpoint, 4, FL_LEFT_BCOL);
            break;

        case FL_FRAME_BOX:
            ps_rectf(x, y, w, h, col);
            ps_start_lw(1.1, 1.1);
            ps_rect(x + 1.4, y, w - 1.4, h - 1.4, FL_TOP_BCOL);
            ps_end_lw();
            ps_rect(x, y + 1.4, w - 1.4, h - 1.4, FL_BOTTOM_BCOL);
            break;

        case FL_EMBOSSED_BOX:
            ps_rectf(x, y, w, h, col);
            ps_start_lw(1.1, 1.1);
            ps_rect(x + 1.4, y, w - 1.4, h - 1.4, FL_BOTTOM_BCOL);
            ps_end_lw();
            ps_rect(x, y + 1.4, w - 1.4, h - 1.4, FL_TOP_BCOL);
            break;

        case FL_FLAT_BOX:
            ps_rectf(x, y, w, h, col);
            break;

        case FL_SHADOW_BOX:
            if (w > 100 && h > 100)
                bw++;
            ps_rectf(x + bw, y + bw, w - bw, -bw, FL_BOTTOM_BCOL);
            ps_rectf(x + w - 1, y, -bw, h - bw - 1, FL_BOTTOM_BCOL);
            ps_rectf(x, y + bw, w - bw, h - bw, col);
            ps_rect(x, y + bw, w - bw, h - bw, FL_BLACK);
            break;

        case FL_BORDER_BOX:
            ps_rectf(x, y, w, h, col);
            ps_rect(x, y, w, h, FL_BLACK);
            break;

        case FL_RFLAT_BOX:
            ps_rbox(1, x, y, w, h, col);
            break;

        case FL_ROUNDED_BOX:
            ps_rbox(1, x, y, w, h, col);
            ps_rbox(0, x, y, w, h, FL_BLACK);
            break;

        case FL_ROUNDED3D_UPBOX:
        case FL_ROUNDED3D_DOWNBOX:
            ps_roundedbox(style, x, y, w, h, col, bw);
            break;

        case FL_RSHADOW_BOX:
            ps_rbox(1, x + bw, y - 1, w - bw + 1, h - bw, FL_BOTTOM_BCOL);
            ps_rbox(1, x, y + bw - 1, w - bw + 1, h - bw + 1, col);
            ps_rbox(0, x, y + bw - 1, w - bw + 1, h - bw + 1, FL_BLACK);
            break;

        case FL_OVAL_BOX:
            ps_oval(1, x, y, w, h, col);
            ps_oval(0, x, y, w, h, FL_BLACK);
            break;

        case FL_OVAL3D_UPBOX:
        case FL_OVAL3D_DOWNBOX:
        case FL_OVAL3D_FRAMEBOX:
        case FL_OVAL3D_EMBOSSEDBOX:
            ps_ovalbox(style, x, y, w, h, col, bw);
            break;

        case FL_TOPTAB_UPBOX:
        case FL_SELECTED_TOPTAB_UPBOX:
        case FL_BOTTOMTAB_UPBOX:
        case FL_SELECTED_BOTTOMTAB_UPBOX:
            ps_foldertab_box(style, x, y, w, h, col, bw_in);
            break;

        default:
            fprintf(stderr, "Unknown Boxtype %d\n", style);
            break;
    }
}


/***************************************
 * Frame is drawn OUTSIDE of the bounding box
 ***************************************/

void
ps_draw_frame( int   style,
               float x,
               float y,
               float w,
               float h,
               long  col  FL_UNUSED_ARG,
               int bw )
{
    int border;
    float B;
    Point xpoint[ 10 ], *xp;

    if ( ! ( border = ( bw > 0 ) ) )
        bw = -bw;

    B = border;

    if ( psinfo.verbose )
        ps_verbatim( "%%frame (%.2f %.2f %.2f %.2f)\n", x, y, w, h );

    switch ( style )
    {
        case FL_UP_FRAME:
            ps_rectf( x - bw - B, y + h - 1, w + 2 * bw, bw + 1 + B,
                      FL_TOP_BCOL);
            ps_rectf( x - bw - B, y - bw - B, w + 2 * bw, bw + 1 + B,
                      FL_BOTTOM_BCOL);

            /* left */

            xp = xpoint;
            AddVertex( xp, x - bw - B, y - bw - B );
            AddVertex( xp, x, y );
            AddVertex( xp, x, y + h - 1 );
            AddVertex( xp, x - bw - B, y + h + bw + B - 1 );
            ps_poly( 1, xpoint, 4, FL_LEFT_BCOL );

            /* right */

            xp = xpoint;
            AddVertex( xp, x + w - 1 + bw + B, y - bw - B );
            AddVertex( xp, x + w - 1 + bw + B, y + h + bw + B - 1 );
            AddVertex( xp, x + w - 1, y + h - 1 );
            AddVertex( xp, x + w - 1, y );
            ps_poly( 1, xpoint, 4, FL_RIGHT_BCOL );
            break;

        case FL_DOWN_FRAME:
            ps_rectf( x - bw - B, y + h - 1, w + 2 * bw, bw + 1 + B,
                      FL_BOTTOM_BCOL);
            ps_rectf( x - bw - B, y - bw - B, w + 2 * bw, bw + 1 + B,
                      FL_TOP_BCOL);

            /* left */

            xp = xpoint;
            AddVertex( xp, x - bw - B, y - bw - B );
            AddVertex( xp, x, y );
            AddVertex( xp, x, y + h - 1 );
            AddVertex( xp, x - bw - B, y + h + bw + B - 1 );
            ps_poly( 1, xpoint, 4, FL_RIGHT_BCOL );

            /* right */

            xp = xpoint;
            AddVertex( xp, x + w - 1 + bw + B, y - bw - B );
            AddVertex( xp, x + w - 1 + bw + B, y + h + bw + B - 1 );
            AddVertex( xp, x + w - 1, y + h - 1 );
            AddVertex( xp, x + w - 1, y );
            ps_poly( 1, xpoint, 4, FL_LEFT_BCOL );
            break;

        case FL_ENGRAVED_FRAME:
            B = ( bw > 2 ? ( bw - 2 ) : 1 );
            B *= 0.5;
            ps_draw_frame( FL_DOWN_FRAME, x, y, w, h, 0, 1 );
            ps_draw_frame( FL_UP_FRAME, x + B, y + B, w - 2 * B,
                           h - 2 * B, 0, -1 );
            break;
    }
}


/***************************************
 ***************************************/

void
ps_draw_checkbox( int   type,
                  float x,
                  float y,
                  float w,
                  float h,
                  long  col,
                  int   bw )
{
    Point xpoint[6], *xp;
    Point allp[10];

    /* generate all points */

    xp = allp;
    AddVertex( xp, x + w / 2, y );
    AddVertex( xp, x, y + h / 2 );
    AddVertex( xp, x + w / 2, y + h );
    AddVertex( xp, x + w, y + h / 2 );

    AddVertex( xp, x + w / 2, y + bw );
    AddVertex( xp, x + bw, y + h / 2 );
    AddVertex( xp, x + w / 2, y + h - bw );
    AddVertex( xp, x + w - bw, y + h / 2 );

    /* draw overall box */

    xp = allp + 4;
    ps_poly( 1, xp, 4, col );
    xp = xpoint;

    switch ( type )
    {
        case FL_DOWN_BOX :
            AddVertex( xp, allp[ 0 ].x, allp[ 0 ].y );
            AddVertex( xp, allp[ 1 ].x, allp[ 1 ].y );
            AddVertex( xp, allp[ 5 ].x, allp[ 5 ].y );
            AddVertex( xp, allp[ 4 ].x, allp[ 4 ].y );
            ps_poly( 1, xp = xpoint, 4, FL_LEFT_BCOL );

            AddVertex(xp, allp[0].x, allp[0].y);
            AddVertex(xp, allp[4].x, allp[4].y);
            AddVertex(xp, allp[7].x, allp[7].y);
            AddVertex(xp, allp[3].x, allp[3].y);
            ps_poly(1, xp = xpoint, 4, FL_TOP_BCOL);

            /* right bottom */

            AddVertex(xp, allp[6].x, allp[6].y);
            AddVertex(xp, allp[2].x, allp[2].y);
            AddVertex(xp, allp[3].x, allp[3].y);
            AddVertex(xp, allp[7].x, allp[7].y);
            ps_poly(1, xp = xpoint, 4, FL_RIGHT_BCOL);

            AddVertex(xp, allp[1].x, allp[1].y);
            AddVertex(xp, allp[2].x, allp[2].y);
            AddVertex(xp, allp[6].x, allp[6].y);
            AddVertex(xp, allp[5].x, allp[5].y);
            ps_poly(1, xp = xpoint, 4, FL_BOTTOM_BCOL);
            break;

        case FL_UP_BOX:
            AddVertex(xp, allp[0].x, allp[0].y);
            AddVertex(xp, allp[1].x, allp[1].y);
            AddVertex(xp, allp[5].x, allp[5].y);
            AddVertex(xp, allp[4].x, allp[4].y);
            ps_poly(1, xp = xpoint, 4, FL_BOTTOM_BCOL);

            AddVertex(xp, allp[0].x, allp[0].y);
            AddVertex(xp, allp[4].x, allp[4].y);
            AddVertex(xp, allp[7].x, allp[7].y);
            AddVertex(xp, allp[3].x, allp[3].y);
            ps_poly(1, xp = xpoint, 4, FL_RIGHT_BCOL);

            /* right bottom */

            AddVertex(xp, allp[6].x, allp[6].y);
            AddVertex(xp, allp[2].x, allp[2].y);
            AddVertex(xp, allp[3].x, allp[3].y);
            AddVertex(xp, allp[7].x, allp[7].y);
            ps_poly(1, xp = xpoint, 4, FL_LEFT_BCOL);

            AddVertex(xp, allp[1].x, allp[1].y);
            AddVertex(xp, allp[2].x, allp[2].y);
            AddVertex(xp, allp[6].x, allp[6].y);
            AddVertex(xp, allp[5].x, allp[5].y);
            ps_poly(1, xp = xpoint, 4, FL_TOP_BCOL);
            break;
    }

    if (psinfo.verbose)
        ps_verbatim("%%BOX }\n");
}

/******* End of high-level drawing routines **********}******/


/************** Handle built-in symbols. ****************{*/

typedef void ( *PSdrawit ) ( float, float, float, float, int, long );

typedef struct {
    const char * name;
    const char * psname;
    const char * draw;
    int          otherdef;
    PSdrawit     fdrawit;
    int          abs_coordinate;    /* fdrawit uses abs coordinate system */
    int          defined;           /* if def code emitted                */
} PS_draw;


/***************************************
 ***************************************/

static void
draw_dnline( float x      FL_UNUSED_ARG,
             float y      FL_UNUSED_ARG,
             float w,
             float h,
             int   angle  FL_UNUSED_ARG,
             long  col    FL_UNUSED_ARG )
{
    float t = 0.20;
    float len;

    ps_output("%.3f %.3f LW ", 3.5 / (w + h), 3.5 / (w + h));
    if ((w + h) > 200)
        len = 0.99;
    else if ((w + h) > 150)
        len = 0.98;
    else
        len = 0.93;

    ps_color(FL_RIGHT_BCOL);
    ps_output("-%.3f %.2f M %.3f %.2f LT S\n", len, t, len, t);
    ps_color(FL_LEFT_BCOL);
    ps_output("-%.3f -%.2f M %.3f -%.2f LT S\n", len, t, len, t);
}


/***************************************
 ***************************************/

static void
draw_upline( float x      FL_UNUSED_ARG,
             float y      FL_UNUSED_ARG,
             float w,
             float h,
             int   angle  FL_UNUSED_ARG,
             long  col    FL_UNUSED_ARG )
{
    float t = 0.033;

    ps_color(FL_LEFT_BCOL);
    ps_output("%.3f %.3f LW ", 3.7 / (w + h), 3.7 / (w + h));
    ps_output("-0.9 %.3f M 0.9 %.3f LT S\n", t, t);
    ps_color(FL_RIGHT_BCOL);
    ps_output("0.9 -%.3f M 0.9 %.3f LT S ", t, t);
    ps_output("-0.9 -%.3f M 0.9 -%.3f LT S\n", t, t);
}


/***************************************
 * due to pixel precision problems, we have to draw uparrow, downarrow
 * and ripple line in absolute unit with the origin
 * at the center of the figure.
 ***************************************/

static void
draw_uparrow( float x,
              float y,
              float w,
              float h,
              int angle,
              long col  FL_UNUSED_ARG )
{
    float yc = y + h * 0.5;
    float xc = x + w * 0.5;
    float dx, dy;
    int d = 3 + (w + h) * 0.06;

    dx = w / 2 - d;
    dy = h / 2 - d;

    if ( angle == 90 )
    {
        ps_line( xc,      yc + dy, xc - dx, yc - dy, FL_LEFT_BCOL   );
        ps_line( xc - dx, yc - dy, xc + dx, yc - dy, FL_BOTTOM_BCOL );
        ps_line( xc + dx, yc - dy, xc,      yc + dy, FL_RIGHT_BCOL  );
    }
    else if ( angle == 180 )
    {
        ps_line( xc - dx, yc,      xc + dx, yc + dy, FL_TOP_BCOL );
        ps_line( xc + dx, yc + dy, xc + dx, yc - dy, FL_RIGHT_BCOL );
        ps_line( xc + dx, yc - dy, xc - dx, yc,      FL_BOTTOM_BCOL );
    }
    else if (angle == 270)
    {
        ps_line( xc - dx, yc + dy, xc,      yc - dy, FL_BOTTOM_BCOL );
        ps_line( xc,      yc - dy, xc + dx, yc + dy, FL_RIGHT_BCOL  );
        ps_line( xc + dx, yc + dy, xc - dx, yc + dy, FL_TOP_BCOL    );
        
    }
    else
    {
        ps_line( xc - dx, yc + dy, xc + dx, yc,      FL_BOTTOM_BCOL );
        ps_line( xc - dx, yc - dy, xc + dx, yc,      FL_RIGHT_BCOL  );
        ps_line( xc - dx, yc - dy, xc - dx, yc + dy, FL_LEFT_BCOL   );
    }
}


/***************************************
 ***************************************/

static void
draw_dnarrow( float x,
              float y,
              float w,
              float h,
              int   angle,
              long  col  FL_UNUSED_ARG )
{
    float yc = y + h * 0.5;
    float xc = x + w * 0.5;
    float dx, dy;
    int d = 3 + ( w + h ) * 0.06;

    dx = w / 2 - d;
    dy = h / 2 - d;

    if ( angle == 90 )
    {
        ps_line( xc,      yc + dy, xc - dx, yc - dy, FL_RIGHT_BCOL );
        ps_line( xc - dx, yc - dy, xc + dx, yc - dy, FL_TOP_BCOL   );
        ps_line( xc + dx, yc - dy, xc,      yc + dy, FL_TOP_BCOL   );
    }
    else if ( angle == 180 )
    {
        ps_line( xc - dx, yc,      xc + dx, yc + dy, FL_RIGHT_BCOL );
        ps_line( xc + dx, yc + dy, xc + dx, yc - dy, FL_LEFT_BCOL  );
        ps_line( xc + dx, yc - dy, xc - dx, yc,      FL_TOP_BCOL   );

    }
    else if ( angle == 270 )
    {
        ps_line( xc - dx, yc + dy, xc,      yc - dy, FL_RIGHT_BCOL  );
        ps_line( xc,      yc - dy, xc + dx, yc + dy, FL_LEFT_BCOL   );
        ps_line( xc + dx, yc + dy, xc - dx, yc + dy, FL_BOTTOM_BCOL );

    }
    else
    {
        ps_line( xc - dx, yc - dy, xc - dx, yc + dy, FL_RIGHT_BCOL );
        ps_line( xc - dx, yc - dy, xc + dx, yc,      FL_TOP_BCOL    );
        ps_line( xc - dx, yc + dy, xc + dx, yc,      FL_BOTTOM_BCOL );
    }
}


/***************************************
 * need single pixel precision, draw in abs. coordiante system
 ***************************************/

static void
draw_ripple_lines( float x,
                   float y,
                   float w,
                   float h,
                   int   angle,
                   long  col  FL_UNUSED_ARG )
{
    float ym = y + h / 2, ys;
    float xm = x + w / 2, xs;
    int mw = FL_BOUND_WIDTH;

    if (h < 9 || w < 9)
    {
        fprintf(stderr, "RippledLine: Area too small\n");
        return;
    }

    xs = xm + 5;
    ys = ym + 5;

    if (angle == 90 || angle == 270)
    {
        int i;

        for ( i = 0; i < 3; i++ )
        {
            ps_line(xs, y + mw, xs, y + h - mw - 1, FL_RIGHT_BCOL);
            xs -= 1;
            ps_line(xs, y + mw, xs, y + h - mw - 1, FL_LEFT_BCOL);
            xs -= 3;
        }
    }
    else
    {
        int i;

        for (i = 0; i < 3; i++)
        {
            ps_line(x + mw, ys, x + w - mw - 1, ys, FL_LEFT_BCOL);
            ys -= 1;
            ps_line(x + mw, ys, x + w - mw - 1, ys, FL_RIGHT_BCOL);
            ys -= 3;
        }
    }
}


/***************************************
 ***************************************/

static void
draw_bararrowhead( float x,
                   float y,
                   float w,
                   float h,
                   int   angle,
                   long  col )
{
    float xc = x + 0.5 * w,
          yc = y + 0.5 * h;
    int d = 3 + 0.06 * (w + h);
    float dx,
          dy,
          mar,
          dbar,
          xl;
    Point point[ 5 ],
          *p;

    dx = w / 2 - d;
    dy = h / 2 - d;

    dbar = dx * 0.4;
    mar  = 0.2 * dx;

    ps_output( "gsave %.1f %.1f translate %d rotate\n", xc, yc, angle );

    xl = -dx + 1.1 * mar;
    p = point;
    AddVertex( p, xl,        - dy );
    AddVertex( p, xl + dbar, - dy );
    AddVertex( p, xl + dbar,   dy );
    AddVertex( p, xl,          dy );
    ps_poly( 1, point, 4, col );
    ps_poly( 0, point, 4, FL_RIGHT_BCOL );

    p = point;
    AddVertex( p, - mar,      - dy );
    AddVertex( p, - mar + dx,   0  );
    AddVertex( p, - mar,        dy ) ;
    ps_poly( 1, point, 3, col );
    ps_poly( 0, point, 3, FL_RIGHT_BCOL );

    ps_output( "grestore\n" );
}


/* all PS drawings have a size of 2 pixels and centered at origin */

static PS_draw psdraw[] =
{
    {"returnarrow", "returnarrow",
     "-0.8 0.0 -0.1 0.7 -0.1 0.05 0.6 0.05 0.6 0.7 0.7 0.7 0.7 -0.05\n"
     "-0.1 -0.05 -0.1 -0.7 9 P", 0, 0, 0, 0
    },

    {"->", "rarrow",
     "-0.8 -0.4 -0.8 0.4 0 0.4 0 0.8 0.8 0 0 -0.8 0 -0.4 7 P", 0, 0, 0, 0
    },
    {"<-", "180 rotate", 0, -1, 0, 0, 0},

    {">", "rarrowh", "-0.2 0.7 M 0.5 0.0 LT -0.2 -0.7 LT C", 0, 0, 0, 0},
    {"<", "180 rotate", 0, -1, 0, 0, 0},

    {"<->", "darrow",
     "-0.25 0.4 0.25 0.4 0.25 0.8 0.85 0 0.25 -0.8 0.25 -0.4 -0.25 -0.4\n"
     "-0.25 -0.8 -0.85 0 -0.25 0.8 10 P", 0, 0, 0, 0
    },

    {"plus", "plus",
     "-0.9 -0.13 -0.9 0.13 -0.13 0.13 -0.13 0.9 0.13 0.9 0.13 0.13 0.9 0.13\n"
     "0.9 -0.13 0.13 -0.13 0.13 -0.9 -0.13 -0.9 -0.13 -0.13 12 P", 0, 0, 0, 0
    },

    {">>", "darrowh",
     "0.15 0.7 0.85 0 0.15 -0.7 0.15 -0.001 -0.55 -0.7 -0.55 0.7 0.15 0.001\n"
     "7 P", 0, 0, 0, 0
    },
    {"<<", "180 rotate", 0, -1, 0, 0, 0},

    {"arrow", "thinarrow",
     "-0.9 0.02 M 0.65 0.02 LT 0.65 0.15 LT 0.9 0 LT 0.65 -0.15 LT\n"
     "0.65 -0.02 LT -0.9 -0.02 LT C", 0, 0, 0, 0
    },

    {"circle", "circle", "0 0 0.77 0 360 arc", 0, 0, 0, 0},

    {"square", "square",
     "-0.77 -0.77 M -0.77 0.77 LT 0.77 0.77 LT 0.77 -0.77 LT C", 0, 0, 0, 0
    },

    {"line", "line",
     "-0.97 0.01 M  0.97 0.01 LT 0.97 -0.01 LT -0.08 -0.01 LT C", 0, 0, 0, 0
    },

    {"->|", "arrowbar",
     "-0.75 0.35 -0.1 0.35 -0.1 0.75 0.6 0.001 0.6 0.75 0.75 0.75\n"
     " 0.75 -0.75 0.6 -0.75 0.6 -0.001 -0.1 -0.75 -0.1 -0.35 -0.75 -0.35 12 P\n",
     0, 0, 0, 0
    },

    {"|<-", "180 rotate", 0, -1, 0, 0, 0},

    {">|", "arrowheadbar",  /* bar 0.25 */
     "-0.60 0.7 0.22 0.001 0.22 0.7 0.47 0.7 0.47 -0.7 0.22 -0.7\n"
     " 0.22 -0.001 -0.60 -0.7 8 P", 0, 0, 0, 0
    },

    {"|<", "180 rotate", 0, -1, 0, 0, 0},

    {"|>", "bararrowhead", 0, -1, draw_bararrowhead, 1, 0},
    {"DnLine", "dnline", 0, -1, draw_dnline, 0, 0},
    {"dnline", "dnline", 0, -1, draw_dnline, 0, 0},
    {"UpLine", "upline", 0, -1, draw_upline, 0, 0},
    {"upline", "upline", 0, -1, draw_upline, 0, 0},
    {"UpArrow", "uparrow", 0, -1, draw_uparrow, 1, 0},
    {"DnArrow", "dnarrow", 0, -1, draw_dnarrow, 1, 0},
    {"=", "RippleLines", 0, -1, draw_ripple_lines, 1, 0},

 /* aliases */
    {"RippleLines", "RippleLines", 0, -1, draw_ripple_lines, 1, 0},

    {"+", "plus",
   "-0.9 -0.13 -0.9 0.13 -0.13 0.13 -0.13 0.9 0.13 0.9 0.13 0.13 0.9 0.13\n"
     "0.9 -0.13 0.13 -0.13 0.13 -0.9 -0.13 -0.9 -0.13 -0.13 12 P",
     0, 0, 0, 0
    },

    {"-->", "thinarrow",
     "-0.9 0.02 M 0.65 0.02 LT 0.65 0.15 LT 0.9 0 LT 0.65 -0.15 LT\n"
     "0.65 -0.02 LT -0.9 -0.02 LT C", 0, 0, 0, 0
    }
};


/***************************************
 ***************************************/

static void
define_symbol( PS_draw * p )
{
    if ( ! p->defined && ! p->fdrawit )
    {
        if ( p->otherdef )
            define_symbol( p + p->otherdef );
        else
            ps_output( "/%s {%s} bind def\n", p->psname, p->draw );
        p->defined = 1;
    }
}


/***************************************
 ***************************************/

static PS_draw *
find( const char *s )
{
    PS_draw *p = psdraw,
            *ps = psdraw + sizeof psdraw / sizeof *psdraw;

    for ( ; p < ps; p++ )
        if ( strcmp( s, p->name ) == 0 )
        {
            define_symbol( p );
            return p;
        }

    return 0;
}

#define swapit( t, a, b ) do { t t_; t_ = a; a = b; b = t_; } while( 0 )


/***************************************
 ***************************************/

int
ps_draw_symbol( const char * label,
                float        x,
                float        y,
                float        w,
                float        h,
                long         col )
{
    int pos,
        shift,
        equalscale = 0;
    short defr[] = { 0, 225, 270, 315, 180, 0, 0, 135, 90, 45 };
    PS_draw *s;
    int rotated = 0;
    int sw = w, sh = h;
    int delta = 0;

    if ( ! label || *label != '@' )
        return 0;

    if ( psinfo.verbose )
        ps_verbatim( "%%Symbol %s: %.1f %.1f %.1f %.1f\n",
                     label + 1, x, y, w, h );

    x += 1.2;
    y += 1.2;
    w -= 2.4;
    h -= 2.4;

    /* check special operators */

    pos = 1;
    while (    ( label[ pos ] == '-' && isdigit( label[ pos + 1 ] ) )
            || ( label[ pos ] == '+' && isdigit( label[ pos + 1 ] ) )
            || label[ pos ] == '#' )
    {
        switch ( label[ pos ] )
        {
            case '+':
                delta = '0' - label[ ++pos ];
                break;

            case '-':
                delta = label[ ++pos ] - '0';
                break;

            case '#':
                equalscale = 1;
                break;
        }

        pos++;
    }

    shift = pos;

    if ( label[ pos ] >= '1' && label[ pos ] <= '9' )
    {
        rotated = defr[ label[ pos ] - '0' ];
        shift = pos + 1;
    }
    else if ( label[ pos ] == '0' )
    {
        rotated =   100 * ( label[ pos + 1 ] - '0' )
                  +  10 * ( label[ pos + 2 ] - '0' )
                  +   1 * ( label[ pos + 3 ] - '0' );
        shift = pos + 4;
    }

    /* short hand with @4 etc */

    if ( ! ( s = ( label[ shift ] ? find( label + shift ) : psdraw ) ) )
    {
        fprintf( stderr, "Bad label %s\n", label + shift );
        if ( psinfo.verbose )
            ps_verbatim( "%% unknown symbol %s. Not drawn\n", label );
        return 0;
    }

    if ( equalscale )
        sw = sh = FL_min( w, h );

    if ( delta )
    {
        if ( s->abs_coordinate )
        {
            x += delta;
            y += delta;
        }

        sw -= 2 * delta;
        sh -= 2 * delta;
    }

    if ( ! s->abs_coordinate )
        ps_output( "gsave\n%.1f %.1f translate %.1f %.1f scale %d rotate "
                   "%.3f %.3f LW\n",
                   x + 0.5 * w, y + 0.5 * h, 0.45 * sw, 0.45 * sh, rotated,
                   3.2 / ( sw + sh ), 3.2 / ( sh + sw ) );

    if ( s->fdrawit )
    {
        s->fdrawit( x, y, w, h, rotated, col );
        if (!s->abs_coordinate)
            ps_output( "grestore\n" );
        ps_invalidate_color_cache( );
        return 1;
    }

    if ( s->otherdef )
    {
        ps_output( "%s ", s->psname );
        s = s + s->otherdef;
    }

    ps_color( col );
    ps_output( "%s F ", s->psname );
    ps_color( FL_BLACK );
    ps_output( "%s S\n", s->psname );
    ps_output( "grestore\n" );
    ps_invalidate_color_cache( );
    return 1;
}

/********************** end of symbols *************************}*/


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
