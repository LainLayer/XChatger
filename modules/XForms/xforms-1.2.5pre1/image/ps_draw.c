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
 *  Copyright (c) 1997-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Some high-level drawing routines
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pflps.h"

#if defined __GNUC__
#define FL_UNUSED_ARG __attribute__ ((unused))
#else
#define FL_UNUSED_ARG
#endif


/* rectangle with rounded corners */

#define RS 16

/*
 * 0.0, 0.034074, 0.1339746, 0.292893, 0.5, 0.741181, 1.0
 */

static float offset[ ] = { 0.0, 0.07612, 0.29289, 0.61732, 1.0 };

#define RN   ( sizeof offset / sizeof *offset )


/***************************************
 ***************************************/

static int
compute_rounded_corners( FL_Coord   x,
                         FL_Coord   y,
                         FL_Coord   w,
                         FL_Coord   h,
                         FL_POINT * point )
{
    FL_POINT *xp;
    size_t i,
           n;
    float rsx,
          rsy;

    rsx = rsy = 0.42 * FL_min( w, h );

    if ( rsx > RS )
        rsx = rsy = RS;

    for ( xp = point, n = i = 0; i < RN; i++, n++, xp++ )
    {
        xp->x = FL_nint( x + offset[ RN - i - 1 ] * rsx );
        xp->y = FL_nint( y + offset[ i ] * rsy );
    }

    for ( i = 0; i < RN; i++, n++, xp++ )
    {
        xp->x = FL_nint( x + offset[ i ] * rsx );
        xp->y = FL_nint( y + h - 1.0 - offset[ RN - i - 1 ] * rsy );
    }

    for ( i = 0; i < RN; i++, n++, xp++ )
    {
        xp->x = FL_nint( x + w - 1.0 - offset[ RN - i - 1 ] * rsx );
        xp->y = FL_nint( y + h - 1.0 - offset[ i ] * rsy );
    }

    for ( i = 0; i < RN; i++, n++, xp++ )
    {
        xp->x = FL_nint( x + w - 1.0 - offset[ i ] * rsx );
        xp->y = FL_nint( y + offset[ RN - i - 1 ] * rsy );
    }

    return n;
}


#define AddVertex( p, xp, yp )    \
    do {                          \
        p->x = xp;                \
        p->y = yp;                \
        p++;                      \
    } while ( 0 )


/***************************************
 ***************************************/

void
flps_roundrectangle( int      fill,
                     int      x,
                     int      y,
                     int      w,
                     int      h,
                     FL_COLOR col )
{
    FL_POINT point[ 5 * RN ];
    int n;

    n = compute_rounded_corners( x, y, w, h, point );
    flps_poly( fill, point, n, col );
}


#define flps_rbox flps_roundrectangle


/************ End of basic drawing routines ********}******/

/*****************************************************************
 *  Some high level drawing routines
 *************************************************************{***/

static void
flps_roundedbox( int      style,
                 int      x,
                 int      y,
                 int      w,
                 int      h,
                 FL_COLOR col,
                 int      bw )
{
    FL_POINT point[ 5 * RN + 2 ];
    int n,
        lw = FL_abs( bw ),
        lw2 = lw / 2;

    n = compute_rounded_corners( x + lw2, y + lw2, w - lw, h - lw, point );
    flps_poly( 1, point, n, col );

    flps_linewidth( lw );

    if ( style == FL_ROUNDED3D_UPBOX )
    {
        flps_lines( point, 2 * RN, FL_TOP_BCOL );
        flps_lines( point + 2 * RN - 3, RN + 1, FL_TOP_BCOL );
        flps_lines( point + 3 * RN - 4, RN + 2, FL_BOTTOM_BCOL );
        point[ n ] = point[ 0 ];
        flps_lines( point + n - 3, 4, FL_BOTTOM_BCOL );
    }
    else
    {
        flps_lines( point, 2 * RN, FL_BOTTOM_BCOL );
        flps_lines( point + 2 * RN - 3, RN + 1, FL_BOTTOM_BCOL );
        flps_lines( point + 3 * RN - 4, RN + 2, FL_LEFT_BCOL );
        point[ n ] = point[ 0 ];
        flps_lines( point + n - 3, 4, FL_TOP_BCOL );
    }

    flps_reset_linewidth();

}


/***************************************
 ***************************************/

static void
flps_ovalbox( int      style,
              int      x,
              int      y,
              int      w,
              int      h,
              FL_COLOR col,
              int      bw )
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

    flps_pieslice( 1, x, y, w, h, 0, 3600, col );

    /* this should be replaced by a loop. Faking it with line thickness looks
       bad when w != h */

    if ( style == FL_OVAL3D_UPBOX )
    {
        flps_linewidth( bw );
        flps_pieslice( 0, x, y, w, h, 450, 2250, FL_TOP_BCOL );
        flps_pieslice( 0, x, y, w, h, 0, 450, FL_BOTTOM_BCOL );
        flps_pieslice( 0, x, y, w, h, 2250, 3600, FL_BOTTOM_BCOL );
    }
    else if ( style == FL_OVAL3D_FRAMEBOX )
    {
        flps_linewidth( 1 );
        flps_pieslice( 0, x, y, w, h, 450, 2250, FL_BOTTOM_BCOL );
        flps_pieslice( 0, xx, yy, ww, hh, 450, 2250, FL_LEFT_BCOL );
        
        flps_pieslice( 0, xx, yy, ww, hh, 0, 450, FL_BOTTOM_BCOL );
        flps_pieslice( 0, x, y, w, h, 0, 450, FL_LEFT_BCOL );

        flps_pieslice( 0, xx, yy, ww, hh, 2250, 3600, FL_BOTTOM_BCOL );
        flps_pieslice( 0, x, y, w, h, 2250, 3600, FL_LEFT_BCOL );
    }
    else if ( style == FL_OVAL3D_EMBOSSEDBOX )
    {
        flps_linewidth( 1 );

        flps_pieslice( 0, x, y, w, h, 450, 2250, FL_LEFT_BCOL );
        flps_pieslice( 0, xx, yy, ww, hh, 450, 2250, FL_BOTTOM_BCOL );

        flps_pieslice( 0, xx, yy, ww, hh, 0, 450, FL_LEFT_BCOL );
        flps_pieslice( 0, x, y, w, h, 0, 450, FL_BOTTOM_BCOL );

        flps_pieslice( 0, xx, yy, ww, hh, 2250, 3600, FL_LEFT_BCOL );
        flps_pieslice( 0, x, y, w, h, 2250, 3600, FL_BOTTOM_BCOL );
    }
    else
    {
        flps_linewidth( bw );

        flps_pieslice( 0, x, y, w, h, 450, 2250, FL_BOTTOM_BCOL );
        flps_pieslice( 0, x, y, w, h, 0, 450, FL_TOP_BCOL );
        flps_pieslice( 0, x, y, w, h, 2250, 3600, FL_TOP_BCOL );
    }

    flps_reset_linewidth( );
}


#define vv2( x1, y1, x2, y2 )      \
    do {                           \
        AddVertex( xp, x1, y1 );   \
        AddVertex( xp, x2, y2 );   \
    } while ( 0 )

#define vv3( x1, y1, x2, y2, x3, y3 )   \
    do {                                \
        vv2( x1, y1, x2, y2 );          \
        AddVertex( xp, x3, y3);         \
    } while ( 0 )


/***************************************
 ***************************************/

static void
flps_foldertab_box( int      style,
                    int      x,
                    int      y,
                    int      w,
                    int      h,
                    FL_COLOR col,
                    int      bw )
{
    float ctr,
          right,
          top;
    FL_POINT vert[ 10 ],
             *xp;
    int border = ( bw > 0 );
    int i;
    float absbw = FL_abs( bw );
    float C = 4;
    int savelw = fl_get_linewidth( );

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
            vv3( x,         y,           x, top - C, x + C, top );
            vv2( x + C,     top, right - C, top );
            vv3( right - C, top, right,     top - C, right, y );
            flps_poly( 1, vert, 8, col );
            flps_linewidth( absbw );
            flps_lines( vert,     3, FL_LEFT_BCOL   );
            flps_lines( vert + 3, 2, FL_TOP_BCOL    );
            flps_lines( vert + 5, 3, FL_BOTTOM_BCOL );
            flps_reset_linewidth( );

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
            vv3( x,         y - absbw, x,          top - C, x + C, top );
            vv2( x + C,     top,       right - C,  top );
            vv3( right - C, top,       right,      top - C, right, y - absbw );
            flps_poly( 1, vert, 8, col );
            flps_linewidth( absbw );
            flps_lines( vert,     3, FL_LEFT_BCOL   );
            flps_lines( vert + 3, 2, FL_TOP_BCOL    );
            flps_lines( vert + 5, 3, FL_BOTTOM_BCOL );
            break;

        default:
            break;
    }

    flps_linewidth( savelw );
}


#define ShrinkBox( x, y, w, h, d )     \
    do {                               \
        x += d;                        \
        y += d;                        \
        w -= 2 * d;                    \
        h -= 2 * d;                    \
    } while ( 0 )


/***************************************
 ***************************************/

void
flps_draw_tbox( int      style,
                int      x,
                int      y,
                int      w,
                int      h,
                FL_COLOR col,
                int      bw )
{
    FL_POINT point[ 8 ],
             *fp;
    int absbw = FL_abs( bw );
    int halfbw = absbw / 2;
    int xc = x + w / 2,
        yc = y + h / 2;

    if ( flps->verbose )
        fprintf( flps->fp, "%%TBOX %d: %d %d %d %d\n", style, x, y, w, h );

    fp = point;

    switch ( style )
    {
        case FLI_TRIANGLE_UPBOX8 :
            AddVertex( fp, xc, y + h - absbw );
            AddVertex( fp, x + w - bw, y + absbw );
            AddVertex( fp, x + bw, y + bw );
            flps_poly( 1, point, 3, col );

            flps_linewidth( absbw );
            ShrinkBox( x, y, w, h, halfbw );
            flps_line( x, y, xc, y + h - 1, FL_LEFT_BCOL );
            flps_line( xc, y + h - 1, x + w - 1, y, FL_RIGHT_BCOL );
            flps_line( x + w - 1, y, x, y, FL_BOTTOM_BCOL );
            flps_reset_linewidth( );
            break;

        case FLI_TRIANGLE_UPBOX2 :
            AddVertex( fp, xc, y + absbw );
            AddVertex( fp, xc, y + h - absbw );
            AddVertex( fp, x + w - absbw, y + h - absbw );
            flps_poly( 1, point, 3, col );

            flps_linewidth( absbw );
            ShrinkBox( x, y, w, h, halfbw );
            flps_line( xc, y, x, y + h - 1, FL_LEFT_BCOL );
            flps_line( x, y + h - 1, x + w - 1, y + h - 1, FL_TOP_BCOL );
            flps_line( x + w - 1, y + h - 1, xc, y, FL_RIGHT_BCOL );
            flps_reset_linewidth( );
            break;

        case FLI_TRIANGLE_UPBOX6 :
            AddVertex( fp, x + bw, y + h - bw );
            AddVertex( fp, x + w - bw, yc );
            AddVertex( fp, x + bw, y + bw );
            flps_poly( 1, point, 3, col );

            flps_linewidth( absbw );
            ShrinkBox( x, y, w, h, halfbw );
            flps_line( x, y + h - 1, x + w - 1, yc, FL_RIGHT_BCOL );
            flps_line( x + w - 1, yc, x, y, FL_BOTTOM_BCOL );
            flps_line( x, y, x, y + h - 1, FL_LEFT_BCOL );
            flps_reset_linewidth( );
            break;

        case FLI_TRIANGLE_UPBOX4 :
            AddVertex( fp, x + bw, yc );
            AddVertex( fp, x + w - bw, y + h - bw );
            AddVertex( fp, x + w - bw, y );
            flps_poly( 1, point, 3, col );

            flps_linewidth( absbw );
            ShrinkBox( x, y, w, h, halfbw );
            flps_line( x, yc, x + w - 1, y + h - 1, FL_TOP_BCOL );
            flps_line( x + w - 1, y + h - 1, x + w - 1, y, FL_RIGHT_BCOL );
            flps_line( x + w - 1, y, x, yc, FL_BOTTOM_BCOL );
            flps_reset_linewidth( );
            break;
    }
}


/***************************************
 ***************************************/

void
flps_draw_box( int      style,
               int      x,
               int      y,
               int      w,
               int      h,
               FL_COLOR col,
               int      bw_in )
{
    int border,
        B;
    FL_POINT xpoint[ 8 ],
             *xp;
    int bw = bw_in;

    if ( ! ( border = ( bw > 0 ) ) )
        bw = -bw;

    B = border;
    xp = xpoint;

    if ( flps->verbose )
        fprintf( flps->fp, "%%BOX %d: %d %d %d %d\n", style, x, y, w, h );

    switch ( style )
    {
        case FL_NO_BOX :
            break;

        case FL_UP_BOX :
            flps_rectf( x + bw, y + bw, w - 2 * bw, h - 2 * bw, col );

            flps_rectf( x + B, y, w - 2 * B, bw + 1, FL_BOTTOM_BCOL );
            flps_rectf( x + B, y + h - 1 - bw, w - 2 * B, bw + 1, FL_TOP_BCOL );

            /* left */

            AddVertex( xp, x + B, y + B );
            AddVertex( xp, x + B, y + h - 1 - B );
            AddVertex( xp, x + bw + B, y + h - 1 - bw - B );
            AddVertex( xp, x + bw + B, y + bw + B );
            flps_poly( 1, xpoint, 4, FL_LEFT_BCOL );

            xp = xpoint;
            AddVertex( xp, x + w - 1, y );
            AddVertex( xp, x + w - 1, y + h - 1 );
            AddVertex( xp, x + w - 1 - bw, y + h - 1 - bw );
            AddVertex( xp, x + w - 1 - bw, y + bw );
            flps_poly( 1, xpoint, 4, FL_RIGHT_BCOL );

            if ( border )
                flps_rect( x, y, w, h, FL_BLACK );
            break;

        case FL_DOWN_BOX :
            flps_rectf( x, y, w, h, col );
            flps_rectf( x, y + h - bw, w, bw, FL_BOTTOM_BCOL );
            flps_rectf( x, y, w, bw, FL_TOP_BCOL );

            AddVertex( xp, x, y );
            AddVertex( xp, x, y + h - 1 );
            AddVertex( xp, x + bw - 1, y + h - bw );
            AddVertex( xp, x + bw - 1, y + bw - 1 );
            flps_poly( 1, xpoint, 4, FL_RIGHT_BCOL );

            /* right */

            xp = xpoint;
            AddVertex( xp, x + w - 1, y );
            AddVertex( xp, x + w - 1, y + h - 1 );
            AddVertex( xp, x + w - bw, y + h - bw );
            AddVertex( xp, x + w - bw, y + bw - 1 );
            flps_poly( 1, xpoint, 4, FL_LEFT_BCOL );
            break;

        case FL_FRAME_BOX :
            flps_rectf( x, y, w, h, col );
            flps_linewidth( 1 );
            flps_rect( x + 1.4, y, w - 1.4, h - 1.4, FL_TOP_BCOL );
            flps_reset_linewidth( );
            flps_rect( x, y + 1.4, w - 1.4, h - 1.4, FL_BOTTOM_BCOL );
            break;

        case FL_EMBOSSED_BOX :
            flps_rectf( x, y, w, h, col );
            flps_linewidth( 1 );
            flps_rect( x + 1.4, y, w - 1.4, h - 1.4, FL_BOTTOM_BCOL );
            flps_reset_linewidth( );
            flps_rect( x, y + 1.4, w - 1.4, h - 1.4, FL_TOP_BCOL );
            break;

        case FL_FLAT_BOX :
            flps_rectf( x, y, w, h, col );
            break;

        case FL_SHADOW_BOX :
            if ( w > 100 && h > 100 )
                bw++;
            flps_rectf( x + bw, y + bw, w - bw, -bw, FL_BOTTOM_BCOL );
            flps_rectf( x + w - 1, y, -bw, h - bw - 1, FL_BOTTOM_BCOL );
            flps_rectf( x, y + bw, w - bw, h - bw, col );
            flps_rect( x, y + bw, w - bw, h - bw, FL_BLACK );
            break;

        case FL_BORDER_BOX :
            flps_rectf( x, y, w, h, col );
            flps_rect( x, y, w, h, FL_BLACK );
            break;

        case FL_RFLAT_BOX :
            flps_rbox( 1, x, y, w, h, col );
            break;

        case FL_ROUNDED_BOX :
            flps_rbox( 1, x, y, w, h, col );
            flps_rbox( 0, x, y, w, h, FL_BLACK );
            break;

        case FL_ROUNDED3D_UPBOX :
        case FL_ROUNDED3D_DOWNBOX :
            flps_roundedbox( style, x, y, w, h, col, bw );
            break;

        case FL_RSHADOW_BOX :
            flps_rbox( 1, x + bw, y - 1, w - bw + 1, h - bw, FL_BOTTOM_BCOL );
            flps_rbox( 1, x, y + bw - 1, w - bw + 1, h - bw + 1, col );
            flps_rbox( 0, x, y + bw - 1, w - bw + 1, h - bw + 1, FL_BLACK );
            break;

        case FL_OVAL_BOX :
            flps_oval( 1, x, y, w, h, col );
            flps_oval( 0, x, y, w, h, FL_BLACK );
            break;

        case FL_OVAL3D_UPBOX :
        case FL_OVAL3D_DOWNBOX :
        case FL_OVAL3D_FRAMEBOX :
        case FL_OVAL3D_EMBOSSEDBOX :
            flps_ovalbox( style, x, y, w, h, col, bw );
            break;

        case FL_TOPTAB_UPBOX :
        case FL_SELECTED_TOPTAB_UPBOX :
        case FL_BOTTOMTAB_UPBOX :
        case FL_SELECTED_BOTTOMTAB_UPBOX :
            flps_foldertab_box( style, x, y, w, h, col, bw_in );
            break;

        default:
            fprintf( stderr, "Unknown Boxtype %d\n", style );
            break;
    }
}


/***************************************
 * Frame is drawn OUTSIDE of the bounding box
 ***************************************/

void
flps_draw_frame( int      style,
                 int      x,
                 int      y,
                 int      w,
                 int      h,
                 FL_COLOR col  FL_UNUSED_ARG,
                 int      bw )
{
    int border;
    int B;
    FL_POINT xpoint[ 10],
             *xp;

    if ( ! ( border = ( bw > 0 ) ) )
        bw = -bw;

    B = border;

    if ( flps->verbose )
        fprintf( flps->fp, "%%frame (%d %d %d %d)\n", x, y, w, h );

    switch ( style )
    {
        case FL_UP_FRAME:
            flps_rectf( x - bw - B, y + h - 1, w + 2 * bw, bw + 1 + B,
                        FL_TOP_BCOL );
            flps_rectf( x - bw - B, y - bw - B, w + 2 * bw, bw + 1 + B,
                        FL_BOTTOM_BCOL );

            /* left */

            xp = xpoint;
            AddVertex( xp, x - bw - B, y - bw - B );
            AddVertex( xp, x, y );
            AddVertex( xp, x, y + h - 1 );
            AddVertex( xp, x - bw - B, y + h + bw + B - 1 );
            flps_poly( 1, xpoint, 4, FL_LEFT_BCOL );

            /* right */

            xp = xpoint;
            AddVertex( xp, x + w - 1 + bw + B, y - bw - B );
            AddVertex( xp, x + w - 1 + bw + B, y + h + bw + B - 1 );
            AddVertex( xp, x + w - 1, y + h - 1 );
            AddVertex( xp, x + w - 1, y );
            flps_poly( 1, xpoint, 4, FL_RIGHT_BCOL );
            break;

        case FL_DOWN_FRAME :
            flps_rectf( x - bw - B, y + h - 1, w + 2 * bw, bw + 1 + B,
                        FL_BOTTOM_BCOL );
            flps_rectf( x - bw - B, y - bw - B, w + 2 * bw, bw + 1 + B,
                        FL_TOP_BCOL );

            /* left */

            xp = xpoint;
            AddVertex( xp, x - bw - B, y - bw - B );
            AddVertex( xp, x, y );
            AddVertex( xp, x, y + h - 1 );
            AddVertex( xp, x - bw - B, y + h + bw + B - 1 );
            flps_poly( 1, xpoint, 4, FL_RIGHT_BCOL );

            /* right */

            xp = xpoint;
            AddVertex( xp, x + w - 1 + bw + B, y - bw - B );
            AddVertex( xp, x + w - 1 + bw + B, y + h + bw + B - 1 );
            AddVertex( xp, x + w - 1, y + h - 1 );
            AddVertex( xp, x + w - 1, y );
            flps_poly( 1, xpoint, 4, FL_LEFT_BCOL );
            break;

        case FL_ENGRAVED_FRAME :
            B = bw > 2 ? ( bw - 2 ) : 1;
            B *= 0.5;
            flps_draw_frame( FL_DOWN_FRAME, x, y, w, h, 0, 1 );
            flps_draw_frame( FL_UP_FRAME, x + B, y + B, w - 2 * B, h - 2 * B,
                             0, -1 );
            break;
    }
}


/***************************************
 ***************************************/

void
flps_draw_checkbox( int      type,
                    int      x,
                    int      y,
                    int      w,
                    int      h,
                    FL_COLOR col,
                    int      bw )
{
    FL_POINT xpoint[ 6 ],
             *xp;
    FL_POINT allp[ 10 ];

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
    flps_poly( 1, xp, 4, col );
    xp = xpoint;

    switch ( type )
    {
        case FL_DOWN_BOX :
            AddVertex( xp, allp[ 0 ].x, allp[ 0 ].y );
            AddVertex( xp, allp[ 1 ].x, allp[ 1 ].y );
            AddVertex( xp, allp[ 5 ].x, allp[ 5 ].y );
            AddVertex( xp, allp[ 4 ].x, allp[ 4 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_LEFT_BCOL );

            AddVertex( xp, allp[ 0 ].x, allp[ 0 ].y );
            AddVertex( xp, allp[ 4 ].x, allp[ 4 ].y );
            AddVertex( xp, allp[ 7 ].x, allp[ 7 ].y );
            AddVertex( xp, allp[ 3 ].x, allp[ 3 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_TOP_BCOL );

            /* right bottom */

            AddVertex( xp, allp[ 6 ].x, allp[ 6 ].y );
            AddVertex( xp, allp[ 2 ].x, allp[ 2 ].y );
            AddVertex( xp, allp[ 3 ].x, allp[ 3 ].y );
            AddVertex( xp, allp[ 7 ].x, allp[ 7 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_RIGHT_BCOL );

            AddVertex( xp, allp[ 1 ].x, allp[ 1 ].y );
            AddVertex( xp, allp[ 2 ].x, allp[ 2 ].y );
            AddVertex( xp, allp[ 6 ].x, allp[ 6 ].y );
            AddVertex( xp, allp[ 5 ].x, allp[ 5 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_BOTTOM_BCOL );
            break;

        case FL_UP_BOX :
            AddVertex( xp, allp[ 0 ].x, allp[ 0 ].y );
            AddVertex( xp, allp[ 1 ].x, allp[ 1 ].y );
            AddVertex( xp, allp[ 5 ].x, allp[ 5 ].y );
            AddVertex( xp, allp[ 4 ].x, allp[ 4 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_BOTTOM_BCOL );

            AddVertex( xp, allp[ 0 ].x, allp[ 0 ].y );
            AddVertex( xp, allp[ 4 ].x, allp[ 4 ].y );
            AddVertex( xp, allp[ 7 ].x, allp[ 7 ].y );
            AddVertex( xp, allp[ 3 ].x, allp[ 3 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_RIGHT_BCOL );

            /* right bottom */

            AddVertex( xp, allp[ 6 ].x, allp[ 6 ].y );
            AddVertex( xp, allp[ 2 ].x, allp[ 2 ].y );
            AddVertex( xp, allp[ 3 ].x, allp[ 3 ].y );
            AddVertex( xp, allp[ 7 ].x, allp[ 7 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_LEFT_BCOL );

            AddVertex( xp, allp[ 1 ].x, allp[ 1 ].y );
            AddVertex( xp, allp[ 2 ].x, allp[ 2 ].y );
            AddVertex( xp, allp[ 6 ].x, allp[ 6 ].y );
            AddVertex( xp, allp[ 5 ].x, allp[ 5 ].y );
            flps_poly( 1, xp = xpoint, 4, FL_TOP_BCOL );
            break;
    }

    if ( flps->verbose )
        fprintf( flps->fp, "%%BOX }\n" );
}

/******* End of high-level drawing routines **********}******/


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
