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


/**
 * \file fldraw.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  High level drawing routines. Uses the routines defined in xdraw.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


#define FLI_SHADOW_COL   FL_RIGHT_BCOL


static void fl_foldertab_box( int,
                              FL_Coord,
                              FL_Coord,
                              FL_Coord,
                              FL_Coord,
                              FL_COLOR,
                              int );


/*******************************************************************
 * Rectangle routines
 ****************************************************************{**/

/***************************************
 *  Make an arbitary rectangle have positive width and height
 ***************************************/

void
fli_canonicalize_rect( FL_Coord * x,
                       FL_Coord * y,
                       FL_Coord * w,
                       FL_Coord * h )
{
    if ( *w < 0 )
    {
        *w = -*w;
        *x -= *w;
    }

    if ( *h < 0 )
    {
        *h = -*h;
        *y -= *h;
    }
}


/***************************************
 * Draw a filled rectangle with a black boundary. Also compensates
 * for the inconsistency in Xlib
 ***************************************/

int flrectboundcolor = FL_BLACK;

void
fl_rectbound( FL_Coord x,
              FL_Coord y,
              FL_Coord w,
              FL_Coord h,
              FL_COLOR col )
{
    fli_canonicalize_rect( &x, &y, &w, &h );

    /* 0 width has special meaning in Xlib */

    if ( h < 2 )
        h = 2;
    if ( w < 2 )
        w = 2;

    fl_rectangle( 1, x + 1, y + 1, w - 1, h - 1, col              );
    fl_rectangle( 0, x,     y,     w,     h,     flrectboundcolor );
}


/****** End of rectangle routines ***********************}***/


#define MAX_RADIUS  18

static double offset[ ] = { 0.0, 0.07612, 0.29289, 0.61732, 1.0 };

#define RN     ( sizeof offset / sizeof *offset )


/***************************************
 ***************************************/

static void
compute_round_corners( FL_Coord   x,
                       FL_Coord   y,
                       FL_Coord   w,
                       FL_Coord   h,
                       FL_POINT * point )
{
    size_t i;
    double rs = 0.45 * FL_min( w, h );
    static double old_rs = -1;
    static FL_Coord o[ RN ];

    if ( rs > MAX_RADIUS )
        rs = MAX_RADIUS;
    if ( rs < 0 )
        rs = 0;

    if ( rs != old_rs )
    {
        for ( i = 0; i < RN; i++ )
            o[ i ] = FL_crnd( offset[ i ] * rs );
        old_rs = rs;
    }

    for ( i = 0; i < RN; i++, point++ )
    {
        point->x = x + o[ RN - i - 1 ];
        point->y = y + o[ i ];
    }

    for ( i = 0; i < RN; i++, point++ )
    {
        point->x = x + o[ i ];
        point->y = y + h - 1 - o[ RN - i - 1 ];
    }

    for ( i = 0; i < RN; i++, point++ )
    {
        point->x = x + w - 1 - o[ RN - i - 1 ];
        point->y = y + h - 1 - o[ i ];
    }

    for ( i = 0; i < RN; i++, point++ )
    {
        point->x = x + w - 1 - o[ i ];
        point->y = y + o[ RN - i - 1 ];
    }
}


/***************************************
 ***************************************/

void
fl_roundrectangle( int      fill,
                   FL_Coord x,
                   FL_Coord y,
                   FL_Coord w,
                   FL_Coord h,
                   FL_COLOR col )
{
    FL_POINT point[ 4 * RN + 1 ];  /* need one extra for closing of polygon! */

    compute_round_corners( x, y, w, h, point );
    fl_polygon( fill, point, 4 * RN, col );
}


#define SHRINK( x, y, w, h, d )  \
    do { x += ( d );             \
         y += ( d );             \
         w -= 2 * ( d );         \
         h -= 2 * ( d );         \
    } while ( 0 )


/***************************************
 ***************************************/

static void
fl_rounded3dbox( int      style,
                 FL_Coord x,
                 FL_Coord y,
                 FL_Coord w,
                 FL_Coord h,
                 FL_COLOR col,
                 int bw )
{
    FL_POINT point[ 4 *  RN + 1 ];     /* on extra for closing of curve */
    int lw = FL_abs( bw );
    int n = 4 * RN,
        olw;

    SHRINK( x, y, w, h, ( int ) ( lw / 2 ) );

    compute_round_corners( x, y, w, h, point );
    fl_polyf( point, n, col );

    olw = fl_get_linewidth( );
    fl_linewidth( lw );

    /* draw the shadow */

    if ( style == FL_ROUNDED3D_UPBOX )
    {
        fl_lines( point,              2 * RN, FL_LEFT_BCOL   );
        fl_lines( point + 2 * RN - 3, RN + 1, FL_BOTTOM_BCOL );
        fl_lines( point + 3 * RN - 4, RN + 2, FL_RIGHT_BCOL  );
        point[ n ] = point[ 0 ];
        fl_lines( point + n - 3, 4, FL_TOP_BCOL );
    }
    else
    {
        fl_lines( point,              2 * RN, FL_BOTTOM_BCOL );
        fl_lines( point + 2 * RN - 3, RN + 1, FL_TOP_BCOL    );
        fl_lines( point + 3 * RN - 4, RN + 2, FL_LEFT_BCOL   );
        point[ n ] = point[ 0 ];
        fl_lines( point + n - 3, 4, FL_BOTTOM_BCOL );
    }

    fl_linewidth( olw );

    if ( bw > 0 && fli_dithered( fl_vmode ) )
    {
        compute_round_corners( x, y, w, h, point );
        fl_polyl( point, n, FL_BLACK );
    }
}


/***************************************
 ***************************************/

static void
fl_oval3dbox( int      style,
              FL_Coord x,
              FL_Coord y,
              FL_Coord w,
              FL_Coord h,
              FL_COLOR col,
              int bw )
{
    int absbw = FL_abs( bw ),
        olw = fl_get_linewidth( );
    int extra = 1 + ( absbw > 3 );
    int xx,
        yy,
        ww,
        hh;

    SHRINK( x, y, w, h, ( int ) ( absbw / 2 ) );
    fl_pieslice( 1, x, y, w, h, 0, 3600, col );

    xx = x + extra;
    yy = y + extra;
    ww = w - 2 * extra;
    hh = h - 2 * extra;

    fl_linewidth( absbw );

    if ( style == FL_OVAL3D_UPBOX )
    {
        fl_pieslice( 0, x, y, w, h, 450, 2250, FL_TOP_BCOL );
        fl_pieslice( 0, x, y, w, h, 0, 450, FL_BOTTOM_BCOL );
        fl_pieslice( 0, x, y, w, h, 2250, 3600, FL_BOTTOM_BCOL );
    }
    else if ( style == FL_OVAL3D_FRAMEBOX )
    {
        fl_linewidth( 0 );

        fl_pieslice( 0, x, y, w, h, 450, 2250, FL_BOTTOM_BCOL );
        fl_pieslice( 0, xx, yy, ww, hh, 450, 2250, FL_LEFT_BCOL );

        fl_pieslice( 0, xx, yy, ww, hh, 0, 450, FL_BOTTOM_BCOL );
        fl_pieslice( 0, x, y, w, h, 0, 450, FL_LEFT_BCOL );

        fl_pieslice( 0, xx, yy, ww, hh, 2250, 3600, FL_BOTTOM_BCOL );
        fl_pieslice( 0, x, y, w, h, 2250, 3600, FL_LEFT_BCOL );
    }
    else if ( style == FL_OVAL3D_EMBOSSEDBOX )
    {
        fl_linewidth( 0 );

        fl_pieslice( 0, x, y, w, h, 450, 2250, FL_LEFT_BCOL );
        fl_pieslice( 0, xx, yy, ww, hh, 450, 2250, FL_BOTTOM_BCOL );

        fl_pieslice( 0, xx, yy, ww, hh, 0, 450, FL_LEFT_BCOL );
        fl_pieslice( 0, x, y, w, h, 0, 450, FL_BOTTOM_BCOL );

        fl_pieslice( 0, xx, yy, ww, hh, 2250, 3600, FL_LEFT_BCOL );
        fl_pieslice( 0, x, y, w, h, 2250, 3600, FL_BOTTOM_BCOL );
    }
    else
    {
        fl_pieslice( 0, x, y, w, h, 450, 2250, FL_BOTTOM_BCOL );
        fl_pieslice( 0, x, y, w, h, 0, 450, FL_TOP_BCOL );
        fl_pieslice( 0, x, y, w, h, 2250, 3600, FL_TOP_BCOL );
    }

    fl_linewidth( olw );

    if ( fli_dithered( fl_vmode ) )
        fl_pieslice( 0, x, y, w, h, 0, 3600, FL_BLACK );
}


#define SET_POINT( v, xp, yp )  \
    do { ( v )->x = xp;         \
         ( v )->y = yp;         \
    } while ( 0 )


/***************************************
 * Draw a rectangular box. TODO: need to change primitive box
 * drawing using frame
 ***************************************/

void
fl_draw_box( int      style,
             FL_Coord x,
             FL_Coord y,
             FL_Coord w,
             FL_Coord h,
             FL_COLOR c,
             int      bw_in )
{
    FL_POINT vert[ 5 ];             /* need one extra for closing of polygon! */
    int B,
        dp = fli_dithered( fl_vmode ),
        bw = bw_in;
    FL_Coord cx,
             cy,
             cw,
             ch;

    if ( c == FL_NoColor )
        c = FL_COL1;

    if ( style == FL_NO_BOX )
        return;

    if ( ! ( B = ( bw > 0 ) ) )
        bw = - bw;

    if ( bw == 0 )
        style = FL_FLAT_BOX;

    /* We must guarantee width of rectangle is larger than 0 */

    if ( w - 2 * bw <= 0 )
        bw = w / 2 - 1;
    if ( h - 2 * bw <= 0 )
        bw = h / 2 - 1;

    if ( w <= 0 || h <= 0 )
        return;

    switch ( style )
    {
        case FL_UP_BOX:
            fl_rectf( x + bw + B, y + bw + B, w - 2 * bw - 2 * B,
                      h - 2 * bw - 2 * B, c );
            fl_rectf( x + B, y + B, w - 1 - B, bw, FL_TOP_BCOL );
            fl_rectf( x + B, y + h - bw - B, w - 1 - B, bw, FL_BOTTOM_BCOL );

            SET_POINT( vert,     x + w - B - bw, y + bw + B     );
            SET_POINT( vert + 1, x + w - B - bw, y + h - B - bw );
            SET_POINT( vert + 2, x + w - B,      y + h - B      );
            SET_POINT( vert + 3, x + w - B,      y + B          );
            fl_polyf( vert, 4, FL_RIGHT_BCOL );

            /* left trapzoidal */

            SET_POINT( vert,     x + B,      y + B          );
            SET_POINT( vert + 1, x + B,      y + h - B      );
            SET_POINT( vert + 2, x + bw + B, y + h - bw - B );
            SET_POINT( vert + 3, x + bw + B, y + bw + B     );

            fl_polyf( vert, 4, FL_LEFT_BCOL );

            if ( B || fli_dithered( fl_vmode ) )
                fl_rect( x, y, w - 1, h - 1, FL_RIGHT_BCOL );

            /* special hack for B&W */

            if ( fli_dithered( fl_vmode ) )
            {
                if ( bw > 2 )
                {
                    SET_POINT( vert,     x + B,          y + B  );
                    SET_POINT( vert + 1, x + B + bw - 1, y + bw );
                    SET_POINT( vert + 2, x + w - bw,     y + bw );

                    fl_lines( vert, 3, FL_BLACK );
                    fl_simple_line( x + B + bw - 1, y + B + bw, x + B + bw - 1,
                                    y + h - bw, FL_BLACK );
                }
                else
                    fl_rect( x, y, w - 1, h - 1, FL_BLACK );
            }
            break;

        case FL_DOWN_BOX:
            fl_rectf( x + bw, y + bw, w - 2 * bw, h - 2 * bw, c );
            fl_rectf( x,      y + h - bw, w,      bw - dp,    FL_TOP_BCOL );
            fl_rectf( x,      y,          w,      bw,         FL_BOTTOM_BCOL );

            /* right trapzoid */

            SET_POINT( vert,     x + w - bw, y + bw     );
            SET_POINT( vert + 1, x + w - bw, y + h - bw );
            SET_POINT( vert + 2, x + w - dp, y + h      );
            SET_POINT( vert + 3, x + w - dp, y          );

            fl_polyf( vert, 4, FL_LEFT_BCOL );

            /* left trapzoid */

            SET_POINT( vert,     x,      y          );
            SET_POINT( vert + 1, x,      y + h - 1  );
            SET_POINT( vert + 2, x + bw, y + h - bw );
            SET_POINT( vert + 3, x + bw, y + bw     );

            fl_polyf( vert, 4, FL_RIGHT_BCOL );

            /* special hack for B&W */

            if ( fli_dithered( fl_vmode ) )
            {
                SET_POINT( vert,     x + B,     y + h - 1 );
                SET_POINT( vert + 1, x + w - 1, y + h - 1 );
                SET_POINT( vert + 2, x + w - 1, y + B     );
                fl_lines( vert, 3, FL_BLACK );
            }
            break;

        case FL_FLAT_BOX:
            fl_rectf( x, y, w, h, c );
            break;

        case FL_BORDER_BOX:
            fl_rectbound( x, y, w - 1, h - 1, c );
            break;

        case FL_FRAME_BOX:
            B = bw > 2 ? bw - 2 : 1;
            fl_draw_box( FL_DOWN_BOX, x, y, w, h, c, 1 );
            x += B + 1;
            y += B + 1;
            w -= 2 * ( B + 1 );
            h -= 2 * ( B + 1 );
            fl_draw_frame( FL_UP_FRAME, x, y, w, h, c, -1 );
            break;

        case FL_EMBOSSED_BOX:
            B = bw > 2 ? bw - 2 : 1;
            fl_draw_box( FL_UP_BOX, x, y, w, h, c, -1 );
            x += B + 1;
            y += B + 1;
            w -= 2 * ( B + 1 );
            h -= 2 * ( B + 1 );
            fl_draw_frame( FL_DOWN_FRAME, x, y, w, h, c, 1 );
            break;

        case FL_ROUNDED_BOX:
            fl_roundrectf( x + 1, y + 1, w - 1, h - 1, c );
            fl_roundrect( x, y, w, h, FL_BLACK );
            break;

        case FL_ROUNDED3D_UPBOX:
        case FL_ROUNDED3D_DOWNBOX:
            fl_rounded3dbox( style, x, y, w, h, c, bw );
            break;

        case FL_SHADOW_BOX:
            bw++;
            fl_rectf( x + bw, y + h - bw, w - bw, bw, FLI_SHADOW_COL );
            fl_rectf( x + w - bw, y + bw, bw, h - bw, FLI_SHADOW_COL );
            fl_rectbound( x, y, w - bw, h - bw, c );
            break;

        case FL_RSHADOW_BOX:
            if ( w > 70 && h > 70 )
                bw++;

            if (    fl_get_clipping( 1, &cx, &cy, &cw, &ch )
                 && ( cw <= 0 || ch <= 0 ) )
                break;

            /* Draw the shadow, raw it several times with clipping */

            fl_roundrectf( x + bw, y + bw, w - bw, h - bw, FLI_SHADOW_COL );

            /* Draw the box */

            fli_set_additional_clipping( x, y, w, h );
            fl_roundrectf( x + 1, y + 1, w - 1 - bw, h - 1 - bw, c );
            fl_roundrect( x, y, w - bw, h - bw, FL_BLACK );
            fl_set_clipping( cx, cy, cw, ch );
            break;

        case FL_RFLAT_BOX:
            fl_roundrectf( x, y, w, h, c );
            break;

        case FL_OVAL_BOX:
            fl_oval( 1, x + 1, y + 1, w - 1, h - 1, c );
            fl_oval( 0, x + 1, y + 1, w - 2, h - 2, FL_BLACK );
            break;

        case FL_OVAL3D_UPBOX:
        case FL_OVAL3D_DOWNBOX:
        case FL_OVAL3D_FRAMEBOX:
        case FL_OVAL3D_EMBOSSEDBOX:
            fl_oval3dbox( style, x, y, w, h, c, bw_in );
            break;

        case FL_TOPTAB_UPBOX:
        case FL_SELECTED_TOPTAB_UPBOX:
        case FL_BOTTOMTAB_UPBOX:
        case FL_SELECTED_BOTTOMTAB_UPBOX:
            fl_foldertab_box( style, x, y, w, h, c, bw_in );
            break;

        default:
            if ( style & FLI_BROKEN_BOX )
                fl_foldertab_box( style, x, y, w, h, c, bw_in );
            else
                M_err( "fl_draw_box", "Unkonwn boxtype: %d", style );
            break;
    }
}


/***************************************
 *     0
 *   1   3
 *     2
 * Draws a box rotated by 45 degrees
 ***************************************/

void
fli_draw_checkbox( int      type,
                   FL_Coord x,
                   FL_Coord y,
                   FL_Coord w,
                   FL_Coord h,
                   FL_COLOR col,
                   int      bw )
{
    int halfw = w / 2,
        halfh = h / 2;
    FL_POINT allp[ 9 ];;
                      
    w = 2 * halfw;
    h = 2 * halfh;

    /* Generate all points */

    SET_POINT( allp,     x + halfw,  y          );
    SET_POINT( allp + 1, x,          y + halfh  );
    SET_POINT( allp + 2, x + halfw,  y + h      );
    SET_POINT( allp + 3, x + w,      y + halfh  );
    SET_POINT( allp + 4, x + halfw,  y + bw     );
    SET_POINT( allp + 5, x + bw,     y + halfh  );
    SET_POINT( allp + 6, x + halfw,  y + h - bw );
    SET_POINT( allp + 7, x + w - bw, y + halfh  );
    SET_POINT( allp + 8, x + halfw,  y + halfh  );            /* center */

    /* Draw the borders for up and down boxes (plus the interior, it will
       be overdrawn in the next step) */

    if ( type == FL_UP_BOX || type == FL_DOWN_BOX )
    {
        FL_POINT xp[ 4 ];         /* need one extra for closing of polygons! */

        xp[ 2 ] = allp[ 8 ];

        xp[ 0 ] = allp[ 0 ];
        xp[ 1 ] = allp[ 1 ];
        fl_polyf( xp, 3, type == FL_UP_BOX ? FL_LEFT_BCOL : FL_RIGHT_BCOL );

        xp[ 0 ] = allp[ 1 ];
        xp[ 1 ] = allp[ 2 ];
        fl_polyf( xp, 3, type == FL_UP_BOX ? FL_BOTTOM_BCOL : FL_TOP_BCOL );

        xp[ 0 ] = allp[ 2 ];
        xp[ 1 ] = allp[ 3 ];
        fl_polyf( xp, 3, type == FL_UP_BOX ? FL_RIGHT_BCOL : FL_LEFT_BCOL );

        xp[ 0 ] = allp[ 3 ];
        xp[ 1 ] = allp[ 0 ];
        fl_polyf( xp, 3, type == FL_UP_BOX ? FL_TOP_BCOL : FL_BOTTOM_BCOL );
    }

    /* Draw the interior */

    fl_polyf( allp + 4, 4, col );

    /* Special hack for B&W, add a border */

    if ( fli_dithered( fl_vmode ) )
        fl_polyl( allp, 4, FL_BLACK );
}


/***************************************
 * Draws a frame around a box. The frame is drawn that it is just
 * outside of the box without any gap. A flat box with the same
 * size as that frame just fit the inside the of the frame.
 ***************************************/

void
fl_draw_frame( int      style,
               FL_Coord x,
               FL_Coord y,
               FL_Coord w,
               FL_Coord h,
               FL_COLOR c,
               int      bw )
{
    FL_POINT vert[ 5 ];          /* need one extra for closing of polygon! */
    int B,
        dp = fli_dithered( fl_vmode );

    if ( w <= 0 || h <= 0 )
        return;

    if ( ! ( B = ( bw > 0 ) ) )
        bw = - bw;

    switch ( style )
    {
        case FL_UP_FRAME:
            /* Must guarante that width of rectangle > 0 */

            if ( ( w - 2 * bw ) <= 0 )
                bw = w / 2;
            if ( ( h - 2 * bw ) <= 0 )
                bw = h / 2;

            x -= bw + B;
            y -= bw + B;
            w += 2 * ( bw + B );
            h += 2 * ( bw + B );

            fl_rectf( x + B, y + B, w - 1 - B, bw, FL_TOP_BCOL );
            fl_rectf( x + B, y + h - bw - B, w - 1 - B, bw, FL_BOTTOM_BCOL );

            SET_POINT( vert,     x + w - B - bw, y + bw + B     );
            SET_POINT( vert + 1, x + w - B - bw, y + h - B - bw );
            SET_POINT( vert + 2, x + w - B,      y + h - B      );
            SET_POINT( vert + 3, x + w - B,      y + B          );

            fl_polyf( vert, 4, FL_RIGHT_BCOL );

            /* Left trapzoidal */

            SET_POINT( vert,     x + B,      y + B          );
            SET_POINT( vert + 1, x + B,      y + h - B      );
            SET_POINT( vert + 2, x + bw + B, y + h - bw - B );
            SET_POINT( vert + 3, x + bw + B, y + bw + B     );

            fl_polyf( vert, 4, FL_LEFT_BCOL );

            if ( B || fli_dithered( fl_vmode ) )
                fl_rect( x, y, w - 1, h - 1, FL_BLACK );

            /* Special hack for B&W */

            if ( dp )
            {
                if ( bw > 2 )
                {
                    SET_POINT( vert,     x + B,          y + B  );
                    SET_POINT( vert + 1, x + B + bw - 1, y + bw );
                    SET_POINT( vert + 2, x + w - bw,     y + bw );

                    fl_lines( vert, 3, FL_BLACK );
                    fl_simple_line( x + B + bw - 1, y + B + bw,
                                    x + B + bw - 1, y + h - bw, FL_BLACK );
                }
                else
                    fl_rect( x, y, w - 1, h - 1, FL_BLACK );
            }
            break;

        case FL_DOWN_FRAME:
            x -= bw;
            y -= bw;
            w += 2 * bw;
            h += 2 * bw;

            /* Top and bottom section */

            fl_rectf( x, y, w, bw, FL_BOTTOM_BCOL );                /* top */
            fl_rectf (x, y + h - bw, w, bw - dp, FL_TOP_BCOL);      /* bottom */

            /* Right trapzoid */

            SET_POINT( vert,     x + w - bw, y + bw     );
            SET_POINT( vert + 1, x + w - bw, y + h - bw );
            SET_POINT( vert + 2, x + w - dp, y + h      );
            SET_POINT( vert + 3, x + w - dp, y          );

            fl_polyf( vert, 4, FL_LEFT_BCOL );

            /* Left trapzoid */

            SET_POINT( vert,     x,      y          );
            SET_POINT( vert + 1, x,      y + h - 1  );
            SET_POINT( vert + 2, x + bw, y + h - bw );
            SET_POINT( vert + 3, x + bw, y + bw     );

            fl_polyf( vert, 4, FL_RIGHT_BCOL );

            /* Special hack for B&W */

            if ( dp )
            {
                SET_POINT( vert,     x + B,     y + h - 1 );
                SET_POINT( vert + 1, x + w - 1, y + h - 1 );
                SET_POINT( vert + 2, x + w - 1, y + B     );
                fl_lines( vert, 3, FL_BLACK );
            }
            break;

        case FL_SHADOW_FRAME:
            if ( w > 70 && h > 70 )
            {
                if ( ( bw += ( w + h ) / 140 ) > 5 )
                    bw = 5;
            }

            fl_rectf( x + bw, y + h,  w,     bw,    FLI_SHADOW_COL );
            fl_rectf( x + w,  y + bw, bw,    h,     FLI_SHADOW_COL );
            fl_rect(  x - 1,  y - 1,  w + 1, h + 1, FL_BLACK      );
            break;

        case FL_BORDER_FRAME:
            fl_rect( x - 1, y - 1, w + 1, h + 1, c );
            break;

        case FL_EMBOSSED_FRAME:
            B = bw > 2 ? ( bw - 2 ) : 1;
            fl_draw_frame( FL_UP_FRAME, x, y, w, h, 0, -1 );
            fl_draw_frame( FL_DOWN_FRAME, x + B, y + B, w - 2 * B, h - 2 * B,
                          0, 1 );
            break;

        case FL_ENGRAVED_FRAME:
            B = bw > 2 ? bw - 2 : 1;
            fl_draw_frame( FL_DOWN_FRAME, x, y, w, h, 0, 1 );
            fl_draw_frame( FL_UP_FRAME, x + B, y + B,
                          w - 2 * B, h - 2 * B, 0, -1 );
            break;

        case FL_ROUNDED_FRAME:
            fl_roundrect( x - 1, y - 1, w + 2, h + 2, c );
            break;

        case FL_OVAL_FRAME:
            fl_oval( 0, x - 1, y - 1, w + 2, h + 2, c );
            break;
    }
}


/********* Some convience functions, sort of GL in X   ******{*****/

#define MAX_BUF_POINT  128
static FL_POINT xpbuf[ MAX_BUF_POINT ];
static int npt;
static FL_COLOR pcol;


/***************************************
 ***************************************/

void
fli_add_vertex( FL_Coord x,
                FL_Coord y )
{
    if ( npt >= MAX_BUF_POINT )
    {
        M_err( "fli_add_vertex", "Vertices Out of bounds" );
        return;
    }

    xpbuf[ npt   ].x = x;
    xpbuf[ npt++ ].y = y;
}


/***************************************
 ***************************************/

void
fli_add_float_vertex( float x,
                      float y )
{
    if ( npt >= MAX_BUF_POINT )
    {
        M_err( "fli_add_float_vertex", "Vertices Out of bounds" );
        return;
    }

    xpbuf[ npt   ].x = FL_nint( x );
    xpbuf[ npt++ ].y = FL_nint( y );
}


/***************************************
 ***************************************/

void
fli_reset_vertex( void )
{
    npt = 0;
    pcol = flx->color;
}


/***************************************
 ***************************************/

void
fli_endline( void )
{
    if ( npt >= MAX_BUF_POINT )
    {
        M_err( "fli_endline", "Vertices Out of bounds" );
        return;
    }

    fl_lines( xpbuf, npt, flx->color );
}


/***************************************
 ***************************************/

void
fli_endclosedline( void )
{
    if ( npt + 1 >= MAX_BUF_POINT )
    {
        M_err( "fli_endclosedline", "Vertices Out of bounds" );
        return;
    }

    fl_polyl( xpbuf, npt, pcol );
}


/***************************************
 ***************************************/

void
fli_endpolygon( void )
{
    if ( npt + 1 >= MAX_BUF_POINT )
    {
        M_err( "fli_endpolygon", "Vertices Out of bounds" );
        return;
    }

    fl_polyf( xpbuf, npt, flx->color );
}


static int Tabfolder_Corner = 3;


/***************************************
 ***************************************/

int
fl_set_default_tabfolder_corner( int n )
{
    int old = Tabfolder_Corner;

    Tabfolder_Corner = FL_abs( n );
    if ( Tabfolder_Corner > 10 )
        Tabfolder_Corner = 10;

    return old;
}


/***************************************
 ***************************************/

static void
fl_foldertab_box( int      style,
                  FL_Coord x,
                  FL_Coord y,
                  FL_Coord w,
                  FL_Coord h,
                  FL_COLOR c,
                  int      bw )
{
    int ctr,
        right,
        bott;
    FL_POINT vert[ 9 ];          /* need one extra for closing of polygon! */
    int border = ( bw > 0 );
    int absbw = FL_abs( bw ),
        i;
    int C = Tabfolder_Corner;
    int isbroken = style & FLI_BROKEN_BOX;

    style &= ~ FLI_BROKEN_BOX;

    /* for foldertab box, actual h is pre-enlarged by absbw pixels so the
       label is draw centered. Here we recover the pixels */

    if ( style == FL_BOTTOMTAB_UPBOX || style == FL_SELECTED_BOTTOMTAB_UPBOX )
        h += absbw;
    else
        h -= absbw;

    /* We must try to guarantee the width of the rectangle is larger than 0 */

    if ( w - 2 * absbw <= 0 )
        absbw = FL_abs( w / 2 - 1 );

    if ( h - 2 * absbw <= 0 )
        absbw = FL_abs( h / 2 - 1 );

    ctr = absbw / 2;
    SHRINK( x, y, w, h, ctr );

    right = x + w - 1;
    bott = y + h - 1;

    switch ( style )
    {
        case FL_TOPTAB_UPBOX:
            SET_POINT( vert,     x,             y + h - ( ctr == 0 ) );
            SET_POINT( vert + 1, x,             y + C - 1            );
            SET_POINT( vert + 2, x + C - 1,     y                    );
            SET_POINT( vert + 3, right - C,     y                    );
            SET_POINT( vert + 4, x + C - 1,     y                    );
            SET_POINT( vert + 5, right - C + 1, y                    );
            SET_POINT( vert + 6, right,         y + C - 1            );
            SET_POINT( vert + 7, right,         y + h - ( ctr == 0 ) );

            fl_polyf( vert, 8, c );

            fl_set_linewidth( absbw );
            fl_lines( vert,     3, FL_LEFT_BCOL );
            fl_lines( vert + 3, 2, FL_TOP_BCOL  );
            if ( ! isbroken )
                fl_lines( vert + 5, 3, FL_BOTTOM_BCOL );
            else
            {
                int yc = ( h - ( ctr == 0 ) ) / 2,
                    yc2 = yc / 2,
                    yc4 = yc / 4;

                fl_line( right, y, right, y + 4, FL_INACTIVE_COL );
                fl_line( right, y + 4, right - 3, y + yc4, FL_INACTIVE_COL );
                fl_line( right - 3, y + yc4, right - 2, y + yc2,
                         FL_INACTIVE_COL );
                fl_line( right - 2, y + yc2, right, y + yc, FL_INACTIVE_COL );
                fl_line( right, y + yc, right, y + yc + 2, FL_INACTIVE_COL );
                fl_line( right, y + yc + 2, right + 1, y + yc + yc4,
                         FL_INACTIVE_COL );
                fl_line( right + 1, y + yc + yc4, right - 2, y + yc + yc,
                         FL_INACTIVE_COL );
            }

            fl_set_linewidth( 0 );

            if ( border || fli_dithered( fl_vmode ) )
            {
                for ( i = 0; i < 8; i++ )
                {
                    if ( vert[ i ].x > x + w / 2 )
                        vert[ i ].x += ctr;
                    else
                        vert[ i ].x -= ctr + 1;

                    if ( vert[ i ].y < y + h / 2 )
                        vert[ i ].y -= ctr + 1;
                }

                fl_lines( vert, 8, FL_RIGHT_BCOL );
            }
            break;

        case FL_SELECTED_TOPTAB_UPBOX:
            SET_POINT( vert,     x,             bott + absbw + 3 );
            SET_POINT( vert + 1, x,             y + C - 1        );
            SET_POINT( vert + 2, x + C - 1,     y                );
            SET_POINT( vert + 3, right - C,     y                );
            SET_POINT( vert + 4, x + C - 1,     y                );
            SET_POINT( vert + 5, right - C + 1, y                );
            SET_POINT( vert + 6, right,         y + C - 1        );
            SET_POINT( vert + 7, right,         bott + absbw + 3 );

            fl_polyf( vert, 8, c );

            fl_set_linewidth( absbw );
            fl_lines( vert,     3, FL_LEFT_BCOL );
            fl_lines( vert + 3, 2, FL_TOP_BCOL );
            fl_lines( vert + 5, 3, FL_BOTTOM_BCOL );
            fl_set_linewidth( 0 );

            if ( border || fli_dithered( fl_vmode ) )
            {
                for ( i = 0; i < 8; i++ )
                {
                    if ( vert[ i ].x > x + w / 2 )
                        vert[ i ].x += ctr;
                    else
                        vert[ i ].x -= ctr + 1;

                    if ( vert[ i ].y < y + h / 2 )
                        vert[ i ].y -= ctr + 1;
                }

                vert[ 0 ].y -= absbw + 1;
                vert[ 7 ].y -= absbw + 1;
                fl_lines( vert, 8, FL_RIGHT_BCOL );
            }
            break;

        case FL_BOTTOMTAB_UPBOX:
            SET_POINT( vert,     x,         y + ( ctr == 0 ) );
            SET_POINT( vert + 1, x,         bott - C + 1     );
            SET_POINT( vert + 2, x + C - 1, bott             );
            SET_POINT( vert + 3, x + C - 1, bott             );
            SET_POINT( vert + 4, right - C, bott             );
            SET_POINT( vert + 5, right - C, bott             );
            SET_POINT( vert + 6, right,     bott - C         );
            SET_POINT( vert + 7, right,     y + ( ctr == 0 ) );

            fl_polyf( vert, 8, c );

            fl_linewidth( absbw );
            fl_lines( vert,     3, FL_TOP_BCOL );
            fl_lines( vert + 3, 2, FL_BOTTOM_BCOL );
            fl_lines( vert + 5, 3, FL_RIGHT_BCOL );
            fl_linewidth( 0 );

            if ( border || fli_dithered( fl_vmode ) )
            {
                for ( i = 0; i < 8; i++ )
                {
                    if ( vert[ i ].x > x + w / 2 )
                        vert[ i ].x += ctr;
                    else
                        vert[ i ].x -= ctr + 1;
                    if ( vert[ i ].y > y + h / 2 )
                        vert[ i ].y += ctr;
                }

                fl_lines( vert, 8, FL_RIGHT_BCOL );
            }
            break;

        case FL_SELECTED_BOTTOMTAB_UPBOX:
            SET_POINT( vert,     x,         y - absbw - 1 );
            SET_POINT( vert + 1, x,         bott - C + 1  );
            SET_POINT( vert + 2, x + C - 1, bott          );
            SET_POINT( vert + 3, x + C - 1, bott          );
            SET_POINT( vert + 4, right - C, bott          );
            SET_POINT( vert + 5, right - C, bott          );
            SET_POINT( vert + 6, right,     bott - C + 1  );
            SET_POINT( vert + 7, right,    y - absbw - 1 );

            fl_polyf( vert, 8, c );

            fl_linewidth( absbw );
            fl_lines( vert,     3, FL_TOP_BCOL    );
            fl_lines( vert + 3, 2, FL_BOTTOM_BCOL );
            fl_lines( vert + 5, 3, FL_RIGHT_BCOL  );
            fl_linewidth( 0 );

            if ( border || fli_dithered( fl_vmode ) )
            {
                for ( i = 0; i < 8; i++ )
                {
                    if ( vert[ i ].x > x + w / 2 )
                        vert[ i ].x += ctr;
                    else
                        vert[ i ].x -= ctr + 1;
                    if ( vert[ i ].y > y + h / 2 )
                        vert[ i ].y += ctr;
                }

                fl_lines( vert, 8, FL_RIGHT_BCOL );
            }
            break;
    }
}


/***************************************
 * draw triangluar box
 ***************************************/

void
fli_draw_tbox( int      style,
               FL_Coord x,
               FL_Coord y,
               FL_Coord w,
               FL_Coord h,
               FL_COLOR c,
               int bw_in )
{
    FL_POINT vert[ 4 ];          /* need one extra for closing of polygon! */
    int dp = fli_dithered( fl_vmode ),
        bw = bw_in;
    int xc = x + w / 2,
        yc = y + h / 2;
    int halfbw = bw / 2;

    if ( c == FL_NoColor )
        c = FL_COL1;

    if ( bw < 0 )
        bw = -bw;

    if ( bw == 0 && style != FL_NO_BOX )
        style = FL_FLAT_BOX;

    switch ( style )
    {
        case FLI_TRIANGLE_UPBOX8:
            SET_POINT( vert,     xc,         y + bw     );
            SET_POINT( vert + 1, x + bw,     y + h - bw );
            SET_POINT( vert + 2, x + w - bw, y + h - bw );
            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            xc = x + w / 2;
            fl_line( xc, y,         x,         y + h - 1, FL_LEFT_BCOL   );
            fl_line( x,  y + h - 1, x + w - 1, y + h - 1, FL_BOTTOM_BCOL );
            fl_line( xc, y,         x + w - 1, y + h - 1, FL_BOTTOM_BCOL );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_DOWNBOX8:
            SET_POINT( vert,     xc,         y + bw     );
            SET_POINT( vert + 1, x + bw,     y + h - bw );
            SET_POINT( vert + 2, x + w - bw, y + h - bw );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            xc = x + w / 2;
            fl_line( xc, y,         x,         y + h - 1, FL_BOTTOM_BCOL );
            fl_line( x,  y + h - 1, x + w - 1, y + h - 1, FL_TOP_BCOL    );
            fl_line( xc, y,         x + w - 1, y + h - 1, FL_LEFT_BCOL   );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_UPBOX2:
            SET_POINT( vert,     xc,         y + h - bw );
            SET_POINT( vert + 1, x + bw,     y + bw     );
            SET_POINT( vert + 2, x + w - bw, y + bw     );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            xc = x + w / 2;
            fl_line( xc, y + h - 1, x, y, FL_LEFT_BCOL );
            fl_line( x, y, x + w - 1, y, FL_TOP_BCOL );
            fl_line( x + w - 1, y, xc, y + h - 1, FL_RIGHT_BCOL );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_DOWNBOX2:
            SET_POINT( vert,     xc,         y + h - bw );
            SET_POINT( vert + 1, x + bw,     y + bw     );
            SET_POINT( vert + 2, x + w - bw, y + bw     );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            xc = x + w / 2;
            fl_line( xc, y + h - 1, x, y, FL_BOTTOM_BCOL );
            fl_line( x, y, x + w - 1, y, FL_BOTTOM_BCOL );
            fl_line( x + w - 1, y, xc, y + h - 1, FL_TOP_BCOL );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_UPBOX4:
            SET_POINT( vert,     x + bw, yc );
            SET_POINT( vert + 1, x + w - bw, y + bw     );
            SET_POINT( vert + 2, x + w - bw, y + h - bw );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            yc = y + h / 2;
            fl_line( x, yc, x + w - 1, y, FL_TOP_BCOL );
            fl_line( x + w - 1, y, x + w - 1, y + h - 1, FL_RIGHT_BCOL );
            fl_line( x + w - 1, y + h - 1, x, yc, FL_BOTTOM_BCOL );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_DOWNBOX4:
            SET_POINT( vert,     x + bw,     yc         );
            SET_POINT( vert + 1, x + w - bw, y + bw     );
            SET_POINT( vert + 2, x + w - bw, y + h - bw );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            yc = y + h / 2;
            fl_line( x, yc, x + w - 1, y, FL_BOTTOM_BCOL );
            fl_line( x + w - 1, y, x + w - 1, y + h - 1, FL_LEFT_BCOL );
            fl_line( x + w - 1, y + h - 1, x, yc, FL_LEFT_BCOL );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_UPBOX6:
            SET_POINT( vert,     x + bw,     y + bw     );
            SET_POINT( vert + 1, x + w - bw, yc         );
            SET_POINT( vert + 2, x + bw,     y + h - bw );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            yc = y + h / 2;
            fl_line( x, y, x + w - 1, yc, FL_RIGHT_BCOL );
            fl_line( x + w - 1, yc, x, y + h - 1, FL_BOTTOM_BCOL );
            fl_line( x, y + h - 1, x, y, FL_LEFT_BCOL );
            fl_linewidth( 0 );
            break;

        case FLI_TRIANGLE_DOWNBOX6:
            SET_POINT( vert,     x + bw,     y + bw     );
            SET_POINT( vert + 1, x + w - bw, yc         );
            SET_POINT( vert + 2, x + bw,     y + h - bw );

            fl_polyf( vert, 3, c );

            fl_linewidth( bw );
            SHRINK( x, y, w, h, halfbw );
            yc = y + h / 2;
            fl_line( x, y, x + w - 1, yc, FL_LEFT_BCOL );
            fl_line( x + w - 1, yc, x, y + h - 1, FL_TOP_BCOL );
            fl_line( x, y + h - 1, x, y, FL_RIGHT_BCOL );
            fl_linewidth( 0 );
            break;
    }

    /* handle black and white */

    if ( dp )
        fl_polyl( vert, 3, FL_BLACK );
}


/***************************************
 ***************************************/

int
fli_boxtype2frametype( int btype )
{
    if ( btype <= FL_EMBOSSED_BOX )
        return btype;
    else if ( btype == FL_FLAT_BOX )
        return FL_NO_FRAME;

    return FL_DOWN_FRAME;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
