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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file xdraw.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Basic low level drawing routines in Xlib.
 *
 *  BUGS: All form window share a common GC and color map.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


static int fli_mono_dither( unsigned long );
static void fli_set_current_gc( GC );

static GC dithered_gc;


/*******************************************************************
 * Rectangle routines
 ****************************************************************{**/


/***************************************
 * Function for drawing a (possibly filled) rectangle
 ***************************************/

void
fl_rectangle( int      fill,
              FL_Coord x,
              FL_Coord y,
              FL_Coord w,
              FL_Coord h,
              FL_COLOR col )
{
    int bw = fli_dithered( fl_vmode ) && fli_mono_dither( col );
    GC gc = flx->gc;
    int ( * draw_as )( Display *,
                       Drawable,
                       GC,
                       int,
                       int,
                       unsigned int,
                       unsigned int );

    if ( flx->win == None || w <= 0 || h <= 0 )
        return;

    fli_canonicalize_rect( &x, &y, &w, &h );

    draw_as = fill ? XFillRectangle : XDrawRectangle;

    if ( bw && fill )
    {
        fli_set_current_gc( fli_whitegc );
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h );
        fli_set_current_gc( dithered_gc );
    }


    fl_color( bw ? FL_BLACK : col );
    draw_as( flx->display, flx->win, flx->gc, x, y, w, h );

    if ( bw )
        fli_set_current_gc( gc );
}


/****** End of rectangle routines ***********************}***/


/****************************************************************
 * Polygon and polylines
 ***********************************************************{****/


/***************************************
 * Function for drawing a closed (possibly filled) polygon.
 * The 'xp' argument must point to an array with n + 1 elements!
 ***************************************/

void
fl_polygon( int        fill,
            FL_POINT * xp,
            int        n,
            FL_COLOR   col )
{
    int bw = fli_dithered( fl_vmode ) && fli_mono_dither( col );
    GC gc = flx->gc;

    if ( flx->win == None || n <= 0 )
        return;

    if ( bw )
    {
        flx->gc = dithered_gc;
        fl_color( FL_WHITE );
        if ( fill )
            XFillPolygon( flx->display, flx->win, flx->gc, xp, n,
                          Nonconvex, CoordModeOrigin );
        else
        {
            xp[ n ].x = xp[ 0 ].x;
            xp[ n ].y = xp[ 0 ].y;
            XDrawLines( flx->display, flx->win, flx->gc, xp, n + 1,
                        CoordModeOrigin );
        }
    }

    fl_color( bw ? FL_BLACK : col );

    if ( fill )
        XFillPolygon( flx->display, flx->win, flx->gc, xp, n,
                      Nonconvex, CoordModeOrigin );
    else
    {
        xp[ n ].x = xp[ 0 ].x;
        xp[ n ].y = xp[ 0 ].y;
        XDrawLines( flx->display, flx->win, flx->gc, xp, n + 1,
                    CoordModeOrigin );
    }

    if ( bw )
        flx->gc = gc;
}


/****************************************************************
 * Draws a circle at (x, y) woth radius r and col as to color
 * of the outline
 **********************************************************{******/

void
fl_circ( FL_COORD x,
         FL_COORD y,
         FL_COORD r,
         FL_COLOR col )
{
    fl_oval( 0, x - r, y - r, 2 * r, 2 * r, col );
}


/****************************************************************
 * Draws a filled circle at (x, y) woth radius r in color col
 **********************************************************{******/

void
fl_circf( FL_COORD x,
          FL_COORD y,
          FL_COORD r,
          FL_COLOR col )
{
    fl_oval( 1, x - r, y - r, 2 * r, 2 * r, col );
}


/****************************************************************
 * Draws a filled circle at (x, y) woth radius r in color col and
 * the circumfence in black.
 **********************************************************{******/

void
fl_circbound( FL_COORD x,
              FL_COORD y,
              FL_COORD r,
              FL_COLOR col )
{
    fl_ovalbound( x - r, y - r, 2 * r, 2 * r, col );
}


/****************************************************************
 * Function for drawing a (possibly filled) ellipse.
 **********************************************************{******/

void
fl_oval( int      fill,
         FL_Coord x,
         FL_Coord y,
         FL_Coord w,
         FL_Coord h,
         FL_COLOR col )
{
    int bw = fli_dithered( fl_vmode ) && fli_mono_dither( col );
    GC gc = flx->gc;
    int ( * draw_as )( Display *,
                       Drawable,
                       GC,
                       int,
                       int,
                       unsigned int,
                       unsigned int,
                       int,
                       int );

    if ( flx->win == None || w <= 0 || h <= 0 )
        return;

    draw_as = fill ? XFillArc : XDrawArc;

    if ( bw )
    {
        fli_set_current_gc( fli_whitegc );
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h, 0, 360 * 64 );
        fli_set_current_gc( dithered_gc );
    }

    fl_color( bw ? FL_BLACK : col );

    if ( w >= 0 && h >= 0 )
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h, 0, 360 * 64 );

    if ( bw )
        fli_set_current_gc( gc );
}


/***************************************
 * Draws a filled ellipse with a black border
 ***************************************/

void
fl_ovalbound( FL_Coord x,
              FL_Coord y,
              FL_Coord w,
              FL_Coord h,
              FL_COLOR col )
{
    if ( flx->win == None || w <= 0 || h <= 0 )
        return;

    fl_color( col );
    XFillArc( flx->display, flx->win, flx->gc, x, y, w, h, 0, 360 * 64 );
    fl_color( FL_BLACK );
    XDrawArc( flx->display, flx->win, flx->gc, x, y, w - 1, h - 1, 0,
              360 * 64 );
}


/******* End of ellipse routines ****************}***********/

/****************************************************************
 *
 * Arcs
 ****************************************************************/

/***************************************
 ***************************************/

void
fl_ovalarc( int      fill,
            FL_Coord x,
            FL_Coord y,
            FL_Coord w,
            FL_Coord h,
            int      t0,
            int      dt,
            FL_COLOR col )
{
    int mono = fli_dithered( fl_vmode ) && fli_mono_dither( col );
    int ( * draw_as )( Display *,
                       Drawable,
                       GC,
                       int,
                       int,
                       unsigned int,
                       unsigned int,
                       int,
                       int );

    if ( flx->win == None || w <= 0 || h <= 0 )
        return;

    draw_as = fill ? XFillArc : XDrawArc;

    if ( mono )
    {
        fli_set_current_gc( fli_whitegc );
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h,
                 t0 * 6.4, dt * 6.4 );
        fli_set_current_gc( dithered_gc );
    }

    fl_color( mono ? FL_BLACK : col );

    if ( w >= 0 && h >= 0 )
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h,
                 t0 * 6.4, dt * 6.4 );

    if ( mono )
        fli_set_current_gc( fl_state[ fl_vmode ].gc[ 0 ] );
}


/***************************************
 ***************************************/

void
fl_arcf( FL_COORD x,
         FL_Coord y,
         FL_COORD r,
         int      a1,
         int      a2,
         FL_COLOR col )
{
    fl_pieslice( 1, x - r, y - r, 2 * r, 2 * r, a1, a2, col );
}


/***************************************
 ***************************************/

void
fl_arc( FL_COORD x,
        FL_Coord y,
        FL_COORD r,
        int      a1,
        int      a2,
        FL_COLOR col )
{
    fl_pieslice( 0, x - r, y - r, 2 * r, 2 * r, a1, a2, col );
}


/***************************************
 ***************************************/

void
fl_pieslice( int      fill,
             FL_Coord x,
             FL_Coord y,
             FL_Coord w,
             FL_Coord h,
             int      a1,
             int      a2,
             FL_COLOR col )
{
    int delta = a2 - a1,
        bw = fli_dithered( fl_vmode ) && fli_mono_dither( col );
    GC gc = flx->gc;
    int ( * draw_as )( Display *,
                       Drawable,
                       GC,
                       int,
                       int,
                       unsigned int,
                       unsigned int,
                       int,
                       int );

    if ( flx->win == None || w <= 0 || h <= 0)
        return;

    draw_as = fill ? XFillArc : XDrawArc;

    if ( bw )
    {
        fli_set_current_gc( fli_whitegc );
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h,
                 a1 * 6.4, delta * 6.4 );
        fli_set_current_gc( dithered_gc );
    }

    fl_color( bw ? FL_BLACK : col );

    if ( w >= 0 && h >= 0 )
        draw_as( flx->display, flx->win, flx->gc, x, y, w, h,
                 a1 * 6.4, delta * 6.4 );
    if ( bw )
        fli_set_current_gc( gc );
}


/*********************************************************************
 * Line segments
 *****************************************************************{***/


/***************************************
 ***************************************/

void
fl_lines( FL_POINT * xp,
          int        n,
          FL_COLOR   col )
{
    if ( flx->win == None  || n <= 0 )
        return;

    fl_color( col );

    /* We may need to break up the request into smaller pieces */

    if ( fli_context->ext_request_size >= n )
        XDrawLines( flx->display, flx->win, flx->gc, xp, n, CoordModeOrigin );
    else
    {
        int req = fli_context->ext_request_size;
        int i,
            nchunks = ( n + ( n / req ) ) / req,
            left;
        FL_POINT *p = xp;

        for ( i = 0; i < nchunks; i++, p += req - 1 )
            XDrawLines( flx->display, flx->win, flx->gc, p, req,
                        CoordModeOrigin );

        left = xp + n - p;

        if ( left )
        {
            if ( left == 1 )
            {
                p--;
                left++;
            }

            XDrawLines( flx->display, flx->win, flx->gc, p, left,
                        CoordModeOrigin );
        }
    }
}


/***************************************
 * Drwas a simple line from (x1,y1) to (x2,y2)
 ***************************************/

void
fl_line( FL_Coord xi,
         FL_Coord yi,
         FL_Coord xf,
         FL_Coord yf,
         FL_COLOR c )
{
    if ( flx->win == None )
        return;

    fl_color( c );
    XDrawLine( flx->display, flx->win, flx->gc, xi, yi, xf, yf );
}


/**************** End of line segments *******************}*********/


/* points */

/***************************************
 * Draws a simple point at the given position
 ***************************************/

void
fl_point( FL_Coord x,
          FL_Coord y,
          FL_COLOR c )
{
    if ( flx->win == None )
        return;

    fl_color( c );
    XDrawPoint( flx->display, flx->win, flx->gc, x, y );
}


/***************************************
 * Draws a set of simple point at the given positions
 ***************************************/

void
fl_points( FL_POINT * p,
           int        np,
           FL_COLOR   c )
{
    if ( flx->win == None || np <= 0 )
        return;

    fl_color( c );
    XDrawPoints( flx->display, flx->win, flx->gc, p, np, CoordModeOrigin );
}


/********************************************************************
 * Basic drawing attributes
 ****************************************************************{*/

static int lw     = 0,
           ls     = LineSolid,
           drmode = GXcopy;


/***************************************
 ***************************************/

void
fl_linewidth( int n )
{
    XGCValues gcvalue;
    unsigned long gcmask;

    if ( lw == n )
        return;

    gcmask = GCLineWidth;
    gcvalue.line_width = lw = n;
    XChangeGC( flx->display, flx->gc, gcmask, &gcvalue );
}


/***************************************
 ***************************************/

int
fl_get_linewidth( void )
{
    return lw;
}


static void fli_xdashedlinestyle( Display *,
                                  GC,
                                  const char *,
                                  int );

/***************************************
 ***************************************/

void
fli_xlinestyle( Display * d,
                GC       gc,
                int      n )
{
    static char dots[ ]    = { 2, 4 };
    static char dotdash[ ] = { 7, 3, 2, 3 };
    static char ldash[ ]   = { 10, 4 };
    XGCValues gcvalue;
    unsigned long gcmask;

    if ( ls == n )
        return;

    ls = n;

    gcmask = GCLineStyle;

    if ( n == FL_DOT )
        fli_xdashedlinestyle( d, gc, dots, 2 );
    else if ( n == FL_DOTDASH )
        fli_xdashedlinestyle( d, gc, dotdash, 4 );
    else if ( n == FL_LONGDASH )
        fli_xdashedlinestyle( d, gc, ldash, 2 );
    if ( n > LineDoubleDash )
        n = LineOnOffDash;

    gcvalue.line_style = n;
    XChangeGC( d, gc, gcmask, &gcvalue );
}


/***************************************
 ***************************************/

void
fl_linestyle( int n )
{
    fli_xlinestyle( flx->display, flx->gc, n );
}


/***************************************
 ***************************************/

int
fl_get_linestyle( void )
{
    return ls;
}


/***************************************
 ***************************************/

int
fl_get_drawmode( void )
{
    return drmode;
}


/***************************************
 ***************************************/

void
fl_drawmode( int request )
{
    if ( drmode != request )
        XSetFunction( flx->display, flx->gc, drmode = request );
}


/***************************************
 ***************************************/

static void
fli_xdashedlinestyle( Display    * d,
                      GC           gc,
                      const char * dash,
                      int          ndash )
{
    static char default_dash[ ] = { 4, 4 };

    if ( dash == NULL )
    {
        dash = default_dash;
        ndash = 2;
    }

    XSetDashes( d, gc, 0, ( char * ) dash, ndash );
}


/***************************************
 ***************************************/

void
fl_dashedlinestyle( const char * dash,
                    int          ndash )
{
    static char default_dash[ ] = { 4, 4 };

    /* Check that the input is reasonable - XSetDashes() requires that
       there's at least one element in the 'dash' array and that none
       of its elements are 0. If one of these conditions isn't satis-
       fied (or 'dash' itself is NULL) set the defaut dash pattern. */

    if ( dash )
    {
        int i;

        for ( i = 0; i < ndash; i++ )
            if ( dash[ i ] == '\0' )
            {
                M_warn( "fl_dashedlinestyle", "Invalid '\0' in dash pattern "
                        "array, using default pattern" );
                ndash = 0;
                break;
            }
    }

    if ( ! dash || ! ndash )
    {
        dash = default_dash;
        ndash = 2;
    }

    XSetDashes( flx->display, flx->gc, 0, ( char * ) dash, ndash );
}


/************************************************************************
 * Clipping stuff
 ***********************************************************************/
/*
 *  Remember global clipping so unset_clipping will restore it. Most
 *  useful as part of event dispatching
 */
 
enum {
    FLI_GLOBAL_CLIP = 0,
    FLI_NORMAL_CLIP = 1,
    FLI_TEXT_CLIP   = 2,
    FLI_GC_CLIP     = 3
};


static int fli_is_clipped[ ] = { 0, 0, 0, 0 };
static FL_RECT fli_clip_rect[ ] = { { 0, 0, 0, 0 },
                                    { 0, 0, 0, 0 },
                                    { 0, 0, 0, 0 },
                                    { 0, 0, 0, 0 } };


#define SET_RECT( t, a, b, c, d )  \
   do {                            \
       ( t ).x      = a;           \
       ( t ).y      = b;           \
       ( t ).width  = c;           \
       ( t ).height = d;           \
   } while ( 0 )


#define GET_RECT( t, a, b, c, d )  \
   do {                            \
       *a = ( t ).x;               \
       *b = ( t ).y;               \
       *c = ( t ).width;           \
       *d = ( t ).height;          \
   } while ( 0 )


/***************************************
 * Returns if global clipping is switched on - in which case
 * the region for global clipping can be obtained via a call
 * of fli_get_global_clipping( ).
 ***************************************/

int
fl_is_global_clipped( void )
{
    return fli_is_clipped[ FLI_GLOBAL_CLIP ];
}


/***************************************
 * Helper function for determining if normal or text clipping is set
 * (also reports if global clipping is set when 'include_global' is
 * set).
 ***************************************/

static int
is_clipped( int type,
            int include_global )
{
    return    fli_is_clipped[ type ]
           || ( include_global && fli_is_clipped[ FLI_GLOBAL_CLIP ] );
}


/***************************************
 * Sets global clipping to the specified rectangle. If normal clipping
 * is already on the rectange use is the one resulting from intersecting
 * the requested rectangle with the one for normal clipping. Text is
 * clipped in the same way. If called with a negative width or height
 * global clipping is switched off.
 ***************************************/

void
fli_set_global_clipping( FL_Coord x,
                         FL_Coord y,
                         FL_Coord w,
                         FL_Coord h )
{
    /* Calling the function with a rectangle with a negative width or height
       results in switching off of global clipping */

    if ( w < 0 || h < 0 )
    {
        fli_unset_global_clipping( );
        return;
    }

    SET_RECT( fli_clip_rect[ FLI_GLOBAL_CLIP ], x, y, w, h );

    /* If normal clipping is already on intersect the new global and the
       normal clip area and set clipping to the result. If normal clipping
       is off just use the rectangle specified by the arguments. */

    if ( fli_is_clipped[ FLI_NORMAL_CLIP ] )
    {
        FL_RECT * r = fli_intersect_rects( fli_clip_rect + FLI_GLOBAL_CLIP,
                                           fli_clip_rect + FLI_NORMAL_CLIP );
        
        if ( r )
        {
            XSetClipRectangles( flx->display, flx->gc, 0, 0, r, 1, Unsorted );
            fli_safe_free( r );
        }
        else
        {
            FL_RECT n = { 0, 0, 0, 0 };

            XSetClipRectangles( flx->display, flx->gc, 0, 0, &n, 1, Unsorted );
        }
    }
    else
        XSetClipRectangles( flx->display, flx->gc, 0, 0,
                            &fli_clip_rect[ FLI_GLOBAL_CLIP ], 1, Unsorted );

    /* The same again for text clipping */

    if ( fli_is_clipped[ FLI_TEXT_CLIP ] )
    {
        FL_RECT * r = fli_intersect_rects( fli_clip_rect + FLI_GLOBAL_CLIP,
                                           fli_clip_rect + FLI_TEXT_CLIP );

        if ( r )
        {
            XSetClipRectangles( flx->display, flx->textgc, 0, 0, r, 1,
                                Unsorted );
            fli_safe_free( r );
        }
        else
        {
            FL_RECT n = { 0, 0, 0, 0 };

            XSetClipRectangles( flx->display, flx->textgc, 0, 0, &n, 1,
                                Unsorted );
        }
    }
    else
        XSetClipRectangles( flx->display, flx->textgc, 0, 0,
                            fli_clip_rect + FLI_GLOBAL_CLIP, 1, Unsorted );

    fli_is_clipped[ FLI_GLOBAL_CLIP ] = 1;
}


/***************************************
 * Unsets global clipping - "normal" and text clipping, if set, are retained
 ***************************************/

void
fli_unset_global_clipping( void )
{
    if ( ! fli_is_clipped[ FLI_GLOBAL_CLIP ] )
        return;

    SET_RECT( fli_clip_rect[ FLI_GLOBAL_CLIP ], 0, 0, 0, 0 );

    /* If normal clipping is also on set the clipping rectangle to that set
       for normal clipping, otherwise switch clipping off completely. */

    if ( fli_is_clipped[ FLI_NORMAL_CLIP ] )
        XSetClipRectangles( flx->display, flx->gc, 0, 0,
                            fli_clip_rect + FLI_NORMAL_CLIP, 1, Unsorted );
    else
        XSetClipMask( flx->display, flx->gc, None );

    /* Same for text clipping */

    if ( fli_is_clipped[ FLI_TEXT_CLIP ] )
        XSetClipRectangles( flx->display, flx->textgc, 0, 0,
                            fli_clip_rect + FLI_TEXT_CLIP, 1, Unsorted );
    else
        XSetClipMask( flx->display, flx->textgc, None );

    fli_is_clipped[ FLI_GLOBAL_CLIP ] = 0;
}


/***************************************
 * Returns a pointer to the rectangle used for global clipping (only
 * to be used when global clipping is on!)
 ***************************************/

FL_RECT *
fli_get_global_clip_rect( void )
{
    return fli_clip_rect + FLI_GLOBAL_CLIP;
}


/***************************************
 * Function returns as its return value if global clipping is on or off
 * and, via the pointer arguments, the clipping rectangle.
 ***************************************/

int
fl_get_global_clipping( FL_Coord * x,
                        FL_Coord * y,
                        FL_Coord * w,
                        FL_Coord * h )
{
    GET_RECT( fli_clip_rect[ FLI_GLOBAL_CLIP ], x, y, w, h );
    return fli_is_clipped[ FLI_GLOBAL_CLIP ];
}


/***************************************
 * Helper function to switch off normal, text or GC clipping - if global
 * clipping is on it will be retained.
 ***************************************/

static void
unset_clipping( int type,
                GC  gc )
{
    if ( ! fli_is_clipped[ type ] )
        return;

    SET_RECT( fli_clip_rect[ type ], 0, 0, 0, 0 );

    if ( fli_is_clipped[ FLI_GLOBAL_CLIP ] )
        XSetClipRectangles( flx->display, gc, 0, 0,
                            fli_clip_rect + FLI_GLOBAL_CLIP, 1, Unsorted );
    else
        XSetClipMask( flx->display, gc, None );

    fli_is_clipped[ type ] = 0;
}


/***************************************
 * Helper function to switch normal, text or GC clipping on for a certain
 * a certain region. 'type' is the type of clipping and 'gc' the GC for
 * which the clipping is to be set. If global clipping is already on the
 * clipping region is the intersection of the requested clipping region
 * with the clipping region for global clipping.
 ***************************************/

static void
set_clipping( int      type,
              GC       gc,
              FL_Coord x,
              FL_Coord y,
              FL_Coord w,
              FL_Coord h )
{
    if ( w < 0 || h < 0 )
    {
        unset_clipping( type, gc );
        return;
    }

    SET_RECT( fli_clip_rect[ type ], x, y, w, h );

    if ( fli_is_clipped[ FLI_GLOBAL_CLIP ] )
    {
        FL_RECT * r = fli_intersect_rects( fli_clip_rect + FLI_GLOBAL_CLIP,
                                           fli_clip_rect + type );
        
        if ( r )
        {
            XSetClipRectangles( flx->display, gc, 0, 0, r, 1, Unsorted );
            fli_safe_free( r );
        }
        else
        {
            FL_RECT n = { 0, 0, 0, 0 };

            XSetClipRectangles( flx->display, gc, 0, 0, &n, 1, Unsorted );
        }
    }
    else
        XSetClipRectangles( flx->display, gc, 0, 0, &fli_clip_rect[ type ],
                            1, Unsorted );

    fli_is_clipped[ type ] = 1;
}


/***************************************
 * Helper function for determining if normal or text clipping is on and the
 * region clipped to. 'type' is the type of clipping. If 'include_global' is
 * set also clipping due to global clipping is taken into account (and the
 * reported clipping region is the one resulting from intersection of the
 * clipping region for the requested type of clipping and the one for global
 * clipping). The function returns as its return value if there's clipping
 * going on (which may, when 'include_global', also be due to global clipping).
 ***************************************/

static int
get_clipping( int        type,
              int        include_global,
              FL_Coord * x,
              FL_Coord * y,
              FL_Coord * w,
              FL_Coord * h )
{
    if (    ! ( include_global && fli_is_clipped[ FLI_GLOBAL_CLIP ] )
         && fli_is_clipped[ type ] )
        GET_RECT( fli_clip_rect[ type ], x, y, w, h );
    else if ( include_global && fli_is_clipped[ FLI_GLOBAL_CLIP ] )
    {
        if ( fli_is_clipped[ type ] )
        {
            FL_RECT * r =
                fli_intersect_rects( fli_clip_rect + FLI_GLOBAL_CLIP,
                                     fli_clip_rect + type );
            
            if ( r )
            {
                GET_RECT( *r, x, y, w, h );
                fl_free( r );
            }
        }
        else
            GET_RECT( fli_clip_rect[ FLI_GLOBAL_CLIP ], x, y, w, h );
    }

    return is_clipped( type, include_global );
}


/***************************************
 * Returns if "normal" (i.e. non-text) clipping is switched on.
 * If 'include_global' is set also also global clipping (used
 * e.g. when redrawing on an expose event) is on, otherwise only
 * clipping set via a call of fl_set_clipping() is reported.
 ***************************************/

int
fl_is_clipped( int include_global )
{
    return is_clipped( FLI_NORMAL_CLIP, include_global );
}


/***************************************
 * Function for setting normal clipping. If global clipping is on the
 * rectangle set for clipping is the intersection of the rectangle specified
 * by the arguments and the one for global clipping.  Specifying a negative
 * clipping width or height results in clipping becoming switched off.
 ***************************************/

void
fl_set_clipping( FL_Coord x,
                 FL_Coord y,
                 FL_Coord w,
                 FL_Coord h )
{
    set_clipping( FLI_NORMAL_CLIP, flx->gc, x, y, w, h );
}


/****************************************
 * Function for switching of normal clipping. Note that global clipping
 * will be retained.
 ***************************************/

void
fl_unset_clipping( void )
{
    unset_clipping( FLI_NORMAL_CLIP, flx->gc );
}


/***************************************
 * Function for determining if normal clipping is on and the region clipped
 * to. If 'include_global' is set also clipping due to global clipping is
 * taken into account (and the reported clipping region is the one resulting
 * from intersection of the normal clipping region and the one for global
 * clipping). The function returns as its return value if there's clipping
 * going on (which may, when 'include_global', also be due to global clipping).
 ***************************************/

int
fl_get_clipping( int        include_global,
                 FL_Coord * x,
                 FL_Coord * y,
                 FL_Coord * w,
                 FL_Coord * h )
{
    return get_clipping( FLI_NORMAL_CLIP, include_global, x, y, w, h );
}


/***************************************
 * Returns if "text" clipping is switched on. If 'include_global'
 * is set also also global clipping (used e.g. when redrawing on
 * an expose event) is on, otherwise only clipping set via a call
 * of fl_set_text_clipping() is reported.
 ***************************************/

int
fl_is_text_clipped( int include_global )
{
    return is_clipped( FLI_TEXT_CLIP, include_global );
}


/***************************************
 * Function for setting text clipping. If global clipping is on the rectangle
 * set for clipping is the intersection of the rectangle specified by the
 * arguments and the one for global clipping. Specifying a negative clipping
 * width or height results in clipping becoming switched off.
 ***************************************/

void
fl_set_text_clipping( FL_Coord x,
                      FL_Coord y,
                      FL_Coord w,
                      FL_Coord h )
{
    set_clipping( FLI_TEXT_CLIP, flx->textgc, x, y, w, h );
}


/***************************************
 * Function for switching of text clipping. Note that global clipping
 * will be retained.
 ***************************************/

void
fl_unset_text_clipping( void )
{
    unset_clipping( FLI_TEXT_CLIP, flx->textgc );
}


/***************************************
 * Function for determining if text clipping is on and the region clipped
 * to. If 'include_global' is set also clipping due to global clipping is
 * taken into account (and the reported clipping region is the one resulting
 * from intersection of the text clipping region and the one for global
 * clipping). The function returns as its return value if there's clipping
 * going on (which may, when 'include_global', also be due to global clipping).
 ***************************************/

int
fl_get_text_clipping( int        include_global,
                      FL_Coord * x,
                      FL_Coord * y,
                      FL_Coord * w,
                      FL_Coord * h )
{
    return get_clipping( FLI_TEXT_CLIP, include_global, x, y, w, h );
}


/***************************************
 * Function for setting clipping for the specified GC. If global clipping is
 * on the rectangle set for clipping is the intersection of the rectangle
 * specified by the arguments and the one for global clipping. Specifying a
 * negative clipping width or height results in clipping becoming switched off.
 ***************************************/

void
fl_set_gc_clipping( GC       gc,
                    FL_Coord x,
                    FL_Coord y,
                    FL_Coord w,
                    FL_Coord h )
{
    fli_is_clipped[ FLI_GC_CLIP ] = 1;
    set_clipping( FLI_GC_CLIP, gc, x, y, w, h );
}


/***************************************
 * Function for switching of clipping for the given gc. Note that global
 * clipping will be retained.
 ***************************************/

void
fl_unset_gc_clipping( GC gc )
{
    fli_is_clipped[ FLI_GC_CLIP ] = 1;
    unset_clipping( FLI_GC_CLIP, gc );
}


/***************************************
 * Function that allows to set additional (always reducing the clipping
 * rectangle further) to already set clipping - the intersection of the
 * region and the already set clipping region is calculated and clipping
 * then set to the resulting rectangle.
 ***************************************/

void
fli_set_additional_clipping( FL_Coord x,
                             FL_Coord y,
                             FL_Coord w,
                             FL_Coord h )
{
    FL_RECT rect;

    SET_RECT( rect, x, y, w, h );

    if ( fli_is_clipped[ FLI_NORMAL_CLIP ] )
    {
        FL_RECT * r = fli_intersect_rects( fli_clip_rect + FLI_NORMAL_CLIP,
                                           &rect );

        if ( r )
        {
            rect = *r;
            fli_safe_free( r );
        }
        else
            SET_RECT( rect, 0, 0, 0, 0 );
    }

    fl_set_clipping( rect.x, rect.y, rect.width, rect.height );
}


/***************************************
 ***************************************/

static void
fli_set_current_gc( GC gc )
{
    if ( flx->gc == gc )
        return;

    flx->gc    = gc;
    flx->color = FL_NoColor;

    if (    fli_is_clipped[ FLI_GLOBAL_CLIP ]
         && fli_is_clipped[ FLI_NORMAL_CLIP ] )
    {
        FL_RECT * r = fli_intersect_rects( fli_clip_rect + FLI_GLOBAL_CLIP,
                                           fli_clip_rect + FLI_NORMAL_CLIP );
        
        if ( r )
        {
            XSetClipRectangles( flx->display, gc, 0, 0, r, 1, Unsorted );
            fli_safe_free( r );
        }
        else
        {
            FL_RECT n = { 0, 0, 0, 0 };

            XSetClipRectangles( flx->display, gc, 0, 0, &n, 1, Unsorted );
        }
    }
    else if ( fli_is_clipped[ FLI_GLOBAL_CLIP ] )
        XSetClipRectangles( flx->display, gc, 0, 0,
                            fli_clip_rect + FLI_GLOBAL_CLIP, 1, Unsorted );
    else if ( fli_is_clipped[ FLI_NORMAL_CLIP ] )
        XSetClipRectangles( flx->display, gc, 0, 0,
                            fli_clip_rect + FLI_NORMAL_CLIP, 1, Unsorted );
    else
        XSetClipMask( flx->display, gc, None );
}


/***************************************
 * Manually dither non-gray scale colors by changing default GC. Grayscales
 * are typically used in buttons, boxes etc, better not to dither them
 ***************************************/

static int
fli_mono_dither( unsigned long col )
{
    int bwtrick = 0;

    switch ( col )
    {
        case FL_RED:
        case FL_MAGENTA:
        case FL_SLATEBLUE:
        case FL_PALEGREEN:
        case FL_DARKGOLD:
        case FL_INACTIVE_COL:
            dithered_gc = fli_bwgc[ 1 ];
            bwtrick     = 1;
            break;

        case FL_YELLOW:
        case FL_CYAN:
        case FL_INDIANRED:
        case FL_GREEN:
            dithered_gc = fli_bwgc[ 2 ];
            bwtrick     = 1;
            break;

        case FL_BLUE:
            dithered_gc = fli_bwgc[ 0 ];
            bwtrick     = 1;
            break;

        default:
            if ( col >= FL_FREE_COL1 )
            {
                int r,
                    g,
                    b;

                fl_get_icm_color( col, &r, &g, &b );
                if ( ( bwtrick = ( r > 70 && r <= 210 ) ) )
                    dithered_gc = fli_bwgc[ r / 70 - 1 ];
            }
            break;
    }

    return bwtrick;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
