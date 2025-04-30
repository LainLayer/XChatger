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
 *  Copyright (c) 1998-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Handling misc. geometric markers
 *
 *   TODO: consolidate symbol and markers.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "flimage.h"
#include "flimage_int.h"
#include <stdlib.h>
#include <math.h>

#ifndef M_PI
#define M_PI  3.1415926f
#endif

#define Min( a, b ) ( ( a ) < ( b ) ? ( a ) : ( b ) )
typedef void ( * Draw )( FLIMAGE_MARKER * );

static void draw_delta( FLIMAGE_MARKER * );
static void draw_arrow( FLIMAGE_MARKER * );
static void draw_thinarrow( FLIMAGE_MARKER * );
static void draw_cross( FLIMAGE_MARKER * );
static void draw_rect( FLIMAGE_MARKER * );
static void draw_oval( FLIMAGE_MARKER * );
static void draw_line( FLIMAGE_MARKER * );
static void draw_star( FLIMAGE_MARKER * );

typedef struct
{
    const char * name;
    Draw         draw_marker;
    const char * psdraw;
} MARKER;

/* M(moveto) LT(lineto) S(stroke) F(fill) LW(setlinewidth) C(closepath) */

static char ps_cross[ ] = "-1 0 1 0 L 0 -1 0 1 L";
static char ps_rect[ ] = "-1 1 -1 -1 L 1 1 LT 1 -1 LT C";
static char ps_delta[ ] = " -1 -1 0 1 L 1 -1 LT C";
static char ps_oval[ ] = " 0 0 1 0 360 arc";
static char ps_line[ ] = "0 1 0 -1 L";
static char ps_star[ ] =
    "0 1 0.2245 0.309 L -0.2245 0.309 LT -0.9511 0.309 LT\n"
    "-0.3633 -0.118 LT -0.5878 -0.809 LT 0 -0.382 LT 0.5878 -0.809 LT\n"
    "0.3633 -0.1180 LT 0.9511 0.309 LT 0.2245 0.309 LT C ";
static char ps_arrow[ ] = 
    "1 0 M 0.3 0.7 LT 0.3 0.3 LT -1 0.3 LT "
    "-1 -0.3 LT 0.3 -0.3 LT 0.3 -0.7 LT C";
static char ps_thinarrow[ ] =
    "1 0 M 0.6 0.4 LT 0.6 0.1 LT -1 0.1 LT "
    "-1 -0.1 LT 0.6 -0.1 LT 0.6 -0.4 LT C";

#define MaxMarkers 32

static MARKER markers[ MaxMarkers ] =
{
    { "oval",      draw_oval,      ps_oval },
    { "cross",     draw_cross,     ps_cross },
    { "delta",     draw_delta,     ps_delta },
    { "rect",      draw_rect,      ps_rect },
    { "arrow",     draw_arrow,     ps_arrow },
    { "thinarrow", draw_thinarrow, ps_thinarrow },
    { "line",      draw_line,      ps_line },
    { "star",      draw_star,      ps_star },
    /* sentinel */
    { NULL,        NULL,           NULL }
};


/***************************************
 ***************************************/

static MARKER *
get_marker( const char *name )
{
    MARKER *m;

    for ( m = markers; m->name; m++ )
        if ( ! strcmp( name, m->name ) )
            return m;

    return 0;
}


/***************************************
 ***************************************/

int
flimage_define_marker( const char * name,
                       void         ( * draw )( FLIMAGE_MARKER * ),
                       const char * psdraw )
{
    MARKER *m, *me;

    if ( ! name || ! *name || ! psdraw )
        return -1;

    if ( ( m = get_marker( name ) ) )
    {
        m->draw_marker = draw;
        m->psdraw = fl_strdup( psdraw );
        return 0;
    }

    /* a new marker */

    for ( m = markers, me = m + MaxMarkers - 1; m < me; m++ )
    {
        if ( ! m->name )
        {
            m->name = fl_strdup( name );
            m->draw_marker = draw;
            m->psdraw = fl_strdup( psdraw );
            break;
        }
    }

    return m->name ? 0 : -1;
}


/***************************************
 ***************************************/

int
flimage_add_marker( FL_IMAGE     * im,
                    const char   * name,
                    double         x,
                    double         y,
                    double         w,
                    double         h,
                    int            style,
                    int            fill,
                    int            rot,
                    unsigned int   col,
                    unsigned int   bcol )
{
    int nm = im->nmarkers;
    FLIMAGE_MARKER *imarker;
    MARKER *m;

    if ( ! im )
    {
        M_err( "AddMarker", "Bad image" );
        return -1;
    }

    if ( ! name || ! *name || ! ( m = get_marker( name ) ) )
    {
        flimage_error( im, "unknown marker: %s", name );
        return -1;
    }

    im->marker = fl_realloc( im->marker, ( nm + 1 ) * sizeof *im->marker );

    if ( ! im->marker )
        return -1;

    while ( rot > 3600 )
        rot -= 3600;
    while ( rot < 0 )
        rot += 3600;

    imarker = im->marker + im->nmarkers;
    memset( imarker, 0, sizeof *imarker );
    imarker->name = m->name;
    imarker->psdraw = m->psdraw;
    imarker->fill = fill != 0;
    imarker->angle = rot;
    imarker->color = col;
    imarker->bcolor = bcol;
    imarker->style = ( style >= 0 && style <= FL_LONGDASH ) ? style : FL_SOLID;
    imarker->x = im->xdist_offset + x * im->xdist_scale;
    imarker->y = im->ydist_offset + y * im->ydist_scale;
    imarker->w = w * im->xdist_scale;
    imarker->h = h * im->ydist_scale;
    im->free_markers = flimage_delete_all_markers;
    im->display_markers = flimage_display_markers;
    return ++im->nmarkers;
}


/***************************************
 ***************************************/

int
flimage_add_marker_struct( FL_IMAGE             * im,
                           const FLIMAGE_MARKER * min )
{
    int nm = im->nmarkers;
    FLIMAGE_MARKER *imarker;
    MARKER *m;

    if ( ! im || ! min )
        return -1;

    if ( ! min->name || ! ( m  = get_marker( min->name ) ) )
    {
        M_err( "AddMarker", "bad marker name: %s", min->name );
        return -1;
    }

    if ( im->marker )
        im->marker = fl_realloc( im->marker, sizeof *im->marker * ( nm + 1 ) );
    else
        im->marker = fl_malloc( sizeof *im->marker * ( nm + 1 ) );

    if ( ! im->marker )
        return -1;

    imarker = im->marker + nm;
    memcpy( imarker, min, sizeof *im->marker );
    imarker->name = m->name;
    imarker->psdraw = m->psdraw;
    im->free_markers = flimage_delete_all_markers;
    im->display_markers = flimage_display_markers;

    return ++im->nmarkers;
}


/***************************************
 ***************************************/

void
flimage_delete_all_markers( FL_IMAGE * im )
{
    if ( ! im )
        return;
    if ( im->marker )
        fl_free( im->marker );
    im->marker = 0;
    im->nmarkers = 0;
}


/***************************************
 ***************************************/

void
flimage_display_markers( FL_IMAGE * im )
{
    int r,
        g,
        b,
        newpix;
    unsigned long pixel;
    FLIMAGE_MARKER *m,
                   *mend;
    MARKER *active;

    if ( im->dont_display_marker )
        return;

    if ( ! im->markergc )
        im->markergc = XCreateGC( im->xdisplay, im->win, 0, 0 );

    for ( m = im->marker, mend = m + im->nmarkers; m < mend; m++ )
    {
        active = get_marker( m->name );

        if ( active && active->draw_marker )
        {
            FL_UNPACK( m->color, r, g, b );
            pixel = flimage_color_to_pixel( im, r, g, b, &newpix );
            m->gc = im->markergc;
            m->win = im->win;
            m->display = im->xdisplay;
            m->x += im->wxd - im->sxd;
            m->y += im->wyd - im->syd;
            XSetForeground( m->display, m->gc, pixel );
            fli_xlinestyle( m->display, m->gc, m->style );
            active->draw_marker( m );
            m->x -= im->wxd - im->sxd;
            m->y -= im->wyd - im->syd;

            if ( newpix )
                XFreeColors( m->display, im->xcolormap, &pixel, 1, 0 );
        }
    }
}


/**********************************************************************
 * Local support routines. Debatible if we should make use of symbol stuff
 *********************************************************************/

/***************************************
 * rotate the coordinates by angle, with the rotation axis at (xo,yo)
 ***************************************/

static void
rotate( FL_POINT * p,
        int        n,
        int        angle,
        int        xo,
        int        yo )
{
    static int last_angle;
    static double sina = 0,
                  cosa = 1;
    int i,
        tx,
        ty;

    if ( angle == 0 || angle == 3600 )
        return;

    if ( last_angle != angle )
    {
        last_angle = angle;
        sina = sin( angle * M_PI / 1800.0 );
        cosa = cos( angle * M_PI / 1800.0 );
    }

    for ( i = 0; i < n; i++ )
    {
        tx = p[ i ].x - xo;
        ty = p[ i ].y - yo;
        p[ i ].x = xo + tx * cosa + ty * sina + 0.5;
        p[ i ].y = yo - tx * sina + ty * cosa + 0.5;
    }
}


typedef struct
{
    float x,
          y;
} FL_FPOINT;

static void
rotatef( FL_FPOINT * p,
         int         n,
         int         angle,
         int         xo,
         int         yo)
{
    static int    last_angle;
    static double sina,
                  cosa;
    int i,
        tx,
        ty;

    if ( angle == 0 || angle == 3600 )
        return;

    if ( last_angle != angle )
    {
        last_angle = angle;
        sina = sin( angle * M_PI / 1800.0 );
        cosa = cos( angle * M_PI / 1800.0 );
    }

    for ( i = 0; i < n; i++ )
    {
        tx = p[ i ].x - xo;
        ty = p[ i ].y - yo;
        p[ i ].x = xo + tx * cosa + ty * sina;
        p[ i ].y = yo - tx * sina + ty * cosa;
    }
}


/***************************************
 ***************************************/

static void
scalef( FL_FPOINT * p,
        FL_FPOINT * pout,
        int         n,
        int         xscale,
        int         yscale )
{
    int i;

    for ( i = 0; i < n; i++ )
    {
        pout[ i ].x = p[ i ].x * xscale;
        pout[ i ].y = p[ i ].y * yscale;
    }
}


#define fill_point( p, sx, sy )  ( p.x = sx, p.y = sy )


/***************************************
 ***************************************/

static void
draw_cross( FLIMAGE_MARKER * m )
{
    int w = m->w / 2,
        h = m->h / 2;
    int xo = m->x,
        yo = m->y;
    FL_POINT p[ 4 ];

    fill_point( p[ 0 ], xo - w, yo     );
    fill_point( p[ 1 ], xo + w, yo     );
    fill_point( p[ 2 ], xo,     yo - h );
    fill_point( p[ 3 ], xo,     yo + h );

    rotate( p, 4, m->angle, xo, yo );

    XDrawLine( m->display, m->win, m->gc,
               p[ 0 ].x, p[ 0 ].y, p[ 1 ].x, p[ 1 ].y );
    XDrawLine( m->display, m->win, m->gc,
               p[ 2 ].x, p[ 2 ].y, p[ 3 ].x, p[ 3 ].y );
}


#define SEG   60

/***************************************
 ***************************************/

static void
draw_oval( FLIMAGE_MARKER * m )
{
    int xo = m->x,
        yo = m->y;
    int w = m->w / 2,
        h = m->h / 2;

    if ( m->angle % 3600 == 0 || w == h )
    {
        ( m->fill ? XFillArc : XDrawArc )
            ( m->display, m->win, m->gc,
              m->x - w, m->y - h, m->w, m->h, 0, 360 * 64 );
    }
    else
    {
        static int mode = CoordModeOrigin;
        static FL_FPOINT fp[ SEG ],
                         pp[ SEG ];
        static int first = 1;
        int i;
        FL_POINT p[ SEG + 1 ];

        if ( first )
        {
            double t;

            for ( t = 0, i = 0; i < SEG; i++, t += 360.0 / ( SEG + 1 ) )
            {
                fp[ i ].x = cos( t * M_PI / 180.0 );
                fp[ i ].y = sin( t * M_PI / 180.0 );
            }

            first = 0;
        }

        scalef( fp, pp, SEG, w, h );
        rotatef( pp, SEG, m->angle, 0, 0 );

        for ( i = 0; i < SEG; i++ )
        {
            p[ i ].x = xo + pp[i].x + 0.5;
            p[ i ].y = yo - pp[i].y + 0.5;
        }

        fill_point( p[ SEG ], p[ 0 ].x, p[ 0 ].y );

        if ( ! m->fill )
            XDrawLines( m->display, m->win, m->gc, p, SEG + 1, mode );
        else
            XFillPolygon( m->display, m->win, m->gc, p, SEG, Nonconvex, mode );
    }
}


/***************************************
 ***************************************/

static void
draw_rect( FLIMAGE_MARKER * m )
{
    static int mode = CoordModeOrigin;
    int w = m->w / 2,
        h = m->h / 2;
    int xo = m->x,
        yo = m->y;
    FL_POINT p[ 5 ];

    fill_point( p[ 0 ], xo - w, yo + h );
    fill_point( p[ 1 ], xo + w, yo + h );
    fill_point( p[ 2 ], xo + w, yo - h );
    fill_point( p[ 3 ], xo - w, yo - h );

    rotate( p, 4, m->angle, xo, yo );

    fill_point( p[ 4 ], p[ 0 ].x, p[ 0 ].y );

    if ( ! m->fill )
        XDrawLines( m->display, m->win, m->gc, p, 5, mode );
    else
        XFillPolygon( m->display, m->win, m->gc, p, 4, Convex, mode );
}


/***************************************
 ***************************************/

static float arrow_xhead,
             arrow_yhead,
             arrow_rod;

static void
drw_arrow( FLIMAGE_MARKER * m )
{
    static int mode = CoordModeOrigin;
    int w = m->w / 2,
        h = m->h / 2;
    int xo = m->x,
        yo = m->y;
    int xhead = 2 + ( int ) ( w * arrow_xhead );
    int yhead = 2 + ( int ) ( h * arrow_yhead );
    int rod = ( int ) ( h * arrow_rod );
    FL_POINT p[ 8 ];

    xhead = yhead = Min( xhead, yhead );

    fill_point( p[ 0 ], xo - w,         yo + rod   );
    fill_point( p[ 1 ], xo + w - xhead, yo + rod   );
    fill_point( p[ 2 ], xo + w - xhead, yo + yhead );
    fill_point( p[ 3 ], xo + w,         yo         );
    fill_point( p[ 4 ], xo + w - xhead, yo - yhead );
    fill_point( p[ 5 ], xo + w - xhead, yo - rod   );
    fill_point( p[ 6 ], xo - w,         yo - rod   );

    rotate( p, 7, m->angle, xo, yo );

    fill_point( p[ 7 ], p[ 0 ].x, p[ 0 ].y );

    if ( ! m->fill )
        XDrawLines( m->display, m->win, m->gc, p, 8, mode );
    else
        XFillPolygon( m->display, m->win, m->gc, p, 7, Nonconvex, mode );
}


/***************************************
 ***************************************/

static void
draw_arrow( FLIMAGE_MARKER * m )
{
    arrow_xhead = arrow_yhead = 0.52;
    arrow_rod = 0.3;
    drw_arrow( m );
}


/***************************************
 ***************************************/

static void
draw_thinarrow( FLIMAGE_MARKER * m )
{
    arrow_xhead = arrow_yhead = 0.26;
    arrow_rod = 0.15;
    drw_arrow( m );
}


/***************************************
 ***************************************/

static void
draw_line( FLIMAGE_MARKER * m )
{
    int w = m->w / 2;
    int xo = m->x,
        yo = m->y;
    FL_POINT p[ 2 ];

    fill_point( p[ 0 ], xo - w, yo );
    fill_point( p[ 1 ], xo + w, yo );

    rotate( p, 2, m->angle, xo, yo );

    XDrawLine( m->display, m->win, m->gc,
               p[ 0 ].x, p[ 0 ].y, p[ 1 ].x, p[ 1 ].y);
}


/***************************************
 ***************************************/

static void
draw_delta( FLIMAGE_MARKER * m )
{
    static int mode = CoordModeOrigin;
    int w = m->w / 2,
        h = m->h / 2;
    int xo = m->x,
        yo = m->y;
    FL_POINT p[ 4 ];

    fill_point( p[ 0 ], xo - w, yo + h );
    fill_point( p[ 1 ], xo + w, yo + h );
    fill_point( p[ 2 ], xo    , yo - h );

    rotate( p, 3, m->angle, xo, yo );

    fill_point( p[ 3 ], p[ 0 ].x, p[ 0 ].y );

    if ( ! m->fill )
        XDrawLines( m->display, m->win, m->gc, p, 4, mode );
    else
        XFillPolygon( m->display, m->win, m->gc, p, 3, Convex, mode );
}


/***************************************
 ***************************************/

static void
draw_star( FLIMAGE_MARKER * m )
{
    static int mode = CoordModeOrigin;
    int w = m->w / 2,
        h = m->h / 2;
    int xo = m->x,
        yo = m->y;
    FL_POINT p[ 11 ];
    static FL_FPOINT fp[ 10 ],
                     pp[ 10 ];
    static int first = 1;
    int i;

    /* generate a unit star */

    if ( first )
    {
        float t,
              l = sin( 18.0 * M_PI / 180.0 ) / sin( 54.0 * M_PI / 180.0 );

        for ( i = 0, t = 54.0; i < 10; i += 2, t += 72.0 )
        {
            fp[ i ].x = l * cos( t * M_PI / 180.0 );
            fp[ i ].y = l * sin( t * M_PI / 180.0 );
        }

        for ( i = 1, t = 90.0; i < 10; i += 2, t += 72.0 )
        {
            fp[ i ].x = cos( t * M_PI / 180.0 );
            fp[ i ].y = sin( t * M_PI / 180.0 );
        }

        first = 0;
    }

    scalef( fp, pp, 10, w, h );
    rotatef( pp, 10, m->angle, 0, 0 );

    for ( i = 0; i < 10; i++ )
    {
        p[ i ].x = xo + pp[i].x + 0.5;
        p[ i ].y = yo - pp[i].y + 0.5;
    }

    fill_point( p[ 10 ], p[ 0 ].x, p[ 0 ].y );

    if ( ! m->fill )
        XDrawLines( m->display, m->win, m->gc, p, 11, mode );
    else
        XFillPolygon( m->display, m->win, m->gc, p, 10, Nonconvex, mode );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
