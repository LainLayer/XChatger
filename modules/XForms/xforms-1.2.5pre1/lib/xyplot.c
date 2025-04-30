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
 * \file xyplot.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1997-2002  T.C. Zhao
 *  All rights reserved.
 *
 * Class FL_XYPLOT. Simple 2D tabulated function plot.
 *
 *   Possible optimization: break update into DRAW_INSET, DRAW_POINT
 *   etc. so an update of inset does not result in complete redraw.
 *
 *  Need to re-think about the entire approach to overlay
 *
 *  The whole thing needs a complete review, lots of things look fishy,
 *  starting with memory allocation!                        JTT
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <math.h>
#include "private/pxyplot.h"


#define XMAJOR       5
#define XMINOR       2
#define YMAJOR       5
#define YMINOR       2

static float gen_tic( float,
                      float,
                      int, int );

static float gen_logtic( float,
                         float,
                         float,
                         int );

static void convert_coord( FL_OBJECT *,
                           FLI_XYPLOT_SPEC * );

static void find_xbounds( FLI_XYPLOT_SPEC * );

static void find_ybounds( FLI_XYPLOT_SPEC * );

static int allocate_spec( FLI_XYPLOT_SPEC *,
                          int );

static void add_xgrid( FL_OBJECT * );

static void add_ygrid( FL_OBJECT * );

static void free_spec_dynamic_mem( FLI_XYPLOT_SPEC * );

static void w2s_draw( FL_OBJECT *,
                      double,
                      double,
                      float *,
                      float * );

static void compute_key_position( FL_OBJECT * );

static void draw_inset( FL_OBJECT * );

static void gen_xtic( FL_OBJECT * );

static void gen_ytic( FL_OBJECT * );


/* This variable is needed because screen positions of data drawn are
 * calculated differently when drawing directly to the screen and when
 * using double buffering and thus drawing to a pixmap - in the first
 * case the positions are calculated relative to the form while in the
 * second relative to the xyplot object. This must be taken into con-
 * sideration when comparing data positions to the mouse position while
 * the user clicks on or moves onto data point in an active xyplot. */

static int draw_to_pixmap = 0;


/***************************************
 * Free data associated with overlay
 ***************************************/

static void
free_overlay_data( FLI_XYPLOT_SPEC * sp,
                   int               id )
{
    if ( sp->x && sp->y && sp->n && sp->n[ id ] )
    {
        fli_safe_free( sp->x[ id ] );
        fli_safe_free( sp->y[ id ] );
        sp->n[ id ] = 0;
    }
}


/***************************************
 * Free strings for alpha-tics
 ***************************************/

static void
free_atic( char ** atic )
{
    size_t cnt;

    for ( cnt = 0; cnt < MAX_MAJOR && *atic; atic++, cnt++ )
        fli_safe_free( *atic );
}


/***************************************
 ***************************************/

static void
extend_screen_data( FLI_XYPLOT_SPEC * sp,
                    int               n )
{
    if ( n > sp->cur_nxp )
    {
        sp->xp--;
        sp->xp = fl_realloc( sp->xp, ( n + 3 ) * sizeof *sp->xp );
        sp->xp++;                 /* Need one extra point for fill */
        sp->cur_nxp = n;
        sp->xpactive = fl_realloc( sp->xpactive,
                                   ( n + 3 ) * sizeof *sp->xpactive );
    }
}


/***************************************
 ***************************************/

static void
free_xyplot( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    fl_clear_xyplot( ob );

    /* Working arrays */

    fli_safe_free( sp->wx );
    fli_safe_free( sp->wy );
    fli_safe_free( sp->xpactive );
    if ( sp->xpi )
        fl_free( --sp->xpi );
    if ( sp->xp )
        fl_free( --sp->xp );

    /* Various labels */

    fli_safe_free( sp->xlabel );
    fli_safe_free( sp->ylabel );
    fli_safe_free( sp->title );
    fli_safe_free( sp->text );

    free_atic( sp->axtic );
    free_atic( sp->aytic );

    fli_safe_free( sp->xmargin1 );
    fli_safe_free( sp->xmargin2 );
    fli_safe_free( sp->ymargin1 );
    fli_safe_free( sp->ymargin2 );

    free_spec_dynamic_mem( sp );
}


/***************************************
 * Symbols. Center at (x,y) spanning a rectangle of (w,h)
 ***************************************/

static void
draw_square( FL_OBJECT * ob  FL_UNUSED_ARG,
             int         Id  FL_UNUSED_ARG,
             FL_POINT  * p,
             int         n,
             int         w,
             int         h )
{
    int w2 = w / 2,
        h2 = h / 2;
    FL_POINT *ps = p + n;

    if ( flx->win != None )
        for ( ; p < ps; p++ )
            XDrawRectangle( flx->display, flx->win, flx->gc,
                            p->x - w2, p->y - h2, w, h );
}


/***************************************
 ***************************************/

static void
draw_circle( FL_OBJECT * ob  FL_UNUSED_ARG,
             int         id  FL_UNUSED_ARG,
             FL_POINT  * p,
             int         n,
             int         w,
             int         h )
{
    int w2 = w / 2,
        h2 = h / 2;
    FL_POINT *ps = p + n;

    if ( flx->win != None )
        for ( ; p < ps; p++ )
            XDrawArc( flx->display, flx->win, flx->gc, p->x - w2, p->y - h2,
                      w, h, 0, 64 * 360 );
}


/***************************************
 ***************************************/

static void
draw_points( FL_OBJECT * ob  FL_UNUSED_ARG,
             int         id  FL_UNUSED_ARG,
             FL_POINT  * p,
             int         n,
             int         w,
             int         h )
{
    FL_POINT *pe = p + n;

    w /= 2;
    h /= h;

    if ( flx->win != None )
        for ( ; p < pe; p++ )
        {
            XSegment seg[ ] = { { p->x - w, p->y,     p->x + w, p->y     },
                                { p->x,     p->y - h, p->x,     p->y + h },
                                { p->x - w, p->y - h, p->x + w, p->y + h },
                                { p->x + w, p->y - h, p->x - w, p->y + h } };

            XDrawSegments( flx->display, flx->win, flx->gc,
                           seg, sizeof seg / sizeof *seg );
        }
}


/***************************************
 ***************************************/

int
fli_xyplot_interpolate( FL_OBJECT * ob,
                        int         id,
                        int         n1,
                        int         n2 )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int newn;
    float *x = sp->x[ id ],
          *y = sp->y[ id ];

    /* Need to resize screen points */

    newn = 1.01 + ( x[ n2 - 1 ] - x[ n1 ] ) / sp->grid[ id ];

    /* Test if the number of points exceeds the screen resolution by a
       large margin */

    if ( newn > 5000 )
    {
        M_err( "fli_xyplot_interpolate",
               "interpolating %d points exceeds screen res", newn );
        return -1;
    }

    if ( newn > sp->nxpi )
    {
        sp->xpi--;
        sp->xpi = fl_realloc( sp->xpi, ( newn + 3 ) * sizeof *sp->xpi );
        sp->xpi++;
        sp->nxpi = newn;
    }

    if ( newn > sp->ninterpol )
    {
        sp->wx = fl_realloc( sp->wx, newn * sizeof *sp->wx );
        sp->wy = fl_realloc( sp->wy, newn * sizeof *sp->wy );

        if ( ! sp->wx || ! sp->wy )
        {
            if ( sp->wx )
                fli_safe_free( sp->wx );
            M_err( "fli_xyplot_interpolate",
                   "Can't allocate memory for %d points", newn );
            return -1;
        }

        sp->ninterpol = newn;
    }

    if ( fl_interpolate( x + n1, y + n1, n2 - n1,
                         sp->wx, sp->wy, sp->grid[ id ],
                         sp->interpolate[ id ] ) != newn )
    {
        M_err( "fli_xyplot_interpolate",
               "An error has occured while interpolating" );
        return -1;
    }

    return newn;
}


/* To avoid singularity or extreme scaling factors */

#define FMIN  1.0e-25

/***************************************
 * This is faster than calling fl_xyplot_w2s N times. Also
 * we call this while drawing, that means we have to
 * use sp->bx, but sp->bxm as fl_xyplot_w2s uses
 ***************************************/

static void
mapw2s( FL_OBJECT * ob,
        FL_POINT  * p,
        int         n1,
        int         n2,
        float     * x,
        float     * y )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int i;

    if ( sp->xscale == FL_LOG )
    {
        double lbase = 1.0 / sp->lxbase;

        for ( i = n1; i < n2; i++ )
        {
            double t = log10( FL_max( x[ i ], FMIN ) ) * lbase;
            p[ i - n1 ].x = FL_crnd( sp->ax * t + sp->bx );
        }
    }
    else
        for ( i = n1; i < n2; i++ )
            p[ i - n1 ].x = FL_crnd( sp->ax * x[ i ] + sp->bx );

    if ( sp->yscale == FL_LOG )
    {
        double lbase = 1.0 / sp->lybase;

        for ( i = n1; i < n2; i++ )
        {
            double t = log10( FL_max( y[ i ], FMIN ) ) * lbase;
            p[ i - n1 ].y = FL_crnd( sp->ay * t + sp->by );
        }
    }
    else
        for ( i = n1; i < n2; i++ )
        {
            int tmp = FL_crnd( sp->ay * y[ i ] + sp->by );

            tmp = FL_max( 0, tmp );
            tmp = FL_min( 30000, tmp );
            p[ i - n1 ].y = tmp;
        }
}


/***************************************
 * While not autoscaling some of the data might fall outside the range
 * to be drawn, get rid of them so actual data that get plotted are bound
 * by (n1, n2)
 ***************************************/

void
fli_xyplot_compute_data_bounds( FL_OBJECT * ob,
                                int       * n1,
                                int       * n2,
                                int         id )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int i;
    float *x = sp->x[ id ];
    float xmin = FL_min( sp->xmin, sp->xmax );
    float xmax = FL_max( sp->xmax, sp->xmin );

    /* Special case for not more than two points */

    if ( sp->n[ id ] <= 2 )
    {
        *n1 = 0;
        *n2 = sp->n[ id ];
        return;
    }

    for ( *n1 = -1, i = 0; i < sp->n[ id ] && *n1 < 0; i++ )
        if ( x[ i ] >= xmin )
            *n1 = i;

    if ( *n1 > 0 )
        *n1 -= 1;
    else if ( *n1 < 0 )
        *n1 = 0;

    for ( *n2 = -1, i = sp->n[ id ]; --i >= 0 && *n2 < 0; )
        if ( x[ i ] <= xmax )
            *n2 = i;

    if ( *n2 < 0 )
        *n2 = sp->n[ id ] > 1 ? sp->n[ id ] : 1;

    if ( *n2 < sp->n[ id ] )
        *n2 += 1;
    if ( *n2 < sp->n[ id ] )
        *n2 += 1;
}


/***************************************
 * Draw curves of data and all overlays
 ***************************************/

static void
draw_curve_only( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int i,
        n1,
        n2,
        noline,
        nplot,
        type,
        nxp,
        newn,
        cur_lw = 0;
    FL_XYPLOT_SYMBOL drawsymbol;
    FL_POINT *xp;
    float *x,
          *y;
    FL_COLOR col;
    int savelw = fl_get_linewidth( ),
        savels = fl_get_linestyle( );
    int key_xs,
        key_ys;

    fl_set_clipping( sp->xi, sp->yi, sp->xf - sp->xi + 1, sp->yf - sp->yi + 1 );

    fl_set_text_clipping( sp->xi, sp->yi, sp->xf - sp->xi + 1,
                          sp->yf - sp->yi + 1 );

    if ( sp->xgrid != FL_GRID_NONE && sp->xtic > 0 )
        add_xgrid( ob );

    if ( sp->ygrid != FL_GRID_NONE && sp->ytic > 0 )
        add_ygrid( ob );

    compute_key_position( ob );
    fl_rect( sp->key_xs, sp->key_ys, sp->key_maxw, sp->key_maxh, *sp->col );

    key_xs = sp->key_xs + 2;
    key_ys = sp->key_ys + sp->key_ascend - sp->key_descend;

    for ( nplot = 0; nplot <= sp->maxoverlay; nplot++ )
    {
        if ( sp->n[ nplot ] == 0 )
            continue;

        fl_color( col = sp->col[ nplot ] );
        drawsymbol = NULL;
        noline = 0;

        /* Without autoscaling some of the data might fall outside the range
           desired, get rid of them so actual data that get plotted are bound
           by (n1, n2) */

        fli_xyplot_compute_data_bounds( ob, &n1, &n2, nplot );
        sp->n1 = n1;

        /* Convert data. If interpolate is requested do it here */

        if (    sp->interpolate[ nplot ] > 1
             && n2 - n1 > 3
             && ( newn = fli_xyplot_interpolate( ob, nplot, n1, n2 ) ) >= 0 )
        {
            x  = sp->wx;
            y  = sp->wy;
            xp = sp->xpi;

            mapw2s( ob, xp, 0, newn, x, y );

            nxp = sp->nxpi = newn;

            mapw2s( ob, sp->xp, n1, n2, sp->x[ nplot ], sp->y[ nplot ] );
            sp->nxp = n2 - n1;
            if (    ( sp->active || sp->inspect )
                 && sp->iactive == nplot
                 && ! sp->update )
                memcpy( sp->xpactive, sp->xp, sp->nxp * sizeof *xp );
        }
        else
        {
            x = sp->x[ nplot ];
            y = sp->y[ nplot ];
            xp = sp->xp;

            mapw2s( ob, xp, n1, n2, x, y );

            nxp = sp->nxp = n2 - n1;

            if (    ( sp->active || sp->inspect )
                 && sp->iactive == nplot
                 && ! sp->update )
                memcpy( sp->xpactive, sp->xp, sp->nxp * sizeof *xp );
        }

        type = nplot > 0 ? sp->type[ nplot ] : ob->type;

        if ( cur_lw != sp->thickness[ nplot ] )
        {
            cur_lw = sp->thickness[ nplot ];
            fl_linewidth( cur_lw );
        }

        switch ( type )
        {
            case FL_ACTIVE_XYPLOT:
                drawsymbol = sp->mark_active ? draw_square : NULL;
                break;

            case FL_SQUARE_XYPLOT:
                drawsymbol = draw_square;
                break;

            case FL_CIRCLE_XYPLOT:
                drawsymbol = draw_circle;
                break;

            case FL_POINTS_XYPLOT:
                noline = 1;
                /* fall through */

            case FL_LINEPOINTS_XYPLOT:
                drawsymbol = sp->symbol[ nplot ] ?
                             sp->symbol[ nplot ] : draw_points;
                break;

            case FL_DOTTED_XYPLOT:
                fl_linestyle( FL_DOT );
                break;

            case FL_DOTDASHED_XYPLOT:
                fl_linestyle( FL_DOTDASH );
                break;

            case FL_LONGDASHED_XYPLOT:
                fl_linestyle( FL_LONGDASH );
                break;

            case FL_DASHED_XYPLOT:
                fl_dashedlinestyle( NULL, 0 );
                fl_linestyle( LineOnOffDash );
                break;

            case FL_FILL_XYPLOT:
                xp[ -1 ].x = xp[ 0 ].x;   /* looks ugly, better recheck ! JTT */
                xp[ -1 ].y = sp->yf;
                xp[ nxp ].x = xp[ nxp - 1 ].x;
                xp[ nxp ].y = sp->yf;
                fl_polyf( xp - 1, nxp + 2, col );
                noline = 1;
                break;

            case FL_EMPTY_XYPLOT:
                noline = 1;
                drawsymbol = NULL;
                break;

            case FL_IMPULSE_XYPLOT:
                noline = 1;
                drawsymbol = NULL;
                for ( i = 0; i < nxp; i++ )
                    fl_line( xp[ i ].x, sp->yf - 1, xp[ i ].x, xp[ i ].y, col );
                break;

            case FL_NORMAL_XYPLOT:
            default:
                break;
        }

        if ( ! noline )
            fl_lines( xp, nxp, col );

        if ( drawsymbol )
            drawsymbol( ob, nplot, sp->xp, sp->nxp, sp->ssize, sp->ssize );

        /* Do keys */

        if ( sp->key[ nplot ] )
        {
            fl_linewidth( 0 );

            if ( ! noline )
                fl_line( key_xs, key_ys, key_xs + 20, key_ys, col );

            if ( type == FL_IMPULSE_XYPLOT )
            {
                fl_line( key_xs + 3, key_ys + 2, key_xs + 3, key_ys - 3, col );
                fl_line( key_xs + 7, key_ys + 2, key_xs + 7, key_ys - 3, col );
                fl_line( key_xs + 11, key_ys + 2, key_xs + 11,
                         key_ys - 3, col );
                fl_line( key_xs + 15, key_ys + 2, key_xs + 15,
                         key_ys - 3, col );
            }
            else if ( sp->type[ nplot ] == FL_FILL_XYPLOT )
                fl_rectf( key_xs + 1, key_ys - 3, 19, 6, col );

            if ( drawsymbol )
            {
                FL_POINT p[ 4 ];

                p[ 0 ].x = key_xs + 3;
                p[ 1 ].x = key_xs + 10;
                p[ 2 ].x = key_xs + 17;
                p[ 0 ].y = p[ 1 ].y = p[ 2 ].y = key_ys;
                drawsymbol( ob, nplot, p, 3, 4, 4 );
            }

            fl_draw_text( FL_ALIGN_LEFT, key_xs + 20, key_ys, 0, 0, col,
                          sp->key_lstyle, sp->key_lsize, sp->key[ nplot ] );

            key_ys += sp->key_ascend + sp->key_descend * 0.9;
        }

        fl_linestyle( savels );
        fl_linewidth( cur_lw = savelw );
    }

    /* Finally we draw extra text */

    draw_inset( ob );

    fl_linestyle( savels );
    fl_linewidth( savelw );
    fl_unset_clipping( );
    fl_unset_text_clipping( );
}


/***************************************
 ***************************************/

void
fli_xyplot_nice_label( float   tic,
                       int     minor,
                       float   f,
                       char  * label )
{
    float crit = tic * minor;

    if ( tic >= 1.0 && crit < 10.0 )
        sprintf( label, "%.1f", f );
    else if ( tic > 1.0 && crit < 1000.0 )
        sprintf( label, "%.0f", f );
    else if ( crit >= 0.40 && crit <= 999.0 )
        sprintf( label, "%.1f", f );
    else if ( crit < 0.40 && crit > 0.01 )
        sprintf( label, "%.2f", f );
    else
        sprintf( label, "%g", f );
}


/***************************************
 ***************************************/

static void
gen_xtic( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float tic = sp->xtic;
    double x;
    float xmin,
          xmax;
    float mxmin,
          mxmax;
    int i;

    if ( tic < 0 )
        return;

    xmin = mxmin = FL_min( sp->xscmin, sp->xscmax );
    xmax = mxmax = FL_max( sp->xscmin, sp->xscmax );

    if (    sp->xtic > 0.0      \
         && ! *sp->axtic                    \
         && sp->xmajor > 1 )
    {
        mxmin = floor( xmin / tic ) * tic;
        mxmax = ceil( xmax / tic ) * tic;
    }

    /* Handle ticlable@location stuff */

    if ( *sp->axtic )
    {
        char *p;
        char *eptr;
        int j = 0;

        for ( i = 0; i < sp->xmajor; i++ )
        {
            if ( ( p = strchr( sp->axtic[ i ], '@' ) ) )
                x = strtod( p + 1, &eptr );
                
            if ( ! p || eptr == p + 1 )
                x = mxmin + ( i * tic * sp->xminor );
            else if ( sp->xscale == FL_LOG )
                x = log10( x ) / sp->lxbase;

            if ( x >= xmin && x <= xmax )
            {
                sp->xtic_major[ i ] = FL_crnd( sp->ax * x + sp->bx );
                sp->xmajor_val[ i ] = x;
                j++;
            }
        }

        sp->num_xmajor = j;
        sp->num_xminor = 1;
        return;
    }

    if ( sp->xscale != FL_LOG )
    {
        /* Minor tics */

        for ( i = 0, x = mxmin; i < MAX_TIC && x <= mxmax; x += tic )
            if ( x >= xmin && x <= xmax )
                sp->xtic_minor[ i++ ] = FL_crnd( sp->ax * x + sp->bx );

        sp->num_xminor = i;

        /* Major tics */

        for ( i = 0, x = mxmin; i < MAX_MAJOR && x <= mxmax;
              x += tic * sp->xminor )
            if ( x >= xmin && x <= xmax )
            {
                sp->xtic_major[ i ] = FL_crnd( sp->ax * x + sp->bx );
                sp->xmajor_val[ i++ ] = x;
            }

        sp->num_xmajor = i;
    }
    else
    {
        if ( sp->log_minor_xtics < 0.5)
        {
            double minortic = tic / sp->xminor;

            /* Minor tics */

            x = floor( xmin / minortic ) * minortic;
            while ( sp->ax * ( xmin - x ) >= 1 )
                x += minortic;

            for ( i = 0; i < MAX_TIC && sp->ax * ( xmax - x ) >= 0;
                  x += minortic )
                sp->xtic_minor[ i++ ] = FL_crnd( sp->ax * x + sp->bx );

            sp->num_xminor = i;

            /* Major tics */

            x = floor( xmin / tic ) * tic;
            while ( sp->ax * ( xmin - x ) > 1 )
                x += tic;

            for ( i = 0; i < MAX_MAJOR && sp->ax * ( xmax - x ) >= 0;
                  x += tic )
            {
                sp->xtic_major[ i ] = FL_crnd( sp->ax * x + sp->bx );
                sp->xmajor_val[ i++ ] = x;
            }

            sp->num_xmajor = i;
        }
        else
        {
            int j;
            int k;

            double xmaj = floor( xmin / tic ) * tic;
            double xmaj_u, xmaj_d;
            double xl, step;

            while ( sp->ax * ( xmin - xmaj ) >= 1 )
                xmaj += tic;

            xmaj_u = pow( sp->xbase, xmaj );
            xmaj_d = pow( sp->xbase, xmaj - tic );
            xl     = pow( sp->xbase, xmin );
            step   = ( xmaj_u - xmaj_d ) / sp->xminor;
            x      = xmaj_u - step;

            /* Create minor tics before first major tic */

            for ( j = 0; x >= xl; x -= step )
                sp->xtic_minor[ j++ ] =
                    FL_crnd( sp->ax * log10( x) / sp->lxbase + sp->bx );

            /* Create all remaining major and minor tics */

            xl = pow( sp->xbase, xmax );

            for ( i = 0; i < MAX_MAJOR && sp->ax * ( xmax - xmaj ) >= 0;
                  xmaj += tic )
            {
                sp->xtic_major[ i ] = FL_crnd( sp->ax * xmaj + sp->bx );
                sp->xmajor_val[ i++ ] = xmaj;

                xmaj_d = pow( sp->xbase, xmaj );
                xmaj_u = pow( sp->xbase, xmaj + tic );
                step = ( xmaj_u - xmaj_d ) / sp->xminor;

                for ( k = 1, x = xmaj_d + step; 
                      j < MAX_TIC && k < sp->xminor && x <= xl; 
                      x += step, k++ )
                    sp->xtic_minor[ j++ ] =
                          FL_crnd( sp->ax * log10( x ) / sp->lxbase + sp->bx );
            }

            sp->num_xmajor = i;
            sp->num_xminor = j;
        }
    }
}


/***************************************
 ***************************************/

static void
gen_ytic( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float ymin,
          ymax,
          mymin,
          mymax,
          tic = sp->ytic;
    double y;
    int i;

    if ( tic < 0 )
        return;

    mymin = ymin = FL_min( sp->yscmin, sp->yscmax );
    mymax = ymax = FL_max( sp->yscmin, sp->yscmax );

    if (    sp->ytic > 0.0
         && ! *sp->aytic                     \
         && sp->ymajor > 1 )
    {
        mymin = floor( ymin / tic ) * tic;
        mymax = ceil( ymax / tic ) * tic;
    }

    /* Handle ticlable@location stuff */

    if ( *sp->aytic )
    {
        char *p;
        char *eptr;
        int j = 0;

        for ( i = 0; i < sp->ymajor; i++ )
        {
            if ( ( p = strchr( sp->aytic[ i ], '@' ) ) )
                y = strtod( p + 1, &eptr );

            if ( ! p || eptr != p + 1 )
                y = mymin + i * tic * sp->yminor;
            else if ( sp->yscale == FL_LOG )
                y = log10( y ) / sp->lybase;

            if ( y >= ymin && y <= ymax )
            {
                sp->ytic_major[ i ] = FL_crnd( sp->ay * y + sp->by );
                sp->ymajor_val[ i ] = y;
                j++;
            }
        }

        sp->num_ymajor = j;
        sp->num_yminor = 1;
        return;
    }

    if ( sp->yscale != FL_LOG )
    {
        for ( i = 0, y = mymin; i < MAX_MAJOR && y <= mymax; y += tic )
            if ( y >= ymin && y <= ymax )
                sp->ytic_minor[i++] = FL_crnd( sp->ay * y + sp->by );

        sp->num_yminor = i;

        for ( i = 0, y = mymin; i < MAX_MINOR && y <= mymax;
              y += tic * sp->yminor )
        {
            if ( y >= ymin && y <= ymax )
            {
                sp->ytic_major[ i ] = FL_crnd( sp->ay * y + sp->by );
                sp->ymajor_val[ i++ ] = y;
            }
        }

        sp->num_ymajor = i;
    }
    else
    {
        if ( sp->log_minor_ytics < 0.5)
        {
            double minortic = sp->ytic / sp->yminor;

            /* Note that sp->ay is always negative! */

            y = floor( ymin / minortic ) * minortic;
            while ( sp->ay * ( ymin - y ) <= -1 )
                y += minortic;

            for ( i = 0; i < MAX_TIC && sp->ay * ( ymax - y ) <= 0;
                  y += minortic )
                sp->ytic_minor[ i++ ] = FL_crnd( sp->ay * y + sp->by );

            sp->num_yminor = i;

            y = floor( ymin / tic ) * tic;
            while ( y + 1.0e-5 < ymin )
                y += tic;

            for ( i = 0; i < MAX_MAJOR && sp->ay * ( ymax - y ) <= 0; y += tic )
            {
                sp->ytic_major[ i ] = FL_crnd( sp->ay * y + sp->by );
                sp->ymajor_val[ i++ ] = y;
            }

            sp->num_ymajor = i;
        }
        else
        {
            int j;
            int k;

            double ymaj = floor( ymin / tic ) * tic;
            double ymaj_u, ymaj_d;
            double yl, step;

            /* Note: sp->ay is always negative */

            while ( sp->ay * ( ymin - ymaj ) <= -1 )
                ymaj += tic;

            ymaj_u = pow( sp->ybase, ymaj );
            ymaj_d = pow( sp->ybase, ymaj - tic );
            yl     = pow( sp->ybase, ymax );
            step   = ( ymaj_u - ymaj_d ) / sp->yminor;
            y      = ymaj_u - step;

            /* Create minor tics before first major tic */

            for ( j = 0; y >= pow( sp->ybase, ymin ); y -= step )
                sp->ytic_minor[ j++ ] =
                    FL_crnd( sp->ay * log10( y ) / sp->lybase + sp->by );

            /* Create all remaining major and minor tics */

            for ( i = 0; i < MAX_MAJOR && sp->ay * ( ymax - ymaj ) <= 0;
                  ymaj += tic )
            {
                sp->ytic_major[ i ] = FL_crnd( sp->ay * ymaj + sp->by );
                sp->ymajor_val[ i++ ] = ymaj;

                ymaj_d = pow( sp->ybase, ymaj );
                ymaj_u = pow( sp->ybase, ymaj + tic );
                step = ( ymaj_u - ymaj_d ) / sp->yminor;

                for ( k = 1, y = ymaj_d + step;
                      j < MAX_TIC && k < sp->yminor && y <= yl;
                      y += step, k++ )
                    sp->ytic_minor[ j++ ] =
                        FL_crnd( sp->ay * log10( y ) / sp->lybase + sp->by );
            }

            sp->num_ymajor = i;
            sp->num_yminor = j;
        }
    }
}


/***************************************
 ***************************************/

static void
add_xgrid( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int yi,
        yf,
        xr,
        i;
    int ls = fl_get_linestyle( );

    yi = sp->yi + 1;
    yf = sp->yf - 1;

    fl_linestyle( sp->grid_linestyle );

    for ( i = 0; sp->xgrid == FL_GRID_MINOR && i < sp->num_xminor; i++ )
    {
        xr = sp->xtic_minor[ i ];
        fl_line( xr, yi, xr, yf, ob->col2 );
    }

    for ( i = 0; i < sp->num_xmajor; i++ )
    {
        xr = sp->xtic_major[ i ];
        fl_line( xr, yi, xr, yf, ob->col2 );
    }

    fl_linestyle( ls );
}


/***************************************
 ***************************************/

static void
add_ygrid( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int yr,
        i,
        xi,
        xf;
    int ls = fl_get_linestyle( );

    xi = sp->xi + 1;
    xf = sp->xf - 1;

    fl_linestyle( sp->grid_linestyle );

    for ( i = 0; sp->ygrid == FL_GRID_MINOR && i < sp->num_yminor; i++ )
    {
        yr = sp->ytic_minor[ i ];
        fl_line( xi, yr, xf, yr, ob->col2 );
    }

    for ( i = 0; i < sp->num_ymajor; i++ )
    {
        yr = sp->ytic_major[ i ];
        fl_line( xi, yr, xf, yr, ob->col2 );
    }

    fl_linestyle( ls );
}


/***************************************
 ***************************************/

static void
add_xtics( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float tic = sp->xtic;
    int xr,
        ticl = 6,
        yi,
        yf,
        i;
    char buf[ 80 ],
         *label;

    if ( tic <= 0 )
        return;

    yi = sp->yf + 1;
    yf = yi + ticl / 2;

    /* Minor tics */

    for ( i = 0; i < sp->num_xminor; i++ )
    {
        xr = sp->xtic_minor[ i ];
        fl_line( xr, yi, xr, yf, ob->col2 );
    }

    yi = sp->yf + 1;
    yf = yi + ticl;

    for ( i = 0; i < sp->num_xmajor; i++ )
    {
        xr = sp->xtic_major[ i ];
        fl_line( xr, yi, xr, yf, ob->col2 );

        if ( ! *sp->axtic || i >= MAX_MAJOR )
            fli_xyplot_nice_label( tic, sp->xminor,
                                   sp->xmajor_val[ i ], label = buf );
        else
        {
            char *p;

            if ( sp->axtic[ i ] && ( p = strchr( sp->axtic[ i ], '@' ) ) )
                label = fli_sstrcpy( buf, sp->axtic[ i ],
                                     p - sp->axtic[ i ] + 1 );
            else
                label = sp->axtic[ i ];
        }
        
        if ( label )
            fl_draw_text( FL_ALIGN_TOP, xr, sp->yf + ticl - 2, 0, 0,
                          ob->col2, sp->lstyle, sp->lsize, label );
    }
}


/***************************************
 ***************************************/

static void
add_logxtics( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float tic = sp->xtic,
          xw;
    int xr,
        ticl = 6,
        i,
        yi,
        yf;
    char label[ 80 ];

    if ( tic < 0 )
        return;

    yi = sp->yf + 1;
    yf = yi + ticl / 2;

    for ( i = 0; i < sp->num_xminor; i++ )
    {
        xr = sp->xtic_minor[ i ];
        fl_line( xr, yi, xr, yf, ob->col2 );
    }

    yi = sp->yf;
    yf = yi + ticl;

    for ( i = 0; i < sp->num_xmajor; i++ )
    {
        xr = sp->xtic_major[ i ];
        fl_line( xr, yi, xr, yf, ob->col2 );

        xw = sp->xmajor_val[ i ];

        if ( sp->xbase == 10.0 )
        {
            sprintf( label, "%g", pow( sp->xbase, xw ) );
            fl_draw_text( FL_ALIGN_TOP, xr, sp->yf + ticl - 2, 0, 0,
                          ob->col2, sp->lstyle, sp->lsize, label );
        }
        else
        {
            int len1,
                len2,
                ll;

            ll = sprintf( label, "%g", sp->xbase );

            fl_draw_text( FL_ALIGN_TOP, xr, yf - 2, 0, 0,
                          ob->col2, sp->lstyle, sp->lsize, label );
            len1 = fl_get_string_width( sp->lstyle, sp->lsize, label, ll );
            ll = sprintf( label, "%d", ( int ) ceil( xw ) );
            len2 = fl_get_string_width( sp->lstyle, sp->lsize, label, ll );
            fl_draw_text( FL_ALIGN_TOP, xr + len1 / 2 + 2 + len2 / 2,
                          yf - 6, 0, 0, ob->col2, sp->lstyle, sp->lsize,
                          label );
        }
    }
}


/***************************************
 ***************************************/

static void
add_logytics( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float yw;
    int yr,
        ticl = 6,
        i;
    char label[ 80 ];

    if ( sp->ytic <= 0 )
        return;

    for ( i = 0; i < sp->num_yminor; i++ )
    {
        yr = sp->ytic_minor[ i ];
        fl_line( sp->xi, yr, sp->xi - ticl / 2, yr, ob->col2 );
    }

    for ( i = 0; i < sp->num_ymajor; i++ )
    {
        yr = sp->ytic_major[ i ];
        fl_line( sp->xi - ticl, yr, sp->xi, yr, ob->col2 );

        yw = sp->ymajor_val[ i ];

        if ( sp->ybase == 10.0 )
        {
            sprintf( label, "%g", pow( sp->ybase, yw ) );
            fl_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl + 2, yr,
                          0, 0, ob->col2, sp->lstyle, sp->lsize, label );
        }
        else
        {
            int len,
                ll;

            ll = sprintf( label, "%d", ( int ) ceil( yw ) );
            fl_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl + 2, yr - 3,
                          0, 0, ob->col2, sp->lstyle, sp->lsize, label );
            len = fl_get_string_width( sp->lstyle, sp->lsize, label, ll );
            sprintf( label, "%g", sp->ybase );
            fl_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl + 1 - len,
                          yr + 1, 0, 0, ob->col2, sp->lstyle, sp->lsize,
                          label );
        }
    }
}


/***************************************
 ***************************************/

static void
add_ytics( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float tic = sp->ytic;
    int yr,
        ticl = 6,
        i;
    char buf[ 80 ],
         *label,
         *p;

    if ( sp->ytic <= 0 )
        return;

    for ( i = 0; i < sp->num_yminor; i++ )
    {
        yr = sp->ytic_minor[ i ];
        fl_line( sp->xi - 4, yr, sp->xi, yr, ob->col2 );
    }

    for ( i = 0; i < sp->num_ymajor; i++ )
    {
        yr = sp->ytic_major[ i ];
        fl_line( sp->xi - ticl, yr, sp->xi, yr, ob->col2 );

        if ( ! *sp->aytic )
            fli_xyplot_nice_label( tic, sp->yminor,
                                   sp->ymajor_val[ i ], label = buf );
        else
        {
            if ( ( p = strchr( sp->aytic[ i ], '@' ) ) )
                label = fli_sstrcpy( buf, sp->aytic[ i ],
                                     p - sp->aytic[ i ] + 1 );
            else
                label = sp->aytic[ i ];
        }

        fl_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl + 2, yr,
                      0, 0, ob->col2, sp->lstyle, sp->lsize, label );
    }
}


/***************************************
 ***************************************/

static void
convert_coord( FL_OBJECT       * ob,
               FLI_XYPLOT_SPEC * sp )
{
    float extrax1,
          extray1;
    float extrax2,
          extray2;
    char buf[ 80 ],
         *label,
         *p;
    int j,
        ticl = 6,
        w = 0;
    int fh = fl_get_string_height( sp->lstyle, sp->lsize, "1pj", 3, &j, &j );
    float halfh = 0.55 * fh;

    /* Min. margins fixed margins */

    extrax1 = extray1 = extrax2 = extray2 = FL_abs( ob->bw ) + 3.0;

    /* Figure out the plot region */

    if ( sp->xtic > 0 )
    {
        extray2 += ticl + fh + ( sp->xscale == FL_LOG );

        if ( ! *sp->axtic )
            fli_xyplot_nice_label( sp->xtic, sp->xminor, sp->xmax,
                                   label = buf );
        else
            label = sp->axtic[ sp->xmajor - 1 ];

        w = fl_get_string_width( sp->lstyle, sp->lsize, label,
                                 strlen( label ) ) / 2;
        extrax2 += w + ( sp->xscale == FL_LOG ) * 2;

        /* Don't need to compute label size if ytic is on */

        if ( sp->ytic < 0 )
        {
            if ( ! *sp->axtic )
                fli_xyplot_nice_label( sp->xtic, sp->xminor, sp->xmin,
                                       label = buf );
            else
                label = *sp->axtic;

            w = fl_get_string_width( sp->lstyle, sp->lsize, label,
                                     strlen( label ) ) / 2;
            extrax1 += w;
        }
    }

    sp->maxytic = 2;

    if ( sp->ytic > 0 )
    {
        label = buf;
        if ( ! *sp->aytic )
        {
            int tmpw = 0;

            if ( sp->yscale == FL_LOG )
            {
                char *fmt = sp->ybase == 10 ? "%g-e%d" : "%g%d  ";
                int ll = sprintf( label, fmt, sp->ybase, ( int ) sp->yscmax );

                w = fl_get_string_width( sp->lstyle, sp->lsize, label, ll );
                ll = sprintf( label, fmt, sp->ybase, ( int ) sp->yscmin );
                tmpw = fl_get_string_width( sp->lstyle, sp->lsize, label, ll );
            }
            else
            {
                fli_xyplot_nice_label( sp->ytic, sp->yminor, sp->yscmax,
                                       label );
                w = fl_get_string_width( sp->lstyle, sp->lsize, label,
                                         strlen( label ) );
                fli_xyplot_nice_label( sp->ytic, sp->yminor, sp->yscmin,
                                       label );
                tmpw = fl_get_string_width( sp->lstyle, sp->lsize, label,
                                            strlen( label ) );
            }

            w = FL_max( w, tmpw );
        }
        else
        {
            if ( ( p = strchr( *sp->aytic, '@' ) ) )
                label = fli_sstrcpy( buf, *sp->aytic, p - *sp->aytic + 1 );
            else
                label = *sp->aytic;

            w = fl_get_string_width( sp->lstyle, sp->lsize, label,
                                     strlen( label ) );
        }

        /* How much space to leave for ytics ylabels */

        extrax1 += ticl + 1;
        extrax1 += w;
        sp->maxytic = extrax1;
        extray1 += halfh + 1;
        if ( sp->xtic < 0 )
            extray2 += halfh + 1;
    }

    if ( *sp->ylabel )
        extrax1 += 6 + fl_get_char_width( sp->lstyle, sp->lsize );

    if ( *sp->xlabel )
        extray2 += 2 + 1.1 * fh;

    if ( *sp->title )
        extray1 += 1 + ( sp->ytic > 0 ? halfh : fh );

    /* If margin is set use it instead of the computed margin */

    if ( sp->xmargin1 )
    {
        extrax1 = extrax2 = FL_abs( ob->bw ) + 1 + fl_get_linewidth( );
        extrax1 += fl_get_string_width( sp->lstyle, sp->lsize, sp->xmargin1,
                                        strlen( sp->xmargin1 ) ) - 1;
        extrax2 += fl_get_string_width( sp->lstyle, sp->lsize, sp->xmargin2,
                                        strlen( sp->xmargin2 ) ) + 1;
    }

    if ( sp->ymargin1 )
    {
        extray1 = extray2 = FL_abs( ob->bw ) + 1;
        extray1 += fl_get_string_width( sp->lstyle, sp->lsize, sp->ymargin1,
                                        strlen( sp->ymargin1 ) ) - 1;
        extray2 += fl_get_string_width( sp->lstyle, sp->lsize, sp->ymargin2,
                                        strlen( sp->ymargin2 ) ) + 1;
    }

    sp->xi = ob->x + extrax1;
    sp->yi = ob->y + extray1;
    sp->xf = ob->x + ob->w - extrax2;
    sp->yf = ob->y + ob->h - extray2;

    sp->ax  = ( sp->xf - sp->xi ) / ( sp->xscmax - sp->xscmin );
    sp->bx  = sp->bxm = sp->xi - sp->ax * sp->xscmin;

    sp->ay  = ( sp->yf - sp->yi ) / ( sp->yscmin - sp->yscmax );
    sp->by  = sp->bym = sp->yi - sp->ay * sp->yscmax;

    gen_xtic( ob );
    gen_ytic( ob );
}


/***************************************
 * Draw a string with alignment given relative to a point.
 * Figure out the bounding box etc so symbols can be drawn
 ***************************************/

static void
draw_text_point( int        lalign,
                 int        x,
                 int        y,
                 FL_COLOR   col,
                 int        lstyle,
                 int        lsize,
                 char     * str )
{
    int align = fl_to_outside_lalign( lalign );
    int bbox = 1.4 * lsize + 6;
    int xx = x,
        yy = y;

    switch ( align )
    {
        case FL_ALIGN_CENTER :
            xx = x - bbox / 2;
            yy = y - bbox / 2;
            break;

        case FL_ALIGN_TOP :
            xx = x - bbox / 2;
            break;

        case FL_ALIGN_BOTTOM :
            xx = x - bbox / 2;
            yy = y - bbox;
            break;

        case FL_ALIGN_LEFT :
            yy = y - bbox / 2;
            break;

        case FL_ALIGN_RIGHT :
            xx = x - bbox;
            yy = y - bbox / 2;
            break;

        case FL_ALIGN_LEFT_TOP :
            xx = x - bbox;
            align = FL_ALIGN_RIGHT_TOP;
            break;

        case FL_ALIGN_RIGHT_TOP :
            align = FL_ALIGN_LEFT_TOP;
            break;

        case FL_ALIGN_RIGHT_BOTTOM :
            yy = y - bbox;
            align = FL_ALIGN_LEFT_BOTTOM;
            break;

        case FL_ALIGN_LEFT_BOTTOM :
            align = FL_ALIGN_RIGHT_BOTTOM;
            yy = y - bbox;
            xx = x - bbox;
            break;
    }

    fl_draw_text_beside( align, xx, yy, bbox, bbox, col, lstyle, lsize, str );
}


/***************************************
 ***************************************/

static void
draw_inset( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int i;
    float tx,
          ty;

    for ( i = 0; i <= sp->maxoverlay; i++ )
        if ( sp->text[ i ] )
        {
            w2s_draw( ob, sp->xt[ i ], sp->yt[ i ], &tx, &ty );
            draw_text_point( sp->talign[ i ], tx, ty, sp->tcol[ i ],
                             sp->lstyle, sp->lsize, sp->text[ i ] );
        }
}


/***************************************
 ***************************************/

static void
compute_key_position( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int w = 0,
        i,
        h,
        align;
    float fx,
          fy;

    h = fl_get_char_height( sp->key_lstyle, sp->key_lsize,
                            &sp->key_ascend, &sp->key_descend );

    /* Find the max width */

    sp->key_maxw = sp->key_maxh = 0;
    for ( i = 0; i <= sp->maxoverlay; i++ )
        if ( sp->key[ i ] && sp->n[ i ] )
        {
            w = fl_get_string_width( sp->key_lstyle, sp->key_lsize,
                                     sp->key[ i ], strlen( sp->key[ i ] ) );
            if ( w > sp->key_maxw )
                sp->key_maxw = w;
            sp->key_maxh += h;
        }

    if ( sp->key_maxw == 0 )
        return;

    /* Get alignment */

    w2s_draw( ob, sp->key_x, sp->key_y, &fx, &fy );
    sp->key_xs = fx;
    sp->key_ys = fy;

    sp->key_maxw += 32;
    sp->key_maxh += 1;

    align = sp->key_align;

    if ( align == FL_ALIGN_LEFT_TOP )
        align = FL_ALIGN_RIGHT_TOP;
    else if ( align == FL_ALIGN_RIGHT_TOP )
        align = FL_ALIGN_LEFT_TOP;
    else if ( align == FL_ALIGN_RIGHT_BOTTOM )
        align = FL_ALIGN_LEFT_BOTTOM;
    else if ( align == FL_ALIGN_LEFT_BOTTOM )
        align = FL_ALIGN_RIGHT_BOTTOM;

    fl_get_align_xy( align, sp->key_xs, sp->key_ys, 0, 0,
                     sp->key_maxw, sp->key_maxh, 0, 0,
                     &sp->key_xs, &sp->key_ys );
}


/***************************************
 ***************************************/

static void
add_border( FLI_XYPLOT_SPEC * sp,
            FL_COLOR          c )
{
    if ( sp->xtic > 0 && sp->ytic > 0 )
        fl_rect( sp->xi, sp->yi, sp->xf - sp->xi, sp->yf - sp->yi, c );
    else if ( sp->xtic > 0 )
        fl_line( sp->xi, sp->yf, sp->xf, sp->yf, c );
    else if ( sp->ytic > 0 )
        fl_line( sp->xi, sp->yi, sp->xi, sp->yf, c );
}


/***************************************
 * (scxmin, scxmax) ultimately determines the plot area in world coord.
 ***************************************/

static void
round_xminmax( FLI_XYPLOT_SPEC * sp )
{
    if ( sp->xscale != FL_LOG )
    {
        sp->xscmin = sp->xmin;
        sp->xscmax = sp->xmax;
    }
    else
    {
        sp->xscmin = log10( sp->xmin ) / sp->lxbase;
        sp->xscmax = log10( sp->xmax ) / sp->lxbase;
    }
}


/***************************************
 * Do the same with y bounds
 ***************************************/

static void
round_yminmax( FLI_XYPLOT_SPEC * sp )
{

    if ( sp->yscale != FL_LOG )
    {
        sp->yscmin = sp->ymin;
        sp->yscmax = sp->ymax;
    }
    else
    {
        sp->yscmin = log10( sp->ymin ) / sp->lybase;
        sp->yscmax = log10( sp->ymax ) / sp->lybase;
    }
}


/***************************************
 ***************************************/

static void
draw_xyplot( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    FL_Coord bw = FL_abs( ob->bw );

    draw_to_pixmap =    ob->use_pixmap
                     && ob->flpixmap
                     && ob->form->window == ob->flpixmap->pixmap;

    fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    fl_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                         ob->lcol, ob->lstyle, ob->lsize, ob->label );

    if ( *sp->n <= 0 || ! *sp->x || ! *sp->y )
        return;

    sp->xtic   = sp->ytic = -1;
    sp->xscmin = sp->xmin;
    sp->xscmax = sp->xmax;
    sp->yscmin = sp->ymin;
    sp->yscmax = sp->ymax;

    if ( sp->xmajor > 0 )
    {
        if ( sp->xscale == FL_LOG )
            sp->xtic = gen_logtic( sp->xmin, sp->xmax, sp->xbase,
                                   sp->xmajor );
        else
            sp->xtic = gen_tic( sp->xmin, sp->xmax, sp->xmajor, sp->xminor );
    }

    round_xminmax( sp );

    if ( sp->ymajor > 0 )
    {
        if ( sp->yscale == FL_LOG )
            sp->ytic = gen_logtic( sp->ymin, sp->ymax, sp->ybase,
                                   sp->ymajor );
        else
            sp->ytic = gen_tic( sp->ymin, sp->ymax, sp->ymajor, sp->yminor );
    }

    round_yminmax( sp );

    convert_coord( ob, sp );
    add_border( sp, ob->col2 );
    draw_curve_only( ob );

    fl_set_text_clipping( ob->x + bw, ob->y + bw,
                          ob->w - 2 * bw, ob->h - 2 * bw );
    fl_set_clipping( ob->x + bw, ob->y + bw, ob->w - 2 * bw, ob->h - 2 * bw );

    /* Do the tics and other things */

    /* Draw the title */

    if ( *sp->title )
        fl_draw_text( FL_ALIGN_BOTTOM, ( sp->xi + sp->xf ) / 2,
                      sp->yi + 1, 0, 0, ob->col2, sp->lstyle, sp->lsize,
                      sp->title );

    ( sp->xscale == FL_LOG ? add_logxtics : add_xtics )( ob );

    if ( *sp->xlabel )
        fl_draw_text( FL_ALIGN_BOTTOM,
                      ( sp->xi + sp->xf ) / 2,
                      ob->y + ob->h - bw - ( draw_to_pixmap ? ob->y : 0 ),
                      1, 1,
                      ob->col2, sp->lstyle, sp->lsize, sp->xlabel );

    ( sp->yscale == FL_LOG ? add_logytics : add_ytics )( ob );

    if ( *sp->ylabel )
    {
        int cw = fl_get_char_width( sp->lstyle, sp->lsize );
        int ch = fl_get_char_height( sp->lstyle, sp->lsize, NULL, NULL );
        int nc = strlen( sp->ylabel );
        int j;
        char s[ 2 ] = "";

        for ( j = 0; ( *s = sp->ylabel[ j ] ); j++ )
            fl_draw_text( FL_ALIGN_CENTER,
                          sp->xi - sp->maxytic - 2 - cw,
                          ( sp->yi + sp->yf ) / 2 + ( j - 0.5 * nc ) * ch,
                          cw, ch, ob->col2, sp->lstyle, sp->lsize, s );
    }

    fl_unset_text_clipping( );
    fl_unset_clipping( );
}


/***************************************
 * Find the data point the mouse falls on. Since log scale is
 * non-linear, can't do search in world coordinates given pixel-delta,
 * thus the xpactive keeps the active screen data.
 ***************************************/

static int
find_data( FL_OBJECT * ob,
           int         deltax,
           int         deltay,
           int         mx,
           int         my,
           int       * n )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int found,
        i,
        dist,
        mindist,
        done,
        newi;
    int dx = 0;                  /* to shut -Wall up */
    int dy = 0;                  /* same here */
    FL_POINT *p = sp->xpactive;

    mx -= ob->x;
    my -= ob->y;

    for ( i = found = 0; i < *sp->n && ! found; i++ )
    {
        dx = p[ i ].x - mx;
        dy = p[ i ].y - my;
        found = FL_abs( dx ) < deltax && FL_abs( dy ) < deltay;
    }

    /* It's possible that the first point we found is not the
       closest. Check for the closest using a linear distance */

    mindist = FL_abs( dx ) + FL_abs( dy );
    newi = i;

    for ( done = ! found; ! done && i < *sp->n; i++ )
    {
        dx = p[ i ].x - mx;
        dy = p[ i ].y - my;
        dist = FL_abs( dx ) + FL_abs( dy );
        if ( dist < mindist )
        {
            mindist = dist;
            newi = i + 1; /* need to overshoot */
        }
        else
            done = 1;
    }

    /* n overshoots by 1 and we're dependent on that ! */

    *n = newi + sp->n1;

    return found;
}


/***************************************
 ***************************************/

static int
handle_mouse( FL_OBJECT * ob,
              FL_Coord    mx,
              FL_Coord    my )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    static FL_Coord lmx,
                    lmy;
    int i;
    int deltax = sp->ssize * ( sp->inspect ? 2.5 : 1.5 ) + 1;
    int deltay = deltax;
    float fmx,
          fmy;
    float xmin = FL_min( sp->xmin, sp->xmax ),
          xmax = FL_max( sp->xmax, sp->xmin );
    float ymin = FL_min( sp->ymin, sp->ymax ),
          ymax = FL_max( sp->ymax, sp->ymin );

    if ( sp->n[ 0 ] == 0 || ! sp->x || ! ( sp->active || sp->inspect ) )
        return FL_RETURN_NONE;

    if ( lmx == mx && lmy == my )
    {
        if ( sp->inside < 0 )
            fl_set_cursor( FL_ObjWin( ob ), XC_tcross );
        return FL_RETURN_NONE;
    }

    lmx = mx;
    lmy = my;

    /* If the mouse hadn't been on one of the points (or it had been released,
       in which case sp->inside is negative) check again. Don't do anything
       yet except changing the way the cursor looks like if we're now on a
       point. */

    if ( sp->inside <= 0 )
    {
        /* find_data() always overshoots by one and we are dependent on that! */

        if ( ( sp->inside =
                         find_data( ob, deltax, deltay, mx, my, &i ) ? i : 0 ) )
        {
            fl_set_cursor( FL_ObjWin( ob ), XC_tcross );
            sp->start_x = mx;
            sp->start_y = my;
        }

        return FL_RETURN_NONE;
    }

    /* If we arrive here, we were on top of a point the last time round. If
       we're in inspect mode check if we still are, otherwise reset the cursor
       and don't do anything further. */

    if ( sp->inspect )
    {
        if ( ! ( sp->inside =
                    find_data( ob, deltax, deltay, mx, my, &i ) ? i : 0 ) )
            fl_reset_cursor( FL_ObjWin( ob ) );

        /* If delayed action, can't keep up with motion event */

#ifndef DELAYED_ACTION
        return FL_RETURN_CHANGED;
#else
        return FL_RETURN_NONE;
#endif
    }

    /* Now we are sure we're not in inspect mode and are shifting around
       one of the points. */

    fmx = ( lmx - sp->bxm - ( draw_to_pixmap ? ob->x : 0 ) ) / sp->ax;
    fmy = ( lmy - sp->bym - ( draw_to_pixmap ? ob->y : 0 ) ) / sp->ay;

    if ( sp->xscale == FL_LOG )
        fmx = pow( sp->xbase, fmx );

    if ( sp->yscale == FL_LOG )
        fmy = pow( sp->ybase, fmy );

    /* Update data and redraw. Need to enforce the bounds */

    i = sp->inside - 1;

    if ( fmx < xmin )
        fmx = xmin;
    else if ( fmx > xmax )
        fmx = xmax;

    if ( fmy < ymin )
        fmy = ymin;
    else if ( fmy > ymax )
        fmy = ymax;

    /* Fix the end points and don't allow crossings */

    if ( i == 0 || i == *sp->n - 1 )
        fmx = sp->x[ 0 ][ i ];
    else
    {
        /* Here we need to leave some seperation. Otherwise too much error in
           interpolation */

        if ( fmx >= sp->x[ 0 ][ i + 1 ] )
        {
            if ( sp->xscale == FL_LOG )
                fmx =   sp->x[ 0 ][ i + 1 ]
                      - ( sp->x[ 0 ][ i + 1 ] - sp->x[ 0 ][ i ] ) / 100;
            else
                fmx = sp->x[ 0 ][ i + 1 ] - 1.0 / sp->ax;
        }
        else if ( fmx <= sp->x[ 0 ][ i - 1 ] )
        {
            if ( sp->xscale == FL_LOG )
                fmx =   sp->x[ 0 ][ i - 1 ]
                      + ( sp->x[ 0 ][ i ] - sp->x[ 0 ][ i - 1 ] ) / 100;
            else
                fmx = sp->x[ 0 ][ i - 1 ] + 1.0 / sp->ax;
        }
    }

    sp->x[ 0 ][ i ] = fmx;
    sp->y[ 0 ][ i ] = fmy;
    fl_redraw_object( ob );

    return ob->how_return & FL_RETURN_END_CHANGED ?
           FL_RETURN_NONE : FL_RETURN_CHANGED;
}


/***************************************
 ***************************************/

static int
handle_xyplot( FL_OBJECT * ob,
               int         event,
               FL_Coord    mx,
               FL_Coord    my,
               int         key  FL_UNUSED_ARG,
               void      * ev   FL_UNUSED_ARG )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int ret = FL_RETURN_NONE;

    sp->lsize  = ob->lsize;
    sp->lstyle = ob->lstyle;
    *sp->col   = ob->col2;

    switch ( event )
    {
        case FL_DRAW:
            draw_xyplot( ob );
            sp->update = 0;
            break;

        case FL_DRAWLABEL:
            fl_draw_object_label( ob );
            break;

        case FL_PUSH:
        case FL_MOTION:
            if ( sp->react_to[ key - 1 ] )
                ret = handle_mouse( ob, mx, my );
            break;

        case FL_RELEASE:
            if (    ! sp->react_to[ key - 1 ]
                 || ! ( sp->active || sp->inspect ) )
                break;

            /* Mark the release by setting inside < 0 */

            if ( sp->inside > 0 )
            {
                sp->inside *= -1;
                ret = FL_RETURN_END;

                if (    sp->inspect
                     || (    ( mx != sp->start_x || my != sp->start_y )
                          && ob->how_return & FL_RETURN_END_CHANGED ) )
                    ret |= FL_RETURN_CHANGED;
            }

            fl_reset_cursor( FL_ObjWin( ob ) );
            break;

        case FL_FREEMEM:
            free_xyplot( ob );
            fl_free( sp );
            break;
    }

    if ( ret && sp->inside == 0 )
        M_err( "handle_xyplot", "Something is wrong\n" );

    return ret;
}


/***************************************
 * Allocates (or reallocates) the dynamically allocated portions
 * of the DLI_XYPLOT_SPEC structure. the second argument is the
 * number of overlays needed.
 ***************************************/

static int
allocate_spec( FLI_XYPLOT_SPEC * sp,
               int               n )
{
    int i,
        oldn = sp->maxoverlay;

    /* If we're supposed to set the spec up for less overlays than allocated
       free the memory used for those that have to go. */

    if ( n < sp->maxoverlay )
        for ( i = n + 1; i <= sp->maxoverlay; ++i )
        {
            free_overlay_data( sp, i );
            fli_safe_free( sp->text[ i ] );
            fli_safe_free( sp->key[ i ] );
        }

    /* (Re-)allocate memory, we need one more than the number of overlays,
       the very first one being for the "normal" data */

    sp->text        = fl_realloc( sp->text, ( n + 1 ) * sizeof *sp->text );
    sp->xt          = fl_realloc( sp->xt, ( n + 1 ) * sizeof *sp->xt );
    sp->yt          = fl_realloc( sp->yt, ( n + 1 ) * sizeof *sp->yt );
    sp->x           = fl_realloc( sp->x, ( n + 1 ) * sizeof *sp->x );
    sp->y           = fl_realloc( sp->y, ( n + 1 ) * sizeof *sp->y );
    sp->n           = fl_realloc( sp->n, ( n + 1 ) * sizeof *sp->n );
    sp->grid        = fl_realloc( sp->grid, ( n + 1 ) * sizeof *sp->grid );
    sp->col         = fl_realloc( sp->col, ( n + 1 ) * sizeof *sp->col );
    sp->tcol        = fl_realloc( sp->tcol, ( n + 1 ) * sizeof *sp->tcol );
    sp->type        = fl_realloc( sp->type, ( n + 1 ) * sizeof *sp->type );
    sp->talign      = fl_realloc( sp->talign, ( n + 1 ) * sizeof *sp->talign );
    sp->interpolate = fl_realloc( sp->interpolate,
                                  ( n + 1 ) * sizeof * sp->interpolate );
    sp->thickness   = fl_realloc( sp->thickness,
                                  ( n + 1 ) * sizeof *sp->thickness );
    sp->key         = fl_realloc( sp->key, ( n + 1 ) * sizeof *sp->key  );
    sp->symbol      = fl_realloc( sp->symbol, ( n + 1 ) * sizeof *sp->symbol );

    /* Initialize the newly allocated parts */

    for ( i = sp->maxoverlay > 0 ? sp->maxoverlay + 1 : 0; i <= n; i++ )
    {
        sp->text[ i ]   = sp->key[ i ]         = NULL;
        sp->x[ i ]      = sp->y[ i ]           = NULL;
        sp->n[ i ]      = sp->type[ i ]        = 0;
        sp->xt[ i ]     = sp->yt[ i ]          = sp->grid[ i ]     = 0.0;
        sp->col[ i ]    = sp->tcol[ i ]        = 0;
        sp->type[ i ]   =  sp->n[ i ]          = 0;
        sp->talign[ i ] = sp->interpolate[ i ] = sp->thickness[ i ] = 0;
        sp->symbol[ i ] = NULL;
    }

    sp->maxoverlay = n;
    return oldn;
}


/***************************************
 * Free all memory that does not depend on the xy-data
 ***************************************/

static void
free_spec_dynamic_mem( FLI_XYPLOT_SPEC * sp )
{
    int i;

    fli_safe_free( sp->xt );
    fli_safe_free( sp->yt );
    fli_safe_free( sp->grid );
    fli_safe_free( sp->col );
    fli_safe_free( sp->tcol );
    fli_safe_free( sp->type );
    fli_safe_free( sp->interpolate );
    fli_safe_free( sp->talign );
    fli_safe_free( sp->thickness );
    fli_safe_free( sp->symbol );

    /* The memory allocated to the elements of sp->x and sp->y should already
       have been freed before the call of this function! */

    fli_safe_free( sp->x );
    fli_safe_free( sp->y );
    fli_safe_free( sp->n );

    if ( sp->text )
    {
        for ( i = 0; i <= sp->maxoverlay; i++ )
            fli_safe_free( sp->text[ i ] );
        fli_safe_free( sp->text );
    }

    if ( sp->key )
    {
        for ( i = 0; i <= sp->maxoverlay; i++ )
            fli_safe_free( sp->key[ i ] );
        fli_safe_free( sp->key );
    }
}


/***************************************
 ***************************************/

static void
init_spec( FL_OBJECT * obj )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;

    sp->text   = sp->key         = NULL;
    sp->x      = sp->y           = NULL;
    sp->xt     = sp->yt          = sp->grid      = NULL;
    sp->col    = sp->tcol        = NULL;
    sp->type   = sp->n           = NULL;
    sp->talign = sp->interpolate = sp->thickness = NULL;
    sp->symbol = NULL;

    allocate_spec( sp, FL_MAX_XYPLOTOVERLAY );

    sp->title          = strdup( "" );
    sp->xlabel         = strdup( "" );
    sp->ylabel         = strdup( "" );
    sp->xscale         = sp->yscale = FL_LINEAR;
    sp->xbase          = sp->ybase = 10.0;
    sp->lxbase         = sp->lybase = 1.0;
    sp->xautoscale     = sp->yautoscale = 1;
    sp->xmajor         = XMAJOR;
    sp->ymajor         = YMAJOR;
    sp->xminor         = XMINOR;
    sp->yminor         = YMINOR;
    sp->ssize          = 4;
    sp->lsize          = obj->lsize;
    sp->lstyle         = obj->lstyle;
    sp->grid_linestyle = FL_DOT;
    sp->wx             = NULL;
    sp->wy             = NULL;

    sp->active         = obj->type == FL_ACTIVE_XYPLOT;
    sp->key_lsize      = obj->lsize;
    sp->key_lstyle     = obj->lstyle;
    *sp->type          = obj->type;

    sp->nxpi           = 1;
    sp->xpi            = fl_malloc( ( sp->nxpi + 3 ) * sizeof  *sp->xpi );
    sp->xpi++;
    sp->n1             = 0;

    sp->cur_nxp        = 1;
    sp->xp             = fl_malloc( ( sp->cur_nxp + 3 ) * sizeof *sp->xp );
    sp->xp++;
    sp->xpactive       = fl_malloc( ( sp->cur_nxp + 3 )
                                    * sizeof *sp->xpactive );

    sp->axtic[ 0 ]     = sp->aytic[ 0 ] = NULL;
    sp->axtic[ MAX_MAJOR ] = sp->aytic[ MAX_MAJOR ] = NULL;

    sp->mark_active    = 1;
    sp->react_to[ 0 ]  = 1;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_xyplot( int          t,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * l )
{
    FL_OBJECT *obj = fl_make_object( FL_XYPLOT, t, x, y, w, h, l,
                                     handle_xyplot );

    obj->boxtype    = FL_XYPLOT_BOXTYPE;
    obj->col2       = obj->lcol = FL_BLACK;
    obj->col1       = FL_COL1;
    obj->lsize      = FL_TINY_SIZE;
    obj->align      = FL_XYPLOT_ALIGN;
    obj->spec       = fl_calloc( 1, sizeof( FLI_XYPLOT_SPEC ) );

    init_spec( obj );
    fl_set_object_return( obj, FL_RETURN_END_CHANGED );

    return obj;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_xyplot( int          t,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * l )
{
    FL_OBJECT *obj = fl_create_xyplot( t, x, y, w, h, l );
    FLI_XYPLOT_SPEC *sp = obj->spec;

    fl_add_object( fl_current_form, obj );

    /* Active_xyplot looks a little better in double buffer mode */

    if ( sp->active )
        fl_set_object_dblbuffer( obj, 1 );
    return obj;
}


/***************************************
 * Returns the number of points a call of fl_get_xyplot_data() will return
 ***************************************/

int
fl_get_xyplot_data_size( FL_OBJECT * obj )
{
    return *( ( FLI_XYPLOT_SPEC * ) obj->spec )->n;
}
    

/***************************************
 ***************************************/

void
fl_get_xyplot_data( FL_OBJECT * obj,
                    float     * x,
                    float     * y,
                    int       * n )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;

    *n = 0;
    if ( *sp->n > 0 )
    {
        memcpy( x, sp->x[ 0 ], sp->n[ 0 ] * sizeof *x );
        memcpy( y, sp->y[ 0 ], sp->n[ 0 ] * sizeof *y );
        *n = *sp->n;
    }
}


/***************************************
 ***************************************/

void
fl_replace_xyplot_point( FL_OBJECT * ob,
                         int         i,
                         double      x,
                         double      y )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( i < 0 || i >= *sp->n )
        return;

    if ( sp->x[ 0 ][ i ] != x || sp->y[ 0 ][ i ] != y )
    {
        sp->x[ 0 ][ i ] = x;
        sp->y[ 0 ][ i ] = y;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_replace_xyplot_point_in_overlay( FL_OBJECT * ob,
                                    int          i,
                                    int          id,
                                    double       x,
                                    double       y )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
        return;

    if ( i < 0 || i >= sp->n[ id ] )
        return;

    if ( sp->x[ id ][ i ] != x || sp->y[ id ][ i ] != y )
    {
        sp->x[ id ][ i ] = x;
        sp->y[ id ][ i ] = y;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_get_xyplot( FL_OBJECT * ob,
               float     * x,
               float     * y,
               int       * i )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    *i = FL_abs( sp->inside ) - 1;

    if ( *i < 0 || *i >= *sp->n )
    {
        *i = -1;
        return;
    }

    *x = sp->x[ 0 ][ *i ];
    *y = sp->y[ 0 ][ *i ];
}


/***************************************
 ***************************************/

int
fl_set_xyplot_maxoverlays( FL_OBJECT * ob,
                           int         maxover )
{
    return allocate_spec( ob->spec, maxover );
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as for internal use
 * only and fl_set_object_return() should be used instead (which then
 * will call this function).
 ***************************************/

void
fl_set_xyplot_return( FL_OBJECT    * obj,
                      unsigned int   when )
{
    if ( obj->type == FL_ACTIVE_XYPLOT )
        obj->how_return = when ? FL_RETURN_CHANGED : FL_RETURN_END_CHANGED;
    else
        obj->how_return = FL_RETURN_NONE;
}


/***************************************
 ***************************************/

void
fl_set_xyplot_symbolsize( FL_OBJECT * ob,
                          int         n )
{
    ( ( FLI_XYPLOT_SPEC * ) ob->spec )->ssize = n;
}


/***************************************
 ***************************************/

FL_XYPLOT_SYMBOL
fl_set_xyplot_symbol( FL_OBJECT        * ob,
                      int                id,
                      FL_XYPLOT_SYMBOL   symbol )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    FL_XYPLOT_SYMBOL old = NULL;
    int i;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_set_xyplot_symbol", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return NULL;
    }

    for ( i = 0; i <= sp->maxoverlay; i++ )
    {
        if ( i == id || id < 0 )
        {
            old = sp->symbol[ i ];
            if ( sp->symbol[ i ] != symbol )
            {
                sp->symbol[ i ] = symbol;
                fl_redraw_object( ob );
            }
        }
    }

    return old;
}


/***************************************
 ***************************************/

void
fl_set_xyplot_inspect( FL_OBJECT * ob,
                       int         yes_no )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( sp->inspect == yes_no )
        return;

    sp->inspect = yes_no;

    if ( ob->type != FL_ACTIVE_XYPLOT )
    {
        /* Work-around, need to use doublebuffer to get inspect work right */

        fl_set_object_dblbuffer( ob, sp->active || sp->inspect );
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_xtics( FL_OBJECT * ob,
                     int         major,
                     int         minor )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    /* 0 restores the default */

    if ( major < 0 )
        major = minor = -1;
    else if ( major == 0 )
        major = XMAJOR;
    else if ( major > MAX_MAJOR )
        major = MAX_MAJOR;

    if ( minor < 0 )
        minor = -1;
    else if ( minor == 0 )
        minor = XMINOR;
    else if ( minor > MAX_MINOR )
        minor = MAX_MINOR;

    if (    major > 0
         && (    ( minor > 0 && major * minor > MAX_TIC )
              || ( minor < 0 && major > MAX_TIC ) ) )
    {
        M_err( "fl_set_xyplot_xtics",
               "More than maximum of %d tics would be required", MAX_TIC );
        if ( minor > 0 )
            minor = 2;
        major = 5;
    }

    if ( *sp->axtic || sp->xmajor != major || sp->xminor != minor )
    {
        sp->xmajor = major;
        sp->xminor = minor;
        free_atic( sp->axtic );
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_ytics( FL_OBJECT * ob,
                     int         major,
                     int         minor )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( major < 0 )
        major = minor = -1;
    else if ( major == 0 )
        major = YMAJOR;
    else if ( major > MAX_MAJOR )
        major = MAX_MAJOR;

    if ( minor < 0 )
        minor = -1;
    else if ( minor == 0 )
        minor = YMINOR;
    else if ( minor > MAX_MINOR )
        minor = MAX_MINOR;

    if (    major > 0
         && (    ( minor > 0 && major * minor > MAX_TIC )
              || ( minor < 0 && major > MAX_TIC ) ) )
    {
        M_err( "fl_set_xyplot_ytics",
               "More than maximum of %d tics would be required", MAX_TIC );
        minor = 2;
        major = 5;
    }

    if ( *sp->aytic || sp->ymajor != major || sp->yminor != minor )
    {
        sp->ymajor = major;
        sp->yminor = minor;
        free_atic( sp->aytic );
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_xgrid( FL_OBJECT * ob,
                     int         xgrid )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( sp->xgrid != xgrid )
    {
        sp->xgrid = xgrid;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_ygrid( FL_OBJECT * ob,
                     int         ygrid )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( sp->ygrid != ygrid )
    {
        sp->ygrid = ygrid;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_set_xyplot_grid_linestyle( FL_OBJECT * ob,
                              int         style )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int ostyle = sp->grid_linestyle;

    if ( sp->grid_linestyle != style )
    {
        sp->grid_linestyle = style;
        fl_redraw_object( ob );
    }

    return ostyle;
}


/***************************************
 ***************************************/

void
fl_set_xyplot_xbounds( FL_OBJECT * ob,
                       double      xmin,
                       double      xmax )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int do_autoscale = xmax == xmin;

    if (    sp->xautoscale != do_autoscale
         || sp->xmin != xmin
         || sp->xmax != xmax )
    {
        sp->xautoscale = do_autoscale;
        sp->xmax = xmax;
        sp->xmin = xmin;
        find_xbounds( sp );

        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_get_xyplot_xbounds( FL_OBJECT * ob,
                       float     * xmin,
                       float     * xmax )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    *xmin = sp->xmin;
    *xmax = sp->xmax;
}


/***************************************
 ***************************************/

void
fl_get_xyplot_ybounds( FL_OBJECT * ob,
                       float     * ymin,
                       float     * ymax )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    *ymin = sp->ymin;
    *ymax = sp->ymax;
}


/***************************************
 ***************************************/

void
fl_set_xyplot_ybounds( FL_OBJECT * ob,
                       double      ymin,
                       double      ymax )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int do_autoscale = ymax == ymin;

    if (    sp->yautoscale != do_autoscale
         || sp->ymin != ymin
         || sp->ymax != ymax )
    {
        sp->yautoscale = do_autoscale;
        sp->ymax = ymax;
        sp->ymin = ymin;
        find_ybounds( sp );

        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

static void
get_min_max( float * x,
             int     n,
             float * xmin,
             float * xmax )
{
    float *xs = x + n;

    if ( ! x || ! n )
        return;

    for ( *xmin = *xmax = *x++; x < xs; x++ )
    {
        *xmin = FL_min( *xmin, *x );
        *xmax = FL_max( *xmax, *x );
    }
}


/***************************************
 ***************************************/

static void
find_xbounds( FLI_XYPLOT_SPEC * sp )
{
    if ( sp->xautoscale )
        get_min_max( *sp->x, *sp->n, &sp->xmin, &sp->xmax );

    if ( sp->xmax == sp->xmin )
    {
        sp->xmin -= 1.0;
        sp->xmax += 1.0;
    }
}


/***************************************
 ***************************************/

static void
find_ybounds( FLI_XYPLOT_SPEC * sp )
{
    if ( sp->yautoscale )
        get_min_max( *sp->y, *sp->n, &sp->ymin, &sp->ymax );

    if ( sp->ymax == sp->ymin )
    {
        sp->ymin -= 1.0;
        sp->ymax += 1.0;
    }
}


/***************************************
 * Overloading would've been nice ...
 ***************************************/

void
fl_set_xyplot_data_double( FL_OBJECT  * ob,
                           double     * x,
                           double     * y,
                           int          n,
                           const char * title,
                           const char * xlabel,
                           const char * ylabel )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int i;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_XYPLOT ) )
    {
        M_err( "fl_set_xyplot_data_double",
               "%s not an xyplot", ob ? ob->label : "" );
        return;
    }
#endif

    free_overlay_data( sp, 0 );

    fli_safe_free( sp->xlabel );
    fli_safe_free( sp->ylabel );
    fli_safe_free( sp->title );

    sp->xlabel = fl_strdup( xlabel ? xlabel : "" );
    sp->ylabel = fl_strdup( ylabel ? ylabel : "" );
    sp->title  = fl_strdup( title ? title : "" );

    *sp->x = fl_malloc( n * sizeof **sp->x );
    *sp->y = fl_malloc( n * sizeof **sp->y );

    if ( ! *sp->x || ! *sp->y )
    {
        if ( *sp->x )
            fl_free( *sp->x );
        M_err( "fl_set_xyplot_data_double", "Can't allocate memory" );
        return;
    }

    extend_screen_data( sp, n );

    for ( i = 0; i < n ; i++ )
    {
        sp->x[ 0 ][ i ] = x[ i ];
        sp->y[ 0 ][ i ] = y[ i ];
    }

    *sp->n = n;

    find_xbounds( sp );
    find_ybounds( sp );

    fl_redraw_object( ob );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_data( FL_OBJECT  * ob,
                    float      * x,
                    float      * y,
                    int          n,
                    const char * title,
                    const char * xlabel,
                    const char * ylabel )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_XYPLOT ) )
    {
        M_err( "fl_set_xyplot_data", "%s not an xyplot", ob ? ob->label : "" );
        return;
    }
#endif

    free_overlay_data( sp, 0 );

    fli_safe_free( sp->xlabel );
    fli_safe_free( sp->ylabel );
    fli_safe_free( sp->title );

    sp->xlabel = fl_strdup( xlabel ? xlabel : "" );
    sp->ylabel = fl_strdup( ylabel ? ylabel : "" );
    sp->title  = fl_strdup( title ? title : "" );

    *sp->x = fl_malloc( n * sizeof **sp->x );
    *sp->y = fl_malloc( n * sizeof **sp->y );

    if ( ! *sp->x || ! *sp->y )
    {
        if ( *sp->x )
            fli_safe_free( *sp->x );
        M_err( "fl_set_xyplot_data", "Can't allocate memory" );
        return;
    }

    extend_screen_data( sp, n );

    memcpy( *sp->x, x, n * sizeof **sp->x );
    memcpy( *sp->y, y, n * sizeof **sp->y );
    *sp->n = n;

    find_xbounds( sp );
    find_ybounds( sp );

    fl_redraw_object( ob );
}


/***************************************
 * Insert a point after n
 ***************************************/

void
fl_insert_xyplot_data( FL_OBJECT * ob,
                       int         id,
                       int         n,
                       double      x,
                       double      y )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float *xx,
          *yy;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_insert_xyplot_data", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return;
    }

    if ( n < -1 )
        n = -1;
    else if ( n >= sp->n[ id ] )
        n = sp->n[ id ] - 1;

    n = n + 1;
    sp->n[ id ] += 1;

    if ( n == sp->n[ id ] - 1 )
    {
        sp->x[ id ] = fl_realloc( sp->x[ id ],
                                  sp->n[ id ] * sizeof **sp->x );
        sp->y[ id ] = fl_realloc( sp->y[ id ],
                                  sp->n[ id ] * sizeof **sp->y );
        sp->x[ id ][ n ] = x;
        sp->y[ id ][ n ] = y;
    }
    else
    {
        xx = fl_malloc( sp->n[ id ] * sizeof *xx );
        yy = fl_malloc( sp->n[ id ] * sizeof *yy );

        if ( n )
        {
            memcpy( xx, sp->x[ id ], n * sizeof *xx );
            memcpy( yy, sp->y[ id ], n * sizeof *yy );
        }

        xx[ n ] = x;
        yy[ n ] = y;

        memcpy( xx + n + 1, sp->x[ id ] + n,
                ( sp->n[ id ] - n - 1 ) * sizeof *xx );
        memcpy( yy + n + 1, sp->y[ id ] + n,
                ( sp->n[ id ] - n - 1 ) * sizeof *yy );

        fl_free( sp->x[ id ] );
        fl_free( sp->y[ id ] );

        sp->x[ id ] = xx;
        sp->y[ id ] = yy;
    }

    extend_screen_data( sp, sp->n[ id ] );

    fl_redraw_object( ob );
}


/***************************************
 ***************************************/

void
fl_add_xyplot_overlay( FL_OBJECT * ob,
                       int         id,
                       float     * x,
                       float     * y,
                       int         n,
                       FL_COLOR    col )
{

    FLI_XYPLOT_SPEC *sp;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_XYPLOT ) )
    {
        M_err( "fl_add_xyplot_overlay", "%s not XYPLOT class",
               ob ? ob->label : "" );
        return;
    }
#endif

    sp = ob->spec;

    if ( id < 1 || id > sp->maxoverlay )
    {
        M_err( "fl_add_xyplot_overlay", "ID %d is not in range (1,%d)",
               id, sp->maxoverlay );
        return;
    }

    /* Free old data */

    free_overlay_data( sp, id );

    /* Copy data */

    sp->x[ id ] = fl_malloc( n * sizeof **sp->x );
    sp->y[ id ] = fl_malloc( n * sizeof **sp->y );

    memcpy( sp->x[ id ], x, n * sizeof **sp->x );
    memcpy( sp->y[ id ], y, n * sizeof **sp->y );

    sp->n[ id ] = n;

    /* Extend screen points if needed. */

    extend_screen_data( sp, n );

    sp->col[ id ] = col;

    /* Set default only for the first time */

    if ( sp->type[ id ] == -1 )
        sp->type[ id ] = ob->type;

    fl_redraw_object( ob );
}


#define MAXP  1024      /* this is the initial space */


/***************************************
 ***************************************/

static int
load_data( const char  * f,
           float      ** x,
           float      ** y )
{
    int n = 0,
        err = 0;
    FILE *fp;
    char buf[ 128 ];
    int maxp = MAXP,
        ncomment = 0;

    if ( ! f || ! ( fp = fopen( f, "r" ) ) )
    {
        M_err( "load_data", "Can't open datafile '%s'", f ? f : "null" );
        return 0;
    }

    *x = fl_malloc( maxp * sizeof **x );
    *y = fl_malloc( maxp * sizeof **y );

    /* Comment chars are semicolon, hash and exclamation mark while seperators
       between numbers are space, comma and tab */

    while ( fgets( buf, sizeof buf, fp ) )
    {
        if ( *buf == '!' || *buf == '#' || *buf == ';' || *buf == '\n' )
        {
            ncomment++;
            continue;
        }

        if ( ( err = ( sscanf( buf, "%f%*[ \t,]%f", *x + n, *y + n ) != 2 ) ) )
        {
            M_err( "load_data", "An error occured at line %d",
                   ++n + ncomment );
            break;
        }

        if ( ++n >= maxp )
        {
            maxp *= 2;
            *x = fl_realloc( *x, maxp * sizeof **x );
            *y = fl_realloc( *y, maxp * sizeof **y );
        }
    }

    fclose( fp );

    if ( err || n == 0 )
    {
        fl_free( *x );
        fl_free( *y );
        n = 0;
    }

    return n;
}


/***************************************
 ***************************************/

int
fl_add_xyplot_overlay_file( FL_OBJECT  * ob,
                            int          id,
                            const char * f,
                            FL_COLOR     c )
{
    float *x,
          *y;
    int n = load_data( f, &x, &y );

    if ( n > 0 )
    {
        fl_add_xyplot_overlay( ob, id, x, y, n, c );
        fl_free( x );
        fl_free( y );
    }

    return n;
}


/***************************************
 ***************************************/

void
fl_set_xyplot_overlay_type( FL_OBJECT * ob,
                            int         id,
                            int         type )
{
    FLI_XYPLOT_SPEC *sp  = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_set_xyplot_overlay_type", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return;
    }

    if ( sp->type[ id ] != type )
    {
        sp->type[ id ] = type;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_get_xyplot_numdata( FL_OBJECT * ob,
                       int         id )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_get_xyplot_numdata", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return -1;
    }

    return sp->n[ id ];
}


/***************************************
 ***************************************/

void
fl_delete_xyplot_overlay( FL_OBJECT * ob,
                          int         id )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id <= 0 || id > sp->maxoverlay )
    {
        M_err( "fl_delete_xyplot_overlay", "ID %d is not in range (1,%d)",
               id, sp->maxoverlay );
        return;
    }

    free_overlay_data( sp, id );
    sp->type[ id ] = -1;
    fl_redraw_object( ob );
}


/***************************************
***************************************/

void
fl_get_xyplot_overlay_data( FL_OBJECT * ob,
                            int         id,
                            float     * x,
                            float     * y,
                            int       * n )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_get_xyplot_overlay_data", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return;
    }

    if ( sp->n[ id ] )
    {
        memcpy( x, sp->x[ id ], sp->n[ id ] * sizeof *x );
        memcpy( y, sp->y[ id ], sp->n[ id ] * sizeof *y );
        *n = sp->n[ id ];
    }
    else
        *n = 0;
}


/***************************************
 ***************************************/

void
fl_get_xyplot_data_pointer( FL_OBJECT  * ob,
                            int          id,
                            float     ** x,
                            float     ** y,
                            int        * n )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_get_xyplot_data_pointer", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return;
    }


    if ( sp->n[ id ] )
    {
        *x = sp->x[ id ];
        *y = sp->y[ id ];
        *n = sp->n[ id ];
    }
    else
        *n = 0;
}


/***************************************
 ***************************************/

void
fl_set_xyplot_linewidth( FL_OBJECT * ob,
                         int         id,
                         int         lw )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_set_xyplot_linewidth", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return;
    }

    if ( lw != sp->thickness[ id ] )
    {
        sp->thickness[ id ] = lw;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_set_xyplot_file( FL_OBJECT  * ob,
                    const char * f,
                    const char * title,
                    const char * xl,
                    const char * yl )
{
    float *x,
          *y;
    int n;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_XYPLOT ) )
    {
        M_err( "fl_set_xyplot_file", "%s not an xyplot", ob ? ob->label : "" );
        return 0;
    }
#endif

    if ( ( n = load_data( f, &x, &y ) ) > 0 )
    {
        fl_set_xyplot_data( ob, x, y, n, title, xl, yl );
        fl_free( x );
        fl_free( y );
    }

    return n;
}


/***************************************
 ***************************************/

void
fl_add_xyplot_text( FL_OBJECT  * ob,
                    double       x,
                    double       y,
                    const char * text,
                    int          al,
                    FL_COLOR     col )
{
    FLI_XYPLOT_SPEC *sp;
    int i;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_XYPLOT ) )
    {
        M_err( "fl_add_xyplot_text", "%s not an xyplot", ob ? ob->label : "" );
        return;
    }
#endif

    sp = ob->spec;

    /* Find an appropriate slot for this */

    for ( i = 0; sp->text[ i ] && i <= sp->maxoverlay; i++ )
        /* empty */ ;

    if ( i <= sp->maxoverlay )
    {
        sp->text[ i ]   = fl_strdup( text );
        sp->xt[ i ]     = x;
        sp->yt[ i ]     = y;
        sp->talign[ i ] = al;
        sp->tcol[ i ]   = col;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_delete_xyplot_text( FL_OBJECT  * ob,
                       const char * text )
{
    FLI_XYPLOT_SPEC *sp;
    int i;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_XYPLOT ) )
    {
        M_err( "fl_delete_xyplot_text", "%s not an xyplot",
               ob ? ob->label : "" );
        return;
    }
#endif

    for ( sp = ob->spec, i = 0; i <= sp->maxoverlay; i++ )
        if ( sp->text[ i ] && strcmp( sp->text[ i ], text ) == 0 )
        {
            fli_safe_free( sp->text[ i ] );
            fl_redraw_object( ob );
        }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_interpolate( FL_OBJECT * ob,
                           int         id,
                           int         deg,
                           double      grid )
{
    int intpl;
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( ! ob || id < 0 || id > sp->maxoverlay )
        return;

    if ( deg >= 2 && grid <= 0.0 )
        return;

    intpl = deg <= 1 ? 0 : ( ( deg < 2 || deg > 7 ) ? 2 : deg );

    if ( sp->interpolate[ id ] != intpl )
    {
        sp->interpolate[ id ] = intpl;
        sp->grid[ id ] = grid;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_fontsize( FL_OBJECT * ob,
                        int         size )
{
    if ( ob->lsize != size )
    {
        ob->lsize = size;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_fontstyle( FL_OBJECT * ob,
                         int         style )
{
    if ( ob->lstyle != style )
    {
        ob->lstyle = style;
        fl_redraw_object( ob );
    }
}


/***************************************
 * Truncates a floating point number to a requested significant digits
 * (if the number of digits is 0 truncate to the nearest integer)
 ***************************************/

static double
trunc_f( double f,
         int    digits )
{
    int sign;
    double fac;
    int expon;

    if ( fabs( f ) < 1.e-20 )
        return 0.0;

    if ( digits < 0 )
        digits = 1;

    if ( ! digits )
        return f >= 0 ? floor( f + 0.5 ) : ceil( f - 0.5 );

    sign = f >= 0 ? 1 : -1;
    f *= sign;

    if ( f >= 1.0 )
        expon = floor( log10( f ) );
	else if ( f == 0.0 )
		return 0.0;
	else
		expon = ceil( log10( f ) );

	fac = pow( 10.0, digits - expon );
	return sign * floor( fac * f + 0.5 ) / fac;
}


#define ADVANCE  0.1        /* shoulde not be greater than 0.25 */
#define FACTOR   1.9        /* max major expansion              */


/***************************************
 ***************************************/

static float
gen_tic( float tmin,
         float tmax,
         int   major,
         int   minor )
{
    float r_range,
          l_range,
          n_range;
    float tic;
    int ipow,
        digit;

    /* Handle special case: Min, MAX and one tic */

    if ( major == 1 && minor == 2 )
    {
        tic = FL_abs( tmax - tmin ) * 0.5;
        return tic;
    }

    r_range = FL_abs( tmax - tmin );
    l_range = log10( r_range );
    ipow = l_range > 0.0 ? l_range : l_range - 1;

    /* Normalized range is between 0 and 10 */

    n_range = pow( 10.0, l_range - ipow );
    n_range += ADVANCE;

    if ( n_range <= major && n_range >= major * 0.5 )
        tic = 1.0;
    else
        tic = n_range / major;

    digit = tic < 1.0f;
    tic = trunc_f( tic, digit );
    tic /= minor;
    tic = trunc_f( tic, 1 );
    tic *= pow( 10.0, ipow );

    /* Final check */

    n_range = r_range / ( tic * minor * major );

    if ( n_range > FACTOR )
    {
        ipow = n_range / FACTOR;
        if ( ipow >= 1 )
            tic *= 2.0 * ipow;
        else
            tic *= 2.0 * n_range / FACTOR;
        tic = trunc_f( tic, 1 );
    }

    return tic;
}


/***************************************
 ***************************************/

static float
gen_logtic( float tmin,
            float tmax,
            float base,
            int   major )
{
    float tic,
          lbase = log10( base );

    if ( tmin <= 0.0 || tmax <= 0.0 )
    {
        M_err( "gen_logtic", "range bordrs must be greater than 0 for "
               "logscale" );
        return -1;
    }

    tic = (   floor( log10( tmax ) / lbase + 0.5 )
            - ceil( log10( tmin )  / lbase - 0.5 ) ) / major;
    if ( tic < 1.0 )
        tic = 1.0;

    return floor( tic + 0.5 );
}


/***************************************
 ***************************************/

void
fl_get_xyplot_xmapping( FL_OBJECT * ob,
                        float     * a,
                        float     * b )
{
    *a = ( ( FLI_XYPLOT_SPEC * ) ob->spec )->ax;
    *b = ( ( FLI_XYPLOT_SPEC * ) ob->spec )->bxm;
}


/***************************************
 ***************************************/

void
fl_get_xyplot_ymapping( FL_OBJECT * ob,
                        float     * a,
                        float     * b )
{
    *a = ( ( FLI_XYPLOT_SPEC * ) ob->spec )->ay;
    *b = ( ( FLI_XYPLOT_SPEC * ) ob->spec )->bym;
}


/***************************************
 ***************************************/

void
fl_xyplot_s2w( FL_OBJECT * ob,
               double      sx,
               double      sy,
               float     * wx,
               float     * wy )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    *wx = ( sx - sp->bxm ) / sp->ax;
    *wy = ( sy - sp->bym ) / sp->ay;

    if ( sp->xscale == FL_LOG )
        *wx = pow( sp->xbase, *wx );
    if ( sp->yscale == FL_LOG )
        *wy = pow( sp->ybase, *wy );
}


/***************************************
 * Draw means we only call this at draw time, thus
 * should be ax, bx, not ax, bxm
 ***************************************/

static void
w2s_draw( FL_OBJECT * ob,
          double      wx,
          double      wy,
          float     * sx,
          float     * sy )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float sbx = sp->bxm,
          sby = sp->bym;

    sp->bxm = sp->bx - ob->x;
    sp->bym = sp->by - ob->y;
    fl_xyplot_w2s( ob, wx, wy, sx, sy );
    if ( ! draw_to_pixmap )
    {
        *sx += ob->x;
        *sy += ob->y;
    }
    sp->bxm = sbx;
    sp->bym = sby;
}


/***************************************
 * Really should be ints for the screen coordinates
 ***************************************/

void
fl_xyplot_w2s( FL_OBJECT * ob,
               double      wx,
               double      wy,
               float     * sx,
               float     * sy )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( sp->xscale == FL_LOG )
        *sx = FL_crnd( log10( wx ) / sp->lxbase * sp->ax + sp->bxm );
    else
        *sx = FL_crnd( wx * sp->ax + sp->bxm );

    if ( sp->yscale == FL_LOG )
        *sy = FL_crnd( log10( wy ) / sp->lybase * sp->ay + sp->bym );
    else
        *sy = FL_crnd( wy * sp->ay + sp->bym );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_xscale( FL_OBJECT * ob,
                      int         scale,
                      double      base )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( scale == FL_LOG && ( base <= 0.0 || base == 1.0 ) )
    {
        M_err( "fl_set_xyplot_xscale", "bad log base %g specified", base );
        return;
    }

    if ( sp->xscale != scale || sp->xbase != base )
    {
        sp->xscale = scale;

        if ( scale == FL_LOG )
        {
            sp->xbase = base;
            sp->lxbase = log10( base );
        }

        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_yscale( FL_OBJECT * ob,
                      int         scale,
                      double      base )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( scale == FL_LOG && ( base <= 0.0 || base == 1.0 ) )
    {
        M_err( "fl_set_xyplot_yscale", "bad log base %g specified", base );
        return;
    }

    if ( sp->yscale != scale || sp->ybase != base )
    {
        sp->yscale = scale;

        if ( scale == FL_LOG )
        {
            sp->ybase = base;
            sp->lybase = log10( base );
        }

        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_xyplot_fixed_xaxis( FL_OBJECT  * ob,
                           const char * lm,
                           const char * rm )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    fli_safe_free( sp->xmargin1 );
    fli_safe_free( sp->xmargin2 );

    sp->xmargin1 = lm ? fl_strdup( lm ) : NULL;
    sp->xmargin2 = rm ? fl_strdup( rm ) : NULL;

    if ( sp->xmargin2 && ! sp->xmargin1 )
        sp->xmargin1 = fl_strdup( "" );

    if ( sp->xmargin1 && ! sp->xmargin2 )
        sp->xmargin2 = fl_strdup( "" );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_fixed_yaxis( FL_OBJECT  * ob,
                           const char * bm,
                           const char * tm )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    fli_safe_free( sp->ymargin1 );
    fli_safe_free( sp->ymargin1 );

    sp->ymargin1 = tm ? fl_strdup( tm ) : NULL;
    sp->ymargin2 = bm ? fl_strdup( bm ) : NULL;

    if ( sp->ymargin2 && ! sp->ymargin1 )
        sp->ymargin1 = fl_strdup( "" );

    if ( sp->ymargin1 && ! sp->ymargin2 )
        sp->ymargin2 = fl_strdup( "" );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_alphaxtics( FL_OBJECT  * ob,
                          const char * m,
                          const char * s   FL_UNUSED_ARG )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    char *tmps,
         *item;
    int n;

    free_atic( sp->axtic );

    tmps = fl_strdup( m ? m : "" );

    for ( n = 0, item = strtok( tmps, "|" ); n < MAX_MAJOR && item;
          item = strtok( NULL, "|" ) )
        sp->axtic[ n++ ] = fl_strdup( item );

    fl_free( tmps );

    sp->xmajor = n;
    sp->xminor = 1;

    fl_redraw_object( ob );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_alphaytics( FL_OBJECT  * ob,
                          const char * m,
                          const char * s   FL_UNUSED_ARG )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    char *tmps,
         *item;
    int n;

    free_atic( sp->aytic );

    tmps = fl_strdup( m ? m : "" );

    for ( n = 0, item = strtok( tmps, "|" ); n < MAX_MAJOR && item;
          item = strtok( NULL, "|" ) )
        sp->aytic[ n++ ] = fl_strdup( item );

    fl_free( tmps );

    sp->ymajor = n;
    sp->yminor = 1;

    fl_redraw_object( ob );
}


/***************************************
 * Free all data and inset text, alphanumerical labels and other stuff
 ***************************************/

void
fl_clear_xyplot( FL_OBJECT * obj )
{
    int i;
    FLI_XYPLOT_SPEC *sp = obj->spec;


    for ( i = 0; i <= sp->maxoverlay; i++ )
    {
        free_overlay_data( sp, i );
        fli_safe_free( sp->text[ i ] );
        fli_safe_free( sp->key[ i ] );
    }

    fl_redraw_object( obj );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_key( FL_OBJECT  * ob,
                   int          id,
                   const char * key )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( id < 0 || id > sp->maxoverlay )
    {
        M_err( "fl_set_xyplot_key", "ID %d is not in range (0,%d)",
               id, sp->maxoverlay );
        return;
    }

    fli_safe_free( sp->key[ id ] );

    if ( key && *key )
        sp->key[ id ] = fl_strdup( key );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_key_position( FL_OBJECT * ob,
                            float       x,
                            float       y,
                            int         align )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    sp->key_x = x;
    sp->key_y = y;
    sp->key_align = fl_to_outside_lalign( align );

    fl_redraw_object( ob );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_keys( FL_OBJECT  * ob,
                    char      ** keys,
                    float        x,
                    float        y,
                    int          align )
{
    int i;
    FLI_XYPLOT_SPEC *sp = ob->spec;

    for ( i = 0; i <= sp->maxoverlay && keys[ i ]; i++ )
        fl_set_xyplot_key( ob, i, keys[ i ] );

    fl_set_xyplot_key_position( ob, x, y, align );
}


/***************************************
 ***************************************/

void
fl_set_xyplot_key_font( FL_OBJECT * ob,
                        int         style,
                        int         size )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( sp->key_lstyle != style || sp->key_lsize != size )
    {
        sp->key_lstyle = style;
        sp->key_lsize = size;

        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_set_xyplot_mark_active( FL_OBJECT * ob,
                           int         y )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int old = sp->mark_active;

    if ( old != y )
    {
        sp->mark_active = y;
        fl_redraw_object( ob );
    }

    return old;
}


/***************************************
 * Function that allows to determine the rectangle into which the data
 * of the xyplot widget get drawn (when axes are drawn this is also the
 * rectangle formed by those axes). The first two return arguments are
 * the coordinates (relative to the object) of the lower left hand corner,
 * while the other two are those of the upper right hand corner.
 ***************************************/

void
fl_get_xyplot_screen_area( FL_OBJECT * obj,
                           FL_COORD  * llx,
                           FL_COORD  * lly,
                           FL_COORD  * urx,
                           FL_COORD  * ury )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;

    *llx = sp->xi;
    *lly = sp->yf;
    *urx = sp->xf;
    *ury = sp->yi;
}


/***************************************
 * Function that allows to determine the rectangle into which the data
 * of the xyplot widget get drawn (when axes are drawn this is also the
 * rectangle formed by those axes). The first two return arguments are
 * the coordinates (in "world" units) of the lower left hand corner,
 * while the other two are those of the upper right hand corner.
 ***************************************/

void
fl_get_xyplot_world_area( FL_OBJECT * obj,
                          float     * llx,
                          float     * lly,
                          float     * urx,
                          float     * ury )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;

    fl_xyplot_s2w( obj, sp->xi, sp->yf, llx, lly );
    fl_xyplot_s2w( obj, sp->xf, sp->yi, urx, ury );
}


/***************************************
 ***************************************/

int
fl_set_xyplot_log_minor_xtics( FL_OBJECT * obj,
                               int         yesno )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;
    int old_state = sp->log_minor_xtics > 0.5;

    if ( old_state != yesno )
    {
        sp->log_minor_xtics = yesno ? 1 : 0;
        fl_redraw_object( obj );
    }

    return old_state;
}
        

/***************************************
 ***************************************/

int
fl_set_xyplot_log_minor_ytics( FL_OBJECT * obj,
                               int         yesno )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;
    int old_state = sp->log_minor_ytics > 0;

    if ( old_state != yesno )
    {
        sp->log_minor_ytics = yesno ? 1 : 0;
        fl_redraw_object( obj );
    }

    return old_state;
}
        

/***************************************
 * Function allows to set up to which mouse
 * buttons the xyplot object will react.
 ***************************************/

void
fl_set_xyplot_mouse_buttons( FL_OBJECT    * obj,
                             unsigned int   mouse_buttons )
{
    FLI_XYPLOT_SPEC *sp = obj->spec;
    unsigned int i;

    for ( i = 0; i < 3; i++, mouse_buttons >>= 1 )
        sp->react_to[ i ] = mouse_buttons & 1;
}


/***************************************
 * Function returns a value via 'mouse_buttons', indicating
 * which mouse buttons the xyplot object will react to.
 ***************************************/

void
fl_get_xyplot_mouse_buttons( FL_OBJECT    * obj,
                             unsigned int * mouse_buttons )
{
    FLI_XYPLOT_SPEC *sp;
    int i;
    unsigned int k;

    if ( ! obj )
    {
        M_err( "fl_get_xyplot_mouse_buttons", "NULL object" );
        return;
    }

    if ( ! mouse_buttons )
        return;

    sp = obj->spec;

    *mouse_buttons = 0;
    for ( i = 0, k = 1; i < 3; i++, k <<= 1 )
        *mouse_buttons |= sp->react_to[ i ] ? k : 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
