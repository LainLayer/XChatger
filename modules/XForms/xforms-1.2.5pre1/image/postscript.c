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
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 *  Supports xyplot PostScript dump. Almost a verbatim copy of
 *  xyplot.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pxyplot.h"
#include "private/pflps.h"
#include <math.h>

static void ps_draw_xyplot( FL_OBJECT * ob );


/***************************************
 ***************************************/

static int
auto_orientation( float pw,
                  float ph,
                  float obw,
                  float obh )
{
    int plm,
        pbm,
        llm,
        lbm;

    plm = ( pw - obw ) / 2;
    pbm = ( ph - obh ) / 2;
    llm = ( pw - obh ) / 2;
    lbm = ( ph - obw ) / 2;

    return ( FL_abs( lbm - llm ) < FL_abs( pbm - plm ) ) ?
           FLPS_LANDSCAPE : FLPS_PORTRAIT;
}


/***************************************
 * find scale factor, in percentage point
 ***************************************/

static int
auto_scale( float pw,
            float ph,
            float obw,
            float obh )
{
    float margin = 0.4 * 72;    /* about 1cm */
    int i = 100;

    pw -= 2 * margin;
    ph -= 2 * margin;

    if (    (     flps->orientation == FLPS_PORTRAIT
              &&  ( pw < obw || ph < obh ) )
         || (    flps->orientation == FLPS_LANDSCAPE
              && ( pw < obh || ph < obw ) ) )
    {
        float gscalex,
              gscaley;

        if ( flps->orientation == FLPS_PORTRAIT )
        {
            gscalex = ( pw - 2.0 ) / obw;
            gscaley = ( ph - 2.0 ) / obh;
        }
        else
        {
            gscalex = ( pw - 2.0 ) / obh;
            gscaley = ( ph - 2.0 ) / obw;
        }

        i = 100.0 * ( ( gscalex < gscaley ) ? gscalex : gscaley );
    }

    return i;
}


/***************************************
 ***************************************/

static char *
strip_newline( char * str )
{
    static char s[ 64 ];
    char *c;

    strncpy( s, str, 63 );
    s[ 63 ] = '\0';

    for ( ; ( c = strchr( s, '\n' ) ); )
        *c = ' ';

    return s;
}


/***************************************
 ***************************************/

int
fl_object_ps_dump( FL_OBJECT  * ob,
                   const char * fname )
{
    float bxi,      /* bounding box */
          byi,
          bxf,
          byf;
    float objw,
          objh,
          pw,
          ph;
    float fgscale;
    int gscale = 100;
    int orientation;

    if ( ! flps )
    {
        flps = ( FLPSInfo * ) flps_init( );
        if (ob->objclass == FL_XYPLOT)
            flps->ps_color = FLPS_BW;;
    }

    /* try to open the file */

    if ( ! fname || ! *fname )
        fname = fl_show_fselector( "Output Filename", "", "*ps", "" );

    /* cancel */

    if ( ! fname )
        return 0;

    if ( ! *fname )
    {
        M_err( "PS_dump", "null filename" );
        return -1;
    }

    if ( strcmp( fname, "-" ) == 0 )
        flps->fp = stdout;
    else
        flps->fp = fopen( fname, "w" );

    if ( ! flps->fp )
    {
        M_err( "PS_dump", "can't open %s", fname );
        return -1;
    }

    /* we need to do this to get repeated call right */

    flps_reset_cache( );

    /* fill in some defaults */

    if ( flps->drawbox < 0 )
        flps->drawbox = 0;

#if 0
    fl_freeze_all_forms( );
    fl_set_cursor( ob->form->window, XC_watch );
    fl_update_display( 0 );
#endif

    flps->s2px = 72.0 / flps->xdpi;
    flps->s2py = 72.0 / flps->ydpi;
    flps->final_xscale = flps->xscale * flps->s2px;
    flps->final_yscale = flps->yscale * flps->s2py;

    /* bounding box always in point */

    pw = flps->paper_w * 72;
    ph = flps->paper_h * 72;
    objw = ob->w * flps->final_xscale;
    objh = ob->h * flps->final_yscale;

    /* handle auto orientation */

    if ( ( orientation = flps->orientation ) == FLPS_AUTO )
        orientation = auto_orientation( pw, ph, objw, objh );

    flps->landscape = orientation == FLPS_LANDSCAPE;

    if ( flps->auto_fit )
        gscale = auto_scale( pw, ph, objw, objh );

    fgscale = gscale * 0.01;

    flps->final_xscale *= fgscale;
    flps->final_yscale *= fgscale;

    if ( flps->landscape )
    {
        bxi = ( pw - objh * fgscale ) * 0.5;
        byi = ( ph - objw * fgscale ) * 0.5;
        bxf = bxi + objh * fgscale;
        byf = byi + objw * fgscale;
    }
    else
    {
        bxi = ( pw - objw * fgscale ) * 0.5;
        byi = ( ph - objh * fgscale ) * 0.5;
        bxf = bxi + objw * fgscale;
        byf = byi + objh * fgscale;
    }

    flps_emit_header( strip_newline( ob->label ), 1, bxi, byi, bxf, byf );
    flps_emit_prolog( );

    if ( flps->landscape )
    {
        /* from now on, we are in pixel unit */

        flps_output( "gsave %.1f %.1f translate 90 rotate\n",
                     bxi + objh, byi );

        flps_output( "%.1f %.1f translate\n",
                     -ob->x * flps->final_yscale, -ob->y * flps->final_xscale );
    }
    else
        flps_output( "gsave %.1f %.1f translate\n",
                     bxi - ob->x * flps->final_xscale,
                     byi - ob->y * flps->final_yscale );

    flps_output( "SX SY scale\n " );

    switch ( ob->objclass )
    {
        case FL_XYPLOT :
            ps_draw_xyplot( ob );
            break;

        default :
            M_err( "PS_dump", "unsupported object class: %d", ob->objclass );
            break;
    }

    fputs( "grestore\nshowpage\n", flps->fp );
    fclose( flps->fp );

#if 0
    fl_reset_cursor( ob->form->window );
    fl_unfreeze_all_forms( );
#endif

    return 0;
}



static void flps_draw_text_point(int, int, int, FL_COLOR, int, int, char * );

#define PCOL( c )   ( ( flps->ps_color == FLPS_BW && ! flps->drawbox ) ? \
                      FL_BLACK : c )
#define SPEC        FLI_XYPLOT_SPEC

static int ym1,
           ym2;
static float ay,
             by;

#define FLIP( ys )   ( ym1 + ( sp->yf - ys ) )

#define FMIN         1.e-25


/***************************************
 ***************************************/

static void
mapw2s( FLI_XYPLOT_SPEC * sp,
        FL_POINT        * p,
        int               n1,
        int               n2,
        float           * x,
        float           * y )
{
    int i;
    float ax = sp->ax,
          bx = sp->bx;
    float lbase,
          t;

    ay = ( sp->yf - sp->yi) / (sp->yscmax - sp->yscmin );
    by = ym1 - ay * sp->yscmin;

    if ( sp->xscale == FL_LOG )
    {
        lbase = 1.0 / sp->lxbase;
        for ( i = n1; i < n2; i++ )
        {
            t = x[ i ] > 0 ? x[ i ] : FMIN;
            p[ i - n1 ].x = ax * log10( t ) * lbase + bx + 0.4;
        }
    }
    else
    {
        for ( i = n1; i < n2; i++ )
            p[ i - n1 ].x = ax * x[ i ] + bx + 0.4;
    }

    if ( sp->yscale == FL_LOG )
    {
        lbase = 1.0 / sp->lybase;
        for ( i = n1; i < n2; i++ )
        {
            t = y[ i ] > 0 ? y[ i ] : FMIN;
            p[ i - n1 ].y = ay * log10( t ) * lbase + by + 0.4;
        }
    }
    else
    {
        for ( i = n1; i < n2; i++ )
            p[ i - n1 ].y = ay * y[ i ] + by + 0.4;
    }
}


/***************************************
 ***************************************/

static void
add_border( FL_OBJECT * ob,
            FL_COLOR    c )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    if ( sp->xtic > 0 && sp->ytic > 0 )
        flps_rect( sp->xi, ym1, sp->xf - sp->xi + 1, ym2 - ym1 + 1, c );
    else if ( sp->xtic > 0 )
        flps_line( sp->xi, ym1, sp->xf, ym1, c );
    else if ( sp->ytic > 0 )
        flps_line( sp->xi, ym1, sp->xi, ym2, c );
}


/***************************************
 ***************************************/

static void
w2s( FL_OBJECT * ob,
     float       wx,
     float       wy,
     float     * sx,
     float     * sy )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;

    *sx = wx * sp->ax + sp->bx;
    *sy = wy * ay + by;
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

    for ( i = 0; i < sp->maxoverlay; i++ )
    {
        if ( sp->text[ i ] )
        {
            w2s( ob, sp->xt[ i ], sp->yt[ i ], &tx, &ty );
            flps_draw_text_point( sp->talign[ i ], tx, ty,
                                  PCOL( sp->tcol[ i ] ),
                                  sp->lstyle, sp->lsize, sp->text[ i ] );
        }
    }
}


#define XRound( s )    \
    ( ( s )->xtic > 0 && ! ( s )->axtic[ 0 ] && ( s )->xmajor > 1 )
#define YRound( s )    \
    ( ( s )->ytic > 0 && ! ( s )->aytic[ 0 ] && ( s )->ymajor > 1 )


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
         *label,
         *p;

    if ( tic <= 0 )
        return;

    yi = ym1;
    yf = yi - ticl / 2;

    for ( i = 0; i < sp->num_xminor; i++ )
    {
        xr = sp->xtic_minor[ i ];
        flps_line( xr, yi, xr, yf, ob->col2 );
    }

    yi = ym1;
    yf = yi - ticl;

    for ( i = 0; i < sp->num_xmajor; i++ )
    {
        xr = sp->xtic_major[ i ];
        flps_line( xr, yi, xr, yf, ob->col2 );

        if ( ! sp->axtic[ 0 ] )
            fli_xyplot_nice_label( tic, sp->xminor,
                                   sp->xmajor_val[ i ], label = buf );
        else
        {
            if ( ( p = strchr( sp->axtic[ i ], '@' ) ) )
            {
                label = strcpy( buf, sp->axtic[ i ] );
                label[ p - sp->axtic[ i ] ] = '\0';
            }
            else
                label = sp->axtic[ i ];
        }

        flps_draw_text( FL_ALIGN_TOP, xr, ym1 - ticl + 1, 0, 0,
                        ob->col2, sp->lstyle, sp->lsize, label );
    }
}


/***************************************
 ***************************************/

static void
add_logxtics( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float xw;
    int xr,
        ticl = 6,
        yi,
        yf,
        i;
    char label[ 80 ];

    if ( sp->xtic < 0 )
        return;

    yi = ym1;
    yf = yi - ticl / 2;

    for ( i = 0; i < sp->num_xminor; i++ )
    {
        xr = sp->xtic_minor[ i ];
        flps_line( xr, yi, xr, yf, ob->col2 );
    }

    yi = ym1;
    yf = ym1 - ticl;

    for ( i = 0; i < sp->num_xmajor; i++ )
    {
        xr = sp->xtic_major[ i ];
        flps_line( xr, yi, xr, yf, ob->col2 );
        xw = sp->xmajor_val[ i ];

        if ( sp->xbase == 10.0 )
        {
            sprintf( label, "%g", pow( 10.0, sp->xmajor_val[ i ] ) );
            flps_draw_text( FL_ALIGN_TOP, xr, yf + 1, 1, 1,
                            ob->col2, sp->lstyle, sp->lsize, label);
        }
        else
        {
            int len1,
                len2,
                ll;

            ll = sprintf( label, "%g", sp->xbase );
            flps_draw_text( FL_ALIGN_TOP, xr - 3, yf - 1, 0, 0,
                            ob->col2, sp->lstyle, sp->lsize, label );
            len1 = fl_get_string_width( sp->lstyle, sp->lsize, label, ll );
            ll = sprintf( label, "%d", ( int ) ceil( xw ) );
            len2 = fl_get_string_width( sp->lstyle, sp->lsize - 2, label, ll );
            flps_draw_text( FL_ALIGN_TOP, xr - 3 + len1 / 2 + len2 / 2,
                            yf + 3, 0, 0, ob->col2, sp->lstyle, sp->lsize - 2,
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
        yr = FLIP( sp->ytic_minor[ i ] );
        flps_line( sp->xi, yr, sp->xi - ticl / 2, yr, ob->col2 );
    }

    for ( i = 0; i < sp->num_ymajor; i++ )
    {
        yr = FLIP( sp->ytic_major[ i ] );
        flps_line( sp->xi - ticl, yr, sp->xi, yr, ob->col2 );

        if ( ! sp->aytic[ 0 ] )
            fli_xyplot_nice_label( tic, sp->yminor,
                                   sp->ymajor_val[ i ], label = buf );
        else
        {
            if ( ( p = strchr( sp->aytic[ i ], '@' ) ) )
            {
                label = strcpy( buf, sp->aytic[ i ] );
                label[ p - sp->aytic[ i ] ] = '\0';
            }
            else
                label = sp->aytic[ i - 1 ];
        }

        flps_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl + 1, yr,
                        0, 0, ob->col2, sp->lstyle, sp->lsize, label );
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
        yr = FLIP( sp->ytic_minor[ i ] );
        flps_line( sp->xi, yr, sp->xi - ticl / 2, yr, ob->col2 );
    }

    for ( i = 0; i < sp->num_ymajor; i++ )
    {
        yr = FLIP( sp->ytic_major[ i ] );
        flps_line( sp->xi - ticl, yr, sp->xi, yr, ob->col2 );

        yw = sp->ymajor_val[ i ];

        if ( sp->ybase == 10.0 )
        {
            sprintf( label, "%g", pow( sp->ybase, yw ) );
            flps_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl, yr,
                            1, 1, ob->col2, sp->lstyle, sp->lsize, label );
        }
        else
        {
            int len,
                ll;

            ll = sprintf( label, "%d", ( int ) ceil( yw ) );
            flps_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl, yr + 3,
                            0, 0, ob->col2, sp->lstyle, sp->lsize - 2, label );
            len = fl_get_string_width( sp->lstyle, sp->lsize - 2, label, ll );
            sprintf( label, "%g", sp->ybase );
            flps_draw_text( FL_ALIGN_RIGHT, sp->xi - ticl - len,
                            yr, 0, 0, ob->col2, sp->lstyle, sp->lsize, label );
        }
    }
}


/***************************************
 ***************************************/

static void
draw_square( FL_POINT * p,
             int        n,
             int        w,
             int        h )
{
    int w2 = w / 2,
        h2 = h / 2;
    FL_POINT *ps = p + n;

    for ( ; p < ps; p++ )
        flps_rectangle( 0, p->x - w2, p->y - h2, w, h, FL_NoColor );
}


/***************************************
 ***************************************/

static void
draw_circle( FL_POINT * p,
             int        n,
             int        w,
             int        h )
{
    FL_POINT *ps = p + n;
    int r = ( w + h ) / 4;

    for ( ; p < ps; p++ )
        flps_circ( 0, p->x, p->y, r, FL_NoColor );  /* nocolor mean current */
}


/***************************************
 ***************************************/

static void
draw_point( FL_POINT * p,
            int        n,
            int        w,
            int        h )
{
    int w2 = w / 2,
        h2 = h / 2;
    FL_POINT *ps = p + n;

    for ( ; p < ps; p++ )
    {
        flps_line( p->x, p->y - h2, p->x, p->y + h2, FL_NoColor );
        flps_line( p->x - w2, p->y, p->x + w2, p->y, FL_NoColor );
        flps_line( p->x - w2, p->y - h2, p->x + w2, p->y + h2, FL_NoColor );
        flps_line( p->x + w2, p->y - h2, p->x - w2, p->y + h2, FL_NoColor );
    }
}


/***************************************
 ***************************************/

static void
add_xgrid( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    int xr, i;
    int savels = flps_get_linestyle( );

    flps_linestyle( sp->grid_linestyle );

    for ( i = 0; sp->xgrid == FL_GRID_MINOR && i < sp->num_xminor; i++ )
    {
        xr = sp->xtic_minor[ i ];
        flps_line( xr, ym1, xr, ym2, ob->col2 );
    }

    for ( i = 0; i < sp->num_xmajor; i++ )
    {
        xr = sp->xtic_major[ i ];
        flps_line( xr, ym1, xr, ym2, ob->col2 );
    }

    flps_linestyle( savels );
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
    int savels = flps_get_linestyle( );

    xi = sp->xi + 1;
    xf = sp->xf - 1;

    flps_linestyle( sp->grid_linestyle );

    for ( i = 0; sp->ygrid == FL_GRID_MINOR && i < sp->num_yminor; i++ )
    {
        yr = FLIP( sp->ytic_minor[ i ] );
        flps_line( xi, yr, xf, yr, ob->col2 );
    }

    for ( i = 0; i < sp->num_ymajor; i++ )
    {
        yr = FLIP( sp->ytic_major[ i ] );
        flps_line( xi, yr, xf, yr, ob->col2 );
    }

    flps_linestyle( savels );
}


/***************************************
 * Draw xyplot in PostScript device. The driver sets things
 * up so the coordinate system is in pixels and the origin
 * of the coordinate system is at form's origin
 *
 * This is an almost verbatim copy of the X xyplot drawing
 ***************************************/

static void
ps_draw_xyplot( FL_OBJECT * ob )
{
    FLI_XYPLOT_SPEC *sp = ob->spec;
    float *x,
          *y;
    FL_POINT *xp;
    int i,
        nplot,
        noline = 0,
        n1,
        n2,
        nxp,
        newn;
    void ( * drawsymbol )( FL_POINT *, int, int, int );
    int savels = flps_get_linestyle( );
    int savelw = flps_get_linewidth( );
    int key_xs,
        key_ys;
    int dblbuffer;
    FL_COLOR col,
             savecol2;

    if ( ! ob->visible || ! ob->form->visible )
    {
        M_err( "PSDrawXYPlot", "object must be visible" );
        return;
    }

    flps_linewidth( 1 );

    /* for BW output, always black ink */

    savecol2 = ob->col2;
    ob->col2 = PCOL( ob->col2 );

    /* bounding box and object label */

    if ( flps->drawbox )
        flps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1,
                       ob->bw );

    flps_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                           PCOL(ob->lcol), ob->lstyle, ob->lsize, ob->label );

    /* if we're in double buffer mode, need to shift the plot. */

    dblbuffer = sp->bym - sp->by >= 1.0 || sp->bxm - sp->bx >= 1.0;

    if ( dblbuffer )
        fprintf( flps->fp, "%d -%d translate\n", sp->objx, sp->objy );

    /* ym1 and ym2 are the y-bounds in PostScript system, i.e., ym1<ym2 */

    ym1 = ob->y + ( ob->y + ob->h - 1 - sp->yf );
    ym2 = ( ob->y + ob->h - 1 ) - ( sp->yi - ob->y );

    add_border( ob, ob->col2 );
    flps_set_clipping( sp->xi, ym1, sp->xf - sp->xi + 1, ym2 - ym1 + 1 );

    if ( sp->xgrid != FL_GRID_NONE && sp->xtic > 0 )
        add_xgrid( ob );

    if ( sp->ygrid != FL_GRID_NONE && sp->ytic > 0 )
        add_ygrid( ob );

    /* too lazy to figure out the transformation to map X to PS. brute force */

    {
        FL_POINT tmpp;
        float keyx = sp->key_x,
              keyy = sp->key_y;

        mapw2s( sp, &tmpp, 0, 1, &keyx, &keyy );
        sp->key_xs = tmpp.x;
        sp->key_ys = tmpp.y;
    }

    flps_rectangle( 0, sp->key_xs - sp->key_maxw - 1,
                    sp->key_ys - sp->key_maxh - 1,
                    sp->key_maxw, sp->key_maxh, PCOL( sp->col[ 0 ] ) );

    key_xs = sp->key_xs - sp->key_maxw + 1;
    key_ys = sp->key_ys - sp->key_ascend + sp->key_descend + ( sp->lsize > 12 );

    for ( nplot = 0; nplot <= sp->maxoverlay; nplot++ )
    {
        if ( sp->n[ nplot ] == 0 )
            continue;

        fli_xyplot_compute_data_bounds( ob, &n1, &n2, nplot );

        noline = 0;
        drawsymbol = NULL;
        col = PCOL( sp->col[ nplot ] );
        flps_color( col );

        /* for PostScript, we don't want 0, too thin */

        flps_linewidth( sp->thickness[ nplot ] ? sp->thickness[ nplot ] : 1 );

        if (    sp->interpolate[ nplot ] > 1
             && n2 - n1 > 3
             && ( newn = fli_xyplot_interpolate( ob, nplot, n1, n2 ) ) >= 0 )
        {
            x = sp->wx;
            y = sp->wy;
            xp = sp->xpi;

            mapw2s( sp, xp, 0, newn, x, y );
            nxp = sp->nxpi = newn;
            mapw2s( sp, sp->xp, n1, n2, sp->x[ nplot ], sp->y[ nplot ] );
            sp->nxp = n2 - n1;
        }
        else
        {
            x = sp->x[ nplot ];
            y = sp->y[ nplot ];
            xp = sp->xp;
            mapw2s( sp, xp, n1, n2, x, y );
            nxp = sp->nxp = n2 - n1;
        }

        switch ( sp->type[ nplot ] )
        {
            case FL_SQUARE_XYPLOT :
            case FL_ACTIVE_XYPLOT :
                drawsymbol = draw_square;
                break;

            case FL_CIRCLE_XYPLOT :
                drawsymbol = draw_circle;
                break;

            case FL_POINTS_XYPLOT :
                noline = 1;
                /* fall through */

            case FL_LINEPOINTS_XYPLOT :
                drawsymbol = draw_point;
                break;

            case FL_DOTTED_XYPLOT :
                flps_linestyle( FL_DOT );
                break;

            case FL_DOTDASHED_XYPLOT :
                flps_linestyle( FL_DOTDASH );
                break;

            case FL_DASHED_XYPLOT :
                flps_linestyle( FL_DASH );
                break;

            case FL_LONGDASHED_XYPLOT :
                flps_linestyle( FL_LONGDASH );
                break;

            case FL_FILL_XYPLOT :
                xp[ -1 ].x = xp[ 0 ].x;
                xp[ -1 ].y = ym1;
                xp[ nxp ].x = xp[ nxp - 1 ].x;
                xp[ nxp ].y = ym1;
                flps_poly( 1, xp - 1, nxp + 2, col );
                noline = 1;
                break;

            case FL_IMPULSE_XYPLOT :
                noline = 1;
                for ( i = 0; i < sp->n[ nplot ]; i++ )
                    flps_line( sp->xp[ i ].x, ym1, sp->xp[ i ].x,
                               sp->xp[ i ].y, col );
                break;

            case FL_EMPTY_XYPLOT :
                noline = 1;
                break;

            case FL_NORMAL_XYPLOT :
            default:
                noline = 0;
                break;
        }

        if ( ! noline )
            flps_lines( xp, nxp, col );

        if ( drawsymbol )
        {
            xp = sp->xp;    /* always use original point for symbol */
            nxp = sp->nxp;
            drawsymbol( xp, nxp, sp->ssize, sp->ssize );
        }

        /* do keys */

        if ( sp->key[ nplot ] )
        {
            flps_linewidth( 0 );

            if ( ! noline )
                flps_line( key_xs, key_ys, key_xs + 20, key_ys, col );

            if ( sp->type[ nplot ] == FL_IMPULSE_XYPLOT )
            {
                flps_line( key_xs + 3, key_ys + 2,
                           key_xs + 3, key_ys - 3, col );
                flps_line( key_xs + 7, key_ys + 2,
                           key_xs + 7, key_ys - 3, col );
                flps_line( key_xs + 11, key_ys + 2,
                           key_xs + 11, key_ys - 3, col );
                flps_line( key_xs + 15, key_ys + 2,
                           key_xs + 15, key_ys - 3, col );
            }
            else if ( sp->type[ nplot ] == FL_FILL_XYPLOT )
                flps_rectangle( 1, key_xs + 1, key_ys - 3, 19, 6, col );

            if ( drawsymbol )
            {
                FL_POINT p[ 3 ];

                p[ 0 ].x = key_xs + 3;
                p[ 1 ].x = key_xs + 10;
                p[ 2 ].x = key_xs + 17;
                p[ 0 ].y = p[ 1 ].y = p[ 2 ].y = key_ys;
                drawsymbol( p, 3, 4, 4 );
            }

            flps_draw_text( FL_ALIGN_LEFT, key_xs + 20, key_ys, 0, 0, col,
                            sp->key_lstyle, sp->key_lsize, sp->key[ nplot ] );

            key_ys -= sp->key_ascend + sp->key_descend;
        }

        flps_linestyle( savels );
        flps_linestyle( savelw );
    }

    flps_unset_clipping( );

    flps_draw_text( FL_ALIGN_BOTTOM, ( sp->xi + sp->xf ) / 2,
                    ym2 + 1,
                    1, 1, ob->col2, sp->lstyle,
                    sp->lsize, sp->title );

    ( sp->xscale == FL_LOG ? add_logxtics : add_xtics )( ob );
    ( sp->xscale == FL_LOG ? add_logytics : add_ytics )( ob );

    draw_inset( ob );

    /* xlabel and y label */

    flps_draw_text( FL_ALIGN_BOTTOM, ( sp->xi + sp->xf ) / 2,
                    ob->y + FL_abs(ob->bw) + ( dblbuffer ? sp->objy : 0 ),
                    1, 1, ob->col2, sp->lstyle, sp->lsize, sp->xlabel );

    flps_draw_text( FL_ALIGN_CENTER | FL_ALIGN_VERT,
                    sp->xi - sp->maxytic -
                    fl_get_char_height( sp->lstyle, sp->lsize, 0, 0 ) / 2,
                    ( ym1 + ym2 ) / 2,
                    1, 1, ob->col2, sp->lstyle, sp->lsize, sp->ylabel );

    ob->col2 = savecol2;
}


/***************************************
 * Draw a string with alignment given relative to a point.
 * Figure out the bounding box etc so symbols can be drawn
 ***************************************/

static void
flps_draw_text_point( int      lalign,
                      int      x,
                      int      y,
                      FL_COLOR col,
                      int      lstyle,
                      int      lsize,
                      char   * str )
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

    flps_draw_text_beside( align, xx, yy, bbox, bbox, col, lstyle, lsize, str );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
