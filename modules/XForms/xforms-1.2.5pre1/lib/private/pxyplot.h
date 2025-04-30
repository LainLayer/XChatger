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
 *  You should have received a copy of the GNU General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file pxyplot.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1995-1997  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  private header for xyplot object
 */

#ifndef PXYPLOT_H
#define PXYPLOT_H


#define MAX_MAJOR         50
#define MAX_MINOR         20
#define MAX_TIC           200


typedef struct {
    float               xmin,               /* true xbounds                 */
                        xmax;
    float               ymin,               /* true ybounds                 */
                        ymax;
    float               xscmin,             /* bounds used in mapping       */
                        xscmax;
    float               yscmin,             /* bounds used in mapping       */
                        yscmax;
    float               ax,                 /* data -> screen conversion    */
                        bx,
                        ay,
                        by;
    float               xtic,               /* tic marks                    */
                        ytic;
    float               xbase,              /* log base                     */
                        ybase;
    float               lxbase,             /* log10 of the log base        */
                        lybase;
    int                 xi,                 /* ploted area bounds           */
                        xf,
                        yi,
                        yf;
    char              * title;              /* overall title                */
    char              * xlabel,
                      * ylabel;             /* the x- and y-axis labels     */
    char              * axtic[ MAX_MAJOR + 1 ]; /* alphanumerical tic marks */
    char              * aytic[ MAX_MAJOR + 1 ]; /* alphanumerical tic marks */
    char              * xmargin1,
                      * xmargin2;
    char              * ymargin1,
                      * ymargin2;           /* fixed area. margins          */
    char             ** text;               /* inset text *text[over]       */
    float             * xt,
                      * yt;                 /* inset text position xt[over] */
    float            ** x,
                     ** y;                  /* real data *x, *y[over+1]     */
    float             * grid;               /* interpolating grid[over+1]   */
    float               log_minor_xtics,    /* use logarithmix minor tics?  */
                        log_minor_ytics;
    float             * wx,                 /* working array for interpol.  */
                      * wy;
    FL_POINT          * xp;                 /* screen data                  */
    FL_POINT          * xpactive;           /* active(mouse) screen data    */
    FL_POINT          * xpi;                /* screen data for interpolated */
    short             * thickness;          /* line thickness [over+1]      */
    FL_COLOR          * col;                /* overlay color [over+1]       */
    FL_COLOR          * tcol;               /* overlay text color [over+1]  */
    int               * type;               /* type[over+1]                 */
    int               * n,                  /* total points/viewable points */
                        nxp;
    int                 n1;
    int                 ninterpol;
    int                 nxpi;
    int                 cur_nxp;            /* length of xp                 */
    int                 inside;
    int                 grid_linestyle;
    FL_XYPLOT_SYMBOL  * symbol;             /* [over + 1] */
    short             * interpolate;        /* if interpolate[over+1]       */
    short             * talign;             /* inset text alignment [over+1] */
    short               xscale;             /* linear or log for x          */
    short               yscale;             /* linear or log for y          */
    short               active;             /* if accepting mouse events    */
    short               ssize;              /* symbol size                  */
    short               lsize,              /* font and style for labels    */
                        lstyle;
    short               xautoscale;         /* autoscale to fit             */
    short               yautoscale;         /* autoscale to fit             */
    short               xmajor, xminor;     /* x-axis scaling               */
    short               ymajor, yminor;     /* y-axis scaling               */
    short               inspect;
    short               update;
    short               maxoverlay;
    short               xgrid, ygrid;       /* if draw grid                 */
    short               iactive;            /* which overlay is active      */
    int                 objx,               /* singlebuffer mode            */
                        objy;
    float               bxm,                /* data -> screen conversion    */
                        bym;
    float               key_x,              /* key place location           */
                        key_y;
    int                 key_lstyle,
                        key_lsize;
    int                 key_align;
    int                 no_keybox;
    char             ** key;
    short               maxytic;            /* max tic mark length in pixels */
    int                 key_maxw,
                        key_maxh,
                        key_ascend,
                        key_descend;
    int                 key_xs,
                        key_ys;

    /* tic locations */

    int                num_xminor;
    int                num_xmajor;
    int                num_yminor;
    int                num_ymajor;
    float              xmajor_val[ MAX_MAJOR ];
    float              ymajor_val[ MAX_MAJOR ];
    short              xtic_minor[ MAX_TIC ];
    short              xtic_major[ MAX_MAJOR ];
    short              ytic_minor[ MAX_TIC ];
    short              ytic_major[ MAX_MAJOR ];
    short              mark_active;
    short              external_data;
    int                start_x;
    int                start_y;
    int                react_to[ 3 ];
} FLI_XYPLOT_SPEC;


#endif /* PXYPLOT.H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
