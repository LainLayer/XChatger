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
 * \file pflps.h
 *
 * private headers of postscript support. Must come
 * after forms.h
 */

#ifndef PFLPS_H
#define PFLPS_H

#include "include/forms.h"

/* configuration infomation. contains all information needed for
 * both regular gui postscript and image_postscript members
 */

typedef struct {
    /* The first entries must be identical to the ones of a FLPS_CONTROL
       structure defined in flps.h */

    int          ps_color;
    int          orientation;
    int          auto_fit;
    int          drawbox;
    int          eps;
    float        xdpi,
                 ydpi;
    float        paper_w,
                 paper_h;
    float        gamma;
    const char * tmpdir;
    int          printer_dpi;
    float        hm,
                 vm;
    float        xscale,
                 yscale;
    int          scale_text;
    int          first_page_only;
    int          clip;

    /* Now follow elements not from the FLPS_CONTROL structure */

    FILE       * fp;
    int          lastc,
                 literal,
                 len;
    int          pack;
    int          verbose;

    /* cache */

    int          cur_lw,            /* line width                */
                 last_lw;
    int          cur_style,         /* font style and size       */
                 cur_size;
    FL_COLOR     cur_color;         /* color cache               */
    int          landscape;
    float        final_xscale,
                 final_yscale;

    /* private fields for regular flps  */

    int          unit;              /* unit of measure           */
    int          pages;             /* how many pages            */
    int          page;              /* current page              */
    int          epsf_import;       /* true if importing EPS     */
    int          inverted;          /* take care of coord switch */
    int          user_bw;           /* bw specified on cmdline   */
    int          bw;                /* current border width      */
    const char * poly_name;         /* PS poly name              */

    /* private field for image postscript */

    char       * prefix;            /* output file prefix        */
    int          misct,             /* misc. margins         */
                 miscl,
                 miscb,
                 miscr;
    int          lastr,
                 lastg,
                 lastb;
    int          comment;
    int          isRGBColor;
    int          rotation;
    float        s2px;             /* screen to paper scaling        */
    float        s2py;             /* screen to paper scaling        */
} FLPSInfo;

extern FLPSInfo *flps;

extern void flps_color( FL_COLOR );

extern void flps_rgbcolor( int,
                           int,
                           int );

extern int flps_get_gray255( FL_COLOR );

extern void flps_emit_prolog( void );

extern void flps_emit_header( const char *,
                              int,
                              int,
                              int,
                              int,
                              int );

extern void flps_switch_flps( FLPSInfo * );

extern void flps_restore_flps( void );


/* basic drawing of simple geomtric figures */

extern void flps_draw_init( void );

extern void flps_rectangle( int,
                            int,
                            int,
                            int,
                            int,
                            FL_COLOR );

extern void flps_roundrectangle( int,
                                 int,
                                 int,
                                 int,
                                 int,
                                 FL_COLOR );

extern void flps_lines( FL_POINT *,
                        int,
                        FL_COLOR );

extern void flps_line( int,
                       int,
                       int,
                       int,
                       FL_COLOR );

extern void flps_poly( int,
                       FL_POINT *,
                       int,
                       FL_COLOR );

extern int flps_draw_symbol( const char *,
                             int,
                             int,
                             int,
                             int,
                             FL_COLOR );

extern void flps_oval( int,
                       int,
                       int,
                       int,
                       int,
                       FL_COLOR );

extern void flps_pieslice( int,
                           int,
                           int,
                           int,
                           int,
                           int,
                           int,
                           FL_COLOR );

extern void flps_circ( int,
                       int,
                       int,
                       int,
                       FL_COLOR );

extern void flps_arc( int,
                      int,
                      int,
                      int,
                      int,
                      int,
                      FL_COLOR );


#define flps_rectf( x, y, w, h, c )   flps_rectangle( 1, x, y, w, h, c )
#define flps_rect( x, y, w, h, c )    flps_rectangle( 0, x, y, w, h, c )


extern void flps_draw_box( int,
                           int,
                           int,
                           int,
                           int,
                           FL_COLOR,
                           int );

extern void flps_draw_tbox( int,
                            int,
                            int,
                            int,
                            int,
                            FL_COLOR,
                            int );

extern void flps_draw_frame( int,
                             int,
                             int,
                             int,
                             int,
                             FL_COLOR,
                             int );

extern void flps_draw_checkbox( int,
                                int,
                                int,
                                int,
                                int,
                                FL_COLOR,
                                int );


/* basic text drawing routines */

extern void flps_draw_text( int,
                            int,
                            int,
                            int,
                            int,
                            FL_COLOR,
                            int,
                            int,
                            const char * );

extern void flps_draw_text_beside( int,
                                   int,
                                   int,
                                   int,
                                   int,
                                   FL_COLOR,
                                   int,
                                   int,
                                   const char * );

extern void flps_text_init( void );

extern int find_type_val( int,
                          const char * );

extern void flps_reset_cache( void );

extern void flps_invalidate_color_cache( void );

extern void flps_invalidate_font_cache( void );

extern void flps_invalidate_linewidth_cache( void );

extern void flps_invalidate_symbol_cache( void );

extern void flps_linewidth( int );

extern int flps_get_linewidth( void );

extern void flps_reset_linewidth( void );

extern void flps_linestyle( int );

extern int flps_get_linestyle( void );

extern void flps_log( const char * );

extern void flps_output( const char *,
                         ... );

extern void flps_set_font( int,
                           int );

extern int get_gray255( FL_COLOR );

extern void get_scale_unit( int,
                            float *,
                            float * );

extern void ps_invalidate_font_cache(void);

extern char *ps_literal( const char * );

extern void flps_set_clipping( int,
                               int,
                               int,
                               int);

extern void flps_unset_clipping( void );

extern void flps_apply_gamma( float );

extern FL_COLOR flps_get_namedcolor( const char * );


#define PS_SPECIAL( c )  (    ( c ) == '('   \
                           || ( c ) == ')'   \
                           || ( c ) == '['   \
                           || ( c ) == ']'   \
                           || ( c ) == '<'   \
                           || ( c ) == '>'   \
                           || ( c ) == '%'   \
                           || ( c ) == '#'   \
                           || ( c ) == '/' )

#endif  /* ifndef PFLPS_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
