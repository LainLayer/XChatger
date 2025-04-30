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
 *  You should have received a copy of the GNU General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/********************** crop here for forms.h **********************/

/**
 * \file xyplot.h
 */

#ifndef FL_XYPLOT_H
#define FL_XYPLOT_H

/*  Class FL_XYPLOT */

typedef enum {
    FL_NORMAL_XYPLOT,       /* solid line                        */
    FL_SQUARE_XYPLOT,       /* with added square                 */
    FL_CIRCLE_XYPLOT,       /* with added circle                 */
    FL_FILL_XYPLOT,         /* fill completely                   */
    FL_POINTS_XYPLOT,       /* only data points                  */
    FL_DASHED_XYPLOT,       /* dashed line                       */
    FL_IMPULSE_XYPLOT,
    FL_ACTIVE_XYPLOT,       /* accepts interactive manipulations */
    FL_EMPTY_XYPLOT,
    FL_DOTTED_XYPLOT,
    FL_DOTDASHED_XYPLOT,
    FL_LONGDASHED_XYPLOT,
    FL_LINEPOINTS_XYPLOT    /* line & points                     */
} FL_XYPLOT_TYPE;

enum {
    FL_LINEAR,
    FL_LOG
};

enum {
    FL_GRID_NONE  = 0,
    FL_GRID_MAJOR = 1,
    FL_GRID_MINOR = 2
};

/***** Defaults *****/

#define FL_XYPLOT_BOXTYPE       FL_FLAT_BOX
#define FL_XYPLOT_COL1          FL_COL1
#define FL_XYPLOT_LCOL          FL_LCOL
#define FL_XYPLOT_ALIGN         FL_ALIGN_BOTTOM
#define FL_MAX_XYPLOTOVERLAY    32

/***** Others   *****/

FL_EXPORT FL_OBJECT * fl_create_xyplot( int          t,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_xyplot( int          t,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_set_xyplot_data( FL_OBJECT  * ob,
                                   float      * x,
                                   float      * y,
                                   int          n,
                                   const char * title,
                                   const char * xlabel,
                                   const char * ylabel );

FL_EXPORT void fl_set_xyplot_data_double( FL_OBJECT  * ob,
                                          double     * x,
                                          double     * y,
                                          int          n,
                                          const char * title,
                                          const char * xlabel,
                                          const char * ylabel );

FL_EXPORT int fl_set_xyplot_file( FL_OBJECT  * ob,
                                  const char * f,
                                  const char * title,
                                  const char * xl,
                                  const char * yl );

FL_EXPORT void fl_insert_xyplot_data( FL_OBJECT * ob,
                                      int         id,
                                      int         n,
                                      double      x,
                                      double      y );

#define fl_set_xyplot_datafile   fl_set_xyplot_file

FL_EXPORT void fl_add_xyplot_text( FL_OBJECT  * ob,
                                   double       x,
                                   double       y,
                                   const char * text,
                                   int          al,
                                   FL_COLOR     col );

FL_EXPORT void fl_delete_xyplot_text( FL_OBJECT  * ob,
                                      const char * text );

FL_EXPORT int fl_set_xyplot_maxoverlays( FL_OBJECT * ob,
                                         int         maxover );

FL_EXPORT void fl_add_xyplot_overlay( FL_OBJECT * ob,
                                      int         id,
                                      float     * x,
                                      float     * y,
                                      int         n,
                                      FL_COLOR    col );

FL_EXPORT int fl_add_xyplot_overlay_file( FL_OBJECT  * ob,
                                          int          id,
                                          const char * f,
                                          FL_COLOR     c );

FL_EXPORT void fl_set_xyplot_return( FL_OBJECT    * ob,
                                     unsigned int   when );

FL_EXPORT void fl_set_xyplot_xtics( FL_OBJECT * ob,
                                    int         major,
                                    int         minor );

FL_EXPORT void fl_set_xyplot_ytics( FL_OBJECT * ob,
                                    int         major,
                                    int         minor );

FL_EXPORT void fl_set_xyplot_xbounds( FL_OBJECT * ob,
                                      double      xmin,
                                      double      xmax );

FL_EXPORT void fl_set_xyplot_ybounds( FL_OBJECT * ob,
                                      double      ymin,
                                      double      ymax );

FL_EXPORT void fl_get_xyplot_xbounds( FL_OBJECT * ob,
                                      float     * xmin,
                                      float     * xmax );

FL_EXPORT void fl_get_xyplot_ybounds( FL_OBJECT * ob,
                                      float     * ymin,
                                      float     * ymax );

FL_EXPORT void fl_get_xyplot( FL_OBJECT * ob,
                              float     * x,
                              float     * y,
                              int       * i );

FL_EXPORT int fl_get_xyplot_data_size( FL_OBJECT * obj );

FL_EXPORT void fl_get_xyplot_data( FL_OBJECT * ob,
                                   float     * x,
                                   float     * y,
                                   int       * n );

FL_EXPORT void fl_get_xyplot_data_pointer( FL_OBJECT  * ob,
                                           int          id,
                                           float     ** x,
                                           float     ** y,
                                           int        *n );

FL_EXPORT void fl_get_xyplot_overlay_data( FL_OBJECT * ob,
                                           int         id,
                                           float     * x,
                                           float     * y,
                                           int       * n );

FL_EXPORT void fl_set_xyplot_overlay_type( FL_OBJECT * ob,
                                           int         id,
                                           int         type );

FL_EXPORT void fl_delete_xyplot_overlay( FL_OBJECT * ob,
                                         int         id );

FL_EXPORT void fl_set_xyplot_interpolate( FL_OBJECT * ob,
                                          int         id,
                                          int         deg,
                                          double      grid );

FL_EXPORT void fl_set_xyplot_inspect( FL_OBJECT * ob,
                                      int         yes );

FL_EXPORT void fl_set_xyplot_symbolsize( FL_OBJECT * ob,
                                         int         n );

FL_EXPORT void fl_replace_xyplot_point( FL_OBJECT * ob,
                                        int         i,
                                        double      x,
                                        double      y );

/* Replace the value of a particular point in dataset setID,
 * where setID=0 is the first data set.
 * This routine is an extension of fl_replace_xyplot_point
 * which acts on the first dataset only. */

FL_EXPORT void fl_replace_xyplot_point_in_overlay( FL_OBJECT * ob,
                                                   int         i,
                                                   int         setID,
                                                   double      x,
                                                   double      y );

FL_EXPORT void fl_get_xyplot_xmapping( FL_OBJECT * ob,
                                       float     * a,
                                       float     * b );

FL_EXPORT void fl_get_xyplot_ymapping( FL_OBJECT * ob,
                                       float     * a,
                                       float     * b );

FL_EXPORT void fl_set_xyplot_keys( FL_OBJECT  * ob,
                                   char      ** keys,
                                   float         x,
                                   float         y,
                                   int           align );

FL_EXPORT void fl_set_xyplot_key( FL_OBJECT  * ob,
                                  int          id,
                                  const char * key );

FL_EXPORT void fl_set_xyplot_key_position( FL_OBJECT * ob,
                                           float       x,
                                           float       y,
                                           int         align );

FL_EXPORT void fl_set_xyplot_key_font( FL_OBJECT * ob,
                                       int         style,
                                       int         size );

FL_EXPORT int fl_get_xyplot_numdata( FL_OBJECT * ob,
                                     int         id );

/* The following two functions will be removed.
 * Use fl_set_object_l[size|style] for the functionalities */

FL_EXPORT void fl_set_xyplot_fontsize( FL_OBJECT * ob,
                                       int         size );

FL_EXPORT void fl_set_xyplot_fontstyle( FL_OBJECT * ob,
                                        int         style );

FL_EXPORT void fl_xyplot_s2w( FL_OBJECT * ob,
                              double      sx,
                              double      sy,
                              float     * wx,
                              float     * wy );

FL_EXPORT void fl_xyplot_w2s( FL_OBJECT * ob,
                              double      wx,
                              double      wy,
                              float     * sx,
                              float     * sy );

FL_EXPORT void fl_set_xyplot_xscale( FL_OBJECT * ob,
                                     int         scale,
                                     double      base );

FL_EXPORT void fl_set_xyplot_yscale( FL_OBJECT * ob,
                                     int         scale,
                                     double      base );

FL_EXPORT void fl_clear_xyplot( FL_OBJECT * ob );

FL_EXPORT void fl_set_xyplot_linewidth( FL_OBJECT * ob,
                                        int         id,
                                        int         lw );

FL_EXPORT void fl_set_xyplot_xgrid( FL_OBJECT * ob,
                                    int         xgrid );

FL_EXPORT void fl_set_xyplot_ygrid( FL_OBJECT * ob,
                                    int         ygrid );

FL_EXPORT int fl_set_xyplot_grid_linestyle( FL_OBJECT * ob,
                                            int         style );

FL_EXPORT void fl_set_xyplot_alphaxtics( FL_OBJECT  * ob,
                                         const char * m,
                                         const char * s );

FL_EXPORT void fl_set_xyplot_alphaytics( FL_OBJECT  * ob,
                                         const char * m,
                                         const char * s );

FL_EXPORT void fl_set_xyplot_fixed_xaxis( FL_OBJECT  * ob,
                                          const char * lm,
                                          const char * rm );

FL_EXPORT void fl_set_xyplot_fixed_yaxis( FL_OBJECT  * ob,
                                          const char * bm,
                                          const char * tm );

FL_EXPORT int fl_interpolate( const float * wx,
                              const float * wy,
                              int           nin,
                              float       * x,
                              float       * y,
                              double        grid,
                              int           ndeg );

typedef void ( * FL_XYPLOT_SYMBOL )( FL_OBJECT *,
                                     int,
                                     FL_POINT *,
                                     int,
                                     int,
                                     int );

FL_EXPORT FL_XYPLOT_SYMBOL fl_set_xyplot_symbol( FL_OBJECT        * ob,
                                                 int                id,
                                                 FL_XYPLOT_SYMBOL   symbol );

FL_EXPORT int fl_set_xyplot_mark_active( FL_OBJECT * ob,
                                         int         y );

FL_EXPORT void fl_get_xyplot_screen_area( FL_OBJECT * obj,
										  FL_COORD  * llx,
										  FL_COORD  * lly,
										  FL_COORD  * urx,
										  FL_COORD  * ury );

FL_EXPORT void fl_get_xyplot_world_area( FL_OBJECT * obj,
										 float     * llx,
										 float     * lly,
										 float     * urx,
										 float     * ury );

FL_EXPORT int fl_set_xyplot_log_minor_xtics( FL_OBJECT * obj,
											 int         yesno );

FL_EXPORT int fl_set_xyplot_log_minor_ytics( FL_OBJECT * obj,
											 int         yesno );

FL_EXPORT void fl_set_xyplot_mouse_buttons( FL_OBJECT    * obj,
											unsigned int   mouse_buttons );

FL_EXPORT void fl_get_xyplot_mouse_buttons( FL_OBJECT    * obj,
											unsigned int * mouse_buttons );

#endif  /* ! defined FL_XYPLOT_H */
