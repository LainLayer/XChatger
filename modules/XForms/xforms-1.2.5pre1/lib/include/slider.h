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

/********************** crop here for forms.h **********************/

/**
 * \file slider.h
 *
 * Object Class: Slider
 */

#ifndef FL_SLIDER_H
#define FL_SLIDER_H


#define FL_HOR_FLAG     1
#define FL_SCROLL_FLAG  16

typedef enum {
    FL_VERT_SLIDER           = 0,
    FL_HOR_SLIDER            = FL_VERT_SLIDER          | FL_HOR_FLAG,

    FL_VERT_FILL_SLIDER      = 2,
    FL_HOR_FILL_SLIDER       = FL_VERT_FILL_SLIDER     | FL_HOR_FLAG,

    FL_VERT_NICE_SLIDER      = 4,
    FL_HOR_NICE_SLIDER       = FL_VERT_NICE_SLIDER     | FL_HOR_FLAG,

    FL_VERT_BROWSER_SLIDER   = 6,
    FL_HOR_BROWSER_SLIDER    = FL_VERT_BROWSER_SLIDER  | FL_HOR_FLAG,

	FL_VERT_PROGRESS_BAR     = 8,
	FL_HOR_PROGRESS_BAR      = FL_VERT_PROGRESS_BAR    | FL_HOR_FLAG,

    /* The following are for use with scrollbars only! */

    /* For FL_VERT_SCROLLBAR and FL_HOR_SCROLLBAR */

    FL_VERT_BROWSER_SLIDER2   = FL_VERT_SLIDER         | FL_SCROLL_FLAG,
    FL_HOR_BROWSER_SLIDER2    = FL_HOR_SLIDER          | FL_SCROLL_FLAG,

    /* for FL_VERT_THIN_SCROLLBAR and FL_VERT_THIN_SCROLLBAR */

    FL_VERT_THIN_SLIDER       = FL_VERT_FILL_SLIDER    | FL_SCROLL_FLAG,
    FL_HOR_THIN_SLIDER        = FL_HOR_FILL_SLIDER     | FL_SCROLL_FLAG,

    /* For FL_VERT_NICE_SCROLLBAR and FL_HOR_NICE_SCROLLBAR */

    FL_VERT_NICE_SLIDER2      = FL_VERT_NICE_SLIDER    | FL_SCROLL_FLAG,
    FL_HOR_NICE_SLIDER2       = FL_HOR_NICE_SLIDER     | FL_SCROLL_FLAG,

    /* for use as FL_VERT_PLAIN_SCROLLBAR and FL_VERT_PLAIN_SCROLLBAR */

    FL_VERT_BASIC_SLIDER      = FL_VERT_BROWSER_SLIDER | FL_SCROLL_FLAG,
    FL_HOR_BASIC_SLIDER       = FL_HOR_BROWSER_SLIDER  | FL_SCROLL_FLAG
} FL_SLIDER_TYPE;

/***** Defaults *****/

#define FL_SLIDER_BW1       FL_BOUND_WIDTH
#define FL_SLIDER_BW2       FL_abs( FL_BOUND_WIDTH )
#define FL_SLIDER_BOXTYPE   FL_DOWN_BOX
#define FL_SLIDER_COL1      FL_COL1
#define FL_SLIDER_COL2      FL_COL1
#define FL_SLIDER_LCOL      FL_LCOL
#define FL_SLIDER_ALIGN     FL_ALIGN_BOTTOM

/***** Others   *****/

#define FL_SLIDER_FINE      0.25
#define FL_SLIDER_WIDTH     0.10

#define FL_SLIDER_MAX_PREC  10

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_slider( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_slider( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_create_valslider( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_valslider( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT void fl_set_slider_value( FL_OBJECT * ob,
                                    double      val );

FL_EXPORT double fl_get_slider_value( FL_OBJECT * ob );

FL_EXPORT void fl_set_slider_bounds( FL_OBJECT * ob,
                                     double      min,
                                     double      max );

FL_EXPORT void fl_get_slider_bounds( FL_OBJECT * ob,
                                     double    * min,
                                     double    * max );

FL_EXPORT void fl_set_slider_return( FL_OBJECT    * ob,
                                     unsigned int   value );

FL_EXPORT void fl_set_slider_step( FL_OBJECT * ob,
                                   double      value );

FL_EXPORT void fl_set_slider_increment( FL_OBJECT * ob,
                                        double      l,
                                        double      r );

FL_EXPORT void fl_get_slider_increment( FL_OBJECT * ob,
                                        double    * l,
                                        double    * r );

FL_EXPORT void fl_set_slider_size( FL_OBJECT * ob,
                                   double      size );

FL_EXPORT double fl_get_slider_size( FL_OBJECT * obj );

FL_EXPORT void fl_set_slider_precision( FL_OBJECT * ob,
                                        int         prec );

FL_EXPORT void fl_set_slider_filter( FL_OBJECT     * ob,
                                     FL_VAL_FILTER   filter );

FL_EXPORT int fl_get_slider_repeat( FL_OBJECT * obj );

FL_EXPORT void fl_set_slider_repeat( FL_OBJECT * obj,
									 int         millisec );

FL_EXPORT void fl_set_slider_mouse_buttons( FL_OBJECT    * obj,
											unsigned int   mouse_buttons );
FL_EXPORT void fl_get_slider_mouse_buttons( FL_OBJECT    * obj,
											unsigned int * mouse_buttons );


#endif /* ! defined FL_SLIDER_H */
