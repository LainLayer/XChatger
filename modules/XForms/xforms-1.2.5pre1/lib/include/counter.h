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

/********************** crop here for forms.h **********************/

/**
 * \file counter.h
 */

#ifndef FL_COUNTER_H
#define FL_COUNTER_H

typedef enum {
    FL_NORMAL_COUNTER,
    FL_SIMPLE_COUNTER
} FL_COUNTER_TYPE;

/***** Defaults *****/

#define FL_COUNTER_BOXTYPE  FL_UP_BOX
#define FL_COUNTER_COL1     FL_COL1
#define FL_COUNTER_COL2     FL_BLUE           /* ct label     */
#define FL_COUNTER_LCOL     FL_LCOL           /* ct reporting */
#define FL_COUNTER_ALIGN    FL_ALIGN_BOTTOM

/***** Others *****/

#define FL_COUNTER_BW       FL_BOUND_WIDTH

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_counter( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_counter( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT void fl_set_counter_value( FL_OBJECT * ob,
                                     double      val );

FL_EXPORT void fl_set_counter_bounds( FL_OBJECT * ob,
                                      double      min,
                                      double      max );

FL_EXPORT void fl_set_counter_step( FL_OBJECT * ob,
                                    double      s,
                                    double      l );

FL_EXPORT void fl_set_counter_precision( FL_OBJECT * ob,
                                         int         prec );

FL_EXPORT int fl_get_counter_precision( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_return( FL_OBJECT    * ob,
                                      unsigned int   how );

FL_EXPORT double fl_get_counter_value( FL_OBJECT * ob );

FL_EXPORT void fl_get_counter_bounds( FL_OBJECT * ob,
                                      double    * min,
                                      double    * max );

FL_EXPORT void fl_get_counter_step( FL_OBJECT * ob,
                                    double    * s,
                                    double    * l );

FL_EXPORT void fl_set_counter_filter( FL_OBJECT     * ob,
                                      FL_VAL_FILTER   filter );

/* Functions to set and get the timeout value used by the
 * counter code to control modification of the counter value. */

FL_EXPORT int fl_get_counter_repeat( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_repeat( FL_OBJECT * ob,
                                      int         millisec );

FL_EXPORT int fl_get_counter_min_repeat( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_min_repeat( FL_OBJECT * ob,
                                          int         millisec );

FL_EXPORT int fl_get_counter_speedjump( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_speedjump( FL_OBJECT * ob,
                                         int         yes_no );

#endif /* ! defined FL_COUNTER_H */
