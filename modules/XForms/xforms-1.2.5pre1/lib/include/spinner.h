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

#ifndef FL_SPINNER_H
#define FL_SPINNER_H

typedef enum {
    FL_INT_SPINNER,
    FL_FLOAT_SPINNER
} FL_SPINNER_TYPE;

FL_EXPORT FL_OBJECT * fl_create_spinner( int            type,
                                         FL_Coord       x,
                                         FL_Coord       y,
                                         FL_Coord       w,
                                         FL_Coord       h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_spinner( int            type,
                                      FL_Coord   x,
                                      FL_Coord   y,
                                      FL_Coord   w,
                                      FL_Coord   h,
                                      const char * label );

FL_EXPORT double fl_get_spinner_value( FL_OBJECT * obj );

FL_EXPORT double fl_set_spinner_value( FL_OBJECT * obj,
                                       double      val );

FL_EXPORT void fl_set_spinner_bounds( FL_OBJECT * obj,
                                      double      min,
                                      double      max );

FL_EXPORT void fl_get_spinner_bounds( FL_OBJECT * obj,
                                      double    * min,
                                      double    * max );

FL_EXPORT void fl_set_spinner_step( FL_OBJECT * obj,
                                    double      step );

FL_EXPORT double fl_get_spinner_step( FL_OBJECT * obj );

FL_EXPORT void fl_set_spinner_precision( FL_OBJECT * obj,
                                         int         prec );

FL_EXPORT int fl_get_spinner_precision( FL_OBJECT * obj );

FL_EXPORT FL_OBJECT * fl_get_spinner_input( FL_OBJECT * obj );

FL_EXPORT FL_OBJECT * fl_get_spinner_up_button( FL_OBJECT * obj );

FL_EXPORT FL_OBJECT * fl_get_spinner_down_button( FL_OBJECT * obj );


#endif /* ! defined FL_SPINNER_H */
