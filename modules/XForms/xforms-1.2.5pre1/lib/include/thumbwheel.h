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
 * \file thumbwheel.h
 */

#ifndef FL_THUMBWHEEL_H
#define FL_THUMBWHEEL_H


enum {
    FL_VERT_THUMBWHEEL,
    FL_HOR_THUMBWHEEL
};

/* defaults */

#define FL_THUMBWHEEL_COL1      FL_COL1
#define FL_THUMBWHEEL_COL2      FL_COL1
#define FL_THUMBWHEEL_LCOL      FL_BLACK
#define FL_THUMBWHEEL_BOXTYPE   FL_BORDER_BOX
#define FL_THUMBWHEEL_ALIGN     FL_ALIGN_BOTTOM

FL_EXPORT double fl_get_thumbwheel_value( FL_OBJECT * ob );

FL_EXPORT double fl_set_thumbwheel_value( FL_OBJECT * ob,
                                          double      value );

FL_EXPORT double fl_get_thumbwheel_step( FL_OBJECT * ob );

FL_EXPORT double fl_set_thumbwheel_step( FL_OBJECT * ob,
                                         double      step );

FL_EXPORT int fl_set_thumbwheel_return( FL_OBJECT    * ob,
                                        unsigned int   when );

FL_EXPORT int fl_set_thumbwheel_crossover( FL_OBJECT * ob,
                                           int         flag );

FL_EXPORT void fl_set_thumbwheel_bounds( FL_OBJECT * ob,
                                         double      min,
                                         double      max );

FL_EXPORT void fl_get_thumbwheel_bounds( FL_OBJECT * ob,
                                         double    * min,
                                         double    * max );

FL_EXPORT FL_OBJECT * fl_create_thumbwheel( int          type,
                                            FL_Coord     x,
                                            FL_Coord     y,
                                            FL_Coord     w,
                                            FL_Coord     h,
                                            const char * label );

FL_EXPORT FL_OBJECT * fl_add_thumbwheel( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

#endif /* ! defined FL_THUMBWHEEL_H */
