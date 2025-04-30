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
 * \file free.h
 *
 *  Object Class: Free
 */

#ifndef FL_FREE_H
#define FL_FREE_H


typedef enum {
    FL_NORMAL_FREE,
    FL_INACTIVE_FREE,
    FL_INPUT_FREE,
    FL_CONTINUOUS_FREE,
    FL_ALL_FREE
} FL_FREE_TYPE;

#define FL_SLEEPING_FREE  FL_INACTIVE_FREE

FL_EXPORT FL_OBJECT * fl_create_free( int            type,
                                      FL_Coord       x,
                                      FL_Coord       y,
                                      FL_Coord       w,
                                      FL_Coord       h,
                                      const char   * label,
                                      FL_HANDLEPTR   handle );

FL_EXPORT FL_OBJECT * fl_add_free( int            type,
                                   FL_Coord       x,
                                   FL_Coord       y,
                                   FL_Coord       w,
                                   FL_Coord       h,
                                   const char   * label,
                                   FL_HANDLEPTR   handle );

#endif /* ! defined FL_FREE_H */
