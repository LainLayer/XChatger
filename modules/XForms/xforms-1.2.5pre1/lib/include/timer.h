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
 * \file timer.h
 *
 *  Object Class: Timer
 */

#ifndef FL_TIMER_H
#define FL_TIMER_H


typedef enum {
    FL_NORMAL_TIMER,
    FL_VALUE_TIMER,
    FL_HIDDEN_TIMER
} FL_TIMER_TYPE;

/***** Defaults *****/

#define FL_TIMER_BOXTYPE    FL_DOWN_BOX
#define FL_TIMER_COL1       FL_COL1
#define FL_TIMER_COL2       FL_RED
#define FL_TIMER_LCOL       FL_LCOL
#define FL_TIMER_ALIGN      FL_ALIGN_CENTER

/***** Others   *****/

#define FL_TIMER_BLINKRATE  0.2

/***** Routines *****/

typedef char * ( * FL_TIMER_FILTER )( FL_OBJECT *, double );

FL_EXPORT FL_OBJECT * fl_create_timer( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_timer( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

FL_EXPORT void fl_set_timer( FL_OBJECT * ob,
                             double      total );

FL_EXPORT double fl_get_timer( FL_OBJECT * ob );

FL_EXPORT void fl_set_timer_countup( FL_OBJECT * ob,
                                     int         yes );

FL_EXPORT FL_TIMER_FILTER fl_set_timer_filter( FL_OBJECT       * ob,
                                               FL_TIMER_FILTER   filter );

FL_EXPORT void fl_suspend_timer( FL_OBJECT * ob );

FL_EXPORT void fl_resume_timer( FL_OBJECT * ob );

#endif /* ! defined FL_TIMER_H */
