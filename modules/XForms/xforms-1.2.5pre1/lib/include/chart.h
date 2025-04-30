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
 * \file chart.h
 *
 * Object Class: Chart
 *
 */

#ifndef FL_CHART_H
#define FL_CHART_H

typedef enum {
    FL_BAR_CHART,
    FL_HORBAR_CHART,
    FL_LINE_CHART,
    FL_FILL_CHART,
    FL_SPIKE_CHART,
    FL_PIE_CHART,
    FL_SPECIALPIE_CHART
} FL_CHART_TYPE;

#define FL_FILLED_CHART  FL_FILL_CHART  /* for backward compatibility */

/***** Defaults *****/

#define FL_CHART_BOXTYPE    FL_BORDER_BOX
#define FL_CHART_COL1       FL_COL1
#define FL_CHART_LCOL       FL_LCOL
#define FL_CHART_ALIGN      FL_ALIGN_BOTTOM

/***** Others   *****/

#define FL_CHART_MAX        2048

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_chart( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_chart( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

FL_EXPORT void fl_clear_chart( FL_OBJECT * ob );

FL_EXPORT void fl_add_chart_value( FL_OBJECT  * ob,
                                   double       val,
                                   const char * str,
                                   FL_COLOR     col );

FL_EXPORT void fl_insert_chart_value( FL_OBJECT  * ob,
                                      int          indx,
                                      double       val,
                                      const char * str,
                                      FL_COLOR     col );

FL_EXPORT void fl_replace_chart_value( FL_OBJECT  * ob,
                                       int          indx,
                                       double       val,
                                       const char * str,
                                       FL_COLOR     col );

FL_EXPORT void fl_set_chart_bounds( FL_OBJECT * ob,
                                    double      min,
                                    double      max );

FL_EXPORT void fl_get_chart_bounds( FL_OBJECT * ob,
                                    double    * min,
                                    double    * max );

FL_EXPORT void fl_set_chart_maxnumb( FL_OBJECT * ob,
									 int         maxnumb );

FL_EXPORT void fl_set_chart_autosize( FL_OBJECT * ob,
                                      int         autosize );

FL_EXPORT void fl_set_chart_lstyle( FL_OBJECT * ob,
                                    int         lstyle );

FL_EXPORT void fl_set_chart_lsize( FL_OBJECT * ob,
                                   int         lsize );

FL_EXPORT void fl_set_chart_lcolor( FL_OBJECT * ob,
                                    FL_COLOR    lcol );

FL_EXPORT void fl_set_chart_baseline( FL_OBJECT * ob,
                                      int         iYesNo );

#define fl_set_chart_lcol   fl_set_chart_lcolor

#endif /* ! defined FL_CHART_H */
