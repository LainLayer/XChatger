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
 * \file pvaluator.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1995-1997  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  private header for valuator object. Someday, all the
 *  valuator functions will be consolidated to take care
 *  most common tasks. Also the struct has redundant stuff in it.
 */

#ifndef PVALUATOR_H
#define PVALUATOR_H

/* The special information for valuators. the size of this structure
 * probably can be reduced quite a bit. */

typedef struct {
    double        min;          /* minimal value of slider */
    double        max;          /* maximal value of slider */
    double        val;          /* current value of slider */
    double        step;         /* step size             */
    int           draw_type;
    int           prec;         /* precision when printing value */
    double        start_val;
    double        ldelta;       /* "left mouse" step   */
    double        rdelta;       /* "right mouse " step   */
    double        sstep;        /* small step for counter */
    double        lstep;        /* large step for counter */
    FL_Coord      x,            /* draw (dbl buffer): adjustment report box */
                  y,
                  w,
                  h;
    double        slsize;       /* size of the slider             */
    FL_VAL_FILTER filter;
    FL_Coord      offx;
    FL_Coord      offy;
    FL_Coord      mx,           /* mouse: after adjustment for report box  */
                  my,
                  mw,
                  mh;
    FL_Coord      old_mx,
                  old_my;
    int           mouse,        /* part the mouse is on                    */
                  lmouse;
    FL_Coord      ww[ 5 ],      /* for counter                             */
                  xx[ 5 ];
    int           changed;
    unsigned int  mouseobj;
    int           cross_over;   /* allow cross over                        */
    int           repeat_ms;
    int           cur_repeat_ms;
    int           min_repeat_ms;
    int           do_speedjump;
    int           timeout_id;
    int           mouse_off_knob;
    int           was_shift;
    int           react_to[ 3 ];
} FLI_VALUATOR_SPEC;

enum
{
    COMPLETE_DRAW  = 1,
    VALUE_DRAW     = 2,
};

#endif /* PVALUTOR_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
