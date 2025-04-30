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
 * \file ppositioner.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1995-1997  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * private header for positioner object
 */

#ifndef PPOSITION_H
#define PPOSITION_H

typedef struct {
    double xmin,                 /* minimal values  */
           ymin;
    double xmax,                 /* maximal values  */
           ymax;
    double xval,                 /* current values  */
           yval;
    double lxval,                /* previous values */
           lyval;
    double xstep,                /* step size to which values are rounded  */
           ystep;
    int    partial;
    double old_x,                /* values at start of ineraction */
           old_y;
    int    react_to[ 5 ];
    int    mousebut;
    Pixmap xpm,
           ypm;
    GC     copy_gc;
    FL_POSITIONER_VALIDATOR validator;
                                 /* funcion for validating a new position */
} FLI_POSITIONER_SPEC;


#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
