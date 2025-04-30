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
 * \file pdial.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1995-1997  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Private header for dial object
 */

#ifndef PDIAL_H
#define PDIAL_H

typedef struct {
    double a,               /* for speed                      */
           b;
    double min,             /* min/max value of dial          */
           max;
    double val;             /* current value of dial          */
    double step;            /* step size                      */
    double thetai;          /* start angle (degrees)          */
    double thetaf;          /* end angle   (degrees)          */
    double origin;          /* where the origin is            */
    short  cross_over;
    double  start_val;
    short  direction;       /* not currently used            */
} FLI_DIAL_SPEC;


#endif /* pdial_h */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
