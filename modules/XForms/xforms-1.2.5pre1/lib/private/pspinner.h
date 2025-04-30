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


#ifndef PSPINNER_H
#define PSPINNER_H

typedef struct {
    FL_OBJECT * input;
    FL_OBJECT * up;
    FL_OBJECT * down;

    int         i_val;
    int         i_min;
    int         i_max;
    int         i_incr;

    double      f_val;
    double      f_min;
    double      f_max;
    double      f_incr;

    int         orient;
    int         prec;

    int         attrib;

    int         old_ival;
    double      old_fval;
} FLI_SPINNER_SPEC;


#define DEFAULT_SPINNER_PRECISION  6


#endif /* PSPINNER_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
