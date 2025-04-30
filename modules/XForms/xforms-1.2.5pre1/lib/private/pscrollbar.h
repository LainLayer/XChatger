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
 * \file pscrollbar.h
 */

#ifndef PSCROLLBAR_H_
#define PSCROLLBAR_H_

#include "pslider.h"

typedef struct {
    FL_OBJECT * slider;
    FL_OBJECT * up;
    FL_OBJECT * down;
    double      increment;
    double      old_val;
} FLI_SCROLLBAR_SPEC;


#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
