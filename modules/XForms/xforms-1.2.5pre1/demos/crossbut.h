/*
 *
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with XForms; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 */


/*
 * Class Crossbutton header file
 */
#ifndef CROSSBUT_H
#define CROSSBUT_H

#define FL_CROSSBUTTON    (FL_USER_CLASS_START + 1)

#define FL_CROSSBUTTON_BW  2

extern FL_OBJECT *fl_add_crossbutton(int, FL_Coord, FL_Coord,
                    FL_Coord, FL_Coord, const char *);

extern FL_OBJECT *fl_create_crossbutton(int, FL_Coord, FL_Coord,
                   FL_Coord, FL_Coord, const char *);

#endif
