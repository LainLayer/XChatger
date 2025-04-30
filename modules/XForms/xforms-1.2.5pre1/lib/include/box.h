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
 * \file box.h
 *
 */

#ifndef FL_BOX_H
#define FL_BOX_H

/* Type is already defined in Basic.h */

FL_EXPORT FL_OBJECT * fl_create_box( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_add_box( int          type,
                                  FL_Coord     x,
                                  FL_Coord     y,
                                  FL_Coord     w,
                                  FL_Coord     h,
                                  const char * label );

#endif /* ! defined FL_BOX_H */
