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
 * \file menubar.h
 */

/*-------------------------------------------------------*/
/* ---- THIS FILE SEEMS NOT TO BE NEEDED AT ALL JTT ---- */
/*-------------------------------------------------------*/

#ifndef FL_MENUBAR_H
#define FL_MENUBAR_H

/************   Object Class: MenuBar         ************/

enum {
    FL_NORMAL_MENUBAR
};

/***** Defaults *****/

#define FL_MENUBAR_BOXTYPE  FL_UP_BOX
#define FL_MENUBAR_COL1     FL_COL1
#define FL_MENUBAR_COL2     FL_MCOL
#define FL_MENUBAR_LCOL     FL_LCOL

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_menubar( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_menubar( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT void fl_clear_menubar( FL_OBJECT * ob );

FL_EXPORT void fl_set_menubar( FL_OBJECT  * ob,
                               const char * label );

FL_EXPORT void fl_set_menubar_entries( FL_OBJECT    * ob,
                                       const char   * label,
                                       FL_PUP_ENTRY * pup );

#endif /* ! defined FL_MENUBAR_H */
