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
 * \file tabfolder.h
 */

#ifndef FL_FOLDER_H
#define FL_FOLDER_H

enum {
    FL_TOP_TABFOLDER,       /* tab on top */
    FL_BOTTOM_TABFOLDER,
    FL_LEFT_TABFOLDER,
    FL_RIGHT_TABFOLDER,
    FL_NORMAL_TABFOLDER = FL_TOP_TABFOLDER
};

enum {
    FL_NO,
    FL_FIT,
    FL_ENLARGE_ONLY
};

FL_EXPORT FL_OBJECT * fl_create_tabfolder( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_tabfolder( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_addto_tabfolder( FL_OBJECT  * ob,
                                          const char * title,
                                          FL_FORM    * form );

FL_EXPORT FL_FORM * fl_get_tabfolder_folder_bynumber( FL_OBJECT * ob,
                                                      int         num );

FL_EXPORT FL_FORM * fl_get_tabfolder_folder_byname( FL_OBJECT  * ob,
                                                    const char * name );

FL_EXPORT FL_FORM * fl_get_tabfolder_folder_byname_f( FL_OBJECT  * ob,
													  const char * fmt,
													  ...);

FL_EXPORT void fl_delete_folder( FL_OBJECT * ob,
                                 FL_FORM   * form );

FL_EXPORT void fl_delete_folder_bynumber( FL_OBJECT * ob,
                                          int         num );

FL_EXPORT void fl_delete_folder_byname( FL_OBJECT  * ob,
                                        const char * name );

FL_EXPORT void fl_delete_folder_byname_f( FL_OBJECT  * ob,
										  const char * fmt,
										  ... );

FL_EXPORT void fl_set_folder( FL_OBJECT * ob,
                              FL_FORM   * form );

FL_EXPORT void fl_set_folder_byname( FL_OBJECT  * ob,
                                     const char * name );

FL_EXPORT void fl_set_folder_byname_f( FL_OBJECT  * ob,
									   const char * fmt,
									   ... );

FL_EXPORT void fl_set_folder_bynumber( FL_OBJECT * ob,
                                       int         num );

FL_EXPORT FL_FORM * fl_get_folder( FL_OBJECT * ob );

FL_EXPORT int fl_get_folder_number( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_folder_name( FL_OBJECT * ob );

FL_EXPORT int fl_get_tabfolder_numfolders( FL_OBJECT * ob );

FL_EXPORT FL_FORM * fl_get_active_folder( FL_OBJECT * ob );

FL_EXPORT int fl_get_active_folder_number( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_active_folder_name( FL_OBJECT * ob );


FL_EXPORT void fl_get_folder_area( FL_OBJECT * ob,
                                   FL_Coord  * x,
                                   FL_Coord  * y,
                                   FL_Coord  * w,
                                   FL_Coord  * h );

FL_EXPORT void fl_replace_folder_bynumber( FL_OBJECT * ob,
                                           int         num,
                                           FL_FORM   * form );

FL_EXPORT int fl_set_tabfolder_autofit( FL_OBJECT * ob,
                                        int         y );

FL_EXPORT int fl_set_default_tabfolder_corner( int n );

FL_EXPORT int fl_set_tabfolder_offset( FL_OBJECT * obj,
                                       int         offset );

FL_EXPORT int fl_get_tabfolder_offset( FL_OBJECT * obj );

#endif /* ! defined FL_FOLDER_H */
