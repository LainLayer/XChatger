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
 * \file choice.h
 *
 */

#ifndef FL_CHOICE_H
#define FL_CHOICE_H


typedef enum {
    FL_NORMAL_CHOICE,
    FL_NORMAL_CHOICE2,
    FL_DROPLIST_CHOICE,
    FL_BROWSER_CHOICE
} FL_CHOICE_TYPE;

#define  FL_SIMPLE_CHOICE  FL_NORMAL_CHOICE

/***** Defaults *****/

#define FL_CHOICE_BOXTYPE   FL_ROUNDED_BOX
#define FL_CHOICE_COL1      FL_COL1
#define FL_CHOICE_COL2      FL_LCOL
#define FL_CHOICE_LCOL      FL_LCOL
#define FL_CHOICE_ALIGN     FL_ALIGN_LEFT

/***** Others   *****/

#define FL_CHOICE_MCOL      FL_MCOL
#define FL_CHOICE_MAXITEMS  128

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_choice( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_choice( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_clear_choice( FL_OBJECT * ob );

FL_EXPORT int fl_addto_choice( FL_OBJECT  * ob,
                               const char * str );

FL_EXPORT int fl_addto_choice_f( FL_OBJECT *  ob,
								 const char * fmt,
								 ... );

FL_EXPORT void fl_replace_choice( FL_OBJECT  * ob,
                                  int          numb,
                                  const char * str );

FL_EXPORT void fl_replace_choice_f( FL_OBJECT *  ob,
									int          numb,
									const char * fmt,
									... );

FL_EXPORT void fl_delete_choice( FL_OBJECT * ob,
                                 int         numb );

FL_EXPORT void fl_set_choice( FL_OBJECT * ob,
                              int         choice );

FL_EXPORT void fl_set_choice_text( FL_OBJECT  * ob,
                                   const char * txt );

FL_EXPORT void fl_set_choice_text_f( FL_OBJECT *  ob,
									 const char * fmt,
									 ... );

FL_EXPORT int fl_get_choice( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_choice_item_text( FL_OBJECT * ob,
                                                int         n );

FL_EXPORT int fl_get_choice_maxitems( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_choice_text( FL_OBJECT * ob );

FL_EXPORT void fl_set_choice_fontsize( FL_OBJECT * ob,
                                       int         size );

FL_EXPORT void fl_set_choice_fontstyle( FL_OBJECT * ob,
                                        int         style );

FL_EXPORT void fl_set_choice_align( FL_OBJECT * ob,
                                    int         align );

FL_EXPORT int fl_get_choice_item_mode( FL_OBJECT *  ob,
                                       int          item );

FL_EXPORT void fl_set_choice_item_mode( FL_OBJECT    * ob,
                                        int            item,
                                        unsigned int   mode );

FL_EXPORT void fl_set_choice_item_shortcut( FL_OBJECT  * ob,
                                            int          item,
                                            const char * sc );

FL_EXPORT int fl_set_choice_entries( FL_OBJECT    * ob,
                                     FL_PUP_ENTRY * ent );

FL_EXPORT int fl_set_choice_notitle( FL_OBJECT * ob,
                                     int         n );

FL_EXPORT int fl_set_choice_align_bottom( FL_OBJECT * ob,
										  int         n );

#endif /* ! defined FL_CHOICE_H */
