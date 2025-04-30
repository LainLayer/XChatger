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
 * \file menu.h
 */

#ifndef FL_MENU_H
#define FL_MENU_H


/************   Object Class: Menu         ************/

typedef enum {
    FL_TOUCH_MENU,
    FL_PUSH_MENU,
    FL_PULLDOWN_MENU
} FL_MENU_TYPE;

/***** Defaults *****/

#define FL_MENU_BOXTYPE     FL_BORDER_BOX
#define FL_MENU_COL1        FL_COL1
#define FL_MENU_COL2        FL_MCOL
#define FL_MENU_LCOL        FL_LCOL
#define FL_MENU_ALIGN       FL_ALIGN_CENTER

/***** Others   *****/

#define FL_MENU_MAXITEMS    128
#define FL_MENU_MAXSTR      64        /* not used anymore! JTT */

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_menu( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT FL_OBJECT * fl_add_menu( int          type,
                                   FL_Coord     x,
                                   FL_Coord     y,
                                   FL_Coord     w,
                                   FL_Coord     h,
                                   const char * label );

FL_EXPORT void fl_clear_menu( FL_OBJECT * ob );

FL_EXPORT void fl_set_menu( FL_OBJECT  * ob,
                            const char * menustr ,
                            ... );

FL_EXPORT int fl_addto_menu( FL_OBJECT  * ob,
                             const char * menustr,
                             ... );

FL_EXPORT void fl_replace_menu_item( FL_OBJECT  * ob,
                                     int          numb,
                                     const char * str,
                                     ... );

FL_EXPORT void fl_delete_menu_item( FL_OBJECT * ob,
                                    int         numb );

FL_EXPORT FL_PUP_CB fl_set_menu_item_callback( FL_OBJECT *  ob,
                                               int          numb,
                                               FL_PUP_CB    cb );

FL_EXPORT void fl_set_menu_item_shortcut( FL_OBJECT  * ob,
                                          int          numb,
                                          const char * str );

FL_EXPORT void fl_set_menu_item_mode( FL_OBJECT    * ob,
                                      int            numb,
                                      unsigned int   mode );

FL_EXPORT void fl_show_menu_symbol( FL_OBJECT * ob,
                                    int         show );

FL_EXPORT void fl_set_menu_popup( FL_OBJECT * ob,
                                  int         pup );

FL_EXPORT int fl_get_menu_popup( FL_OBJECT * ob );

FL_EXPORT int fl_get_menu( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_menu_item_text( FL_OBJECT * ob,
                                              int         numb );

FL_EXPORT int fl_get_menu_maxitems( FL_OBJECT * ob );

FL_EXPORT unsigned int fl_get_menu_item_mode( FL_OBJECT * ob,
                                              int         numb );

FL_EXPORT const char *fl_get_menu_text( FL_OBJECT * ob );

FL_EXPORT int fl_set_menu_entries( FL_OBJECT    * ob,
                                   FL_PUP_ENTRY * ent );

FL_EXPORT int fl_set_menu_notitle( FL_OBJECT * ob,
                                   int         off );

FL_EXPORT int fl_set_menu_item_id( FL_OBJECT * ob,
                                   int         item,
                                   int         id );

#endif /* ! defined FL_MENU_H */
