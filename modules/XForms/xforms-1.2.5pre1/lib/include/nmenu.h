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


#ifndef FL_NMENU_H
#define FL_NMENU_H


/* Nmenu object types */

enum {
    FL_NORMAL_NMENU,
    FL_NORMAL_TOUCH_NMENU,
    FL_BUTTON_NMENU,
    FL_BUTTON_TOUCH_NMENU
};

FL_EXPORT FL_OBJECT *fl_create_nmenu(
        int,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        const char *
        );

FL_EXPORT FL_OBJECT *fl_add_nmenu(
        int,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        const char *
        );

FL_EXPORT int fl_clear_nmenu(
        FL_OBJECT *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_add_nmenu_items(
        FL_OBJECT  *,
        const char *,
        ...
        );

FL_EXPORT FL_POPUP_ENTRY *fl_insert_nmenu_items(
        FL_OBJECT *,
        FL_POPUP_ENTRY *,
        const char     *,
        ...
        );

FL_EXPORT FL_POPUP_ENTRY *fl_replace_nmenu_item(
        FL_OBJECT *,
        FL_POPUP_ENTRY *,
        const char *,
        ...
        );

FL_EXPORT int fl_delete_nmenu_item(
        FL_OBJECT *,
        FL_POPUP_ENTRY *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_set_nmenu_items(
        FL_OBJECT *,
        FL_POPUP_ITEM *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_add_nmenu_items2(
		FL_OBJECT *,
		FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP_ENTRY *fl_insert_nmenu_items2(
		FL_OBJECT *,
		FL_POPUP_ENTRY *,
		FL_POPUP_ITEM  * );

FL_EXPORT FL_POPUP_ENTRY *fl_replace_nmenu_items2(
		FL_OBJECT *,
		FL_POPUP_ENTRY *,
		FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP *fl_get_nmenu_popup(
        FL_OBJECT *
        );

FL_EXPORT int fl_set_nmenu_popup(
        FL_OBJECT *,
        FL_POPUP  *
        );

FL_EXPORT FL_POPUP_RETURN *fl_get_nmenu_item(
        FL_OBJECT *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_get_nmenu_item_by_value(
        FL_OBJECT *,
        long int
        );

FL_EXPORT FL_POPUP_ENTRY *fl_get_nmenu_item_by_label(
        FL_OBJECT *,
        const char *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_get_nmenu_item_by_text(
        FL_OBJECT *,
        const char *
        );

FL_EXPORT int fl_set_nmenu_policy(
        FL_OBJECT *,
        int
        );

FL_EXPORT FL_COLOR fl_set_nmenu_hl_text_color(
        FL_OBJECT *,
        FL_COLOR
        );

#endif /* ! defined FL_NMENU_H */
