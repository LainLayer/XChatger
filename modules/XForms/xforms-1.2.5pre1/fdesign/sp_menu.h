/*
 * This file is part of XForms.
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
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef SP_MENU_H_
#define SP_MENU_H_

void menu_change_type( FL_OBJECT * obj,
 						 int         new_type );
FL_FORM * menu_create_spec_form( void );
void menu_fill_in_spec_form( FL_OBJECT * obj );
void menu_emit_spec_fd_code( FILE      * fp,
 							FL_OBJECT * obj );
void menu_emit_spec_c_code( FILE      * fp,
 						   FL_OBJECT * obj );
void menu_emit_spec_header( FILE      * fp,
 						   FL_OBJECT * obj );
void menu_emit_spec_global_header( FILE      * fp,
 								  FL_OBJECT * obj );
void menu_emit_item_callback_headers( FILE      * fn,
                                      FL_OBJECT * obj,
                                      int         code );

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
