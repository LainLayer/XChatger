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
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef FD_SPEC_H_
#define FD_SPEC_H_


void spec_change_type( FL_OBJECT * obj,
                       int         new_type );
FL_FORM * create_spec_form( FL_OBJECT * obj );
void prepare_spec_form( FL_OBJECT * obj );
void reread_spec_form( FL_OBJECT * obj );
void restore_spec( FL_OBJECT * obj );

void set_finput_value( FL_OBJECT *,
                       double,
                       int );
int get_checked_float( const char * str,
                       double     * r );
int get_checked_int( const char *,
                     int * );
double get_finput_value( FL_OBJECT * );

const char * get_scrollbar_pref_name( int );
int get_scrollbar_pref_value( const char * );
const char * get_scrollbar_pref_string( void );

const char * get_scale_name( int );
int get_scale_value( const char * );
const char * get_scale_string( void );

const char * get_grid_name( int );
int get_grid_value( const char * );
const char * get_grid_string( void );

const char * get_linestyle_name( int );
int get_linestyle_value( const char * );
const char * get_linestyle_string( void );

const char * get_pupmode_name( int );
int get_pupmode_value( const char * );
const char * get_pupmode_string( void );

int get_direction_value( const char * );

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
