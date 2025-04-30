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


#if ! defined FD_ICONINFO_H
#define FD_ICONINFO_H


typedef struct {
    int  align;
    int  dx,
         dy;
    int  show_focus;
    char filename[ 2048 ];
    char focus_filename[ 2048 ];
    char data[ MAX_VAR_LEN ];
    char focus_data[ MAX_VAR_LEN ];
    char width[ MAX_VAR_LEN ];
    char height[ MAX_VAR_LEN ];
    int  use_data;
    int  fullpath;
} IconInfo;


IconInfo * get_iconinfo( FL_OBJECT * obj );
void copy_iconinfo( FL_OBJECT * target,
                    FL_OBJECT * src );
void free_iconinfo( FL_OBJECT * obj );
void get_xbm_stuff( IconInfo * info,
                    FILE     * fp );
void get_xpm_stuff( char * in,
                    FILE * fp );

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
