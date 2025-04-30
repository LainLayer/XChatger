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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/********************** crop here for forms.h **********************/

/* the following (fl_fheight) etc. were never documented and were
   removed from V0.89, but apparently this broke some applications that
   were using them. Put them back in 10/22/00 */

#define fl_textgc      fl_textgc_( )
#define fl_gc          fl_gc_( )
#define fl_cur_win     fl_cur_win_( )
#define fl_fheight     fl_fheight_( )
#define fl_fdesc       fl_fdesc_( )
#define fl_cur_fs      fl_cur_fs_( )

FL_EXPORT GC fl_gc_( void );
FL_EXPORT GC fl_textgc_( void );
FL_EXPORT int fl_fheight_( void );
FL_EXPORT int fl_fdesc_( void );
FL_EXPORT Window fl_cur_win_( void );
FL_EXPORT XFontStruct * fl_cur_fs_( void );
FL_EXPORT Display * fl_display_( void );

#if ! defined FL_TRUE && ! defined FL_FALSE
#define FL_FALSE        0
#define FL_TRUE         ( ! FL_FALSE )
#endif

#if defined __cplusplus
}
#endif

#endif /* FL_FORMS_H */
