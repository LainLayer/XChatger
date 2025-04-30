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

/*
 * \file browser.h
 *
 *  Object class Browser
 */

#ifndef FL_BROWSER_H
#define FL_BROWSER_H


/***** Types    *****/

typedef enum {
    FL_NORMAL_BROWSER,
    FL_SELECT_BROWSER,
    FL_HOLD_BROWSER,
    FL_MULTI_BROWSER,
	FL_DESELECTABLE_HOLD_BROWSER
} FL_BROWSER_TYPE;

/***** Defaults *****/

#define FL_BROWSER_BOXTYPE  FL_DOWN_BOX
#define FL_BROWSER_COL1     FL_COL1
#define FL_BROWSER_COL2     FL_YELLOW
#define FL_BROWSER_LCOL     FL_LCOL
#define FL_BROWSER_ALIGN    FL_ALIGN_BOTTOM


/***** Others   *****/

#define FL_BROWSER_SLCOL        FL_COL1
#define FL_BROWSER_FONTSIZE     FL_SMALL_SIZE


/* This exists only for backward compatibility and isn't used anymore! */

#define FL_BROWSER_LINELENGTH   2048


/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_browser( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_browser( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT void fl_clear_browser( FL_OBJECT * ob );

FL_EXPORT void fl_add_browser_line( FL_OBJECT  * ob,
                                    const char * newtext );

FL_EXPORT void fl_add_browser_line_f( FL_OBJECT  * ob,
									  const char * fmt,
									  ... );


FL_EXPORT void fl_addto_browser( FL_OBJECT  * obj,
                                 const char * text );

FL_EXPORT void fl_addto_browser_f( FL_OBJECT  * obj,
								   const char * fmt,
								   ...);

#define fl_append_browser  fl_addto_browser_chars
FL_EXPORT void fl_addto_browser_chars( FL_OBJECT  * ob,
                                       const char * str );

FL_EXPORT void fl_addto_browser_chars_f( FL_OBJECT  * ob,
										 const char * fmt,
										 ... );

#define fl_append_browser_f  fl_addto_browser_chars_f
FL_EXPORT void fl_insert_browser_line( FL_OBJECT  * ob,
                                       int          linenumb,
                                       const char * newtext );

FL_EXPORT void fl_insert_browser_line_f( FL_OBJECT  * ob,
										 int          linenumb,
										 const char * fmt,
										 ... );

FL_EXPORT void fl_delete_browser_line( FL_OBJECT * ob,
                                       int         linenumb );

FL_EXPORT void fl_replace_browser_line( FL_OBJECT  * ob,
                                        int          linenumb,
                                        const char * newtext );

FL_EXPORT void fl_replace_browser_line_f( FL_OBJECT  * ob,
										  int          linenumb,
										  const char * fmt,
										  ... );

FL_EXPORT const char *fl_get_browser_line( FL_OBJECT * ob,
                                           int         linenumb );

FL_EXPORT int fl_load_browser( FL_OBJECT  * ob,
                               const char * filename );

FL_EXPORT void fl_select_browser_line( FL_OBJECT * ob, 
                                       int         line );

FL_EXPORT void fl_deselect_browser_line( FL_OBJECT * ob,
                                         int         line );

FL_EXPORT void fl_deselect_browser( FL_OBJECT * ob );

FL_EXPORT int fl_isselected_browser_line( FL_OBJECT * ob,
                                          int         line );

FL_EXPORT int fl_get_browser_topline( FL_OBJECT * ob );

FL_EXPORT int fl_get_browser( FL_OBJECT * ob );

FL_EXPORT int fl_get_browser_maxline( FL_OBJECT * ob );

FL_EXPORT int fl_get_browser_screenlines( FL_OBJECT * ob );

FL_EXPORT void fl_set_browser_topline( FL_OBJECT * ob,
                                       int         line );

FL_EXPORT void fl_set_browser_bottomline( FL_OBJECT * ob,
										  int         line );

FL_EXPORT void fl_set_browser_fontsize( FL_OBJECT * ob,
                                        int         size );

FL_EXPORT void fl_set_browser_fontstyle( FL_OBJECT * ob,
                                         int         style );

FL_EXPORT void fl_set_browser_specialkey( FL_OBJECT * ob,
                                          int         specialkey );

FL_EXPORT void fl_set_browser_vscrollbar( FL_OBJECT * ob,
                                          int         on );

FL_EXPORT void fl_set_browser_hscrollbar( FL_OBJECT * ob,
                                          int         on );

FL_EXPORT void fl_set_browser_line_selectable( FL_OBJECT * ob,
                                               int         line,
                                               int         flag );

FL_EXPORT void fl_get_browser_dimension( FL_OBJECT * ob,
                                         FL_Coord  * x,
                                         FL_Coord  * y,
                                         FL_Coord  * w,
                                         FL_Coord  * h );

FL_EXPORT void fl_set_browser_dblclick_callback( FL_OBJECT      * ob,
                                                 FL_CALLBACKPTR   cb,
                                                 long             a );

FL_EXPORT FL_Coord fl_get_browser_xoffset( FL_OBJECT * ob );

FL_EXPORT double fl_get_browser_rel_xoffset( FL_OBJECT * ob );

FL_EXPORT void fl_set_browser_xoffset( FL_OBJECT * ob,
                                       FL_Coord    npixels );

FL_EXPORT void fl_set_browser_rel_xoffset( FL_OBJECT * ob,
                                           double      val );

FL_EXPORT FL_Coord fl_get_browser_yoffset( FL_OBJECT * ob );

FL_EXPORT double fl_get_browser_rel_yoffset( FL_OBJECT * ob );

FL_EXPORT void fl_set_browser_yoffset( FL_OBJECT * ob,
                                       FL_Coord    npixels );

FL_EXPORT void fl_set_browser_rel_yoffset( FL_OBJECT * ob,
                                           double      val );

FL_EXPORT void fl_set_browser_scrollbarsize( FL_OBJECT * ob,
                                             int         hh,
                                             int         vw );

FL_EXPORT void fl_show_browser_line( FL_OBJECT * ob,
                                     int         j );

FL_EXPORT int fl_set_default_browser_maxlinelength( int n );

#ifndef FL_BROWSER_SCROLL_CALLBACKt
#define FL_BROWSER_SCROLL_CALLBACKt
typedef void ( * FL_BROWSER_SCROLL_CALLBACK )( FL_OBJECT *,
                                               int,
                                               void * );
#endif

FL_EXPORT void
    fl_set_browser_hscroll_callback( FL_OBJECT *,
                                     FL_BROWSER_SCROLL_CALLBACK,
                                     void * );

FL_EXPORT void
    fl_set_browser_vscroll_callback( FL_OBJECT *,
                                     FL_BROWSER_SCROLL_CALLBACK,
                                     void * );

FL_EXPORT int fl_get_browser_line_yoffset( FL_OBJECT *,
										   int  );

FL_EXPORT FL_BROWSER_SCROLL_CALLBACK
    fl_get_browser_hscroll_callback( FL_OBJECT * );

FL_EXPORT FL_BROWSER_SCROLL_CALLBACK
    fl_get_browser_vscroll_callback( FL_OBJECT * );

FL_EXPORT int fl_get_browser_scrollbar_repeat( FL_OBJECT * );

FL_EXPORT void fl_set_browser_scrollbar_repeat( FL_OBJECT *,
												int  );

#endif /* ! defined FL_BROWSER_H */
