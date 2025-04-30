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
 * \file button.h
 *
 * All Buttons: regular button, light button and round button
 *
 */

#ifndef FL_BUTTON_H
#define FL_BUTTON_H


typedef enum {
    FL_NORMAL_BUTTON,
    FL_PUSH_BUTTON,
    FL_RADIO_BUTTON,
    FL_HIDDEN_BUTTON,
    FL_TOUCH_BUTTON,
    FL_INOUT_BUTTON,
    FL_RETURN_BUTTON,
    FL_HIDDEN_RET_BUTTON,
    FL_MENU_BUTTON
} FL_BUTTON_TYPE;

#define FL_TOGGLE_BUTTON    FL_PUSH_BUTTON

typedef struct {
    Pixmap         pixmap,
                   mask;
    unsigned int   bits_w,
                   bits_h;
    int            val;             /* state of button (on/off) */
    int            mousebut;        /* mouse button that caused the push     */
    int            timdel;          /* time since last touch (TOUCH buttons) */
    int            event;           /* what event triggers redraw            */
    int            is_pushed;       /* set while drawn as pushed down        */
    int            react_to[ 5 ];   /* mouse buttons button reacts to        */
    long           cspecl;          /* reserved for class specfic stuff      */
    void         * cspecv;          /* misc. things                          */
    char         * filename;
    Pixmap         focus_pixmap,
                   focus_mask;
    char         * focus_filename;
} FL_BUTTON_SPEC;

#define FL_BUTTON_STRUCT FL_BUTTON_SPEC

typedef void ( * FL_DrawButton )( FL_OBJECT * );
typedef void ( * FL_CleanupButton )( FL_BUTTON_STRUCT * );

#define FL_DRAWBUTTON      FL_DrawButton
#define FL_CLEANUPBUTTON   FL_CleanupButton

/* normal button default */

#define FL_BUTTON_BOXTYPE           FL_UP_BOX
#define FL_BUTTON_COL1              FL_COL1
#define FL_BUTTON_COL2              FL_COL1
#define FL_BUTTON_LCOL              FL_LCOL
#define FL_BUTTON_ALIGN             FL_ALIGN_CENTER
#define FL_BUTTON_MCOL1             FL_MCOL
#define FL_BUTTON_MCOL2             FL_MCOL
#define FL_BUTTON_BW                FL_BOUND_WIDTH

/* light button defaults */

#define FL_LIGHTBUTTON_BOXTYPE      FL_UP_BOX
#define FL_LIGHTBUTTON_COL1         FL_COL1
#define FL_LIGHTBUTTON_COL2         FL_YELLOW
#define FL_LIGHTBUTTON_LCOL         FL_LCOL
#define FL_LIGHTBUTTON_ALIGN        ( FL_ALIGN_CENTER | FL_ALIGN_INSIDE )
#define FL_LIGHTBUTTON_TOPCOL       FL_COL1
#define FL_LIGHTBUTTON_MCOL         FL_MCOL
#define FL_LIGHTBUTTON_MINSIZE      ( ( FL_Coord ) 12 )

/* round button defaults */

#define FL_ROUNDBUTTON_BOXTYPE      FL_NO_BOX
#define FL_ROUNDBUTTON_COL1         FL_MCOL
#define FL_ROUNDBUTTON_COL2         FL_YELLOW
#define FL_ROUNDBUTTON_LCOL         FL_LCOL
#define FL_ROUNDBUTTON_ALIGN        FL_ALIGN_CENTER
#define FL_ROUNDBUTTON_TOPCOL       FL_COL1
#define FL_ROUNDBUTTON_MCOL         FL_MCOL

/* round3d button defaults */

#define FL_ROUND3DBUTTON_BOXTYPE    FL_NO_BOX
#define FL_ROUND3DBUTTON_COL1       FL_COL1
#define FL_ROUND3DBUTTON_COL2       FL_BLACK
#define FL_ROUND3DBUTTON_LCOL       FL_LCOL
#define FL_ROUND3DBUTTON_ALIGN      FL_ALIGN_CENTER
#define FL_ROUND3DBUTTON_TOPCOL     FL_COL1
#define FL_ROUND3DBUTTON_MCOL       FL_MCOL

/* check button defaults */

#define FL_CHECKBUTTON_BOXTYPE      FL_NO_BOX
#define FL_CHECKBUTTON_COL1         FL_COL1
#define FL_CHECKBUTTON_COL2         FL_YELLOW
#define FL_CHECKBUTTON_LCOL         FL_LCOL
#define FL_CHECKBUTTON_ALIGN        FL_ALIGN_CENTER

#define FL_CHECKBUTTON_TOPCOL       FL_COL1
#define FL_CHECKBUTTON_MCOL         FL_MCOL

/* bitmap button defaults */

#define FL_BITMAPBUTTON_BOXTYPE     FL_UP_BOX
#define FL_BITMAPBUTTON_COL1        FL_COL1         /* bitmap background  */
#define FL_BITMAPBUTTON_COL2        FL_BLUE         /* "focus" color       */
#define FL_BITMAPBUTTON_LCOL        FL_LCOL         /* bitmap foreground   */
#define FL_BITMAPBUTTON_ALIGN       FL_ALIGN_BOTTOM

/* bitmap button defaults */

#define FL_PIXMAPBUTTON_BOXTYPE     FL_UP_BOX
#define FL_PIXMAPBUTTON_COL1        FL_BUTTON_COL1
#define FL_PIXMAPBUTTON_COL2        FL_BUTTON_COL2
#define FL_PIXMAPBUTTON_LCOL        FL_BUTTON_LCOL
#define FL_PIXMAPBUTTON_MCOL1       FL_BUTTON_MCOL1
#define FL_PIXMAPBUTTON_MCOL2       FL_BUTTON_MCOL2
#define FL_PIXMAPBUTTON_ALIGN       FL_ALIGN_BOTTOM

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_button( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_create_roundbutton( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT FL_OBJECT * fl_create_round3dbutton( int        type,
                                               FL_Coord   x,
                                               FL_Coord   y,
                                               FL_Coord   w,
                                               FL_Coord   h,
                                               const char * label );

FL_EXPORT FL_OBJECT * fl_create_lightbutton( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT FL_OBJECT * fl_create_checkbutton( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT FL_OBJECT * fl_create_bitmapbutton( int          type,
                                              FL_Coord     x,
                                              FL_Coord     y,
                                              FL_Coord     w,
                                              FL_Coord     h,
                                              const char * label );

FL_EXPORT FL_OBJECT * fl_create_pixmapbutton( int          type,
                                              FL_Coord     x,
                                              FL_Coord     y,
                                              FL_Coord     w,
                                              FL_Coord     h,
                                              const char * label );

FL_EXPORT FL_OBJECT * fl_create_scrollbutton( int          type,
                                              FL_Coord     x,
                                              FL_Coord     y,
                                              FL_Coord     w,
                                              FL_Coord     h,
                                              const char * label );

FL_EXPORT FL_OBJECT * fl_create_labelbutton( int           type,
                                             FL_Coord      x,
                                             FL_Coord      y,
                                             FL_Coord      w,
                                             FL_Coord      h,
                                             const char * label );

FL_EXPORT FL_OBJECT *fl_add_roundbutton( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_round3dbutton( int          type,
                                            FL_Coord     x,
                                            FL_Coord     y,
                                            FL_Coord     w,
                                            FL_Coord     h,
                                            const char * label );

FL_EXPORT FL_OBJECT * fl_add_lightbutton( int         type,
                                          FL_Coord    x,
                                          FL_Coord    y,
                                          FL_Coord    w,
                                          FL_Coord    h,
                                          const char * label );

FL_EXPORT FL_OBJECT * fl_add_checkbutton( int          type,
                                          FL_Coord     x,
                                          FL_Coord     y,
                                          FL_Coord     w,
                                          FL_Coord     h,
                                          const char * label );

FL_EXPORT FL_OBJECT * fl_add_button( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_add_bitmapbutton( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_scrollbutton( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_labelbutton( int          type,
                                          FL_Coord     x,
                                          FL_Coord     y,
                                          FL_Coord     w,
                                          FL_Coord     h,
                                          const char * label );

#define fl_set_bitmapbutton_file  fl_set_bitmap_file

FL_EXPORT void fl_set_bitmapbutton_data( FL_OBJECT     * ob,
                                         int             w,
                                         int             h,
                                         unsigned char * bits );

#define fl_set_bitmapbutton_datafile  fl_set_bitmapbutton_file

FL_EXPORT FL_OBJECT * fl_add_pixmapbutton( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

#define fl_set_pixmapbutton_data       fl_set_pixmap_data
#define fl_set_pixmapbutton_file       fl_set_pixmap_file
#define fl_set_pixmapbutton_pixmap     fl_set_pixmap_pixmap
#define fl_get_pixmapbutton_pixmap     fl_get_pixmap_pixmap
#define fl_set_pixmapbutton_align      fl_set_pixmap_align
#define fl_free_pixmapbutton_pixmap    fl_free_pixmap_pixmap
#define fl_set_pixmapbutton_datafile   fl_set_pixmapbutton_file
#define fl_set_pixmapbutton_show_focus fl_set_pixmapbutton_focus_outline


FL_EXPORT void fl_set_pixmapbutton_focus_outline( FL_OBJECT * ob,
                                                  int         yes );

FL_EXPORT void fl_set_pixmapbutton_focus_data( FL_OBJECT  * ob,
                                               char      ** bits );

FL_EXPORT void fl_set_pixmapbutton_focus_file( FL_OBJECT  * ob,
                                               const char * fname );

FL_EXPORT void fl_set_pixmapbutton_focus_pixmap( FL_OBJECT * ob,
                                                 Pixmap      id,
                                                 Pixmap      mask );

FL_EXPORT int fl_get_button( FL_OBJECT * ob );

FL_EXPORT void fl_set_button( FL_OBJECT * ob,
                              int         pushed );

FL_EXPORT int fl_get_button_numb( FL_OBJECT * ob );

#define fl_set_button_shortcut  fl_set_object_shortcut

FL_EXPORT FL_OBJECT * fl_create_generic_button( int          objclass,
                                                int          type,
                                                FL_Coord     x,
                                                FL_Coord     y,
                                                FL_Coord     w,
                                                FL_Coord     h,
                                                const char * label );

FL_EXPORT void fl_add_button_class( int              bclass,
                                    FL_DrawButton    drawit,
                                    FL_CleanupButton cleanup );

FL_EXPORT void fl_set_button_mouse_buttons( FL_OBJECT    * ob,
                                            unsigned int   buttons );

FL_EXPORT void fl_get_button_mouse_buttons( FL_OBJECT    * ob,
                                            unsigned int * buttons );

#endif /* ! defined FL_BUTTON_H */
