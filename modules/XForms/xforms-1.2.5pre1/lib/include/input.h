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
 * \file input.h
 */

#ifndef FL_INPUT_H
#define FL_INPUT_H


/***** Types    *****/

typedef enum {
    FL_NORMAL_INPUT,
    FL_FLOAT_INPUT,
    FL_INT_INPUT,
    FL_DATE_INPUT,
    FL_MULTILINE_INPUT,
    FL_HIDDEN_INPUT,
    FL_SECRET_INPUT
} FL_INPUT_TYPE;

/* for date input */

enum {
    FL_INPUT_MMDD,
    FL_INPUT_DDMM
};

enum {
    FL_NORMAL_INPUT_MODE,
    FL_DOS_INPUT_MODE
};

/***** Defaults *****/

#define FL_INPUT_BOXTYPE    FL_DOWN_BOX
#define FL_INPUT_COL1       FL_COL1
#define FL_INPUT_COL2       FL_MCOL
#define FL_INPUT_LCOL       FL_LCOL
#define FL_INPUT_ALIGN      FL_ALIGN_LEFT

/***** Others   *****/

#define FL_INPUT_TCOL       FL_LCOL
#define FL_INPUT_CCOL       FL_BLUE

#define FL_RINGBELL         ( 1 << 4 )

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_input( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_input( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

FL_EXPORT void fl_set_input( FL_OBJECT  * ob,
                             const char * str );

FL_EXPORT void fl_set_input_f( FL_OBJECT  * obj,
							   const char * fmt,
							   ... );

FL_EXPORT void fl_set_input_return( FL_OBJECT    * ob,
                                    unsigned int   when );

FL_EXPORT void fl_set_input_color( FL_OBJECT * ob,
                                   FL_COLOR    textcol,
                                   FL_COLOR    curscol );

FL_EXPORT void fl_get_input_color( FL_OBJECT * ob,
                                   FL_COLOR  * textcol,
                                   FL_COLOR  * curscol );

FL_EXPORT void fl_set_input_scroll( FL_OBJECT * ob,
                                    int         yes );

FL_EXPORT void fl_set_input_cursorpos( FL_OBJECT * ob,
                                       int         xpos,
                                       int         ypos );

FL_EXPORT void fl_set_input_selected( FL_OBJECT * ob,
                                      int         yes );

FL_EXPORT void fl_set_input_selected_range( FL_OBJECT * ob,
                                            int         begin,
                                            int         end );

FL_EXPORT const char *fl_get_input_selected_range( FL_OBJECT * ob,
                                                   int       * begin,
                                                   int       * end );

FL_EXPORT void fl_set_input_maxchars( FL_OBJECT * ob,
                                      int         maxchars );

FL_EXPORT void fl_set_input_format( FL_OBJECT * ob,
                                    int         fmt,
                                    int         sep );

FL_EXPORT void fl_set_input_hscrollbar( FL_OBJECT * ob,
                                        int         pref );

FL_EXPORT void fl_set_input_vscrollbar( FL_OBJECT * ob,
                                        int         pref );

FL_EXPORT void fl_set_input_topline( FL_OBJECT * ob,
                                     int         top );

FL_EXPORT void fl_set_input_scrollbarsize( FL_OBJECT * ob,
                                           int         hh,
                                           int         vw );

FL_EXPORT void fl_get_input_scrollbarsize( FL_OBJECT * ob,
                                           int       * hh,
                                           int       * vw );

FL_EXPORT void fl_set_input_xoffset( FL_OBJECT * ob,
                                     int         xoff );

FL_EXPORT int fl_get_input_xoffset( FL_OBJECT * ob );

FL_EXPORT int fl_set_input_fieldchar( FL_OBJECT * ob,
                                      int         fchar );

FL_EXPORT int fl_get_input_topline( FL_OBJECT * ob );

FL_EXPORT int fl_get_input_screenlines( FL_OBJECT * ob );

FL_EXPORT int fl_get_input_cursorpos( FL_OBJECT * ob,
                                      int       * x,
                                      int       * y );

FL_EXPORT void fl_set_input_cursor_visible( FL_OBJECT * ob,
                                            int         visible );

FL_EXPORT int fl_get_input_numberoflines( FL_OBJECT * ob );

FL_EXPORT void fl_get_input_format( FL_OBJECT * ob,
                                    int       * fmt,
                                    int       * sep );

FL_EXPORT const char * fl_get_input( FL_OBJECT * ob );

typedef int ( * FL_INPUT_VALIDATOR )(FL_OBJECT  *,
									 const char *,
									 const char *,
									 int );

#define FL_INPUTVALIDATOR FL_INPUT_VALIDATOR

FL_EXPORT FL_INPUT_VALIDATOR
fl_set_input_filter( FL_OBJECT          * ob,
					 FL_INPUT_VALIDATOR   validate );

FL_EXPORT int fl_validate_input( FL_OBJECT *obj );

#define fl_set_input_shortcut   fl_set_object_shortcut

/* edit keys. */

typedef struct {
    /* basic editing */

    long del_prev_char;     /* delete previous char    */
    long del_next_char;     /* delete next char        */
    long del_prev_word;     /* delete previous word    */
    long del_next_word;     /* delete next word        */

    /* movement */

    long moveto_prev_line;  /* one line  up             */
    long moveto_next_line;  /* one line down            */
    long moveto_prev_char;  /* one char left            */
    long moveto_next_char;  /* one char right           */
    long moveto_prev_word;  /* one word left            */
    long moveto_next_word;  /* one word right           */
    long moveto_prev_page;  /* one page up              */
    long moveto_next_page;  /* one page down            */
    long moveto_bol;        /* move to begining of line */
    long moveto_eol;        /* move to end of line      */
    long moveto_bof;        /* move to begin of file    */
    long moveto_eof;        /* move to end of file      */

    /* misc. stuff */

    long transpose;         /* switch two char positions */
    long paste;             /* paste the edit buffer    */
    long backspace;         /* another  del_prev_char   */
    long del_to_bol;        /* cut to begining of line  */
    long del_to_eol;        /* cut to end of line       */
    long clear_field;       /* delete everything        */
    long del_to_eos;        /* not implemented          */
} FL_EditKeymap;

FL_EXPORT void fl_set_input_editkeymap( const FL_EditKeymap * keymap );

FL_EXPORT void fl_get_input_editkeymap( FL_EditKeymap * keymap );

FL_EXPORT void fl_set_default_editkeymap( void );

FL_EXPORT int fl_set_input_mode( int mode );

#endif /* ! defined FL_INPUT_H */
