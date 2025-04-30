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

#ifndef PTBOX_H
#define PTBOX_H


typedef struct {
    char         * fulltext;         /* text of line with flags */
    char         * text;             /* text of line without flags */
    unsigned int   len;              /* line length */
    int            selected;         /* whether line is selected  */
    int            selectable;       /* whether line is selectable */
    int            x;                /* vertical position relative to topline */
    int            y;                /* horizontal position of text */
    int            w;                /* length of text in pixels */
    int            h;                /* height of text in pixels */
    int            size;             /* font size */
    int            style;            /* font style */
    int            asc;              /* font ascent */
    int            desc;             /* font descent */
    FL_COLOR       color;            /* font color */
    int            align;            /* alignment of text */
    int            is_underlined;    /* whether to draw underlined */
    int            is_separator;     /* is this a separator line? */
    int            is_special;       /* does it need special GC? */
    GC             specialGC;        /* GC for if not default font/color */
    int            incomp_esc;       /* text has incomplete escape sequence */
} TBOX_LINE;


typedef struct {
    TBOX_LINE      ** lines;         /* strurctures for lines of text */
    int               num_lines;     /* number of structures */
    int               xoffset;       /* horizontal scroll in pixels    */
    int               yoffset;       /* vertical scroll in pixels    */
    int               x,             /* coordinates and sizes of drawing area */
                      y,
                      w,
                      h;
    int               attrib;        /* set when attributes changed */
    int               no_redraw;     /* flags when no redraw is to be done */
    int               select_line;   /* last selected line */
    int               deselect_line; /* last deselected line */
    int               max_width;     /* length of longest line in pixels */
    int               max_height;    /* height of all lines in pixels */
    int               def_size;      /* default front size */
    int               def_style;     /* default font style */
    int               def_align;     /* default alignment */
    int               def_height;    /* height of line with default font size */
    GC                defaultGC;     /* text drawing GC */
    GC                backgroundGC;  /* background GC */
    GC                selectGC;      /* background for selection GC */
    GC                nonselectGC;   /* for text of non-selectable lines */
    GC                bw_selectGC;   /* b&w selection text GC */
    int               specialkey;   /* Key that indicates a special symbol */
    FL_CALLBACKPTR    callback;      /* double and triple click callback */
    long              callback_data; /* data for callback */
    int               old_yoffset;
    int               react_to_vert;
    int               react_to_hori;
} FLI_TBOX_SPEC;


/* Defaults */

#define FLI_TBOX_BOXTYPE   FL_DOWN_BOX
#define FLI_TBOX_COL1      FL_WHITE
#define FLI_TBOX_COL2      FL_YELLOW
#define FLI_TBOX_LCOL      FL_LCOL
#define FLI_TBOX_ALIGN     FL_ALIGN_BOTTOM
#define FLI_TBOX_FONTSIZE  FL_SMALL_SIZE


extern FL_OBJECT * fli_create_tbox( int,
                                    FL_Coord,
                                    FL_Coord,
                                    FL_Coord,
                                    FL_Coord,
                                    const char *);

extern void fli_tbox_delete_line( FL_OBJECT * obj,
                                  int         line );

extern void fli_tbox_insert_lines( FL_OBJECT *,
                                   int,
                                   const char * );

extern void fli_tbox_insert_line( FL_OBJECT *,
                                  int,
                                  const char * );

extern void fli_tbox_add_line( FL_OBJECT *,
                               const char *,
                               int );

extern void fli_tbox_add_chars( FL_OBJECT *,
                                const char * );

extern const char * fli_tbox_get_line( FL_OBJECT *,
                                       int );

extern void fli_tbox_replace_line( FL_OBJECT *,
                                   int,
                                   const char * );

extern void fli_tbox_clear( FL_OBJECT * );

extern int fli_tbox_load( FL_OBJECT *,
                          const char * );

extern void fli_tbox_recalc_area( FL_OBJECT * );

extern void fli_tbox_set_fontsize( FL_OBJECT *,
                                   int );

extern void fli_tbox_set_fontstyle( FL_OBJECT *,
                                    int );

extern int fli_tbox_set_xoffset( FL_OBJECT *,
                                 int );

extern double fli_tbox_set_rel_xoffset( FL_OBJECT *,
                                        double );

extern int fli_tbox_set_yoffset( FL_OBJECT *,
                                 int );

extern double fli_tbox_set_rel_yoffset( FL_OBJECT *,
                                        double );

extern int fli_tbox_get_xoffset( FL_OBJECT * );

extern double fli_tbox_get_rel_xoffset( FL_OBJECT * );

extern int fli_tbox_get_yoffset( FL_OBJECT * );

extern double fli_tbox_get_rel_yoffset( FL_OBJECT * );

extern void fli_tbox_set_topline( FL_OBJECT *,
                                  int );

extern void fli_tbox_set_bottomline( FL_OBJECT *,
                                     int );

extern void fli_tbox_set_centerline( FL_OBJECT *,
                                     int );

extern void fli_tbox_deselect( FL_OBJECT * obj );

extern void fli_tbox_deselect_line( FL_OBJECT *,
                                    int );

extern void fli_tbox_select_line( FL_OBJECT *,
                                  int );

extern int fli_tbox_is_line_selected( FL_OBJECT *,
                                      int );

extern int fli_tbox_get_selection( FL_OBJECT *obj );

extern void fli_tbox_make_line_selectable( FL_OBJECT *,
                                           int,
                                           int );

extern void fli_tbox_set_dblclick_callback( FL_OBJECT *,
                                            FL_CALLBACKPTR,
                                            long );

extern int fli_tbox_get_num_lines( FL_OBJECT * );

extern int fli_tbox_get_topline( FL_OBJECT * obj );

extern int fli_tbox_get_bottomline( FL_OBJECT * );

extern void fli_tbox_react_to_vert( FL_OBJECT *,
                                    int );
extern void fli_tbox_react_to_hori( FL_OBJECT *,
                                    int );

extern int fli_tbox_get_line_yoffset( FL_OBJECT *,
                                      int );

#endif



/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
