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


#ifndef FL_POPUP_H
#define FL_POPUP_H

typedef struct FL_POPUP_ FL_POPUP;
typedef struct FL_POPUP_ENTRY_ FL_POPUP_ENTRY;
typedef struct FL_POPUP_RETURN_ FL_POPUP_RETURN;

typedef int ( * FL_POPUP_CB )( FL_POPUP_RETURN * );

struct FL_POPUP_RETURN_ {
    long int               val;          /* value assigned to popup entry */
    void                 * user_data;    /* pointer to user data */
    const char           * text;         /* text of the selected popup entry */
    const char           * label;        /* left-flushed label part */
    const char           * accel;        /* right-flushed label part */
    const FL_POPUP_ENTRY * entry;        /* pointer to selected popup entry */
    const FL_POPUP       * popup;        /* popup we're called for */
};

struct FL_POPUP_ {
    FL_POPUP         * next;             /* next in linked list */
    FL_POPUP         * prev;             /* previous in linked list */
    FL_POPUP         * parent;           /* for sub-popups: direct parent */
    FL_POPUP         * top_parent;       /* and top-most parent */
    FL_POPUP_ENTRY   * entries;          /* pointer to list of entries */
    char             * title;
    Window             win;              /* popup window */
    Window             parent_win;       /* parent window of popup window */
    Cursor             cursor;           /* cursor for the popup */
    FL_POPUP_CB        callback;
    int                use_req_pos;      /* if set use req_x, req_y */
    int                req_x,
                       req_y;
    int                x,                /* position of popup window */
                       y;
    unsigned int       w,                /* dimensions of popup window */
                       h;
    int                min_width;        /* minimum width of popup */
    int                title_box_x,      /* position of title box */
                       title_box_y;
    unsigned int       title_box_w,      /* dimensions of title box */
                       title_box_h;
    int                has_subs,
                       has_boxes;
    int                counter;
    int                title_font_style;
    int                title_font_size;
    int                entry_font_style;
    int                entry_font_size;
    unsigned long      event_mask;
    int                bw;               /* border width */
    FL_COLOR           bg_color;         /* background color of popup*/
    FL_COLOR           on_color;         /* color of entry under mouse */
    FL_COLOR           title_color;      /* color of title text */
    FL_COLOR           text_color;       /* normal text color of entry */
    FL_COLOR           text_on_color;    /* text color when mouse on entry */
    FL_COLOR           text_off_color;   /* text color of disabled entry */
    FL_COLOR           radio_color;      /* color of radio buttons */
    int                policy;
    int                need_recalc;      /* do we need to recalc position? */
    FL_POPUP_RETURN    ret;              /* structure passed to calbacks
                                            and returned on selection */
};

struct FL_POPUP_ENTRY_ {
    FL_POPUP_ENTRY * prev;               /* next in linked list */
    FL_POPUP_ENTRY * next;               /* previous in linked list */
    FL_POPUP       * popup;              /* popup it belongs to */
    int              is_act;             /* set while mouse is over it */
    char           * text;               /* complete text of entry */
    char           * label;              /* cleaned-up label text */
    char           * accel;              /* cleaned-up accelerator key text */
    long int         val;                /* value associated with entry */
    void           * user_data;          /* pointer to user data */
    int              type;               /* normal, toggle, radio, sub-popup */
    unsigned int     state;              /* disabled, hidden, checked */
    int              group;              /* group (for radio entries only) */
    FL_POPUP       * sub;                /* sub-popup bound to entry */
    long int       * shortcut;           /* keyboard shortcuts */
    int              ulpos;              /* underline position in text */
    FL_POPUP_CB      callback;           /* callback for entry */
    FL_POPUP_CB      enter_callback;     /* callback for entering entry */
    FL_POPUP_CB      leave_callback;     /* callback for leaving entry */
    int              x,                  /* position of entry text */
                     y;
    unsigned int     w,
                     h;                  /* height of entry text */
    int              box_x,
                     box_y;
    unsigned int     box_w,
                     box_h;
    unsigned int     sl_h;
    int              ul_x,
                     ul_y;
    unsigned int     ul_w,
                     ul_h;
};

typedef struct {
    const char     * text;               /* text of entry */
    FL_POPUP_CB      callback;           /* (selection) callback */
    const char     * shortcut;           /* keyboard shortcut description */
    int              type;               /* type of entry */
    int              state;              /* disabled, hidden, checked */
} FL_POPUP_ITEM;

/* Popup policies */

enum {
    FL_POPUP_NORMAL_SELECT,
    FL_POPUP_DRAG_SELECT
};

/* Popup states */

enum {
    FL_POPUP_NONE     = 0,
    FL_POPUP_DISABLED = 1,               /* entry is disabled */
    FL_POPUP_HIDDEN   = 2,               /* entry is temporarily hidden */
    FL_POPUP_CHECKED  = 4                /* tooogle/radio item is in on state */
};

/* Popup entry types */

enum {
    FL_POPUP_NORMAL,                     /* normal popup entry */
    FL_POPUP_TOGGLE,                     /* toggle ("binary") popup entry */
    FL_POPUP_RADIO,                      /* radio popup entry */
    FL_POPUP_SUB,                        /* sub-popup popup entry */
    FL_POPUP_LINE                        /* line popup entry */
};

/* Popup color types */

enum {
    FL_POPUP_BACKGROUND_COLOR,
    FL_POPUP_HIGHLIGHT_COLOR,
    FL_POPUP_TITLE_COLOR,
    FL_POPUP_TEXT_COLOR,
    FL_POPUP_HIGHLIGHT_TEXT_COLOR,
    FL_POPUP_DISABLED_TEXT_COLOR,
    FL_POPUP_RADIO_COLOR
};

FL_EXPORT FL_POPUP *fl_popup_add( Window,
                                  const char * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_add_entries( FL_POPUP *,
                                                const char *,
                                                ... );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_insert_entries( FL_POPUP *,
                                                   FL_POPUP_ENTRY *,
                                                   const char *,
                                                   ... );

FL_EXPORT FL_POPUP *fl_popup_create( Window,
                                     const char *,
                                     FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_add_items( FL_POPUP      *,
											  FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_insert_items( FL_POPUP       *,
												 FL_POPUP_ENTRY *,
												 FL_POPUP_ITEM  * );

FL_EXPORT int fl_popup_delete( FL_POPUP * );

FL_EXPORT int fl_popup_entry_delete( FL_POPUP_ENTRY * );

FL_EXPORT FL_POPUP_RETURN *fl_popup_do( FL_POPUP * );

FL_EXPORT void fl_popup_set_position( FL_POPUP *,
                                      int,
                                      int );

FL_EXPORT int fl_popup_get_policy( FL_POPUP * );

FL_EXPORT int fl_popup_set_policy( FL_POPUP *,
                                   int );

FL_EXPORT FL_POPUP_CB fl_popup_set_callback( FL_POPUP *,
                                             FL_POPUP_CB );

FL_EXPORT void fl_popup_get_title_font( FL_POPUP *,
                                        int *,
                                        int * );

FL_EXPORT void fl_popup_set_title_font( FL_POPUP *,
                                        int,
                                        int );

FL_EXPORT void fl_popup_entry_get_font( FL_POPUP *,
                                        int *,
                                        int * );

FL_EXPORT void fl_popup_entry_set_font( FL_POPUP *,
                                        int,
                                        int );

FL_EXPORT int fl_popup_get_bw( FL_POPUP * );

FL_EXPORT int fl_popup_set_bw( FL_POPUP *,
                               int );

FL_EXPORT FL_COLOR fl_popup_get_color( FL_POPUP *,
                                       int );

FL_EXPORT FL_COLOR fl_popup_set_color( FL_POPUP *,
                                       int,
                                       FL_COLOR );

FL_EXPORT void fl_popup_set_cursor( FL_POPUP *,
                                    int );

FL_EXPORT const char *fl_popup_get_title( FL_POPUP   * );

FL_EXPORT FL_POPUP *fl_popup_set_title( FL_POPUP *,
                                        const char * );

FL_EXPORT FL_POPUP * fl_popup_set_title_f( FL_POPUP   * popup,
										   const char * fmt,
										   ... );

FL_EXPORT FL_POPUP_CB fl_popup_entry_set_callback( FL_POPUP_ENTRY *,
                                                   FL_POPUP_CB );

FL_EXPORT FL_POPUP_CB fl_popup_entry_set_enter_callback( FL_POPUP_ENTRY *,
                                                         FL_POPUP_CB );

FL_EXPORT FL_POPUP_CB fl_popup_entry_set_leave_callback( FL_POPUP_ENTRY *,
                                                         FL_POPUP_CB );

FL_EXPORT unsigned int fl_popup_entry_get_state( FL_POPUP_ENTRY * );

FL_EXPORT unsigned int fl_popup_entry_set_state( FL_POPUP_ENTRY *,
                                                 unsigned int );

FL_EXPORT unsigned int fl_popup_entry_clear_state( FL_POPUP_ENTRY *,
                                                   unsigned int );

FL_EXPORT unsigned int fl_popup_entry_raise_state( FL_POPUP_ENTRY *,
                                                   unsigned int );

FL_EXPORT unsigned int fl_popup_entry_toggle_state( FL_POPUP_ENTRY *,
                                                    unsigned int );

FL_EXPORT int fl_popup_entry_set_text( FL_POPUP_ENTRY *,
                                       const char * );

FL_EXPORT void fl_popup_entry_set_shortcut( FL_POPUP_ENTRY *,
                                            const char * );

FL_EXPORT long int fl_popup_entry_set_value( FL_POPUP_ENTRY *,
                                             long int );

FL_EXPORT void *fl_popup_entry_set_user_data( FL_POPUP_ENTRY *,
                                              void * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_position( FL_POPUP *,
                                                          int );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_value( FL_POPUP *,
                                                       long );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_user_data( FL_POPUP *,
                                                           void * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_text( FL_POPUP *,
                                                      const char * );

FL_EXPORT FL_POPUP_ENTRY * fl_popup_entry_get_by_text_f( FL_POPUP *,
														 const char *,
														 ... );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_label( FL_POPUP *,
                                                       const char * );

FL_EXPORT FL_POPUP_ENTRY * fl_popup_entry_get_by_label_f( FL_POPUP *,
														  const char *,
														  ... );

FL_EXPORT int fl_popup_entry_get_group( FL_POPUP_ENTRY * );

FL_EXPORT int fl_popup_entry_set_group( FL_POPUP_ENTRY *,
                                        int );

FL_EXPORT FL_POPUP *fl_popup_entry_get_subpopup( FL_POPUP_ENTRY * );

FL_EXPORT FL_POPUP *fl_popup_entry_set_subpopup( FL_POPUP_ENTRY *,
                                                 FL_POPUP * );

FL_EXPORT int fl_popup_get_size( FL_POPUP *,
                                 unsigned int *,
                                 unsigned int * );

FL_EXPORT int fl_popup_get_min_width( FL_POPUP * );

FL_EXPORT int fl_popup_set_min_width( FL_POPUP *,
                                      int );

#endif /* ! defined FL_POPUP_H */
