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
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"
#include <ctype.h>


/***************************************
 * Local global variables
 ***************************************/

/* Head of linked list of popups */

static FL_POPUP *popups = NULL;


/* Default policy (i.e. does popup get closed when the user releases
   the mouse button when not on an active entry or not?) */

static int popup_policy;


/* Default font styles and sizes for title and entries */

static int popup_entry_font_style;
static int popup_title_font_style;

static int popup_entry_font_size;
static int popup_title_font_size;


/* Default color of popup */

static FL_COLOR popup_bg_color;


/* Default color of entry the mouse is over (unless disabled) */

static FL_COLOR popup_on_color;


/* Default color of title text */

static FL_COLOR popup_title_color;


/* Default color of normal entrys text */

static FL_COLOR popup_text_color;


/* Default color of entrys text when mouse is on the entry (unless disabled) */

static FL_COLOR popup_text_on_color;


/* Default color of disabled entrys text */

static FL_COLOR popup_text_off_color;


/* Default color of button for radio entries */

static FL_COLOR popup_radio_color;


/* Default popup border width */

static int popup_bw;


/* Default cursor type to be used */

static int popup_cursor;


/***************************************
 * Local functions           *
 ***************************************/

static FL_POPUP_ENTRY *parse_entries( FL_POPUP *, char *, va_list,
                                      const char *, int );
static FL_POPUP_ENTRY * failed_add( FL_POPUP_ENTRY * );
static int check_sub( FL_POPUP_ENTRY * );
static void radio_check( FL_POPUP_ENTRY * );
static void convert_shortcut( const char *, FL_POPUP_ENTRY * );
static void recalc_popup( FL_POPUP * );
static void title_dimensions( FL_POPUP *, unsigned int *, unsigned int * );
static void entry_text_dimensions( FL_POPUP_ENTRY *, unsigned int *,
                                   unsigned int * );
static void draw_popup( FL_POPUP * );
static void draw_title( FL_POPUP * );
static void draw_entry( FL_POPUP_ENTRY * );
static void calculate_window_position( FL_POPUP * );
static void create_popup_window( FL_POPUP * );
static void grab( FL_POPUP * );
static void close_popup( FL_POPUP *, int );
static FL_POPUP_RETURN * popup_interaction( FL_POPUP * );
static int is_on_popups( FL_POPUP * pooup, int x, int y );
static FL_POPUP_RETURN * handle_selection( FL_POPUP_ENTRY * );
static FL_POPUP * handle_motion( FL_POPUP *, int, int );
static void motion_shift_window( FL_POPUP *, int *, int * );
static FL_POPUP * handle_key( FL_POPUP *, XKeyEvent *, FL_POPUP_ENTRY ** );
static void key_shift_window( FL_POPUP *, FL_POPUP_ENTRY * );
static FL_POPUP * open_subpopup( FL_POPUP_ENTRY * );
static FL_POPUP_ENTRY * handle_shortcut( FL_POPUP *, long, unsigned int );
static void enter_leave( FL_POPUP_ENTRY *, int );
static FL_POPUP * find_popup( int, int );
static FL_POPUP_ENTRY * find_entry( FL_POPUP *, int, int );
static void setup_subpopups( FL_POPUP * );
static char * cleanup_string( char * );
static void set_need_recalc( FL_POPUP * );


/***************************************
 * #defines
 ***************************************/

/* Inner padding is used within the title box of popups only */

#define INNER_PADDING_LEFT    3
#define INNER_PADDING_RIGHT   3
#define INNER_PADDING_TOP     3
#define INNER_PADDING_BOTTOM  3


/* Spacing around title and entries of a popup */

#define OUTER_PADDING_LEFT    3
#define OUTER_PADDING_RIGHT   3
#define OUTER_PADDING_TOP     0
#define OUTER_PADDING_BOTTOM  0

/* Vert. spacing between symbols (box, hook, triangle) and text in an entry */

#define SYMBOL_PADDING        0


/* Height of the box for separation line in popup, must be at least 3 */

#define LINE_HEIGHT           4


/* Extra offsets added by fl_draw_text() that need to be taken into account
   (see variables 'xoff' and 'yoff' of 'fli_draw_text_inside()' in xtext.c) */

#define STR_OFFSET_X    5
#define STR_OFFSET_Y    4


/* Amount window is shifted in horizontal direction if the popup doesn't fit on
   the screen in that direction and delay (in usec) between shifts (in both
   directions) when the user is pushing the mouse at the screen borders */

#define WINDOW_SHIFT        ( fl_scrw / 10 )
#define WINDOW_SHIFT_DELAY  100000 


/* Macro for testing if a popup entry can be made "active" (i.e. if it
   gets highlighted when under the mouse) */

#define IS_ACTIVATABLE( e )                                               \
    (     ( e )->type != FL_POPUP_LINE                                    \
      && ! ( ( e ) ->state & ( FL_POPUP_HIDDEN | FL_POPUP_DISABLED ) ) )



/***************************************
 * Create a new popup
 ***************************************/

FL_POPUP *
fl_popup_add( Window       win,
              const char * title )
{
    return fli_popup_add( win, title, "fl_popup_add" );
}


/***************************************
 * Internal function to create a new popup
 ***************************************/

FL_POPUP *
fli_popup_add( Window       win,
               const char * title,
               const char * caller )
{
    FL_POPUP *p;

    /* Try to get memory for the popup itself and the optional title string */

    if ( ( p = fl_malloc( sizeof *p ) ) == NULL )
    {
        M_err( caller, "Running out of memory" );
        return NULL;
    }

    if ( ! title || ! *title )
        p->title = NULL;
    else if ( ( p->title = fl_strdup( title ) ) == NULL )
    {
        fl_free( p );
        M_err( caller, "Running out of memory" );
        return NULL;
    }

    /* Link the new popup into the list of popups */

    p->next = NULL;
    if ( popups == NULL )
    {
        popups = p;
        p->prev = NULL;
    }
    else
    {
        p->prev = popups;
        while ( p->prev->next != NULL )
            p->prev = p->prev->next;
        p->prev->next = p;
    }

    p->parent = NULL;
    p->top_parent = p;         /* points at itself except for sub-popups */

    p->win = None;
    p->parent_win = win != None ? win : fl_root;
    p->cursor     = fli_get_cursor_byname( popup_cursor );

    p->entries     = NULL;
    p->callback    = NULL;
    p->use_req_pos = 0;
    p->need_recalc = 1;
    p->min_width   = 0;
    p->has_subs    = 0;
    p->has_boxes   = 0;
    p->counter     = 0;
    p->policy      = popup_policy;

    fl_popup_set_title_font( p, popup_title_font_style, popup_title_font_size );
    fl_popup_entry_set_font( p, popup_entry_font_style, popup_entry_font_size );

    p->bw               = popup_bw;
    p->on_color         = popup_on_color;
    p->bg_color         = popup_bg_color;
    p->title_color      = popup_title_color;
    p->text_color       = popup_text_color;
    p->text_on_color    = popup_text_on_color;
    p->text_off_color   = popup_text_off_color;
    p->radio_color      = popup_radio_color;

    return p;
}


/***************************************
 * Add (append) entries to a popup
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_add_entries( FL_POPUP   * popup,
                      const char * entries,
                      ... )
{
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    va_start( ap, entries );
    new_entries = fli_popup_add_entries( popup, entries, ap,
                                         "fl_popup_add_entries", 0 );
    va_end( ap );

    return new_entries;
}


/***************************************
 * Internal function to add entries
 ***************************************/

FL_POPUP_ENTRY *
fli_popup_add_entries( FL_POPUP   * popup,
                       const char * entries,
                       va_list      ap,
                       const char * caller,
                       int          simple )
{
    FL_POPUP_ENTRY *new_entries,
                   *e;
    char *str;

    /* Calling this function with no string for the entries doesn't make
       sense */

    if ( entries == NULL )
    {
        M_err( caller, "NULL entries argument" );
        return NULL;
    }

    /* Check if the popup we're supposed to add to does exist at all */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( caller, "Popup does not exist" );
        return NULL;
    }

    /* Now analyze the string with the information about the entries */

    if ( ( str = fl_strdup( entries ) ) == NULL )
    {
        M_err( caller, "Running out of memory" );
        return NULL;
    }

    new_entries = parse_entries( popup, str, ap, caller, simple );
    fl_free( str );

    /* A return value of NULL says something went wrong (warning was altready
       output) */

    if ( new_entries == NULL )
        return NULL;

    /* Now all left to do is append the list of new entries to the list of
       already existing ones (if there are any) */

    if ( popup->entries == NULL )
        popup->entries = new_entries;
    else
    {
        for ( e = popup->entries; e->next != NULL; e = e->next )
            /* empty */ ;
        e->next = new_entries;
        new_entries->prev = e;
    }

    /* Make sure all sub-popus are set up correctly */

    setup_subpopups( popup );

    /* Set flag that indicates that the dimension of the popup have to be
       recalculated */

    set_need_recalc( popup );

    /* Return a pointer to the first of the newly added entries */

    return new_entries;
}


/***************************************
 * Insert new entries after an entry (use NULL for inserting at the start)
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_insert_entries( FL_POPUP       * popup,
                         FL_POPUP_ENTRY * after,
                         const char     * entries,
                         ... )
{
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    va_start( ap, entries );
    new_entries = fli_popup_insert_entries( popup, after, entries, ap,
                                            "fl_popup_insert_entries", 0 );
    va_end( ap );

    return new_entries;
}


/***************************************
 * Internal function to insert new entries after an entry
 ***************************************/

FL_POPUP_ENTRY *
fli_popup_insert_entries( FL_POPUP       * popup,
                          FL_POPUP_ENTRY * after,
                          const char     * entries,
                          va_list          ap,
                          const char     * caller,
                          int              simple)
{
    FL_POPUP_ENTRY *new_entries,
                   *new_last,
                   *e;
    char *str;

    if ( after != NULL )
    {
        for ( e = popup->entries; e != NULL; e = e->next )
            if ( e == after )
                break;

        if ( e == NULL )
        {
            M_err( caller, "Invalid 'after' argument" );
            return NULL;
        }
    }

    /* Calling this function with no string for the entries doesn't make
       sense */

    if ( entries == NULL )
    {
        M_err( caller, "NULL entries argument" );
        return NULL;
    }

    /* Check if the popup we're supposed to add to does exist at all */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( caller, "Popup does not exist" );
        return NULL;
    }

    /* Now analyze the string with the information about the entries */

    if ( ( str = fl_strdup( entries ) ) == NULL )
    {
        M_err( caller, "Running out of memory" );
        return NULL;
    }

    new_entries = parse_entries( popup, str, ap, "fl_popup_insert_entries",
                                 simple );
    fl_free( str );

    /* A return value of NULL says something went wrong (warning was already
       output) */

    if ( new_entries == NULL )
        return NULL;

    /* Now all left to do is insert the list of new entries into the list of
       already existing ones. 'after' being NULL means at the start of the
       list. */

    for ( new_last = new_entries;
          new_last->next != NULL; new_last = new_last->next )
        /* empty */ ;

    if ( after == NULL )
    {
        if ( popup->entries != NULL )
        {

            new_last->next = popup->entries;
            popup->entries->prev = new_last;
        }

        popup->entries = new_entries;
    }
    else
    {
        if ( after->next )
            after->next->prev = new_last;

        new_last->next = after->next;

        new_entries->prev = after;
        after->next = new_entries;
    }

    /* Make sure all sub-popus are set up correctly */

    setup_subpopups( popup );

    /* Set flag that indicates that the dimension of the popup have to be
       recalculated */

    set_need_recalc( popup );

    /* Return a pointer to the first of the newly added entries */

    return new_entries;
}


/***************************************
 * Internal function for inserting entries into a popup after entry
 * 'after' (NULL stands for "insert at start") from a list of FL_POPUP_ITEM
 * structures - they are converted into a string that then gets passed
 * with the required additional arguments to fl_popup_insert_entries()
 ***************************************/

FL_POPUP_ENTRY *
fli_popup_insert_items( FL_POPUP       * popup,
                        FL_POPUP_ENTRY * after,
                        FL_POPUP_ITEM  * entries,
                        const char     * caller)
{
    FL_POPUP_ITEM *e;
    const char *c;
    char *txt;
    size_t cnt;
    static long val = 0;
    int level = 0;
    int need_line = 0;
    int is_sub = 0;
    FL_POPUP_ENTRY *entry = NULL;
    int first = 1;

    /* Return if the array of items is NULL */

    if ( entries == NULL )
        return NULL;

    /* Check if the popup we're supposed to add to does exist at all */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( caller, "Popup does not exist" );
        return NULL;
    }

    /* If 'after' isn't NULL (indicating that we have to insert at the
       start) check that this popup entry exists */

    if ( after != NULL )
    {
        for ( entry = popup->entries; entry != NULL; entry = entry->next )
            if ( entry == after )
                break;

        if ( entry == NULL )
        {
            M_err( caller, "Invalid 'after' argument" );
            return NULL;
        }
    }

    /* Iterate over all items, inserting each individually */

    for ( e = entries; e->text != NULL; e++ )
    {
        /* Check that the type is ok */

        if (    e->type != FL_POPUP_NORMAL
             && e->type != FL_POPUP_TOGGLE
             && e->type != FL_POPUP_RADIO )
        {
            M_err( caller, "Invalid entry type" );
            return NULL;
        }

        c = e->text;

        /* Check for '/' and '_' at the very start of the text */

        if ( c[ 0 ] == '_' || ( c[ 0 ] == '/' && c[ 1 ] == '_' ) )
            need_line = 1;

        if ( c[ 0 ] == '/' || ( c[ 0 ] == '_' && c[ 1 ]  == '/' ) )
        {
            if ( e->type != FL_POPUP_NORMAL )
            {
                M_err( caller, "Entry can't be for a sub-popup "
                       "and toggle or radio entry at the same time" );
                return NULL;
            }
            is_sub = 1;
        }

        if (    ( *c == '/' && *++c == '_' )
             || ( *c == '_' && *++c == '/' ) )
            c++;

        /* Count the number of '%' in the string (without a directly following
           'S') since all of them need to be escaped */

        cnt = 0;
        for ( txt = strchr( c, '%' ); txt != NULL; txt = strchr( ++txt, '%' ) )
            if ( txt[ 1 ] != 'S' )
                cnt++;

        /* Get enough memory for the string to pass to
           fl_popup_insert_entries() */

        if ( ( txt = fl_malloc( strlen( c ) + cnt + 13 ) ) == NULL )
        {
            M_err( caller, "Running out of memory" );
            return NULL;
        }

        /* Copy the original text, doubling all '%'s (except those in
           front of 'S') */

        for ( cnt = 0; *c != '\0'; c++, cnt++ )
        {
            txt[ cnt ] = *c;
            if ( c[ 0 ] == '%' && c[ 1 ] != 'S' )
                txt[ ++cnt ] = '%';
        }

        /* Add special sequences passed in every case */

        memcpy( txt + cnt, "%x%f%s", 6 );
        cnt += 6;

        /* Optionally add those for for disabling or hiding the entry */

        if ( e->state & FL_POPUP_DISABLED )
        {
            memcpy( txt + cnt, "%d", 2 );
            cnt += 2;
        }

        if ( e->state & FL_POPUP_HIDDEN )
        {
            memcpy( txt + cnt, "%h", 2 );
            cnt += 2;
        }

        txt[ cnt ] = '\0';

        /* Now we can start creating the entry. To make sure that the
           value assigned to the entry is correct even when sub-popus
           are to be created we need to know the level of recursion */

        level++;

        if ( need_line )
        {
            if ( ( after = fl_popup_insert_entries( popup, after, "%l" ) )
                                                                      == NULL )
            {
                if ( --level == 0 )
                    val = 0;
                return NULL;
            }

            need_line = 0;
        }

        if ( e->type == FL_POPUP_NORMAL && ! is_sub )
        {
            if ( ( after = fl_popup_insert_entries( popup, after, txt, val++,
                                                    e->callback, e->shortcut ) )
                                                                       == NULL )
            {
                fl_free( txt );
                if ( --level == 0 )
                    val = 0;
                return NULL;
            }
        }
        else if ( e->type == FL_POPUP_TOGGLE )
        {
            strcat( txt, e->state & FL_POPUP_CHECKED  ? "%T" : "%t" );

            if ( ( after = fl_popup_insert_entries( popup, after, txt, val++,
                                                    e->callback, e->shortcut ) )
                                                                       == NULL )
            {
                fl_free( txt );
                if ( --level == 0 )
                    val = 0;
                return NULL;
            }
        }
        else if ( e->type == FL_POPUP_RADIO )
        {
            strcat( txt, e->state & FL_POPUP_CHECKED ? "%R" : "%r" );

            if ( ( after = fl_popup_insert_entries( popup, after, txt, val++,
                                                    e->callback, e->shortcut,
                                                    INT_MIN ) ) == NULL )
            {
                fl_free( txt );
                if ( --level == 0 )
                    val = 0;
                return NULL;
            }
        }
        else if ( is_sub )
        {
            FL_POPUP *sub;
            long pval = val++;

            strcat( txt, "%m" );

            if (    ( sub = fl_popup_create( popup->win, NULL, e + 1 ) ) == NULL
                 || ( after = fl_popup_insert_entries( popup, after,txt, pval,
                                                       e->callback, e->shortcut,
                                                       sub ) ) == NULL )
            {
                fl_free( txt );
                if ( ! fli_check_popup_exists( sub ) )
                    fl_popup_delete( sub );
                if ( --level == 0 )
                    val = 0;
                return NULL;
            }
        }

        fl_free( txt );

        /* Set the entries text member to exactly what the user gave us */

        fli_safe_free( after->text );
        if ( ( after->text = fl_strdup( e->text ) ) == NULL )
        {
            fl_popup_delete( popup );
            if ( --level == 0 )
                val = 0;
            return NULL;
        }

        /* If this was a sub-popup entry skip items that were for the sub- or
           sub-sub-popus etc. */

        if ( is_sub )
        {
            cnt = 1;
            while ( cnt > 0 )
            {
                e++;

                if ( e->text == NULL )
                    cnt--;
                else if (    e->text[ 0 ] == '/'
                          || ( e->text[ 0 ] == '_' && e->text[ 1 ] == '/' ) )
                    cnt++;
            }

            is_sub = 0;
        }

        if ( first )
        {
            entry = after;
            first = 0;
        }
    }

    val++;
    if ( --level == 0 )
        val = 0;

    return entry;
}


/***************************************
 * Create a popup and populate it from a list of FL_POPUP_ITEM structures
 ***************************************/

FL_POPUP *
fl_popup_create( Window          win,
                 const char    * title,
                 FL_POPUP_ITEM * entries )
{
    FL_POPUP *popup;

    if ( ( popup = fl_popup_add( win, title ) ) == NULL )
        return NULL;

    if ( fli_popup_insert_items( popup, NULL, entries,
                                 "fl_popup_create" ) == NULL )
    {
        fl_popup_delete( popup );
        return NULL;
    }

    return popup;
}


/***************************************
 * Appends entries to a popup from a list of FL_POPUP_ITEM structures
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_add_items( FL_POPUP      * popup,
                    FL_POPUP_ITEM * entries )
{
    FL_POPUP_ENTRY *after;

    /* Return if the array of items is NULL */

    if ( entries == NULL )
        return NULL;

    /* Check if the popup we're supposed to add to does exist at all */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_add_items", "Popup does not exist" );
        return NULL;
    }

    /* Determine the last existing entry in the popup */

    after = popup->entries;
    while ( after != NULL && after->next != NULL )
        after = after->next;

    return fli_popup_insert_items( popup, after, entries,
                                   "fl_popup_add_items" );
}


/***************************************
 * Insert entries into a popup from a list of FL_POPUP_ITEM structures
 * after an entry
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_insert_items( FL_POPUP       * popup,
                       FL_POPUP_ENTRY * after,
                       FL_POPUP_ITEM  * entries )
{
    return fli_popup_insert_items( popup, after, entries,
                                   "fl_popup_insert_items" );
}


/***************************************
 * Removes a popup, returns 0 on success and -1 on failure.
 ***************************************/

int
fl_popup_delete( FL_POPUP * popup )
{
    /* Check if the popup we're asked to delete does exist */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_delete", "Popup does not exist" );
        return -1;
    }

    /* Don't delete a popup that's currently shown */

    if ( popup->win != None )
    {
        M_err( "fl_popup_delete", "Can't free popup that is still shown" );
        return -1;
    }

    /* Remove all entries (including sub-popups refered to there) */

    while ( popup->entries )
        fl_popup_entry_delete( popup->entries );

    /* Get rid of the title string (if it exists) */

    fli_safe_free( popup->title );

    /* Finally unlink it from the list */

    if ( popup->prev != NULL )
        popup->prev->next = popup->next;
    else
        popups = popup->next;

    if ( popup->next != NULL )
        popup->next->prev = popup->prev;

    fl_free( popup );

    return 0;
}


/***************************************
 * Delete a single popup entry (if it's a sub-popup entry also delete
 * the popup it refers to)
 ***************************************/

int
fl_popup_entry_delete( FL_POPUP_ENTRY * entry )
{
    if ( entry == NULL )
    {
        M_err( "fl_popup_entry_delete", "Invalid argument" );
        return -1;
    }

    /* We don't remove entries that are shown at the moment */

    if ( entry->popup->win != None )
    {
        M_err( "fl_popup_entry_delete", "Can't free entry of a popup that is "
                "shown" );
        return -1;
    }

    /* Remove the entry from the entry list of the popup it belongs to */

    if ( entry->prev == NULL )
        entry->popup->entries = entry->next;
    else
        entry->prev->next = entry->next;

    if ( entry->next != NULL )
        entry->next->prev = entry->prev;

    entry->popup->need_recalc = 1;

    /* Free all remaining memory used by entry */

    fli_safe_free( entry->text );
    fli_safe_free( entry->label );
    fli_safe_free( entry->accel );
    fli_safe_free( entry->shortcut );

    /* For entries that refer to sub-popups delete the sub-popup */

    if ( entry->type == FL_POPUP_SUB )
        fl_popup_delete( entry->sub );

    return 0;
}


/***************************************
 * Do interaction with a popup
 ***************************************/

FL_POPUP_RETURN *
fl_popup_do( FL_POPUP * popup )
{
    /* Check that the popup exists */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_do", "Invalid popup" );
        return NULL;
    }

    /* We don't interact directly with sub-popups */

    if ( popup->parent != NULL )
    {
        M_err( "fl_popup_do", "Can't do direct interaction with sub-popup" );
        return NULL;
    }

    draw_popup( popup );

    return popup_interaction( popup );
}


/***************************************
 * Set position where the popup is supposed to appear (if
 * never called the popup appears at the mouse position)
 ***************************************/

void
fl_popup_set_position( FL_POPUP * popup,
                       int        x,
                       int        y )
{
    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_position", "Invalid popup" );
        return;
    }

    popup->use_req_pos = 1;
    popup->req_x = x;
    popup->req_y = y;
}


/***************************************
 * Returns the policy set for a popup or the default policy if called
 * with a NULL pointer
 ***************************************/

int
fl_popup_get_policy( FL_POPUP * popup )
{
    if ( popup == NULL )
        return popup_policy;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_title_font", "Invalid popup" );
        return -1;
    }

    return popup->top_parent->policy;
}


/***************************************
 * Set policy of handling the popup (i.e. does it get closed when the
 * user releases the mouse button outside an active entry or not?)
 ***************************************/

int
fl_popup_set_policy( FL_POPUP * popup,
                     int        policy )
{
    int old_policy;

    if ( policy < FL_POPUP_NORMAL_SELECT || policy > FL_POPUP_DRAG_SELECT )
    {
        M_err( "fl_popup_set_policy", "Invalid policy argument" );
        return -1;
    }

    if ( popup == NULL )
    {
        old_policy = popup_policy;
        popup_policy = policy;
        return old_policy;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_policy", "Invalid popup" );
        return -1;
    }

    old_policy = popup->policy;
    popup->policy = policy;
    return old_policy;
}


/***************************************
 * Set new text for an entry. Returns 0 on succes and -1 on failure.
 ***************************************/

int
fl_popup_entry_set_text( FL_POPUP_ENTRY * entry,
                         const char     * text )
{
    char *t,
         *label,
         *accel,
         sc_str[ 2 ];
    int ret = -1;
    long *old_sc;
        

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_text", "Invalid entry argument" );
        return -1;
    }

    /* If the new text is NULL (not very useful;-) we're already done */

    if ( text == NULL )
    {
        M_err( "fl_popup_entry_set_text", "Invalid text argument" );
        return -1;
    }

    /* Get rid  of the old text, label and accelerator strings */

    fli_safe_free( entry->text );
    fli_safe_free( entry->label );
    fli_safe_free( entry->accel );

    /* Make two copies of the text, the first one for storing in the entry,
       the second one for creating the label the accelerator string */

    if ( ( t = fl_strdup( text ) ) == NULL )
        goto REPLACE_DONE;

    if ( ( entry->text = fl_strdup( text ) ) == NULL )
        goto REPLACE_DONE;

    /* Split up the text at the first '%S' */

    label = t;
    if ( ( accel = strstr( t, "%S" ) ) != NULL )
    {
        *accel = '\0';
        accel += 2;
    }

    /* Remove all backspace characters and replace tabs by spaces in both the
       label and the accelerator string */

    cleanup_string( label );
    cleanup_string( accel );

    /* Finally set up the label and accel members of the structure */

    if ( ! *label )
        entry->label = NULL;
    else if ( ( entry->label = fl_strdup( label ) ) == NULL )
         goto REPLACE_DONE;

    if ( ! accel || ! *accel )
        entry->accel = NULL;
    else if ( ( entry->accel = fl_strdup( accel ) ) == NULL )
        goto REPLACE_DONE;

    ret = 0;

 REPLACE_DONE:

    fli_safe_free( t );

    if ( ret == -1 )
    {
        fli_safe_free( entry->text );
        fli_safe_free( entry->label );
        fli_safe_free( entry->accel );
        M_err( "fl_popup_entry_set_text", "Running out of memory" );
    }

    for ( old_sc = entry->shortcut; *old_sc != 0; old_sc++ )
        if (    ( *old_sc & ~ ( FL_CONTROL_MASK | FL_ALT_MASK ) ) > 0
             && ( *old_sc & ~ ( FL_CONTROL_MASK | FL_ALT_MASK ) ) <= 0xFF )
        {
            sc_str[ 0 ] = *old_sc & ~ ( FL_CONTROL_MASK | FL_ALT_MASK );
            sc_str[ 1 ] = '\0';
            convert_shortcut( sc_str, entry );
            break;
        }

    entry->popup->need_recalc = 1;

    return 0;
}


/***************************************
 * Set new shortcuts for an entry
 ***************************************/

void
fl_popup_entry_set_shortcut( FL_POPUP_ENTRY * entry,
                             const char     * sc )
{
    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_shortcut", "Invalid entry argument" );
        return;
    }

    fli_safe_free( entry->shortcut );

    if ( sc == NULL )
        entry->ulpos = -1;
    else
        convert_shortcut( sc, entry );
}


/***************************************
 * Set callback function for a popup
 ***************************************/

FL_POPUP_CB
fl_popup_set_callback( FL_POPUP    * popup,
                       FL_POPUP_CB   callback )
{
    FL_POPUP_CB old_cb;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_callback", "Invalid popup" );
        return NULL;
    }

    old_cb = popup->callback;
    popup->callback = callback;
    return old_cb;
}


/***************************************
 * Set a new title for a popup
 ***************************************/

const char *
fl_popup_get_title( FL_POPUP * popup )
{
    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_title", "Invalid popup" );
        return NULL;
    }

    return popup->title;
}


/***************************************
 * Set a new title for a popup
 ***************************************/

FL_POPUP *
fl_popup_set_title( FL_POPUP   * popup,
                    const char * title )
{
    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_title", "Invalid popup" );
        return NULL;
    }

    fli_safe_free( popup->title );

    if ( title && *title )
    {
        popup->title = fl_strdup( title );
        if ( popup->title == NULL )
        {
            M_err( "fl_popup_set_title", "Running out of memory" );
            return NULL;
        }
    }

    popup->need_recalc = 1;

    return popup;
}


/***************************************
 * Set a new title for a popup
 ***************************************/

FL_POPUP *
fl_popup_set_title_f( FL_POPUP   * popup,
                      const char * fmt,
                      ... )
{
    char *buf;
    FL_POPUP *p;

    EXPAND_FORMAT_STRING( buf, fmt );
    p = fl_popup_set_title( popup, buf );
    fl_free( buf );
    return p;
}


/***************************************
 * Return title font for a popup
 ***************************************/

void
fl_popup_get_title_font( FL_POPUP * popup,
                         int      * style,
                         int      * size )
{
    if ( popup == NULL )
    {
        if ( style != NULL )
            *style = popup_title_font_style;
        if ( size != NULL )
            *size  = popup_title_font_size;
        return;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_title_font", "Invalid popup" );
        return;
    }

    if ( style != NULL )
        *style = popup->top_parent->title_font_style;
    if ( size != NULL )
        *size  = popup->top_parent->title_font_size ;
}


/***************************************
 * Set title font for a popup (or change the default if called with NULL)
 ***************************************/

void
fl_popup_set_title_font( FL_POPUP * popup,
                         int        style,
                         int        size )
{
    if ( popup == NULL )
    {
        popup_title_font_style = style;
        popup_title_font_size  = size;
        return;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_title_font", "Invalid popup" );
        return;
    }

    popup->title_font_style = style;
    popup->title_font_size  = size;

    if ( popup->parent == NULL )
        set_need_recalc( popup );
}


/***************************************
 * Return entry font for a popup
 ***************************************/

void
fl_popup_entry_get_font( FL_POPUP * popup,
                         int      * style,
                         int      * size )
{
    if ( popup == NULL )
    {
        if ( style != NULL )
            *style = popup_entry_font_style;
        if ( size != NULL )
            *size  = popup_entry_font_size;
        return;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_get_font", "Invalid popup" );
        return;
    }

    if ( style != NULL )
        *style = popup->top_parent->entry_font_style;
    if ( size != NULL )
        *size  = popup->top_parent->entry_font_size ;
}


/***************************************
 * Set entry font for a popup (or change the default if called with NULL)
 ***************************************/

void
fl_popup_entry_set_font( FL_POPUP * popup,
                         int        style,
                         int        size )
{
    if ( popup == NULL )
    {
        popup_entry_font_style = style;
        popup_entry_font_size  = size;
        return;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_set_font", "Invalid popup" );
        return;
    }

    popup->entry_font_style = style;
    popup->entry_font_size  = size;

    if ( popup->parent == NULL )
        set_need_recalc( popup );
}


/***************************************
 * Return the border width of a popup (or the default border width if
 * called with NULL or an invalid argument)
 ***************************************/

int
fl_popup_get_bw( FL_POPUP * popup )
{
    if ( popup == NULL )
        return popup_bw;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_bw", "Invalid argument" );
        return popup_bw;
    }

    return popup->top_parent->bw;
}


/***************************************
 * Sets the border width of a popup or the default border width (if called
 * with NULL)
 ***************************************/

int
fl_popup_set_bw( FL_POPUP * popup,
                 int        bw )
{
    int old_bw;

    /* Clamp border width to a reasonable range */

    if ( bw == 0 || FL_abs( bw ) > FL_MAX_BW )
    {
        bw = bw == 0 ? -1 : ( bw > 0 ? FL_MAX_BW : - FL_MAX_BW );
        M_warn( "fl_popup_set_bw", "Adjusting invalid border width to %d",
                bw ); 
    }

    if ( popup == NULL )
    {
        old_bw = popup_bw;
        popup_bw = bw;
        return old_bw;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_bw", "Invalid popup argument" );
        return INT_MIN;
    }

    old_bw = bw;
    popup->bw = bw;

    if ( popup->parent == NULL )
        set_need_recalc( popup );

    return old_bw;
}


/***************************************
 * Get one of the colors of the popup (NULL or invalid popup returns the
 * default settings)
 ***************************************/

FL_COLOR
fl_popup_get_color( FL_POPUP * popup,
                    int        color_type )
{
    /* Check if the popup exists */

    if ( popup != NULL && fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_color", "Invalid popup argument" );
        popup = NULL;
    }

    /* For sub-popups always return the color of the controlling popup */

    if ( popup != NULL )
        popup = popup->top_parent;

    switch ( color_type )
    {
        case FL_POPUP_BACKGROUND_COLOR :
            return popup ? popup->bg_color : popup_bg_color;

        case FL_POPUP_HIGHLIGHT_COLOR :
            return popup ? popup->on_color : popup_on_color;

        case FL_POPUP_TITLE_COLOR :
            return popup ? popup->title_color : popup_title_color;

        case FL_POPUP_TEXT_COLOR :
            return popup ? popup->text_color : popup_text_color;

        case FL_POPUP_HIGHLIGHT_TEXT_COLOR :
            return popup ? popup->text_on_color : popup_text_on_color;

        case FL_POPUP_DISABLED_TEXT_COLOR :
            return popup ? popup->text_off_color : popup_text_off_color;

        case FL_POPUP_RADIO_COLOR :
            return popup ? popup->radio_color : popup_radio_color;

    }

    M_err( "fl_popup_get_color", "Invalid color type argument" );
    return FL_BLACK;
}


/***************************************
 * Set one of the colors of the popup (NULL sets the default)
 ***************************************/

FL_COLOR
fl_popup_set_color( FL_POPUP * popup,
                    int        color_type,
                    FL_COLOR   color )
{
    FL_COLOR old_color;

    /* Check if the popup exists */

    if ( popup != NULL && fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_color", "Invalid popup argument" );
        return FL_MAX_COLORS;
    }

    if ( color >= FL_MAX_COLORS )
    {
        M_err( "fl_popup_set_color", "Invalid color argument" );
        return FL_MAX_COLORS;
    }

    switch ( color_type )
    {
        case FL_POPUP_BACKGROUND_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->bg_color;
                popup->bg_color = color;
            }
            else
            {
                old_color = popup_bg_color;
                popup_bg_color = color;
            }
            break;

        case FL_POPUP_HIGHLIGHT_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->on_color;
                popup->on_color = color;
            }
            else
            {
                old_color = popup_on_color;
                popup_on_color = color;
            }
            break;

        case FL_POPUP_TITLE_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->title_color;
                popup->title_color = color;
            }
            else
            {
                old_color = popup_title_color;
                popup_title_color = color;
            }
            break;

        case FL_POPUP_TEXT_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->text_color;
                popup->text_color = color;
            }
            else
            {
                old_color = popup_text_color;
                popup_text_color = color;
            }
            break;

        case FL_POPUP_HIGHLIGHT_TEXT_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->text_on_color;
                popup->text_on_color = color;
            }
            else
            {
                old_color = popup_text_on_color;
                popup_text_on_color = color;
            }
            break;

        case FL_POPUP_DISABLED_TEXT_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->text_off_color;
                popup->text_off_color = color;
            }
            else
            {
                old_color = popup_text_off_color;
                popup_text_off_color = color;
            }
            break;

        case FL_POPUP_RADIO_COLOR :
            if ( popup != NULL )
            {
                old_color = popup->radio_color;
                popup->radio_color = color;
            }
            else
            {
                old_color = popup_radio_color;
                popup_radio_color = color;
            }
            break;

        default :
            M_err( "fl_popup_set_color", "Invalid color type argument" );
            return FL_MAX_COLORS;
    }

    return old_color;
}


/***************************************
 * Sets the cursor of a popup (or change the
 * default cursor if called with NULL)
 ***************************************/

void 
fl_popup_set_cursor( FL_POPUP * popup,
                     int        cursor )
{
    if ( popup == NULL )
    {
        popup_cursor = fli_get_cursor_byname( cursor );
        return;
    }

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_set_cursor", "Invalid popup argument" );
        return;
    }

    popup->cursor =  fli_get_cursor_byname( cursor );

    if ( popup->win )
        XDefineCursor( flx->display, popup->win, popup->cursor );
}


/***************************************
 * Set selection callback function for a popup entry
 ***************************************/

FL_POPUP_CB
fl_popup_entry_set_callback( FL_POPUP_ENTRY * entry,
                             FL_POPUP_CB      callback )
{
    FL_POPUP_CB old_cb;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_enter_callback", "Invalid entry argument" );
        return NULL;
    }

    old_cb = entry->callback;
    entry->callback = callback;
    return old_cb;
}


/***************************************
 * Set enter callback function for a popup entry
 ***************************************/

FL_POPUP_CB
fl_popup_entry_set_enter_callback( FL_POPUP_ENTRY * entry,
                                   FL_POPUP_CB      callback )
{
    FL_POPUP_CB old_cb;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_enter_callback", "Invalid entry argument" );
        return NULL;
    }

    old_cb = entry->enter_callback;
    entry->enter_callback = callback;
    return old_cb;
}


/***************************************
 * Set leave callback function for a popup entry
 ***************************************/

FL_POPUP_CB
fl_popup_entry_set_leave_callback( FL_POPUP_ENTRY * entry,
                                   FL_POPUP_CB      callback )
{
    FL_POPUP_CB old_cb;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_leave_callback", "Invalid entry argument" );
        return NULL;
    }

    old_cb = entry->leave_callback;
    entry->leave_callback = callback;
    return old_cb;
}


/***************************************
 * Get state (disabled, hidden, checked) of a popup entry
 ***************************************/

unsigned int
fl_popup_entry_get_state( FL_POPUP_ENTRY * entry )
{
    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_get_state", "Invalid entry argument" );
        return UINT_MAX;
    }

    return entry->state;
}


/***************************************
 * Set state (disabled, hidden, checked) of a popup entry
 ***************************************/

unsigned int
fl_popup_entry_set_state( FL_POPUP_ENTRY * entry,
                          unsigned int     state )
{
    unsigned int old_state;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_state", "Invalid entry argument" );
        return UINT_MAX;
    }

    /* Nothing to be done if new and old state are identical */

    if ( entry->state == state )
        return state;

    old_state = entry->state;
    entry->state = state;

    /* If the entry gets disabled or hidden we may have to switch off it's
       "activated" state - don't call leave callback in this case */

    if ( entry->state & ( FL_POPUP_DISABLED | FL_POPUP_HIDDEN ) )
        entry->is_act = 0;

    /* If a radio entry gets checked uncheck all radio other entries belonging
       to the same group in the popup */

    if ( entry->type == FL_POPUP_RADIO && state & FL_POPUP_CHECKED )
    {
        FL_POPUP_ENTRY *e;

        for ( e = entry->popup->entries; e != NULL; e = e->next )
            if (    e->type == FL_POPUP_RADIO
                 && entry->group == e->group
                 && entry != e )
                e->state &= ~ FL_POPUP_CHECKED;
    }

    /* If the entry was hidden or made visible again the dimensions of the
       popup need to be recalculated */

    if ( ( old_state & FL_POPUP_HIDDEN ) ^ ( state & FL_POPUP_HIDDEN ) )
         entry->popup->need_recalc = 1;

    /* If the popup the entry belongs to is visible redraw the popup */

    if ( entry->popup->win != None )
        draw_popup( entry->popup );

    return old_state;
}


/***************************************
 * Clear certain bits of an entries state
 ***************************************/

unsigned int
fl_popup_entry_clear_state( FL_POPUP_ENTRY * entry,
                            unsigned int     what )
{
    unsigned int old_state;
    size_t i;
    unsigned int flags[ ] = { FL_POPUP_DISABLED,
                              FL_POPUP_HIDDEN,
                              FL_POPUP_CHECKED };

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_clear_state", "Invalid entry argument" );
        return UINT_MAX;
    }

    old_state = entry->state;

    for ( i = 0; i < sizeof flags / sizeof *flags; i++ )
        if ( what & flags[ i ] )
            fl_popup_entry_set_state( entry, entry->state & ~ flags[ i ] );

    return old_state;
}


/***************************************
 * Set certain bits of an entrys state
 ***************************************/

unsigned int
fl_popup_entry_raise_state( FL_POPUP_ENTRY * entry,
                            unsigned int     what )
{
    unsigned int old_state;
    size_t i;
    unsigned int flags[ ] = { FL_POPUP_DISABLED,
                              FL_POPUP_HIDDEN,
                              FL_POPUP_CHECKED };

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_raise_state", "Invalid entry argument" );
        return UINT_MAX;
    }

    old_state = entry->state;

    for ( i = 0; i < sizeof flags / sizeof *flags; i++ )
        if ( what & flags[ i ] )
            fl_popup_entry_set_state( entry, entry->state | flags[ i ] );

    return old_state;
}


/***************************************
 * Toggle certain bits of an entries state
 ***************************************/

unsigned int
fl_popup_entry_toggle_state( FL_POPUP_ENTRY * entry,
                             unsigned int     what )
{
    unsigned int old_state;
    size_t i;
    unsigned int flags[ ] = { FL_POPUP_DISABLED,
                              FL_POPUP_HIDDEN,
                              FL_POPUP_CHECKED };

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_toggle_state", "Invalid entry argument" );
        return UINT_MAX;
    }

    old_state = entry->state;

    for ( i = 0; i < sizeof flags / sizeof *flags; i++ )
        if ( what & flags[ i ] )
            fl_popup_entry_set_state( entry, entry->state ^ flags[ i ] );

    return old_state;
}


/***************************************
 * Set the value associated with an entry
 ***************************************/

long
fl_popup_entry_set_value( FL_POPUP_ENTRY * entry,
                          long             value )
{
    long old_val;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_value", "Invalid entry argument" );
        return INT_MIN;
    }

    old_val = entry->val;
    entry->val = value;
    return old_val;
}


/***************************************
 * Set the user data pointer associated with an entry
 ***************************************/

void *
fl_popup_entry_set_user_data( FL_POPUP_ENTRY * entry,
                              void           * user_data )
{
    void *old_user_data;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_user_data", "Invalid entry argument" );
        return NULL;
    }

    old_user_data = entry->user_data;
    entry->user_data = user_data;
    return old_user_data;
}


/***************************************
 * Returns the group a radio entry belongs to.
 * Returns group number on success and INT_MAX on failure.
 ***************************************/

int
fl_popup_entry_get_group( FL_POPUP_ENTRY * entry )
{
    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_get_group", "Invalid entry argument" );
        return INT_MAX;
    }

    return entry->group;
}


/***************************************
 * Set a new group a radio entry
 * Returns old group number on success and INT_MAX on failure.
 ***************************************/

int
fl_popup_entry_set_group( FL_POPUP_ENTRY * entry,
                          int              group )
{
    int old_group;
    FL_POPUP_ENTRY *e;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_group", "Invalid entry argument" );
        return INT_MAX;
    }

    old_group = entry->group;

    if ( entry->type != FL_POPUP_RADIO )
    {
        entry->group = group;
        return old_group;
    }

    if ( old_group == group )
        return entry->group;

    for ( e = entry; e != NULL; e = e->next )
        if ( e->type == FL_POPUP_RADIO
             && e->group == group
             && e->state & FL_POPUP_CHECKED )
            entry->state &= ~ FL_POPUP_CHECKED;

    entry->group = group;
    return old_group;
}


/***************************************
 * Returns the sub-popup for a sub-popup entry.
 * Returns the sub-popups address on success and NULL on failure.
 ***************************************/

FL_POPUP *
fl_popup_entry_get_subpopup( FL_POPUP_ENTRY * entry )
{
    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_get_subpopup", "Invalid entry argument" );
        return NULL;
    }

    if ( entry->type != FL_POPUP_SUB )
    {
        M_err( "fl_popup_entry_get_subpopup", "Entry isn't a subpopup entry" );
        return NULL;
    }

    return entry->sub;
}


/***************************************
 * Set a new sub-popup for an entry, requires that this a sub-popup entry.
 * Returns the new sub-popups address on success and NULL on failure.
 ***************************************/

FL_POPUP *
fl_popup_entry_set_subpopup( FL_POPUP_ENTRY * entry,
                             FL_POPUP       * subpopup )
{
    FL_POPUP *old_sub;

    if ( fli_check_popup_entry_exists( entry ) )
    {
        M_err( "fl_popup_entry_set_subpopup", "Invalid entry argument" );
        return NULL;
    }

    if ( entry->type != FL_POPUP_SUB )
    {
        M_err( "fl_popup_entry_set_subpopup", "Entry isn't a subpopup entry" );
        return NULL;
    }
        
    if ( entry->sub == subpopup )
        return entry->sub;

    if ( entry->sub->win != None || subpopup->win != None )
    {
        M_err( "fl_popup_entry_set_subpopup", "Can't change sub-popup while "
               "entries sub-popup is shown.");
        return NULL;
    }

    old_sub = entry->sub;
    entry->sub = subpopup;
    if ( check_sub( entry ) )
    {
        entry->sub = old_sub;
        M_err( "fl_popup_entry_set_subpopup", "Invalid sub-popup argument" );
        return NULL;
    }

    fl_popup_delete( entry->sub );
    return entry->sub = subpopup;
}


/***************************************
 * Find a popup entry by its position in the popup, starting at 1.
 * (Line entries aren't counted, but hidden entries are.)
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_position( FL_POPUP * popup,
                                int        position )
{
    FL_POPUP_ENTRY *e;
    int i = 0;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_get_by_position", "Invalid popup argument" );
        return NULL;
    }

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->type == FL_POPUP_LINE )
            continue;

        if ( i++ == position )
            return e;
    }

    return NULL;
}


/***************************************
 * Find a popup entry by its value
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_value( FL_POPUP * popup,
                             long       val )
{
    FL_POPUP_ENTRY *e,
                   *r;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_get_by_value", "Invalid popup argument" );
        return NULL;
    }

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->type == FL_POPUP_LINE )
            continue;

        if ( e->val == val )
            return e;

        if (    e->type == FL_POPUP_SUB
             && ( r = fl_popup_entry_get_by_value( e->sub, val ) ) )
            return r;
    }

    return NULL;
}


/***************************************
 * Find a popup entry by its user data
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_user_data( FL_POPUP * popup,
                                 void     * user_data )
{
    FL_POPUP_ENTRY *e,
                   *r;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_get_by_value", "Invalid popup argument" );
        return NULL;
    }

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->type == FL_POPUP_LINE )
            continue;

        if ( e->user_data == user_data )
            return e;

        if (    e->type == FL_POPUP_SUB
             && ( r = fl_popup_entry_get_by_user_data( e->sub, user_data ) ) )
            return r;
    }

    return NULL;
}


/***************************************
 * Find a popup entry by its text
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_text( FL_POPUP   * popup,
                            const char * text )
{
    FL_POPUP_ENTRY *e,
                   *r;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_get_by_text", "Invalid popup argument" );
        return NULL;
    }

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->type == FL_POPUP_LINE )
            continue;

        if ( ! strcmp( e->text, text ) )
            return e;

        if (    e->type == FL_POPUP_SUB
             && ( r = fl_popup_entry_get_by_text( e->sub, text ) ) )
            return r;
    }

    return NULL;
}


/***************************************
 * Find a popup entry by its text
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_text_f( FL_POPUP   * popup,
                              const char * fmt,
                              ... )
{
    FL_POPUP_ENTRY *e;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    e = fl_popup_entry_get_by_text( popup, buf );
    fl_free( buf );
    return e;
}


/***************************************
 * Find a popup entry by its label
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_label( FL_POPUP   * popup,
                             const char * label )
{
    FL_POPUP_ENTRY *e,
                   *r;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_entry_get_by_label", "Invalid popup argument" );
        return NULL;
    }

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->type == FL_POPUP_LINE || e->label == NULL )
            continue;

        if ( ! strcmp( e->label, label ) )
            return e;

        if (    e->type == FL_POPUP_SUB
             && ( r = fl_popup_entry_get_by_label( e->sub, label ) ) )
            return r;
    }

    return NULL;
}


/***************************************
 * Find a popup entry by its label
 ***************************************/

FL_POPUP_ENTRY *
fl_popup_entry_get_by_label_f( FL_POPUP   * popup,
                               const char * fmt,
                               ... )
{
    FL_POPUP_ENTRY *e;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    e = fl_popup_entry_get_by_label( popup, buf );
    fl_free( buf );
    return e;
}


/***************************************
 * Get size of a popup, returns 0 on success and -1 on error
 ***************************************/

int
fl_popup_get_size( FL_POPUP     * popup,
                   unsigned int * w,
                   unsigned int * h )
{
    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_size", "Invalid popup argument" );
        return -1;
    }

    if ( popup->need_recalc )
        recalc_popup( popup );

    *w = popup->w;
    *h = popup->h;

    return 0;
}


/***************************************
 * Get minimum width of a popup
 ***************************************/

int
fl_popup_get_min_width( FL_POPUP * popup )
{
    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_size", "Invalid popup argument" );
        return -1;
    }

    if ( popup->need_recalc )
        recalc_popup( popup );

    return popup->min_width;
}


/***************************************
 * Set minimum width of a popup
 ***************************************/

int
fl_popup_set_min_width( FL_POPUP * popup,
                        int        min_width )
{
    int old_min_width;

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_popup_get_size", "Invalid popup argument" );
        return -1;
    }

    old_min_width = popup->min_width;

    if ( min_width < 0 )
        min_width = 0;

    popup->min_width = min_width;
    popup->need_recalc = 1;

    return old_min_width;
}


/***************************************
 * Set up a linked list of entries for a popup according to a string
 * and optional arguments. The resulting list then can be merged into
 * an already existing list of entries of the popup. The 'simple'
 * argument, when set, says that the new entry can't be a sub-entry,
 * a toggle, line or radio entry.
 ***************************************/

static FL_POPUP_ENTRY *
parse_entries( FL_POPUP   * popup,
               char       * str,
               va_list      ap,
               const char * caller,
               int          simple )
{
    FL_POPUP_ENTRY *entry,
                   *entry_first = NULL;
    char *c,
         *s,
         *sc = NULL,
         *acc = NULL;

    /* Split the string at '|' and create a new entry for each part */

    for ( c = strtok( str, "|" ); c != NULL; c = strtok( NULL, "|" ) )
    {
        /* Allocate a new entry and append it to the list of new entries */

        if ( ( entry = fl_malloc( sizeof *entry ) ) == NULL )
        {
            M_err( caller, "Running out of memory" );
            return failed_add( entry_first );
        }

        if ( entry_first == NULL )
        {
            entry_first = entry;
            entry->prev = NULL;
        }
        else
        {
            FL_POPUP_ENTRY *e;

            for ( e = entry_first; e->next != NULL; e = e->next )
                /* empty */;

            e->next = entry;
            entry->prev = e;
        }

        entry->next = NULL;

        entry->label = NULL;
        entry->accel = NULL;

        /* The text field is exactly what the user gave us */

        if ( ( entry->text = fl_strdup( c ) ) == NULL )
        {
            M_err( caller, "Running out of memory" );
            return failed_add( entry_first );
        }

        /* Set some default values */

        entry->user_data = NULL;
        entry->val = popup->counter++;

        entry->is_act   = 0;
        entry->type     = FL_POPUP_NORMAL;
        entry->state    = 0;

        entry->shortcut = NULL;
        entry->ulpos    = -1;

        entry->callback = NULL;
        entry->enter_callback = NULL;
        entry->leave_callback = NULL;
        entry->sub = NULL;
        entry->popup = popup;

        /* Now analyze the string for the entry */

        s = c;
        while ( ( s = strchr( s, '%' ) ) != NULL )
        {
            switch ( s[ 1 ] )
            {
                case '%' :
                    memmove( s, s + 1, strlen( s ) );
                    s++;
                    break;

                case 'x' :           /* set a value */
                    entry->val = va_arg( ap, long );
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'u' :           /* set pointer to user data */
                    entry->user_data = va_arg( ap, void * );
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'f' :           /* set callback function */
                    entry->callback = va_arg( ap, FL_POPUP_CB );
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'E' :           /* set enter callback function */
                    entry->enter_callback = va_arg( ap, FL_POPUP_CB );
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'L' :           /* set leave callback function */
                    entry->leave_callback = va_arg( ap, FL_POPUP_CB );
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'm' :           /* set a submenu */
                    if ( entry->type != FL_POPUP_NORMAL )
                    {
                        M_err( caller, "Entry can't be submenu and something "
                               "else" );
                        return failed_add( entry_first );
                    }

                    entry->sub = va_arg( ap, FL_POPUP * );

                    if ( ! simple )
                    {
                        if ( check_sub( entry ) )
                        {
                            M_err( caller, "Invalid submenu popup" );
                            return failed_add( entry_first );
                        }

                        entry->type = FL_POPUP_SUB;
                        entry->sub->parent = popup;
                    }
                    else
                        entry->sub = NULL;

                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'l' :           /* set up entry as a line entry */
                    if ( entry->type != FL_POPUP_NORMAL )
                    {
                        M_err( caller, "Entry can't be a line marker and "
                               "something else" );
                        return failed_add( entry_first );
                    }

                    entry->type = FL_POPUP_LINE;
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;
                    
                case 'T' :           /* set up as toggle entry */
                case 't' :
                    if ( entry->type != FL_POPUP_NORMAL )
                    {
                        M_err( caller, "Entry can't be a toggle entry and "
                               "something else" );
                        return failed_add( entry_first );
                    }

                    if ( ! simple )
                    {
                        entry->type = FL_POPUP_TOGGLE;
                        if ( s[ 1 ] == 'T' )
                            entry->state |= FL_POPUP_CHECKED;
                    }
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'R' :           /* set up as radio entry */
                case 'r' :           /* set up as radio entry */
                    if ( entry->type != FL_POPUP_NORMAL )
                    {
                        M_err( caller, "Entry can't be radio entry and "
                               "something else" );
                        return failed_add( entry_first );
                    }

                    entry->group = va_arg( ap, int );

                    if ( ! simple )
                    {
                        entry->type = FL_POPUP_RADIO;
                        if ( s[ 1 ] == 'R' )
                            entry->state |= FL_POPUP_CHECKED;
                    }

                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'd' :           /* mark entry as disabled */
                    entry->state |= FL_POPUP_DISABLED;
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'h' :           /* mark entry as hidden */
                    entry->state |= FL_POPUP_HIDDEN;
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 's' :           /* set a shortcut */
                    sc = va_arg( ap, char * );
                    memmove( s, s + 2, strlen( s + 1 ) );
                    break;

                case 'S' :
                    if ( acc != NULL )
                    {
                        M_err( caller, "'%%S' sequence found more than once in "
                               "entry definition" );
                        return failed_add( entry_first );
                    }
                    *s++ = '\0';
                    acc = ++s;
                    break;

                default :
                    M_err( caller, "Invalid flag '%%%c'", s[ 1 ] );
                    return failed_add( entry_first );
            }
        }

        /* If we're asked to create simple popup (for a FL_SELECT object)
           remove the entry again if it's a line entry */

        if ( simple && entry->type == FL_POPUP_LINE )
        {
            if ( entry->prev != NULL )
                entry->prev->next = NULL;
            else
                entry_first = NULL;
            fl_free( entry );

            popup->counter--;

            continue;
        }

        /* Now all flags should be removed from text string, so we can set
           the entries label and accelerator key text after also removing
           backspace characters and replacing tabs by spaces. */

        cleanup_string ( c );

        if ( ! *c )
            entry->label = NULL;
        else if ( ( entry->label = fl_strdup( c ) ) == NULL )
        {
            M_err( caller, "Running out of memory" );
            return failed_add( entry_first );
        }       

        acc = cleanup_string( acc );

        if ( ! acc || ! *acc )
            entry->accel = NULL;
        else if ( ( entry->accel = fl_strdup( acc ) ) == NULL )
        {
            M_err( caller, "Running out of memory" );
            return failed_add( entry_first );
        }

        acc = NULL;

        /* Having the text we can set up the shortcuts */

        if ( sc )
        {
            convert_shortcut( sc, entry );
            sc = NULL;
        }
    }

    /* Make sure the settings for radio entries are consistent, i.e. only
       a single one of a group (taking both the already existing as well
       as the new ones into account) is set (the last created wins) */

    for ( entry = entry_first; entry != NULL; entry = entry->next )
        if ( entry->type == FL_POPUP_RADIO && entry->state * FL_POPUP_CHECKED )
            radio_check( entry );

    /* List is complete and the caller can link it into its list */

    return entry_first;
}


/***************************************
 * Called when adding popup entries fails due to whatever reasons
 * to get rid of all already created ones
 ***************************************/

static FL_POPUP_ENTRY *
failed_add( FL_POPUP_ENTRY * first )
{
    FL_POPUP_ENTRY *e;

    while ( first )
    {
        e = first->next;
        fl_popup_entry_delete( first );
        first = e;
    }

    return NULL;
}


/***************************************
 * Checks if a popup is suitable for use as a sub-popup
 ***************************************/

static int
check_sub( FL_POPUP_ENTRY * entry )
{
    /* Sub-popup can't be NULL */

    if ( entry->sub == NULL )
        return 1;

    /* Check if the sub-popup exists */

    if ( fli_check_popup_exists( entry->sub ) )
        return 1;

    /* The sub-popup can't be the entries popup itself */

    if ( entry->popup == entry->sub )
        return 1;

    /* The sub-popup can not already be a sub-popup for some other entry */

    if ( entry->sub->parent )
        return 1;

    return 0;
}


/***************************************
 * Go through all entries of a popup and resets the checked state of
 * all other entries belonging to the same group before the one we
 * were called with.
 ***************************************/

static void
radio_check( FL_POPUP_ENTRY * entry )
{
    FL_POPUP_ENTRY *e;

    /* First reset (if necessary) the old ones */

    for ( e = entry->popup->entries; e != NULL; e = e->next )
        if (    e->type == FL_POPUP_RADIO
             && e != entry
             && entry->group == e->group )
            e->state &= ~ FL_POPUP_CHECKED;

    /* Also reset all the new ones (except the one we were called for) */ 

    for ( e = entry->prev; e != NULL; e = e->prev )
        if ( e->type == FL_POPUP_RADIO
             && e != entry
             && entry->group == e->group )
            e->state &= ~ FL_POPUP_CHECKED;
}       


/***************************************
 * Makes a shortcut out of an entries text and determines where to underline
 ***************************************/

static void
convert_shortcut( const char     * shortcut,
                  FL_POPUP_ENTRY * entry )
{
    long sc[ MAX_SHORTCUTS + 1 ];
    int cnt;

    if (    entry->label && *entry->label
         && ( ! entry->accel || ! *entry->accel ) )
        entry->ulpos = fli_get_underline_pos( entry->label, shortcut ) - 1;
    else
        entry->ulpos = -1;

    cnt = fli_convert_shortcut( shortcut, sc );

    fli_safe_free( entry->shortcut );
    entry->shortcut = fl_malloc( ( cnt + 1 ) * sizeof *entry->shortcut );
    memcpy( entry->shortcut, sc, ( cnt + 1 ) * sizeof *entry->shortcut );
}


/***************************************
 * Recalculate the dimensions of a popup and the positions of the entries
 ***************************************/

static void
recalc_popup( FL_POPUP * popup )
{
    FL_POPUP_ENTRY *e;
    int offset =   FL_abs( popup->top_parent->bw )
                 + ( popup->top_parent->bw > 0 ? 1 : 0 );
    unsigned int cur_w = 0,
                 cur_h = offset,
                 w,
                 h;

    title_dimensions( popup, &w, &h );

    if ( w > 0 )
    {
        /* Note: title box should always have a bit of spacing to the top
           of the window */

        popup->title_box_x = offset + OUTER_PADDING_LEFT;
        popup->title_box_y = offset + FL_max( OUTER_PADDING_TOP, 3 );

        cur_w = w + INNER_PADDING_LEFT + INNER_PADDING_RIGHT;
        popup->title_box_h = h + INNER_PADDING_TOP + INNER_PADDING_BOTTOM;
        cur_h +=   popup->title_box_h
                 + FL_max( OUTER_PADDING_TOP, 3 ) + OUTER_PADDING_BOTTOM + 2;
    }

    popup->has_subs = 0;
    popup->has_boxes = 0;

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->state & FL_POPUP_HIDDEN )
            continue;

        e->box_x = offset + OUTER_PADDING_LEFT;
        e->box_y = cur_h;

        entry_text_dimensions( e, &w, &h );

        cur_w = FL_max( cur_w, w );
        cur_h += e->box_h = h + OUTER_PADDING_TOP + OUTER_PADDING_BOTTOM;

        if ( e->type == FL_POPUP_TOGGLE || e->type == FL_POPUP_RADIO )
            popup->has_boxes = 1;
        else if ( e->type == FL_POPUP_SUB )
            popup->has_subs = 1;
    }

    if ( popup->has_boxes )
        cur_w += popup->top_parent->entry_font_size + SYMBOL_PADDING;

    if ( popup->has_subs )
        cur_w += SYMBOL_PADDING + popup->top_parent->entry_font_size;

    popup->w = cur_w + 2 * offset + OUTER_PADDING_LEFT + OUTER_PADDING_RIGHT;
    popup->h = cur_h + offset + 1;

    popup->w = FL_max( popup->w, ( unsigned int ) popup->min_width );
    popup->title_box_w =   popup->w - 2 * offset
                         - OUTER_PADDING_LEFT - OUTER_PADDING_RIGHT;

    popup->need_recalc = 0;
}


/***************************************
 * Calculate the dimensions of the title
 ***************************************/

static void
title_dimensions( FL_POPUP     * popup,
                  unsigned int * w,
                  unsigned int * h )
{
    FL_POPUP *ptp = popup->top_parent;
    char *s,
         *c;
    int dummy;

    if ( popup->title == NULL )
    {
        *w = *h = 0;
        return;
    }

    s = c = fl_strdup( popup->title );

    /* Now calculate the dimensions of the string */

    *w = 0;
    *h = 0;

    for ( c = strtok( s, "\n" ); c != NULL; c = strtok( NULL, "\n" ) )
    {
        *w = FL_max( *w, ( unsigned int )
                     fl_get_string_width( ptp->title_font_style,
                                          ptp->title_font_size,
                                          c, strlen( c ) ) );
        *h += fl_get_string_height( ptp->title_font_style,
                                    ptp->title_font_size,
                                    c, strlen( c ), &dummy, &dummy );
    }

    fl_free( s );

    /* Add offsets the string drawing function will add */

    *w += 2 * STR_OFFSET_X;
    *h += 2 * STR_OFFSET_Y;
}


/***************************************
 * Calculate the (minimum) dimensions of an entry
 ***************************************/

static void
entry_text_dimensions( FL_POPUP_ENTRY * entry,
                       unsigned int   * w,
                       unsigned int   * h )
{
    FL_POPUP *ptp = entry->popup->top_parent;
    char *s,
         *c;
    int ulpos = entry->ulpos;
    XRectangle *xr;
    int asc;
    int dummy;

    *w = *h = 0;

    if ( entry->type == FL_POPUP_LINE )
    {
        *h = LINE_HEIGHT;
        return;
    }

    /* Determine length and height of label string */

    if ( entry->label && *entry->label )
    {
        s = c = fl_strdup( entry->label );

        /* Calculate the dimensions of the label (always use the font of the
           top-most parent) */

        for ( c = strtok( s, "\n" ); c != NULL; c = strtok( NULL, "\n" ) )
        {
            unsigned int old_h = *h;

            *w = FL_max( *w, ( unsigned int )
                         fl_get_string_width( ptp->entry_font_style,
                                              ptp->entry_font_size,
                                              c, strlen( c ) ) );
            *h += fl_get_string_height( ptp->entry_font_style,
                                        ptp->entry_font_size,
                                        c, strlen( c ), &asc, &dummy );

            if ( c == s )
                entry->sl_h = *h;

            /* Not very nice hack to get the underline position */

            if ( ulpos >= 0 )
            {
                if ( ulpos < ( int ) strlen( c ) )
                {
                    xr = fli_get_underline_rect(
                                    fl_get_font_struct( ptp->entry_font_style,
                                                        ptp->entry_font_size ),
                                    0, asc, c, ulpos );
                    entry->ul_x = xr->x + STR_OFFSET_X;
                    entry->ul_y = old_h + xr->y + STR_OFFSET_Y;
                    entry->ul_w = xr->width; 
                    entry->ul_h = xr->height; 
                }

                ulpos -= strlen( c ) + 1;
            }
        }

        fli_safe_free( s );
    }

    /* Repeat this for the accelerator key text (minimum spacing between this
       and the label is 1.5 times the font size) */

    if ( entry->accel && *entry->accel )
    {
        unsigned int aw = 0,
                     ah = 0;

        *w += 1.5 * ptp->entry_font_size;

        s = c = fl_strdup( entry->accel );

        for ( c = strtok( s, "\n" ); c != NULL; c = strtok( NULL, "\n" ) )
        {
            aw = FL_max( aw, ( unsigned int )
                         fl_get_string_width( ptp->entry_font_style,
                                              ptp->entry_font_size,
                                              c, strlen( c ) ) );
            ah += fl_get_string_height( ptp->entry_font_style,
                                        ptp->entry_font_size,
                                        c, strlen( c ), &dummy, &dummy );
        }

        fli_safe_free( s );

        *w += aw;
        *h = FL_max( *h, ah );
    }

    *w += 2 * STR_OFFSET_X;
    *h += 2 * STR_OFFSET_Y;
}


/***************************************
 * Draw a popup
 ***************************************/

static void
draw_popup( FL_POPUP * popup )
{
    FL_POPUP_ENTRY *e;

    /* If necessary recalculate the size of the popup window and,
       if it's already shown, resize it */

    if ( popup->need_recalc )
    {
        unsigned int old_w = popup->w,
                     old_h = popup->h;

        recalc_popup( popup );

        if (    popup->win != None
             && ( popup->w != old_w || popup->h != old_h ) )
            XResizeWindow( flx->display, popup->win, popup->w, popup->h );
    }

    /* If necessary create and map the popup window, otherwise just draw it
       (no drawing needed when the window gets opened, we will receive an
       Expose event that will induce the drawing) */

    if ( popup->win == None )
        create_popup_window( popup );
    else
    {
        /* Draw the popup box  */

        fl_draw_box( FL_UP_BOX, 0, 0, popup->w, popup->h, popup->bg_color,
                     popup->top_parent->bw );

        /* Draw the title and all entries */

        draw_title( popup );

        for ( e = popup->entries; e != NULL; e = e->next )
            draw_entry( e );
    }
}


/***************************************
 * Draws the title of a popup
 ***************************************/

static void
draw_title( FL_POPUP * popup )
{
    FL_POPUP *ptp = popup->top_parent;

    if ( popup->title == NULL )
        return;

    /* Draw a box with a frame around the title */

    fl_draw_box( FL_FRAME_BOX, popup->title_box_x - 1, popup->title_box_y - 1,
                 popup->title_box_w + 2, popup->title_box_h + 2,
                 ptp->bg_color, 1 );

    fl_draw_text( FL_ALIGN_CENTER, popup->title_box_x, popup->title_box_y,
                  popup->title_box_w, popup->title_box_h, ptp->title_color,
                  ptp->title_font_style, ptp->title_font_size, popup->title );
}


/***************************************
 * Draws an entry of a popup
 ***************************************/

static void
draw_entry( FL_POPUP_ENTRY * entry )
{
    FL_POPUP *p = entry->popup,
             *ptp = p->top_parent;
    FL_COLOR color;
    int offset = FL_abs( ptp->bw ) + ( ptp->bw > 0 ? 1 : 0 );
    int x;
    unsigned int w;

    /* Hidden entries need no further work */

    if ( entry->state & FL_POPUP_HIDDEN )
        return;

    /* Calculate the width of the box we're going to be drawning in */

    x = entry->box_x;
    w = entry->box_w =   p->w - 2 * offset
                       - OUTER_PADDING_LEFT - OUTER_PADDING_RIGHT;

    /* For entries that just stand for separating lines draw that line
       and be done with it */

    if ( entry->type == FL_POPUP_LINE )
    {
        fl_draw_box( FL_DOWN_BOX, x, entry->box_y + OUTER_PADDING_TOP + 1,
                     w, LINE_HEIGHT - 1, ptp->bg_color, 1 );
        return;
    }

    /* Draw the background of the entry */

    fl_rectangle( 1, offset, entry->box_y, p->w - 2 * offset - 1, entry->box_h,
                  entry->is_act ? ptp->on_color : ptp->bg_color );

    /* Find out what color the text is to be drawn in */

    if ( entry->state & FL_POPUP_DISABLED )
        color = ptp->text_off_color;
    else
        color = entry->is_act ? ptp->text_on_color : ptp->text_color;

    /* If there are radio/toggle entries extra space at the start is needed.
       For checked toggle items a check mark is drawn there and for radio
       items a circle */

    if ( p->has_boxes )
    {
        if ( entry->type == FL_POPUP_RADIO )
            fl_draw_box( FL_ROUNDED3D_DOWNBOX, x + 0.2 * entry->sl_h,
                         entry->box_y + 0.25 * entry->sl_h + STR_OFFSET_Y,
                         0.5 * entry->sl_h, 0.5 * entry->sl_h,
                         entry->state & FL_POPUP_CHECKED ?
                         ptp->radio_color : ptp->bg_color, 1 );
        else if ( entry->state & FL_POPUP_CHECKED )
        {
            FL_POINT xp[ 3 ];

            xp[ 0 ].x = x + 0.25 * entry->sl_h;
            xp[ 0 ].y = entry->box_y + 0.5 * entry->sl_h + STR_OFFSET_Y;
            xp[ 1 ].x = xp[ 0 ].x + 0.2 * entry->sl_h;
            xp[ 1 ].y = xp[ 0 ].y + 0.25 * entry->sl_h;
            xp[ 2 ].x = xp[ 1 ].x + 0.2 * entry->sl_h;
            xp[ 2 ].y = xp[ 1 ].y - 0.5 * entry->sl_h;

            fl_lines( xp, 3, color );

            xp[ 2 ].x += 1;

            fl_lines( xp + 1, 2, color );
        }

        w -= ptp->entry_font_size + SYMBOL_PADDING;
        x += ptp->entry_font_size + SYMBOL_PADDING;;
    }

    /* If there are sub-popups we need some extra space at the end of the
       entries and for sub-popups entries a triangle at the end */

    if ( p->has_subs )
    {
        if ( entry->type == FL_POPUP_SUB )
        {
            FL_POINT xp[ 4 ];

            xp[ 0 ].x = x + w - 0.125 * entry->sl_h;
            xp[ 0 ].y = entry->box_y + 0.5 * entry->box_h;
            xp[ 1 ].x = xp[ 0 ].x - 0.35355 * entry->sl_h;
            xp[ 1 ].y = xp[ 0 ].y - 0.25 * entry->sl_h;
            xp[ 2 ].x = xp[ 1 ].x;
            xp[ 2 ].y = xp[ 1 ].y + 0.5 * entry->sl_h;

            fl_polygon( 1, xp, 3, color );
        }
        
        w -= ptp->entry_font_size + SYMBOL_PADDING;
    }

    /* Finally it's time to draw the label and accelerator. Underlining is not
       done via the "normal" functions since they are too much of a mess...*/

    if ( entry->label && *entry->label )
    {
        fl_draw_text( FL_ALIGN_LEFT_TOP, x, entry->box_y, w, entry->box_h,
                      color, ptp->entry_font_style, ptp->entry_font_size,
                      entry->label );
        if ( entry->ulpos >= 0 )
            fl_rectangle( 1, x + entry->ul_x, entry->box_y + entry->ul_y ,
                          entry->ul_w, entry->ul_h, color );
    }

    if ( entry->accel && *entry->accel )
        fl_draw_text( FL_ALIGN_RIGHT_TOP, x, entry->box_y, w, entry->box_h,
                      color, ptp->entry_font_style, ptp->entry_font_size,
                      entry->accel );
}


/***************************************
 * Figure out where to draw a popup window
 ***************************************/

static void
calculate_window_position( FL_POPUP * popup )
{
    FL_POPUP_ENTRY *e;
    int x, y;
    unsigned int dummy;

    /* If no position has been requested use the mouse position, otherwise
       the requested coordinates. Negatve positions mean relative to right
       edge or botton of the screen. */

    fl_get_mouse( &x, &y, &dummy );

    if ( ! popup->use_req_pos )
    {
        popup->x = x + 1;
        popup->y = y + 1;
    }
    else
    {
        if ( popup->req_x >= 0 )
            popup->x = popup->req_x;
        else
            popup->x = - popup->req_x - popup->w;

        if ( popup->req_y >= 0 )
            popup->y = popup->req_y;
        else
            popup->y = - popup->req_y - popup->h;
    }

    /* Try to make sure the popup is fully on the screen (for sub-popups
       display to the left of the parent popup if necessary) */

    if ( popup->y + ( int ) popup->h > fl_scrh && ! popup->use_req_pos )
        popup->y = popup->y - ( int ) popup->h - 1;

    if ( popup->y + ( int ) popup->h > fl_scrh )
        popup->y = FL_max( fl_scrh - ( int ) popup->h, 0 );

    if ( popup->y < 0 )
        popup->y = 0;

    if ( popup->x + ( int ) popup->w > fl_scrw )
    {
        if ( popup->parent != NULL )
            popup->x = FL_max( popup->parent->x - ( int ) popup->w, 0 );
        else
            popup->x = FL_max( fl_scrw - ( int ) popup->w, 0 );
    }

    if (    ( e = find_entry( popup, x - popup->x, y - popup->y ) ) != NULL
         && ! ( e->state & FL_POPUP_DISABLED ) )
        enter_leave( e, 1 );
}


/***************************************
 * Create the popup's window
 ***************************************/

static void
create_popup_window( FL_POPUP * popup )
{
    XSetWindowAttributes xswa;
    unsigned long vmask;

    /* Figure out where to open the window */

    calculate_window_position( popup );

    /* Create a new window */

    popup->event_mask =   ExposureMask
                        | ButtonPressMask
                        | ButtonReleaseMask
                        | OwnerGrabButtonMask
                        | PointerMotionMask
                        | PointerMotionHintMask
                        | KeyPressMask;

    xswa.event_mask            = popup->event_mask;
    xswa.save_under            = True;
    xswa.backing_store         = WhenMapped;
    xswa.override_redirect     = True;
    xswa.cursor                = popup->cursor;
    xswa.border_pixel          = 0;
    xswa.colormap              = fli_colormap( fl_vmode );
    xswa.do_not_propagate_mask = ButtonPress | ButtonRelease | KeyPress;

    vmask =   CWEventMask     | CWSaveUnder        | CWBackingStore
            | CWCursor        | CWBorderPixel      | CWColormap
            | CWDontPropagate | CWOverrideRedirect;

    popup->win = XCreateWindow( flx->display, fl_root,
                                popup->x, popup->y, popup->w, popup->h, 0,
                                fli_depth( fl_vmode ), InputOutput,
                                fli_visual( fl_vmode ), vmask, &xswa );

    XSetTransientForHint( flx->display, popup->win, fl_root );

    if ( popup->title )
        XStoreName( flx->display, popup->win, popup->title );

    /* Special hack for B&W */

    if ( fli_dithered( fl_vmode ) )
    {
        XGCValues xgcv;
        GC gc;

        xgcv.stipple    = FLI_INACTIVE_PATTERN;
        vmask           = GCForeground | GCFont | GCStipple;
        xgcv.foreground = fl_get_flcolor( popup->text_off_color );
        gc              = XCreateGC( flx->display, popup->win, vmask, &xgcv );
        XSetFillStyle( flx->display, gc, FillStippled );
    }

    XSetWMColormapWindows( flx->display, fl_root, &popup->win, 1 );

    XMapRaised( flx->display, popup->win );
    fl_winset( popup->win );

    grab( popup );
}


/***************************************
 * Grabs both the pointer and the keyboard
 ***************************************/

static void
grab( FL_POPUP * popup )
{
    unsigned int evmask = popup->event_mask;

    /* Set the window we're using */

    fl_winset( popup->win );

    /* Get rid of all non-pointer events in event_mask */

    evmask &= ~ ( ExposureMask | KeyPressMask );
    XSync( flx->display, False );
    XChangeActivePointerGrab( flx->display, evmask,
                              popup->cursor, CurrentTime );

    /* Do pointer and keyboard grab */

    if ( XGrabPointer( flx->display, popup->win, False, evmask, GrabModeAsync,
                       GrabModeAsync, None, popup->cursor, CurrentTime )
                                                                != GrabSuccess )
        M_err( "grab", "Can't grab pointer" );
    else if ( XGrabKeyboard( flx->display, popup->win, False, GrabModeAsync,
                             GrabModeAsync, CurrentTime ) != GrabSuccess )
    {
        M_err( "grab", "Can't grab keyboard" );
        XUngrabPointer( flx->display, CurrentTime );
    }
}


/***************************************
 * Close a popup window
 ***************************************/

static void
close_popup( FL_POPUP * popup,
             int        do_callback )
{
    FL_POPUP_ENTRY *e;
    XEvent ev;

    /* Change grab to parent popup window (if there's one), delete popup
       window and drop all events for it. Sync before waiting for events
       to make sure all events are already in the event queue. */

    if ( popup->parent )
        grab( popup->parent );

    XDestroyWindow( flx->display, popup->win );

    XSync( flx->display, False );

    while ( XCheckWindowEvent( flx->display, popup->win, AllEventsMask, &ev ) )
        /* empty */ ;

    popup->win = None;

    /* We have to redraw forms or popups that received a Expose event due to
       the closing of a sub-popup (at least if the Xserver did not save the
       content under the popups window). Not needed for top-level popups
       since there the normal event loop takes care of this. */

    if (    popup->parent != NULL 
         && ! DoesSaveUnders( ScreenOfDisplay( flx->display, fl_screen ) ) )
    {
        FL_FORM *form;
        FL_POPUP *p;

        while ( XCheckMaskEvent( flx->display, ExposureMask, &ev ) != False )
            if ( ( form = fl_win_to_form( ( ( XAnyEvent * ) &ev )->window ) )
                                                                       != NULL )
            {
                fl_winset( form->window );
                fl_redraw_form( form );
            }
            else
                for ( p = popups; p != NULL; p = p->next )
                    if ( ( ( XAnyEvent * ) &ev )->window == p->win )
                    {
                        fl_winset( p->win );
                        draw_popup( p );
                    }

        fl_winset( popup->parent->win );
    }

    /* Run the leave callback for an active entry if we're asked to */

    for ( e = popup->entries; e != NULL; e = e->next )
        if ( e->is_act )
        {
            if ( do_callback )
                enter_leave( e, 0 );
            else
                e->is_act = 0;
            break;
        }
}


/***************************************
 * Do all the interaction with the popup, also dealing with other
 * background tasks (taking over from the main event loop in forms.c
 * while the popup is shown)
 ***************************************/

static FL_POPUP_RETURN *
popup_interaction( FL_POPUP * popup )
{
    FL_POPUP *p;
    FL_POPUP_ENTRY *e = NULL;
    XEvent ev;
    int timer_cnt = 0;

    ev.xmotion.time = 0;                  /* for fli_handle_idling() */

    while ( 1 )
    {
        long msec = fli_context->idle_delta;

        if ( fli_context->timeout_rec )
            fli_handle_timeouts( &msec );

        /* Check for new event for the popup window, if there's none deal
           with idle tasks */

        if ( ! XCheckWindowEvent( flx->display, popup->win, popup->event_mask,
                                  &ev ) )
        {
            if ( timer_cnt++ % 10 == 0 )
            {
                timer_cnt = 0;
                fli_handle_idling( &ev, msec, 1 );
                fl_winset( popup->win );
            }

            continue;
        }

        timer_cnt = 0;
        fli_int.query_age++;

        switch ( ev.type )
        {
            case Expose :
                draw_popup( popup );
                break;

            case MotionNotify :
                fli_int.mousex    = ev.xmotion.x;
                fli_int.mousey    = ev.xmotion.y;
                fli_int.keymask   = ev.xmotion.state;
                fli_int.query_age = 0;

                fli_compress_event( &ev, PointerMotionMask );
                popup = handle_motion( popup, ev.xmotion.x, ev.xmotion.y );
                break;

            case ButtonRelease :
            case ButtonPress :
                fli_int.mousex    = ev.xbutton.x;
                fli_int.mousey    = ev.xbutton.y;
                fli_int.keymask   = ev.xbutton.state;
                fli_int.query_age = 0;

                /* Don't react to mouse wheel buttons */

                if (    ev.xbutton.button == Button4
                     || ev.xbutton.button == Button5 )
                    break;

                /* Try to find "active" entry */

                e = find_entry( popup, ev.xmotion.x, ev.xmotion.y );

                /* Implement policy: in normal select mode don't react to
                   button release except when on a selectable item. React
                   to button press only when outside of popup(s). */

                if (    popup->top_parent->policy == FL_POPUP_NORMAL_SELECT
                     && ev.type == ButtonRelease
                     && ( e == NULL || e->state & FL_POPUP_DISABLED ) )
                    break;

                if (    ev.type == ButtonPress
                     && is_on_popups( popup, ev.xmotion.x, ev.xmotion.y ) )
                    break;

                /* Close all popups, invoking the leave callbacks if no
                   selection was made */

                for ( p = popup; p != NULL; p = p->parent )
                    close_popup( p, e == NULL );

                return handle_selection( e );

            case KeyPress :
                fli_int.mousex    = ev.xkey.x;
                fli_int.mousey    = ev.xkey.y;
                fli_int.keymask   = ev.xkey.state;
                fli_int.query_age = 0;

                if ( ( p = handle_key( popup, ( XKeyEvent * ) &ev, &e ) ) )
                    popup = p;
                else
                    return handle_selection( e );
        }
    }

    return NULL;
}


/***************************************
 * Returns if the mouse is within a popup window
 ***************************************/

static int
is_on_popups( FL_POPUP * popup,
              int        x,
              int        y )
{
    do
    {
        if (    x >= 0 && x < ( int ) popup->w
             && y >= 0 && y < ( int ) popup->h )
            return 1;

        if ( popup->parent == NULL )
            break;;

        x += popup->x - popup->parent->x;
        y += popup->y - popup->parent->y;
    } while ( ( popup = popup->parent ) != NULL );

    return 0;
}


/***************************************
 * Deals with everything to be done once a selection has been made
 ***************************************/

static FL_POPUP_RETURN *
handle_selection( FL_POPUP_ENTRY * entry )
{
    FL_POPUP *p;
    int cb_result = 1;

    /* If there wasn't a selection or the selected entry is disabled report
       "failure" */

    if (    entry == NULL || entry->state & FL_POPUP_DISABLED )
        return NULL;

    /* Toggle entries must change state */

    if ( entry->type == FL_POPUP_TOGGLE )
    {
        if ( entry->state & FL_POPUP_CHECKED )
            entry->state &= ~ FL_POPUP_CHECKED;
        else
            entry->state |= FL_POPUP_CHECKED;
    }

    /* For a radio entry that wasn't already set the other radio entries for
       the same group must be unset before the selected one becomes set */

    if (    entry->type == FL_POPUP_RADIO
         && ! ( entry->state & FL_POPUP_CHECKED ) )
    {
        FL_POPUP_ENTRY *e;

        for ( e = entry->popup->entries; e != NULL; e = e->next )
            if (    e->type == FL_POPUP_RADIO
                 && e->group == entry->group )
                e->state &= ~ FL_POPUP_CHECKED;
        entry->state |= FL_POPUP_CHECKED;
    }

    /* Set up the structure to be returned and call the entries callback
       function */

    fli_set_popup_return( entry );

    if ( entry->callback )
        cb_result = entry->callback( &entry->popup->top_parent->ret );

    /* Call all popup callback functions (if the selected entry is in a
       sub-popup call that of the sub-popup first, then that of the parent,
       grand-parent etc.). Interrupt chain of callbacks if one of them
       returns FL_IGNORE. */

    for ( p = entry->popup; p && cb_result != FL_IGNORE; p = p->parent )
        if ( p->callback )
        {
            entry->popup->top_parent->ret.popup = p;
            cb_result = p->callback( &entry->popup->top_parent->ret );
        }

    return ( cb_result != FL_IGNORE && entry->popup ) ?
                                        &entry->popup->top_parent->ret : NULL;
}


/***************************************
 * Deal with motion of the mouse
 * Note: the coordinates received are relative to the current popup.
 ***************************************/

static FL_POPUP *
handle_motion( FL_POPUP * popup,
               int        x,
               int        y )
{
    FL_POPUP_ENTRY *e,
                   *ce;

    /* First deal with the situation where the mouse isn't on the popup */

    if (    x < 0 || x >= ( int ) popup->w
         || y < 0 || y >= ( int ) popup->h )
    {
        FL_POPUP *p;

        /* If there was an active entry make it inactive and call its
           leave callback */

        for ( e = popup->entries; e != NULL; e = e->next )
            if ( e->is_act )
            {
                enter_leave( e, 0 );
                break;
            }

        /* Check if we're on a different popup and return if we aren't.
           Coordinates must be transformed to relative to the root window. */

        if ( ( p = find_popup( x + popup->x, y + popup->y ) ) == NULL )
            return popup;

        /* Otherwise first check if we need to shift the window - coordinates
         must now be relative to the new popups window and might be changed by
         the routine */

        x += popup->x - p->x;
        y += popup->y - p->y;

        motion_shift_window( p, &x, &y );

        /* Also check if we're on the entry for the sub-entry we were on
           before. In that case nothing needs to be done yet. Take care:
           find_entry() needs to be called with the coordinates transformed to
           those relative to the other popup. */

        e = find_entry( p, x, y );

        if ( e != NULL && e->type == FL_POPUP_SUB && e->sub == popup )
            return popup;

        /* Otherwise close the current sub-popup, invoking the leave callback
           for an activate entry */

        close_popup( popup, 1 );

        /* We might not have ended up on the parent popup but a parent of
           the parent, in which case also the parent popup must be closed.
           Note that the coordinates must again be transformed so that they
           are now relative to that of the parents window. */

        return handle_motion( popup->parent, x + p->x - popup->parent->x,
                              y + p->y - popup->parent->y );
    }

    /* Check if we need to shift the window */

    motion_shift_window( popup, &x, &y );

    /* Test if the mouse is on a new entry*/

    ce = find_entry( popup, x, y );

    /* If we're still on the same entry as we were on the last call do nothing
       (except for the case that we're on a entry for a sub-popup, in that case
       we've got onto it via the keyboard and the sub-popup isn't open yet) */

    if ( ce != NULL && ce->is_act )
        return ce->type == FL_POPUP_SUB ? open_subpopup( ce ) : popup;

    /* Redraw former active entry as inactive and call its leave callback*/

    for ( e = popup->entries; e != NULL; e = e->next )
        if ( e->is_act )
        {
            enter_leave( e, 0 );
            break;
        }

    /* If we are on a new, non-disabled entry mark it as active and call its
       enter callback. If the new entry is a sub-entry open the corresponding
       sub-popup (per default at the same height as the entry and to the
       right of it.*/

    if ( ce != NULL && ! ( ce->state & FL_POPUP_DISABLED ) )
    {
        enter_leave( ce, 1 );

        if ( ce->type == FL_POPUP_SUB )
            return open_subpopup( ce );
    }

    return popup;
}


/***************************************
 * Shift popup window if it doesn't fit completely on the screen and the
 * user is trying to move the mouse in the direction of the non-visible
 * parts of the popups window.
 ***************************************/

static void
motion_shift_window( FL_POPUP * popup,
                     int      * x,
                     int      * y )
{
    FL_POPUP_ENTRY *e;
    static long sec   = 0,
                usec  = 0;
    long now_sec,
         now_usec;
    int xr = *x + popup->x,        /* coordinates relative to root window */
        yr = *y + popup->y;
    int old_x_pos,
        old_y_pos;

    /* First check if parts of the popup window are off-screen and the user
       is tryng to move the mouse out of the screen into a direction where
       non-visible parts are. If not we're done. */

    if (    ( xr > 0           || popup->x >= 0 )
         && ( xr < fl_scrw - 1 || popup->x + ( int ) popup->w <= fl_scrw )
         && ( yr > 0           || popup->y >= 0 )
         && ( yr < fl_scrh - 1 || popup->y + ( int ) popup->h <= fl_scrh ) )
        return;

    /* Check if the minimum time delay since last shift is over */

    fl_gettime( &now_sec, &now_usec );

    if ( 1000000 * ( now_sec - sec ) + now_usec - usec < WINDOW_SHIFT_DELAY )
        return;

    /* Shift window left/right by a fixed amout of pixels*/

    old_x_pos = popup->x;
    if ( xr == fl_scrw - 1 && popup->x + ( int ) popup->w > fl_scrw )
        popup->x = FL_max( popup->x - WINDOW_SHIFT,
                           fl_scrw - ( int ) popup->w );
    else if ( xr == 0 && popup->x < 0 )
        popup->x = FL_min( popup->x + WINDOW_SHIFT, 0 );
    *x -= popup->x - old_x_pos;

    /* Shift window up/down by one entry*/

    old_y_pos = popup->y;
    if ( yr == fl_scrh - 1 && popup->y + ( int ) popup->h > fl_scrh)
    {
        /* Find first entry that extends below the bottom of the screen
           and set the windows y-position so that it is shown completely */

        for ( e = popup->entries; e != NULL; e = e->next )
            if (    e->type != FL_POPUP_LINE
                 && ! (  e->state & FL_POPUP_HIDDEN )
                 && e->box_y + ( int ) e->box_h - 1 > *y )
                break;

        if ( e != NULL )
            popup->y = fl_scrh - e->box_y - ( int ) e->box_h;
    }
    else if ( yr == 0 && popup->y < 0 )
    {
        /* Find first entry that's at least one pixel below the upper screen
           border */

        for ( e = popup->entries; e != NULL; e = e->next )
            if (    ! (  e->state & FL_POPUP_HIDDEN )
                    && e->box_y >= *y )
                break;

        /* Go to the one before that which isn't a line or hidden and make it
           the one at the very top of the screen */

        if ( e != NULL )
            do
                e = e->prev;
            while (    e != NULL
                    && ( e->type == FL_POPUP_LINE
                         || e->state & FL_POPUP_HIDDEN ) );
            
        if ( e == NULL )
            popup->y = 0;
        else
            popup->y = - e->box_y;
    }
    *y -= popup->y - old_y_pos;

    /* Move the window to the new position */

    if ( popup->x != old_x_pos || popup->y != old_y_pos )
    {
        XMoveWindow( flx->display, popup->win, popup->x, popup->y );

        sec  = now_sec;
        usec = now_usec;
    }
}


/***************************************
 * Handle keyboard input. If NULL gets returned either a selection was
 * made (in that case 'entry' points to the selected entry) or dealing
 * with the popup is to be stopped. If non-NULL is returned it's the
 * popup we now have to deal with.
 ***************************************/

static FL_POPUP *
handle_key( FL_POPUP        * popup,
            XKeyEvent       * ev,
            FL_POPUP_ENTRY ** entry )
{
    KeySym keysym = NoSymbol;
    char buf[ 16 ];
    FL_POPUP_ENTRY *e,
                   *ce;

    XLookupString( ev, buf, sizeof buf, &keysym, 0 );

    /* Start of with checking for shortcut keys, they may have overridden some
       of the keys normally used */

    if ( ( e = handle_shortcut( popup, keysym, ev->state ) ) != NULL )
    {
        /* Special handling for sub-popup entries: shortcut key doesn't
           result in a selection but in the corresponding sub-popup being
           opened (if it isn't already shown) */

        if ( e->type == FL_POPUP_SUB )
        {
            if ( e->sub->win != None )
                return popup;

            for ( ce = popup->entries; ce != NULL; ce = ce->next )
                if ( ce->is_act )
                {
                    if ( ce != e )
                        enter_leave( ce, 0 );
                    break;
                }

            if ( ce != e )
                enter_leave( e, 1 );

            return open_subpopup( e );
        }

        /* Close all popups. Leave callbacks are not invoked since a
           selection was made */

        while ( popup )
        {
            close_popup( popup, 0 );
            popup = popup->parent;
        }

        *entry = e;
        return NULL;
    }

    /* <Esc> and <Cancel> close the current popup, invoking leave callback */

    if ( keysym == XK_Escape || keysym == XK_Cancel )
    {
        close_popup( popup, 1 );
        return popup->parent;
    }

    /* Try to find the "active" entry (there may not exist one) */

    for ( ce = popup->entries; ce != NULL; ce = ce->next )
        if ( ce->is_act )
            break;

    /* <Return> does nothing (returning the original popup) if there isn't
       an active entry. If we're on a sub-entry open the sup-popup. Otherwise
       return indicating that the active entry was selected after closing all
       popups. */

    if ( keysym == XK_Return )
    {
        if ( ce == NULL )
            return popup;

        /* If we're on a sun-popup entry open the corresponding sub-pupop */

        if ( ce->type == FL_POPUP_SUB )
            return open_subpopup( ce );

        /* Otherwise we got a selection, so close all popups, invoke no leave
           callbacks (since selection was made) and return the selected entry */

        while ( popup )
        {
            close_popup( popup, 0 );
            popup = popup->parent;
        }

        *entry = ce;
        return NULL;
    }

    /* The <Right> key only does something when we're on a sub-entry. In
       this case the sub-popup is opened and the top-most usable entry is
       activated. */

    if ( IsRight( keysym ) )
    {
        if ( ce == NULL || ce->type != FL_POPUP_SUB )
            return popup;

        for ( e = ce->sub->entries; e != NULL; e = e->next )
            if ( IS_ACTIVATABLE( e ) )
                break;

        if ( e != NULL )
            enter_leave( e, 1 );

        return open_subpopup( ce );
    }

    /* The <Left> key only has a meaning if we're in a sub-popup. In this
       case the sub-popup gets closed (leave callbacks get invoked). */

    if ( IsLeft( keysym ) )
    {
        if ( popup->parent == NULL )
            return popup;

        close_popup( popup, 1 );
        return popup->parent;
    }

    /* The <Down> key moves down to the next "activatable" entry (with
       wrap-around). If no entry was active yet the first in the popup
       is activated. */

    if ( IsDown( keysym ) )
    {
        e = NULL;

        if ( ce != NULL )
            for ( e = ce->next; e != NULL; e = e->next )
                if ( IS_ACTIVATABLE( e ) )
                    break;

        if ( e == NULL )
            for ( e = popup->entries; e != ce; e = e->next )
                if ( IS_ACTIVATABLE( e ) )
                    break;

        if ( e != NULL )
            key_shift_window( popup, e );

        if ( e != ce )
        {
            if ( ce != NULL )
                enter_leave( ce, 0 );

            enter_leave( e, 1 );
        }

        return popup;
    }

    /* The <Up> key moves up to the previous "activatable" entry (with
       wrap-around). If no entry was active yet the last in the popup
       is activated. */

    if ( IsUp( keysym ) )
    {
        FL_POPUP_ENTRY * ei;

        for ( e = NULL, ei = popup->entries; ei != ce; ei = ei->next )
            if ( IS_ACTIVATABLE( ei ) )
                e = ei;

        if ( e == NULL && ce != NULL )
            for ( ei = ce->next; ei != NULL; ei = ei->next )
                if ( IS_ACTIVATABLE( ei ) )
                    e = ei;

        if ( ce != NULL && e != NULL )
        {
            key_shift_window( popup, e );
            enter_leave( ce, 0 );
        }

        if ( e != NULL )
            enter_leave( e, 1 );

        return popup;
    }

    /* The <End> key moves to the last "activatable" in the popup */

    if ( IsEnd( keysym ) )
    {
        FL_POPUP_ENTRY *ei;

        for ( e = NULL, ei = ce != NULL ? ce->next : popup->entries; ei != NULL;
              ei = ei->next )
            if ( IS_ACTIVATABLE( ei ) )
                e = ei;

        if ( ce != NULL && e != NULL )
            enter_leave( ce, 0 );

        if ( e != NULL )
        {
            key_shift_window( popup, e );
            enter_leave( e, 1 );
        }

        return popup;
    }

    /* The <Home> key moves to the first "activatable" in the popup */

    if ( IsHome( keysym ) )
    {
        for ( e = popup->entries; e != ce; e = e->next )
            if ( IS_ACTIVATABLE( e ) )
                break;

        if ( ce != NULL && e != ce )
            enter_leave( ce, 0 );

        if ( e != ce )
        {
            key_shift_window( popup, e );
            enter_leave( e, 1 );
        }

        return popup;
    }

    /* All other keys do nothing, returning the original popup indicates that */

    return popup;
}


/***************************************
 * Shift popup window if it doesn't fit completely on the screen and the
 * user pressed a key that takes us to a non-visible entry of the window.
 ***************************************/

static void
key_shift_window( FL_POPUP       * popup,
                  FL_POPUP_ENTRY * entry )
{
    /* Test if the window is only partially visible on the window (in vertical
       direction) and the entry we're supposed to go to isn't in the visible
       part of the window. If not we're done.*/

    if (    ( popup->y >= 0 && popup->y + ( int ) popup->h < fl_scrh )
         || (    popup->y + entry->box_y >= 0
              && popup->y + entry->box_y + ( int ) entry->box_h < fl_scrh ) )
        return;

    /* Shift window up/down */

    if ( popup->y + entry->box_y < 0 )
        popup->y = - entry->box_y + 1;
    else
        popup->y = fl_scrh - entry->box_y - ( int ) entry->box_h - 1;

    XMoveWindow( flx->display, popup->win, popup->x, popup->y );
}


/***************************************
 * Open a sub-popup
 ***************************************/

static FL_POPUP *
open_subpopup( FL_POPUP_ENTRY * entry )
{
    FL_POPUP *popup = entry->popup;
    int offset =   FL_abs( popup->top_parent->bw )
                 + ( popup->top_parent->bw > 0 ? 1 : 0 ) + OUTER_PADDING_TOP;

    /* Set the position of the new sub-popup. Normally show it to the right of
       the parent popup, but if this is a sub-popup of a sub-popup and the
       parent sub-pupop is to the left of its parent (because there wasn't
       enough room on the right side) position it also to the left. Vertically
       put it at the same height as the entry its opened up from. But the
       function for opening the window for the sub-popup may overrule these
       settings if there isn't enough room on the screen. */

    if (    popup->parent == NULL
         || popup->x > popup->parent->x )
        fl_popup_set_position( entry->sub, popup->x + popup->w,
                               popup->y + entry->box_y - offset );
    else
    {
        if ( entry->sub->need_recalc )
            recalc_popup( entry->sub );

        fl_popup_set_position( entry->sub, popup->x - entry->sub->w,
                               popup->y + entry->box_y - offset );
    }

    draw_popup( entry->sub );
    return entry->sub;
}


/***************************************
 * Check popup entries for a shortcut identical to a pressed key
 ***************************************/

static FL_POPUP_ENTRY *
handle_shortcut( FL_POPUP     * popup,
                 long           keysym,
                 unsigned int   keymask )
{
    FL_POPUP_ENTRY *e;
    long *sc;

    if ( controlkey_down( keymask ) && keysym >= 'a' && keysym <= 'z' )
        keysym = toupper( keysym );
    keysym +=   ( controlkey_down( keymask ) ? FL_CONTROL_MASK : 0 )
              + ( metakey_down( keymask )    ? FL_ALT_MASK     : 0 );

    /* Look at the shortcuts for all of the entries of the current popup,
       then those of the parent etc. */

    while ( popup != NULL )
    {
        for ( e = popup->entries; e != NULL; e = e->next )
            if ( IS_ACTIVATABLE( e ) && e->shortcut != NULL )
                for ( sc = e->shortcut; *sc != 0; sc++ )
                    if ( *sc == keysym )
                        return e;
        popup = popup->parent;
    }

    return NULL;
}


/***************************************
 * Handle entering (act = 1) or leaving (act = 0) of an entry
 ***************************************/

static void
enter_leave( FL_POPUP_ENTRY * entry,
             int              act )
{
    /* Mark entry as entered or left */

    entry->is_act = act;

    /* Redraw the entry (at least while popup is shown) */

    if ( entry->popup->win != None )
        draw_entry( entry );

    /* If a callback for the situation exists invoke it */

    if (    (   act && entry->enter_callback == NULL )
         || ( ! act && entry->leave_callback == NULL ) )
        return;

    fli_set_popup_return( entry );

    if ( act )
        entry->enter_callback( &entry->popup->top_parent->ret );
    else
        entry->leave_callback( &entry->popup->top_parent->ret );
}


/***************************************
 * Try to find a (shown) popup from its position (coordinates must be
 * relative to the root window)
 ***************************************/

static FL_POPUP *
find_popup( int x,
            int y )
{
    FL_POPUP *p;

    for ( p = popups; p != NULL; p = p->next )
    {
        if ( p->win == None )
            continue;

        if (    x >= p->x && x < p->x + ( int ) p->w
             && y >= p->y && y < p->y + ( int ) p->h )
            return p;
    }

    return NULL;
}


/***************************************
 * Try to find an entry in a popup from its position (coordinates must be
 * relative to the popup's window)
 ***************************************/

static FL_POPUP_ENTRY *
find_entry( FL_POPUP * popup,
            int        x,
            int        y )
{
    FL_POPUP_ENTRY *e;

    for ( e = popup->entries; e != NULL; e = e->next )
    {
        if ( e->type == FL_POPUP_LINE || e->state & FL_POPUP_HIDDEN )
            continue;

        if (    x >= 0        && x < ( int ) popup->w
             && y >= e->box_y && y < e->box_y + ( int ) e->box_h )
            return e;
    }

    return NULL;
}


/***************************************
 * Makes sure the top-parent pointers in sub-popups are set correctly
 ***************************************/

static void
setup_subpopups( FL_POPUP * popup )
{
    FL_POPUP *p;
    FL_POPUP_ENTRY *e;

    /* The top-parent of sub-popups must be set to the top-most  popup since
       it gets all its drawing properties etc. from that one. In normal popups
       the top_parent entry just points back to the popup itself. */

    if ( ( p = popup->parent ) != NULL )
    {
        while ( p->parent != NULL )
            p = p->parent;
        popup->top_parent = p;
    }
    else
        popup->top_parent = popup;

    for ( e = popup->entries; e != NULL; e = e->next )
        if ( e->type == FL_POPUP_SUB )
            setup_subpopups( e->sub );
}


/***************************************
 * Removes all backspace characters from a string
 * and replaces all tabs by spaces.
 ***************************************/

static char *
cleanup_string( char *s )
{
    char *c;

    if ( ! s || ! *s )
        return s;

    /* Remove all backspace charscters */

    c = s;
    while ( ( c = strchr( c, '\b' ) ) )
        memmove( c, c + 1, strlen( c ) );

    /* Replace tabs by single blanks */

    c = s;
    while ( ( c = strchr( c, '\t' ) ) )
        *c++ = ' ';

    return s;
}


/***************************************
 * Set need_recalc flag for a popup and all its sub-popups
 ***************************************/

static void
set_need_recalc( FL_POPUP * popup )
{
    FL_POPUP_ENTRY *e;

    popup->need_recalc = 1;

    for ( e = popup->entries; e != NULL; e = e->next )
        if ( e->type == FL_POPUP_SUB )
            set_need_recalc( e->sub );
}


/***************************************
 * Function called by fl_initialize() to set up defaults
 ***************************************/

void
fli_popup_init( void )
{
    fli_popup_finish( );      /* just to make sure... */

    popup_entry_font_style = FL_NORMAL_STYLE;
    popup_title_font_style = FL_EMBOSSED_STYLE;

#ifdef __sgi
    popup_entry_font_size  = FL_SMALL_SIZE,
    popup_title_font_size  = FL_SMALL_SIZE;
#else
    popup_entry_font_size  = FL_NORMAL_SIZE;
    popup_title_font_size  = FL_NORMAL_SIZE;
#endif

    popup_bg_color       = FL_MCOL;
    popup_on_color       = FL_BOTTOM_BCOL;
    popup_title_color    = FL_BLACK;
    popup_text_color     = FL_BLACK;
    popup_text_on_color  = FL_WHITE;
    popup_text_off_color = FL_INACTIVE_COL;
    popup_radio_color    = FL_BLUE;

    popup_bw = (    fli_cntl.borderWidth
                 && FL_abs( fli_cntl.borderWidth ) <= FL_MAX_BW ) ?
               fli_cntl.borderWidth : FL_BOUND_WIDTH;
    popup_cursor = XC_sb_right_arrow;

    popup_policy = FL_POPUP_NORMAL_SELECT;
}


/***************************************
 * Function called by fl_finish() to release all memory used by popups.
 ***************************************/

void
fli_popup_finish( void )
{
    FL_POPUP *p;

    /* Delete all top-level popups, sub-popus get taken care of automatically */

    while ( popups )
        for ( p = popups; p != NULL; p = p->next )
            if ( p->parent == NULL )
            {
                fl_popup_delete( p );
                break;
            }
}


/***************************************
 * Checks if a popup exists, returns 0 if it does, 1 otherwise.
 ***************************************/

int
fli_check_popup_exists( FL_POPUP * popup )
{
    FL_POPUP *p;

    for ( p = popups; p != NULL; p = p->next )
        if ( popup == p )
            return 0;

    return 1;
}


/***************************************
 * Checks if an entry exists, returns 0 if it does, 1 otherwise.
 ***************************************/

int
fli_check_popup_entry_exists( FL_POPUP_ENTRY * entry )
{
    FL_POPUP_ENTRY *e;

    if ( entry == NULL )
        return 1;

    if ( fli_check_popup_exists( entry->popup ) )
        return 1;

    for ( e = entry->popup->entries; e != NULL; e = e->next )
        if ( entry == e )
            return 0;

    return 1;
}


/***************************************
 * Set up the return structure of a popup for a certain entry
 ***************************************/

FL_POPUP_RETURN *
fli_set_popup_return( FL_POPUP_ENTRY * entry )
{
    entry->popup->top_parent->ret.text      = entry->text;
    entry->popup->top_parent->ret.label     = entry->label;
    entry->popup->top_parent->ret.accel     = entry->accel;
    entry->popup->top_parent->ret.val       = entry->val;
    entry->popup->top_parent->ret.user_data = entry->user_data;
    entry->popup->top_parent->ret.entry     = entry;
    entry->popup->top_parent->ret.popup     = entry->popup;

    return &entry->popup->top_parent->ret;
}


/***************************************
 * Reset the popups counter to 0
 ***************************************/

void
fli_popup_reset_counter( FL_POPUP *popup )
{
    popup->counter = 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
