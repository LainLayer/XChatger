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
#include "private/pselect.h"
#include "private/flvasprintf.h"


static void timeout_cb( int, void * );
static int handle_select( FL_OBJECT *, int, FL_Coord, FL_Coord, int, void * );
static int handle_push( FL_OBJECT *, int );
static FL_POPUP_RETURN * find_first_item( FL_OBJECT * );
static FL_POPUP_RETURN * find_last_item( FL_OBJECT * );
static FL_POPUP_RETURN * find_next_item( FL_OBJECT * );
static FL_POPUP_RETURN * find_prev_item( FL_OBJECT * );
static void draw_select( FL_OBJECT * );
static void draw_droplist( FL_OBJECT * );


#define IS_ACTIVATABLE( e )                                               \
    (     ( e )->type != FL_POPUP_LINE                                    \
      && ! ( ( e ) ->state & ( FL_POPUP_HIDDEN | FL_POPUP_DISABLED ) ) )


/***************************************
 * Create a select object
 ***************************************/

FL_OBJECT *
fl_create_select( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    FL_OBJECT *obj;
    FLI_SELECT_SPEC *sp;

    obj = fl_make_object( FL_SELECT, type, x, y, w, h, label, handle_select );

    obj->boxtype = type == FL_NORMAL_SELECT ? FL_ROUNDED_BOX : FL_UP_BOX;

    obj->col1        = FL_SELECT_COL1;
    obj->col2        = FL_SELECT_COL2;
    obj->lcol        = FL_SELECT_LCOL;
    obj->align       = FL_SELECT_ALIGN;
    obj->want_update = 1;

    sp = obj->spec = fl_malloc( sizeof *sp );

    sp->popup      = NULL;
    sp->sel        = NULL;
    sp->align      = FL_ALIGN_CENTER;
    sp->style      = FL_NORMAL_STYLE;
    sp->size       = FL_NORMAL_SIZE;
    sp->color      = FL_BLACK;
    sp->timeout_id = -1;
    sp->repeat_ms  = 500;

    fl_set_object_return( obj, FL_RETURN_CHANGED );

    return obj;
}


/***************************************
 * Add a select object
 ***************************************/

FL_OBJECT *
fl_add_select( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label )
{
    FL_OBJECT *obj;

    obj = fl_create_select( type, x, y, w, h, label );
    fl_add_object( fl_current_form, obj );

    /* Popup can only be created after the object has been added to its form,
       otherwise we don't know which window is its parent window... */

    ( ( FLI_SELECT_SPEC * ) obj->spec )->popup =
                      fli_popup_add( FL_ObjWin( obj ), NULL, "fl_add_select" );

    return obj;
}


/***************************************
 * Remove all items from select objects popup
 ***************************************/

int
fl_clear_select( FL_OBJECT * obj )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_clear_select_popup", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    /* Remove all existing entries and reset the popups internal counter */

    if ( sp->popup != NULL )
    {
        while ( sp->popup->entries != NULL )
            fl_popup_entry_delete( sp->popup->entries );

        fli_popup_reset_counter( sp->popup );
    }
    else 
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL, "fl_clear_select" );

    sp->sel = NULL;

    fl_redraw_object( obj );

    return 0;
}


/***************************************
 * Add item(s) to the select object
 ***************************************/

FL_POPUP_ENTRY *
fl_add_select_items( FL_OBJECT  * obj,
                     const char * items,
                     ... )
{
    FLI_SELECT_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    if ( obj == NULL )
    {
        M_err( "fl_add_select_items", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_add_select_items" );

    /* Create and append the new entries to the popup */

    va_start( ap, items );
    new_entries = fli_popup_add_entries( sp->popup, items, ap,
                                         "fl_add_select_items", 1 );
    va_end( ap );

    /* If there's no currently selected entry try to find one */

    if ( sp->sel == NULL )
        sp->sel = find_first_item( obj );

    fl_redraw_object( obj );

    return new_entries;
}


/***************************************
 * Insert item(s) into the select object after an already existing item
 ***************************************/

FL_POPUP_ENTRY *
fl_insert_select_items( FL_OBJECT      * obj,
                        FL_POPUP_ENTRY * after,
                        const char     * items,
                        ... )
{
    FLI_SELECT_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    if ( obj == NULL )
    {
        M_err( "fl_add_select_items", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_insert_select_items" );

    if ( after != NULL && fli_check_popup_entry_exists( after ) != 0 )
    {
        M_err( "fl_add_select_items", "Item to insert after doesn't exist" );
        return NULL;
    }

    va_start( ap, items );
    new_entries = fli_popup_insert_entries( sp->popup, after, items, ap,
                                            "fl_insert_select_items", 1 );
    va_end( ap );

    /* If there's no currently selected entry try to find one */

    if ( sp->sel == NULL )
        sp->sel = find_first_item( obj );

    fl_redraw_object( obj );

    return new_entries;
}


/***************************************
 * Replace an item by new item(s)
 ***************************************/

FL_POPUP_ENTRY *
fl_replace_select_item( FL_OBJECT      * obj,
                        FL_POPUP_ENTRY * old_item,
                        const char     * items,
                          ... )
{
    FLI_SELECT_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    if ( obj == NULL )
    {
        M_err( "fl_replace_select_items", "NULL object" );
        return NULL;
    }

    if ( ! items || ! *items )
    {
        M_err( "fl_replace_select_items", "Items string NULL or empty" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_replace_select_items" );

    /* Test if the item we're supposed to replace exists */

    if ( fli_check_popup_entry_exists( old_item ) )
    {
        M_err( "fl_replace_select_items", "Item to replace doesn't exist" );
        return NULL;
    }

    /* Add the new item(s) after the one to replaced */

    va_start( ap, items );
    new_entries = fli_popup_insert_entries( sp->popup, old_item, items, ap,
                                            "fl_replace_select_items", 1 );
    va_end( ap );

    /* If the insert worked out ok delete the old item (and check if we
       have to set a new displayed item) */

    if ( new_entries != NULL )
    {
        if ( sp->sel != NULL && sp->sel->entry == old_item )
            sp->sel = find_next_item( obj );

        fl_popup_entry_delete( old_item );

        if ( sp->sel != NULL && sp->sel->entry == old_item )
            sp->sel = find_first_item( obj );
    }
    else
        sp->sel = NULL;

    fl_redraw_object( obj );

    return new_entries;
}


/***************************************
 * Delete an item of a select object
 ***************************************/

int
fl_delete_select_item( FL_OBJECT      * obj,
                       FL_POPUP_ENTRY * item )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_delete_select_item", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_delete_select_items" );

    if ( fli_check_popup_entry_exists( item ) != 0 )
    {
        M_err( "fl_delete_select_item", "Item doesn't exist" );
        return -1;
    }

    /* Delete the entry */

    fl_popup_entry_delete( item );

    /* Check if we have to change the currently selected item */

    if ( item == sp->sel->entry )
        sp->sel = find_next_item( obj );

    fl_redraw_object( obj );

    return 0;
}
    

/***************************************
 * (Re)populate a select object's popup via an
 * array of FL_POPUP_ITEM structures
 ***************************************/

long
fl_set_select_items( FL_OBJECT     * obj,
                     FL_POPUP_ITEM * items )
{
    FLI_SELECT_SPEC *sp;
    FL_POPUP_ENTRY *e;
    long count;

    if ( obj == NULL )
    {
        M_err( "fl_set_select_items", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    /* If no popup exists yet create it, otherwise remove all entries */

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_set_select_items" );
    else
    {
        while ( sp->popup->entries != NULL )
            fl_popup_entry_delete( sp->popup->entries );

        fli_popup_reset_counter( sp->popup );
    }

    /* Now add the new ones */

    for ( count = 0; items && items->text != NULL; count++, items++ )
    {
        size_t len = strlen( items->text ) + 9;
        char *txt;
        char *t = ( char * ) items->text;

        /* Figure out how many chars we need for the text */

        while ( ( t = strchr( t, '%' ) ) != NULL )
            if ( *++t != 'S' )
                len++;

        t = txt = fl_malloc( len );

        strcpy( txt, items->text );
        
        while ( ( t = strchr( t, '%' ) ) != NULL )
        {
            if ( *++t == 'S' )
                continue;
            memmove( t + 1, t, strlen( t ) + 1 );
            *t++ = '%';
        }

        if ( items->state & FL_POPUP_DISABLED )
            strcat( txt, "%d" );
        if ( items->state & FL_POPUP_HIDDEN )
            strcat( txt, "%h" );
        strcat( txt, "%f%s" );

        e = fl_popup_add_entries( sp->popup, txt, items->callback,
                                  items->shortcut );

        fl_free( txt );

        fli_safe_free( e->text );
        e->text = fl_strdup( items->text );
    }

    if ( count > 0 )
        sp->sel = find_first_item( obj );

    return count;
}


/***************************************
 * Returns the popup of a select object
 ***************************************/

FL_POPUP *
fl_get_select_popup( FL_OBJECT * obj )
{
    return ( ( FLI_SELECT_SPEC * ) obj->spec )->popup;
}


/***************************************
 * Set a (new) popup for a select object
 ***************************************/

int
fl_set_select_popup( FL_OBJECT * obj,
                     FL_POPUP  * popup )
{
    FLI_SELECT_SPEC *sp;
    FL_POPUP *old_popup;
    FL_POPUP_ENTRY *e;

    /* We need a valid object */

    if ( obj == NULL )
    {
        M_err( "fl_set_select_popup", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    /* The popup must exist */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_set_select_popup", "Popup doesn't exist" );
        return -1;
    }

    /* The popup can't be a sub-popup nor may it contain any entries that
       are not "normal" entries */

    if ( popup->parent != NULL )
    {
        M_err( "fl_set_select_popup", "Popup is a sub-popup" );
        return -1;
    }

    for ( e = popup->entries; e != NULL; e = e->next )
        if ( e->type != FL_POPUP_NORMAL )
        {
            M_err( "fl_set_select_popup", "Invalid entries in popup" );
            return -1;
        }

    /* Delete a popup already associated with the select object */

    old_popup = ( ( FLI_SELECT_SPEC * ) obj->spec )->popup;
    if ( old_popup != NULL )
        fl_popup_delete( old_popup );

    /* Set the new popup as the select pbjects popup and redraw */

    sp->popup = popup;

    sp->sel = find_first_item( obj );

    fl_redraw_object( obj );

    return 1;
}


/***************************************
 * Return currently selected item
 ***************************************/

FL_POPUP_RETURN *
fl_get_select_item( FL_OBJECT * obj )
{
    if ( obj == NULL )
    {
        M_err( "fl_get_select_item", "NULL object" );
        return NULL;
    }

    return ( ( FLI_SELECT_SPEC * ) obj->spec )->sel;
}


/***************************************
 * Set a new item as currently selected
 ***************************************/

FL_POPUP_RETURN *
fl_set_select_item( FL_OBJECT      * obj,
                    FL_POPUP_ENTRY * entry )
{
    FL_POPUP_ENTRY *e;
    FLI_SELECT_SPEC *sp;
    FL_POPUP_RETURN *r;

    if ( obj == NULL )
    {
        M_err( "fl_get_select_item", "NULL object" );
        return NULL;
    }

    if ( entry == NULL )
    {
        M_err( "fl_set_select_item", "NULL entry" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_set_select_items" );

    for ( e = sp->popup->entries; e != NULL; e = e->next )
        if ( e == entry )
            break;

    if ( e == NULL )
    {
        M_err( "fl_set_select_item", "Entry does not exist" );
        return NULL;
    }

    if ( ! IS_ACTIVATABLE( entry ) )
    {
        M_err( "fl_set_select_item", "Entry can't be set as selected" );
        return NULL;
    }

    r = fli_set_popup_return( entry );
    fl_redraw_object( obj );
    return r;
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_select_item_by_value( FL_OBJECT * obj,
                             long int    val )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_select_item_by_value", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_select_item_by_value" );

    return fl_popup_entry_get_by_value( sp->popup, val );
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_select_item_by_label( FL_OBJECT  * obj,
                             const char * label )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_select_item_by_label", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_select_item_by_label" );

    return fl_popup_entry_get_by_label( sp->popup, label );
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_select_item_by_label_f( FL_OBJECT  * obj,
                               const char * fmt,
                               ... )
{
    FL_POPUP_ENTRY *e;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    e = fl_get_select_item_by_label( obj, buf );
    fl_free( buf );
    return e;
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_select_item_by_text( FL_OBJECT  * obj,
                            const char * text )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_select_item_by_text", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_select_item_by_text" );

    return fl_popup_entry_get_by_text( sp->popup, text );
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_select_item_by_text_f( FL_OBJECT  * obj,
                              const char * fmt,
                              ... )
{
    FL_POPUP_ENTRY *e;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    e = fl_get_select_item_by_text( obj, buf );
    fl_free( buf );
    return e;
}


/***************************************
 * Returns one of the different colors set for the object and its popup
 ***************************************/

FL_COLOR
fl_get_select_text_color( FL_OBJECT * obj )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_select_color", "NULL object" );
        return FL_MAX_COLORS;
    }

    sp = obj->spec;

    return sp->color;
}


/***************************************
 * Set one of the different colors of the object
 ***************************************/

FL_COLOR
fl_set_select_text_color( FL_OBJECT * obj,
                          FL_COLOR    color )
{
    FLI_SELECT_SPEC *sp;
    FL_COLOR old_color;

    if ( obj == NULL )
    {
        M_err( "fl_set_select_color", "NULL object" );
        return FL_MAX_COLORS;
    }

    if ( color >= FL_MAX_COLORS )
    {
        M_err( "fl_select_set_color", "Invalid color argument" );
        return FL_MAX_COLORS;
    }

    sp = obj->spec;

    old_color = sp->color;
    sp->color = color;
    fl_redraw_object( obj );

    return old_color;
}


/***************************************
 * Returns style and size of the fonts used for the text on the object
 ***************************************/

int
fl_get_select_text_font( FL_OBJECT * obj,
                         int       * style,
                         int       * size )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_select_font", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    if ( style != NULL )
        *style = sp->style;
    if ( size != NULL )
        *size = sp->size;

    return 0;
}


/***************************************
 * Sets style and size of the fonts used for the text on the object
 ***************************************/

int
fl_set_select_text_font( FL_OBJECT * obj,
                         int         style,
                         int         size )
{
    FLI_SELECT_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_set_select_font", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    sp->style = style;
    sp->size  = size;
    fl_redraw_object( obj );

    return 0;
}


/***************************************
 * Gets the alignment of the text within the box of the object
 ***************************************/

int
fl_get_select_text_align( FL_OBJECT * obj )
{
    if ( obj == NULL )
    {
        M_err( "fl_set_select_text_align", "NULL object" );
        return -1;
    }

    return ( ( FLI_SELECT_SPEC * ) obj->spec )->align;
}


/***************************************
 * Sets the alignment of the text within the box of the object
 ***************************************/

int
fl_set_select_text_align( FL_OBJECT * obj,
                          int         align )
{
    FLI_SELECT_SPEC *sp;
    int old_align;

    if ( obj == NULL )
    {
        M_err( "fl_set_select_text_align", "NULL object" );
        return -1;
    }

    if ( fl_is_outside_lalign( align ) )
    {
        M_warn( "fl_set_select_text_align", "Adding FL_ALIGN_INSIDE flag" );
        align = fl_to_inside_lalign( align );
    }

    if (    fl_to_outside_lalign( align ) < FL_ALIGN_CENTER
         || fl_to_outside_lalign( align ) > FL_ALIGN_RIGHT_BOTTOM )
    {
        M_err( "fl_set_select_text_align", "Invalid value for align" );
        return -1;
    }

    sp = obj->spec;
    
    old_align = sp->align;
    sp->align = align;
    fl_redraw_object( obj );

    return old_align;
}


/***************************************
 * Sets how the popup of the object behaves
 ***************************************/

int
fl_set_select_policy( FL_OBJECT * obj,
                      int         policy )
{
    FLI_SELECT_SPEC *sp;
    int old_policy;

    if ( obj == NULL )
    {
        M_err( "fl_set_select_policy", "NULL object" );
        return INT_MIN;
    }

    if ( policy < FL_POPUP_NORMAL_SELECT || policy > FL_POPUP_DRAG_SELECT )
    {
        M_err( "fl_set_select_policy", "Invalid policy argument" );
        return -1;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_set_select_policy" );

    old_policy = fl_popup_get_policy( sp->popup );
    fl_popup_set_policy( sp->popup, policy );

    return old_policy;
}


/***************************************
 * Callback for timeout used when mouse buttons 2 or 3 are kept pressed down
 ***************************************/

static void
timeout_cb( int    val  FL_UNUSED_ARG,
            void * data )
{
    ( ( FLI_SELECT_SPEC * ) data )->timeout_id = -1;
}


/***************************************
 * Central routine for interaction with object
 ***************************************/

static int
handle_select( FL_OBJECT * obj,
               int         event,
               FL_Coord    mx   FL_UNUSED_ARG,
               FL_Coord    my   FL_UNUSED_ARG,
               int         key,
               void      * ev   FL_UNUSED_ARG )
{
    FLI_SELECT_SPEC *sp = obj->spec;
    FL_POPUP_RETURN *ret = NULL;
    unsigned int w,
                 h;
    int sret = FL_RETURN_NONE;

    switch ( event )
    {
        case FL_ATTRIB :
            obj->align = fl_to_outside_lalign( obj->align );
            if ( fl_is_center_lalign( obj->align ) )
                obj->align = FL_SELECT_ALIGN;
            break;

        case FL_DRAW :
            if ( obj->type != FL_DROPLIST_SELECT )
                draw_select( obj );
            else
                draw_droplist( obj );
            /* fall through */

        case FL_DRAWLABEL :
            fl_draw_text_beside( obj->align, obj->x, obj->y,
                                 obj->w, obj->h, obj->lcol, obj->lstyle,
                                 obj->lsize, obj->label );
            break;

        case FL_ENTER :
        case FL_LEAVE :
            fl_redraw_object( obj );
            break;

        case FL_SHORTCUT :
            obj->pushed = 1;
            key = FL_MBUTTON1;
            fl_popup_get_size( sp->popup, &w, &h );
            fl_popup_set_position( sp->popup,
                                   obj->form->x + obj->x + ( obj->w - w ) / 2,
                                   obj->form->y + obj->y + obj->h );
            sret |= FL_RETURN_END;
            /* fall through */

        case FL_PUSH :
            if ( handle_push( obj, key ) )
                sret |= FL_RETURN_CHANGED;
            break;

        case FL_RELEASE :
            if ( key != FL_MBUTTON2 && key != FL_MBUTTON3 )
                break;

            if ( sp->timeout_id != -1 )
            {
                fl_remove_timeout( sp->timeout_id );
                sp->timeout_id = -1;
            }

            fl_redraw_object( obj );
            sret |= FL_RETURN_END;
            break;

        case FL_UPDATE:
            if (    ( key == FL_MBUTTON2 || key == FL_MBUTTON3 )
                 && sp->timeout_id == -1 )
            {
                const FL_POPUP_ENTRY *old_entry = sp->sel ?
                                                  sp->sel->entry : NULL;

                ret = ( key == FL_MBUTTON2 ?
                        find_prev_item : find_next_item )( obj );
                if (    ret != NULL
                     && ret->entry != old_entry
                     && ret->entry->callback
                     && ret->entry->callback( ret ) == FL_IGNORE )
                    ret = NULL;
                fl_redraw_object( obj );
                sp->timeout_id = fl_add_timeout( sp->repeat_ms, timeout_cb,
                                                 sp );
                if ( ret != NULL )
                    sret |= FL_RETURN_CHANGED;
            }
            break;

        case FL_FREEMEM :
            if ( sp && sp->popup )
                fl_popup_delete( sp->popup );
            fli_safe_free( obj->spec );
            break;
    }

    return sret;
}


/***************************************
 * Deals with pushes on the select object
 ***************************************/

static int
handle_push( FL_OBJECT * obj,
             int         key )
{
    FLI_SELECT_SPEC *sp = obj->spec;
    FL_POPUP_RETURN *ret = NULL;
    const FL_POPUP_ENTRY *old_entry = sp->sel ? sp->sel->entry : NULL;
    unsigned int w,
                 h;

    if ( key == FL_MBUTTON1 )
    {
        fl_redraw_object( obj );

        if ( obj->type == FL_DROPLIST_SELECT )
        {
            fl_popup_get_size( sp->popup, &w, &h );
            if ( obj->w >= 2 )
                fl_popup_set_position( sp->popup,
                                       obj->form->x + obj->x + obj->w - w,
                                       obj->form->y + obj->y + obj->h );
            else
                fl_popup_set_position( sp->popup,
                                       obj->form->x + obj->x
                                       + ( obj->w - w ) / 2,
                                       obj->form->y + obj->y + obj->h );
        }

        if ( ( ret = fl_popup_do( sp->popup ) ) != NULL )
            sp->sel = ret;
        obj->pushed = 0;
    }
    else if ( key == FL_MBUTTON2 || key == FL_MBUTTON3 )
    {
        sp->timeout_id = fl_add_timeout( sp->repeat_ms, timeout_cb, sp );
        fl_redraw_object( obj );
        ret = ( key == FL_MBUTTON2 ?
                find_prev_item : find_next_item )( obj );
        if (    ret != NULL
             && ret->entry != old_entry
             && ret->entry->callback
             && ret->entry->callback( ret ) == FL_IGNORE )
            ret = NULL;
    }
    else if ( key == FL_MBUTTON4 || key == FL_MBUTTON5 )
    {
        obj->pushed = 0;
        ret = ( key == FL_MBUTTON4 ?
                find_prev_item : find_next_item )( obj );
        if (    ret != NULL
             && ret->entry != old_entry
             && ret->entry->callback
             && ret->entry->callback( ret ) == FL_IGNORE )
            ret = NULL;
    }
    fl_redraw_object( obj );

    return ret != NULL;
}


/***************************************
 * Returns the first "activatable" entry of a select object
 ***************************************/

static FL_POPUP_RETURN *
find_first_item( FL_OBJECT * obj )
{
    FL_POPUP_ENTRY *e = ( ( FLI_SELECT_SPEC * ) obj->spec )->popup->entries;

    for ( ; e != NULL; e = e->next )
        if ( IS_ACTIVATABLE( e ) )
            return fli_set_popup_return( e );

    return NULL;
}


/***************************************
 * Returns the last "activatable" entry of a select object
 ***************************************/

static FL_POPUP_RETURN *
find_last_item( FL_OBJECT * obj )
{
    FL_POPUP_ENTRY *ec = ( ( FLI_SELECT_SPEC * ) obj->spec )->popup->entries,
                   *e = ec->next;

    for ( ; e != NULL; e = e->next )
        if ( IS_ACTIVATABLE( e ) )
            ec = e;

    if ( ec != NULL )
        return fli_set_popup_return( ec );

    return NULL;
}


/***************************************
 * Returns the next "activatable" entry of a select object after the
 * currently selected entry
 ***************************************/

static FL_POPUP_RETURN *
find_next_item( FL_OBJECT * obj )
{
    FL_POPUP_ENTRY *e;
    FLI_SELECT_SPEC *sp = obj->spec;

    for ( e = sp->sel->entry->next; e != NULL; e = e->next )
        if ( IS_ACTIVATABLE( e ) )
            return fli_set_popup_return( e );

    return find_first_item( obj );;
}


/***************************************
 * Returns the previous "activatable" entry of a select object before the
 * currently selected entry
 ***************************************/

static FL_POPUP_RETURN *
find_prev_item( FL_OBJECT * obj )
{
    FL_POPUP_ENTRY *e;
    FLI_SELECT_SPEC *sp = obj->spec;

    for ( e = sp->sel->entry->prev; e != NULL; e = e->prev )
        if ( IS_ACTIVATABLE( e ) )
            return fli_set_popup_return( e );

    return find_last_item( obj );
}


/***************************************
 * Draws select objects of type FL_NORMAL_SELECT and FL_MENU_SELECT
 ***************************************/

static void
draw_select( FL_OBJECT * obj )
{
    FL_COLOR color;
    FLI_SELECT_SPEC *sp = obj->spec;
    int bw = FL_abs( obj->bw ) + ( obj->bw > 0 );
    int box_w = 0;

    color = ( obj->belowmouse && sp->popup ) ? obj->col2 : obj->col1;

    /* Draw the box of the object, possibly lowered if the object is pushed */

    if ( FL_IS_UPBOX( obj->boxtype ) && obj->pushed )
        fl_draw_box( FL_TO_DOWNBOX( obj->boxtype ), obj->x, obj->y, obj->w,
                     obj->h, color, obj->bw );
    else
        fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h, color,
                     obj->bw );

    /* The FL_MENU_SELECT type has a small raised box on the right hand
       side */

    if ( obj->type == FL_MENU_SELECT )
    {
        int box_h  =   FL_max( 6 + ( obj->bw > 0 ), 0.1 * obj->h ),
            box_bw = - FL_max( bw - ( obj->bw > 0 ), 1 );

        box_w = FL_max( 0.11 * obj->w, 13 );

        if (    box_w <= obj->w - 2 * bw
             && box_h <= obj->h - 2 * bw
             && box_w >= 2 * box_bw
             && box_h >= 2 * box_bw )
        {
            int box_x = obj->x + obj->w -box_w - bw - 2;
            int box_y = obj->y + ( obj->h - box_h ) / 2;

            fl_draw_box( FL_UP_BOX, box_x, box_y, box_w, box_h, obj->col1,
                         box_bw );

            box_w += 3;
        }
    }

    if ( sp->sel && sp->sel->label && *sp->sel->label )
    {
        fl_set_text_clipping( obj->x + bw, obj->y + bw,
                              obj->w - box_w - 2 * bw, obj->h - 2 * bw );
        fl_draw_text( sp->align, obj->x + bw, obj->y + bw,
                      obj->w - box_w - 2 * bw, obj->h - 2 * bw,
                      sp->color, sp->style, sp->size, sp->sel->label );
        fl_unset_text_clipping( );
    }
}


/***************************************
 * Draws select objects of type FL_DROPLIST_SELECT
 ***************************************/

static void
draw_droplist( FL_OBJECT * obj )
{
    int box_x = obj->x,
        box_y = obj->y,
        box_w,
        box_h,
        button_x,
        button_y,
        button_w,
        button_h;
    FL_COLOR color;
    FLI_SELECT_SPEC *sp = obj->spec;
    int bw = FL_abs( obj->bw ) + ( obj->bw > 0 );

    /* Calculate the size of the box with the arrow - if the object is
       higher than wide place it below the text of the currently selected
       item */

    if ( obj->w >= obj->h )
    {
        button_x = obj->x + obj->w - obj->h;
        button_y = obj->y;
        button_w = button_h = obj->h;
        box_w = obj->w - obj->h;
        box_h = obj->h;
    }
    else
    {
        button_x = obj->x;
        button_y = obj->y + obj->h - obj->w;
        button_w = button_h = obj->w;
        box_w = obj->w;
        box_h = obj->h - obj->w;
    }

    color = ( obj->belowmouse && sp->popup ) ? obj->col2 : obj->col1;

    /* Draw the box for the text of the selected item */

    fl_draw_box( obj->boxtype, box_x, box_y, box_w, box_h, obj->col1,
                 obj->bw );

    /* Draw the box for the arrow button, possibly lowered if the object is
       pushed */

    if ( FL_IS_UPBOX( obj->boxtype ) && obj->pushed )
        fl_draw_box( FL_TO_DOWNBOX( obj->boxtype ), button_x, button_y,
                     button_w, button_h, color, obj->bw );
    else
        fl_draw_box( obj->boxtype, button_x, button_y, button_w, button_h,
                     color, obj->bw );

    /* Draw the arrow */

    fl_draw_text( FL_ALIGN_CENTER, button_x + bw, button_y + bw,
                  button_w - 2 * bw, button_h - 2 * bw, sp->color, 0, 0,
                  "@#2->" );

    /* Draw the text of the currently selected item */

    if ( sp->sel && sp->sel->label && *sp->sel->label )
    {
        fl_set_text_clipping( box_x + bw, box_y + bw,
                              box_w - 2 * bw, box_h - 2 * bw );
        fl_draw_text( sp->align, box_x + bw, box_y + bw,
                      box_w - 2 * bw, box_h - 2 * bw,
                      sp->color, sp->style, sp->size, sp->sel->label );
        fl_unset_text_clipping( );
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
