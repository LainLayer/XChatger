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
#include "private/pnmenu.h"


static int handle_nmenu( FL_OBJECT *, int, FL_Coord, FL_Coord,
                         int , void * );
static void draw_menu( FL_OBJECT * );


#define IS_TOUCH_NMENU( o )                      \
	(    ( o )->type == FL_NORMAL_TOUCH_NMENU    \
      || ( o )->type == FL_BUTTON_TOUCH_NMENU )

#define IS_BUTTON_NMENU( o )                     \
	(    ( o )->type == FL_BUTTON_NMENU          \
      || ( o )->type == FL_BUTTON_TOUCH_NMENU )


/***************************************
 * Create a nmenu object
 ***************************************/

FL_OBJECT *
fl_create_nmenu( int          type,
                 FL_Coord     x,
                 FL_Coord     y,
                 FL_Coord     w,
                 FL_Coord     h,
                 const char * label )
{
    FL_OBJECT *obj;
    FLI_NMENU_SPEC *sp;

    obj = fl_make_object( FL_NMENU, type, x, y, w, h, label, handle_nmenu );

    obj->boxtype = FL_FLAT_BOX;
    obj->col1    = FL_COL1;
    obj->col2    = IS_BUTTON_NMENU( obj ) ? FL_MCOL : FL_BOTTOM_BCOL;
    obj->lcol    = FL_LCOL;
    obj->lstyle  = FL_NORMAL_STYLE;
    obj->align   = FL_ALIGN_CENTER;

    sp = obj->spec = fl_malloc( sizeof *sp );

    sp->popup = NULL;
    sp->sel   = NULL;
    sp->hl_color = IS_BUTTON_NMENU( obj ) ? FL_LCOL : FL_WHITE;

    fl_set_object_return( obj, FL_RETURN_END_CHANGED );

    return obj;
}


/***************************************
 * Add a nmenu object
 ***************************************/

FL_OBJECT *
fl_add_nmenu( int          type,
              FL_Coord     x,
              FL_Coord     y,
              FL_Coord     w,
              FL_Coord     h,
              const char * label )
{
    FL_OBJECT *obj;

    obj = fl_create_nmenu( type, x, y, w, h, label );
    fl_add_object( fl_current_form, obj );

    /* Popup can only be created after the object has been added to its form,
       otherwise we don't know which window is its parent window... */

    ( ( FLI_NMENU_SPEC * ) obj->spec )->popup =
                       fli_popup_add( FL_ObjWin( obj ), NULL, "fl_add_nmenu" );

    return obj;
}


/***************************************
 * Remove all items from nmenu objects popup
 ***************************************/

int
fl_clear_nmenu( FL_OBJECT * obj )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_clear_nmenu_popup", "NULL object" );
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
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL, "fl_clear_nmenu" );

    sp->sel = NULL;

    fl_redraw_object( obj );

    return 0;
}


/***************************************
 * Add (append) item(s) to the nmenu object
 ***************************************/

FL_POPUP_ENTRY *
fl_add_nmenu_items( FL_OBJECT  * obj,
                    const char * items,
                     ... )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    if ( obj == NULL )
    {
        M_err( "fl_add_nmenu_items", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_add_nmenu_items" );

    /* Create and append the new entries to the popup */

    va_start( ap, items );
    new_entries = fli_popup_add_entries( sp->popup, items, ap,
                                         "fl_add_nmenu_items", 0 );
    va_end( ap );

    return new_entries;
}


/***************************************
 * Insert item(s) into the nmenu object after an already existing item
 ***************************************/

FL_POPUP_ENTRY *
fl_insert_nmenu_items( FL_OBJECT      * obj,
                       FL_POPUP_ENTRY * after,
                       const char     * items,
                        ... )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    if ( obj == NULL )
    {
        M_err( "fl_add_nmenu_items", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_insert_nmenu_items" );

    if ( after != NULL && fli_check_popup_entry_exists( after ) != 0 )
    {
        M_err( "fl_add_nmenu_items", "Item to insert after doesn't exist" );
        return NULL;
    }

    va_start( ap, items );
    new_entries = fli_popup_insert_entries( sp->popup, after, items, ap,
                                            "fl_insert_nmenu_items", 0 );
    va_end( ap );

    return new_entries;
}


/***************************************
 * Replace an item by new item(s)
 ***************************************/

FL_POPUP_ENTRY *
fl_replace_nmenu_item( FL_OBJECT      * obj,
                       FL_POPUP_ENTRY * old_item,
                       const char     * items,
                       ... )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;
    va_list ap;

    if ( obj == NULL )
    {
        M_err( "fl_replace_nmenu_items", "NULL object" );
        return NULL;
    }

    if ( ! items || ! *items )
    {
        M_err( "fl_replace_nmenu_item", "Items string NULL or empty" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_replace_nmenu_items" );

    /* Test if the item we're supposed to replace exists */

    if ( fli_check_popup_entry_exists( old_item ) )
    {
        M_err( "fl_replace_nmenu_item", "Item to replace doesn't exist" );
        return NULL;
    }

    /* Add the new item(s) after the one to replaced */

    va_start( ap, items );
    new_entries = fli_popup_insert_entries( sp->popup, old_item, items, ap,
                                            "fl_replace_nmenu_item", 0 );
    va_end( ap );

    /* If the insert worked out ok delete the old item (and check if we
       have to set a new displayed item) */

    if ( new_entries != NULL )
    {
        if ( sp->sel != NULL && sp->sel->entry == old_item )
            sp->sel = NULL;

        fl_popup_entry_delete( old_item );
    }

    return new_entries;
}


/***************************************
 * Delete an item of a nmenu object
 ***************************************/

int
fl_delete_nmenu_item( FL_OBJECT      * obj,
                      FL_POPUP_ENTRY * item )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_delete_nmenu_item", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_delete_nmenu_items" );

    if ( fli_check_popup_entry_exists( item ) != 0 )
    {
        M_err( "fl_delete_nmenu_item", "Item doesnt exist" );
        return -1;
    }

    /* Delete the entry */

    fl_popup_entry_delete( item );

    if ( item == sp->sel->entry )
        sp->sel = NULL;

    return 0;
}
    

/***************************************
 * (Re)polulate a nmenu objects popup via an array of FL_POPUP_ITEM structures
 ***************************************/

FL_POPUP_ENTRY *
fl_set_nmenu_items( FL_OBJECT     * obj,
                    FL_POPUP_ITEM * items )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_set_nmenu_items", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    /* If no popup exists yet create it, otherwise remove all entries */

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_set_nmenu_items" );
    else
    {
        while ( sp->popup->entries != NULL )
            fl_popup_entry_delete( sp->popup->entries );

        fli_popup_reset_counter( sp->popup );
    }

    sp->sel = NULL;

    return fli_popup_insert_items( sp->popup, NULL, items,
                                   "fl_set_nmenu_items" );
}


/***************************************
 * Add (append) item(s) to the nmenu object from a list of FL_POPUP_ITEM
 * structures
 ***************************************/

FL_POPUP_ENTRY *
fl_add_nmenu_items2( FL_OBJECT     * obj,
                     FL_POPUP_ITEM * items )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP_ENTRY *after;
    FL_POPUP_ENTRY *new_entries;

    if ( obj == NULL )
    {
        M_err( "fl_add_nmenu_items2", "NULL object" );
        return NULL;
    }

    if ( ! items || ! items->text )
    {
        M_err( "fl_add_nmenu_items2", "Items list NULL or empty" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_add_nmenu_items2" );

    /* Determine the last existing entry in the nmenu's popup */

    after = sp->popup->entries;
    while ( after != NULL && after->next != NULL )
        after = after->next;

    /* Create and append the new entries to the popup */

    new_entries = fli_popup_insert_items( sp->popup, after, items,
                                          "fl_add_nmenu_items2" );

    return new_entries;
}


/***************************************
 * Insert item(s) into the nmenu object from a list of FL_POPUP_ITEM
 * structures after an already existing item
 ***************************************/

FL_POPUP_ENTRY *
fl_insert_nmenu_items2( FL_OBJECT      * obj,
                        FL_POPUP_ENTRY * after,
                        FL_POPUP_ITEM  * items )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;

    if ( obj == NULL )
    {
        M_err( "fl_add_nmenu_items2", "NULL object" );
        return NULL;
    }

    if ( ! items || ! items->text )
    {
        M_err( "fl_insert_nmenu_items2", "Items list NULL or empty" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_insert_nmenu_items2" );

    if ( after != NULL && fli_check_popup_entry_exists( after ) != 0 )
    {
        M_err( "fl_add_nmenu_items2", "Item to insert after doesn't exist" );
        return NULL;
    }

    new_entries = fli_popup_insert_items( sp->popup, after, items,
                                          "fl_insert_nmenu_items2" );

    return new_entries;
}


/***************************************
 * Replace an item by new item(s) from a list of FL_POPUP_ITEM structures
 ***************************************/

FL_POPUP_ENTRY *
fl_replace_nmenu_items2( FL_OBJECT      * obj,
                         FL_POPUP_ENTRY * old_item,
                         FL_POPUP_ITEM  * items )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP_ENTRY *new_entries;

    if ( obj == NULL )
    {
        M_err( "fl_replace_nmenu_items2", "NULL object" );
        return NULL;
    }

    if ( ! items || ! items->text )
    {
        M_err( "fl_replace_nmenu_items2", "Items list NULL or empty" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_replace_nmenu_items2" );

    /* Test if the item we're supposed to replace exists */

    if ( fli_check_popup_entry_exists( old_item ) )
    {
        M_err( "fl_replace_nmenu_item2", "Item to replace doesn't exist" );
        return NULL;
    }

    /* Add the new item(s) after the one to replaced */

    new_entries = fli_popup_insert_items( sp->popup, old_item, items,
                                          "fl_replace_nmenu_item2" );

    /* If the insert worked out ok delete the old item (and check if we
       have to set a new displayed item) */

    if ( new_entries != NULL )
    {
        if ( sp->sel != NULL && sp->sel->entry == old_item )
            sp->sel = NULL;

        fl_popup_entry_delete( old_item );
    }

    return new_entries;
}


/***************************************
 * Returns the popup of a nmenu object
 ***************************************/

FL_POPUP *
fl_get_nmenu_popup( FL_OBJECT * obj )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_nmenu_popup", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_nmenu_popup" );

    return sp->popup;
}


/***************************************
 * Set a (new) popup for a nmenu object
 ***************************************/

int
fl_set_nmenu_popup( FL_OBJECT * obj,
                    FL_POPUP  * popup )
{
    FLI_NMENU_SPEC *sp;
    FL_POPUP *old_popup;

    /* We need a valid object */

    if ( obj == NULL )
    {
        M_err( "fl_set_nmenu_popup", "NULL object" );
        return -1;
    }

    sp = obj->spec;

    /* The popup must exist */

    if ( fli_check_popup_exists( popup ) )
    {
        M_err( "fl_set_nmenu_popup", "Popup doesn't exist" );
        return -1;
    }

    /* The popup can't be a sub-popup */

    if ( popup->parent != NULL )
    {
        M_err( "fl_set_nmenu_popup", "Popup is a sub-popup" );
        return -1;
    }

    /* Delete a popup already associated with the nmenu object */

    old_popup = ( ( FLI_NMENU_SPEC * ) obj->spec )->popup;
    if ( old_popup != NULL )
        fl_popup_delete( old_popup );

    /* Set the new popup as the nmenu objects popup and redraw */

    sp->popup = popup;

    sp->sel = NULL;

    fl_redraw_object( obj );

    return 1;
}


/***************************************
 * Sets how the popup of the object behaves
 ***************************************/

int
fl_set_nmenu_policy( FL_OBJECT * obj,
                     int         policy )
{
    FLI_NMENU_SPEC *sp;
    int old_policy;

    if ( obj == NULL )
    {
        M_err( "fl_set_nmenu_policy", "NULL object" );
        return INT_MIN;
    }

    if ( policy < FL_POPUP_NORMAL_SELECT || policy > FL_POPUP_DRAG_SELECT )
    {
        M_err( "fl_set_nmenu_policy", "Invalid policy argument" );
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
 * Return last selected item
 ***************************************/

FL_POPUP_RETURN *
fl_get_nmenu_item( FL_OBJECT * obj )
{
    if ( obj == NULL )
    {
        M_err( "fl_get_nmenu_item", "NULL object" );
        return NULL;
    }

    return ( ( FLI_NMENU_SPEC * ) obj->spec )->sel;
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_nmenu_item_by_value( FL_OBJECT * obj,
                            long int    val )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_nmenu_item_by_value", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_nmenu_item_by_value" );

    return fl_popup_entry_get_by_value( sp->popup, val );
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_nmenu_item_by_label( FL_OBJECT  * obj,
                             const char * label )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_nmenu_item_by_label", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_nmenu_item_by_label" );

    return fl_popup_entry_get_by_label( sp->popup, label );
}


/***************************************
 ***************************************/

FL_POPUP_ENTRY *
fl_get_nmenu_item_by_text( FL_OBJECT  * obj,
                            const char * text )
{
    FLI_NMENU_SPEC *sp;

    if ( obj == NULL )
    {
        M_err( "fl_get_nmenu_item_by_text", "NULL object" );
        return NULL;
    }

    sp = obj->spec;

    if ( sp->popup == NULL )
        sp->popup = fli_popup_add( FL_ObjWin( obj ), NULL,
                                   "fl_get_nmenu_item_by_text" );

    return fl_popup_entry_get_by_text( sp->popup, text );
}


/***************************************
 ***************************************/

FL_COLOR
fl_set_nmenu_hl_text_color(FL_OBJECT * obj,
                           FL_COLOR    color )
{
    FLI_NMENU_SPEC *sp;
    FL_COLOR old_color;

    if ( obj == NULL )
    {
        M_err( "fl_set_nmenu_hl_text_color", "NULL object" );
        return FL_MAX_COLORS;
    }

    if ( color >= FL_MAX_COLORS )
    {
        M_err( "fl_set_nmenu_hl_text_color", "Invalid color argument" );
        return FL_MAX_COLORS;
    }

    sp = obj->spec;

    old_color = sp->hl_color;
    sp->hl_color = color;
    fl_redraw_object( obj );

    return old_color;
}


/***************************************
 * Central routine for interaction with nmenu object
 ***************************************/

static int
handle_nmenu( FL_OBJECT * obj,
              int         event,
              FL_Coord    mx   FL_UNUSED_ARG,
              FL_Coord    my   FL_UNUSED_ARG,
              int         key  FL_UNUSED_ARG,
              void      * ev   FL_UNUSED_ARG )
{
    FLI_NMENU_SPEC *sp = obj->spec;
    unsigned int w,
                 h;
    int ret = FL_RETURN_NONE;

    switch ( event )
    {
        case FL_DRAW :
            draw_menu( obj );
            break;

        case FL_ENTER :
            if ( ! IS_TOUCH_NMENU( obj ) )
                break;
            /* fall through */

        case FL_SHORTCUT :
        case FL_PUSH :
            if ( ! sp->popup || ! sp->popup->entries )
                break;
            obj->pushed = 1;
            fl_redraw_object( obj );
            fl_popup_get_size( sp->popup, &w, &h );
            if ( obj->form->y + obj->y + obj->h + h < ( unsigned int ) fl_scrh )
                fl_popup_set_position( sp->popup,
                                       obj->form->x + obj->x,
                                       obj->form->y + obj->y + obj->h );
            else
                fl_popup_set_position( sp->popup,
                                       obj->form->x + obj->x,
                                       obj->form->y + obj->y - h );
            sp->sel = fl_popup_do( sp->popup );
            obj->pushed = 0;
            fl_redraw_object( obj );
            if ( sp->sel != NULL )
                ret |= FL_RETURN_CHANGED | FL_RETURN_END;
            break;

        case FL_FREEMEM :
            if ( sp && sp->popup )
                fl_popup_delete( sp->popup );
            fli_safe_free( obj->spec );
            break;
    }

    return ret;
}


/***************************************
 ***************************************/

static void
draw_menu( FL_OBJECT * obj )
{
    if ( ! obj->pushed )
    {
        fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h, obj->col1,
                     obj->bw );
        obj->align = fl_to_outside_lalign( obj->align );
        fl_draw_text( obj->align, obj->x, obj->y, obj->w, obj->h, obj->lcol,
                      obj->lstyle, obj->lsize, obj->label );
    }
    else
    {
        FLI_NMENU_SPEC *sp = obj->spec;

        fl_draw_box( ( IS_BUTTON_NMENU( obj ) && obj->boxtype == FL_FLAT_BOX ) ?
                     FL_UP_BOX : obj->boxtype,
                     obj->x, obj->y, obj->w, obj->h, obj->col2, obj->bw );
        obj->align = fl_to_inside_lalign( obj->align );
        fl_draw_text( obj->align, obj->x, obj->y, obj->w, obj->h, sp->hl_color,
                      obj->lstyle, obj->lsize, obj->label );
    }   
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
