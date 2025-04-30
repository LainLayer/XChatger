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


/**
 * \file menu.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  XForms Class FL_MENU.
 *    call PopUp to handle the actual random access
 *
 *  possible optimization:
 *   upon first creation of the popup, set extern_menu to the popup ID
 *   and let popup manage all the modes/values from then on.
 *
 *  OR use the following to simplify code for extern pup
 *    when extern_menu is used, gets all text and mode, then
 *    all the code would be the same for extern and native menu.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pmenu.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>


#define ISPUP( sp )   ( ( sp )->extern_menu >= 0 )


/***************************************
 * Returns the index into the array of items from the items menu ID
 ***************************************/

static int
val_to_index( FL_OBJECT * ob,
              int         val )
{
    int i;
    FLI_MENU_SPEC *sp = ob->spec;

    if ( ISPUP( sp ) )
        return val;

    for ( i = 1; i <= sp->numitems; i++ )
        if ( val == sp->mval[ i ] )
            return i;

    return -1;
}


/***************************************
 * Creates the menu and shows it. Returns the item selected.
 ***************************************/

static int
do_menu_low_level( FL_OBJECT * ob )
{
    int popup_id,
        i,
        val,
        k;
    FLI_MENU_SPEC *sp = ob->spec;

    /* The number of items can be 0 only if the menu is an external popup */

    if ( sp->numitems == 0 && ! ISPUP( sp ) )
        return 0;

    /* If it's an external popup let the xpopup code deal with everything */

    if ( ISPUP( sp ) )
    {
        if ( ob->label && *ob->label && ob->type != FL_PULLDOWN_MENU )
            fl_setpup_title( sp->extern_menu, ob->label );

        if ( ( val = fl_dopup( sp->extern_menu ) ) > 0 )
            sp->val = val;

        return val;
    }

    /* Create a new popup */

    popup_id = fl_newpup( FL_ObjWin( ob ) );

    if ( ob->type != FL_PULLDOWN_MENU && ! sp->no_title )
        fl_setpup_title( popup_id, ob->label );
    else
        fl_setpup_softedge( popup_id, 1 );

    for ( i = 1; i <= sp->numitems; i++ )
    {
        if ( sp->mval[ i ] == i && ! sp->cb[ i ] )
            fl_addtopup( popup_id, sp->items[ i ] );
        else
        {
            char *s = fl_malloc(   strlen( sp->items[ i ] )
                                 + 6 + log10( INT_MAX ) );

            sprintf( s, "%s%%x%d%s", sp->items[ i ], sp->mval[ i ],
                     sp->cb[ i ] ? "%f" : "" );

            if ( ! sp->cb[ i ] )
                fl_addtopup( popup_id, s );
            else
                fl_addtopup( popup_id, s, sp->cb[ i ] );

            fl_free( s );
        }

        if ( sp->modechange[ i ] || sp->mode[ i ] != FL_PUP_NONE )
        {
            fl_setpup_mode( popup_id, sp->mval[ i ], sp->mode[ i ] );
            sp->modechange[ i ] = 0;
        }

        fl_setpup_shortcut( popup_id, sp->mval[ i ], sp->shortcut[ i ] );
    }

    /* Pulldown menus and those without a title appear directly
       below the menu itself, the others more or less on top of
       the menu */

    if ( ob->type == FL_PULLDOWN_MENU || sp->no_title )
        fl_setpup_position( ob->form->x + ob->x + 1,
                            ob->form->y + ob->y + ob->h + 1 );
    else
        fl_setpup_position( ob->form->x + ob->x + 5,
                            ob->form->y + ob->y + 5 );

    /* Now do the user interaction */

    val = fl_dopup( popup_id );

    /* Deal with whatever is needed according to the return value */

    if ( val > 0 && ( k = val_to_index( ob, val ) ) > 0 )
    {
        /* If shown for the first time, need to get all mode right as the
           menu item string may have embedded mode setting strings in it */

        if ( sp->shown == 0 )
        {
            for ( i = 1; i <= sp->numitems; i++ )
            {
                int m = fl_getpup_mode( popup_id, sp->mval[ i ] );

                sp->modechange[ i ] = sp->mode[ i ] != m;
                sp->mode[ i ] = m;
                sp->shown = 1;
            }
        }
        else
        {
            sp->mode[ k ] = fl_getpup_mode( popup_id, val );
            sp->modechange[ k ] = 1;

            /* Old val also might change mode if binary */

            if ( sp->val > 0 )
            {
                int m = fl_getpup_mode( popup_id, sp->mval[ sp->val ] );

                sp->modechange[ sp->val ] = sp->mode[ sp->val ] != m;
                sp->mode[ sp->val ] = m;
            }
        }

        sp->val = k;
    }

    /* Get rid of the popup */

    fl_freepup( popup_id );

    return val;
}


/***************************************
 ***************************************/

static int
do_menu( FL_OBJECT *ob )
{
    int val;

    ob->pushed = 1;
    fl_redraw_object( ob );

    val = do_menu_low_level( ob ) > 0;

    ob->pushed = 0;
    fl_redraw_object( ob );

    return val > 0;
}


/***************************************
 * Handles an event, return non-zero if an item has been selected.
 ***************************************/

static int
handle_menu( FL_OBJECT * ob,
             int         event,
             FL_Coord    mx   FL_UNUSED_ARG,
             FL_Coord    my   FL_UNUSED_ARG,
             int         key  FL_UNUSED_ARG,
             void      * ev   FL_UNUSED_ARG )
{
    FLI_MENU_SPEC *sp = ob->spec;
    int val,
        boxtype = ob->boxtype;
    FL_COLOR col;
    int ret = FL_RETURN_NONE;

#if FL_DEBUG >= ML_DEBUG
    M_info2( "handle_menu", fli_event_name( event ) );
#endif

    switch ( event )
    {
        case FL_ATTRIB :
            ob->align = fl_to_inside_lalign( ob->align );
            break;

        case FL_DRAW:
            /* Draw the object */

            if ( ob->pushed )
            {
                boxtype = FL_UP_BOX;
                col = ob->col2;
            }
            else
                col = ob->col1;

            fl_draw_box( boxtype, ob->x, ob->y, ob->w, ob->h, col, ob->bw );
            fl_draw_text( ob->align, ob->x, ob->y, ob->w, ob->h,
                          ob->lcol, ob->lstyle, ob->lsize, ob->label );

            if ( sp->showsymbol )
            {
                int dm = 0.85 * FL_min( ob->w, ob->h );

                fl_draw_text( 0, ob->x + ob->w - dm - 1, ob->y + 1,
                              dm, dm, col, 0, 0, "@menu" );
            }
            break;

        case FL_ENTER:
            if ( ob->type == FL_TOUCH_MENU && do_menu( ob ) > 0 )
                ret |= FL_RETURN_CHANGED;
            break;

        case FL_PUSH:
            /* Touch menus and push menus without a title don't do anything
               on a button press */

            if (    key != FL_MBUTTON1
                 || ( ob->type == FL_PUSH_MENU && sp->no_title ) )
                break;

            if ( ob->type == FL_TOUCH_MENU )
            {
                ret |= FL_RETURN_END;
                break;
            }

            if ( do_menu( ob ) > 0 )
                ret |= FL_RETURN_END | FL_RETURN_CHANGED;

            break;

        case FL_RELEASE :
            /* Button release is only important for push menus without a
               title, all others get started by a button press or by just
               moving the mouse on top of it (and they also don't expect
               a release - that gets eaten by the popup handler) */

            if (    key != FL_MBUTTON1
                 || ! ( ob->type == FL_PUSH_MENU && sp->no_title )
                 || mx < ob->x
                 || mx > ob->x + ob->w
                 || my < ob->y
                 || my > ob->y + ob->h )
                break;

            if ( do_menu( ob ) > 0 )
                ret |= FL_RETURN_CHANGED | FL_RETURN_END;

            break;

        case FL_SHORTCUT:
            /* Show menu as highlighted */

            ob->pushed = 1;
            fl_redraw_object( ob );

            /* Do interaction and then redraw without highlighting */

            val = do_menu( ob );
            ob->pushed = 0;
            fl_redraw_object( ob );
            if ( val > 0 )
                ret |= FL_RETURN_CHANGED | FL_RETURN_END;
            break;

        case FL_FREEMEM:
            fl_clear_menu( ob );
            fl_free( ob->spec );
            return 0;
    }

    return ret;
}


/***************************************
 * Creates a menu object
 ***************************************/

FL_OBJECT *
fl_create_menu( int          type,
                FL_Coord     x,
                FL_Coord     y,
                FL_Coord     w,
                FL_Coord     h,
                const char * label )
{
    FL_OBJECT *obj;
    FLI_MENU_SPEC *sp;

    obj = fl_make_object( FL_MENU, type, x, y, w, h, label, handle_menu );

    obj->boxtype = FL_FLAT_BOX;
    obj->col1   = FL_MENU_COL1;
    obj->col2   = FL_MENU_COL2;
    obj->lcol   = FL_MENU_LCOL;
    obj->lstyle = FL_NORMAL_STYLE;
    obj->align  = FL_MENU_ALIGN;

    if ( type == FL_TOUCH_MENU )
        fl_set_object_return( obj, FL_RETURN_CHANGED );
    else
        fl_set_object_return( obj, FL_RETURN_END_CHANGED );

    sp = obj->spec = fl_calloc( 1, sizeof *sp );
    sp->extern_menu = -1;

    return obj;
}


/***************************************
 * Adds a menu object
 ***************************************/

FL_OBJECT *
fl_add_menu( int          type,
             FL_Coord     x,
             FL_Coord     y,
             FL_Coord     w,
             FL_Coord     h,
             const char * label )
{
    FL_OBJECT *ob;

    ob = fl_create_menu( type, x, y, w, h, label );
    fl_add_object( fl_current_form, ob );

    return ob;
}


/***************************************
 * Clears the menu object
 ***************************************/

void
fl_clear_menu( FL_OBJECT * ob )
{
    int i;
    FLI_MENU_SPEC *sp = ob->spec;

    if ( ISPUP( sp ) )
    {
        fl_freepup( sp->extern_menu );
        sp->extern_menu = -1;
        return;
    }

    sp->val = 0;
    sp->cur_val = 0;

    for ( i = 1; i <= sp->numitems; i++ )
    {
        fli_safe_free( sp->items[ i ] );
        fli_safe_free( sp->shortcut[ i ] );
        sp->mode[ i ] = FL_PUP_NONE;
        sp->cb[ i ] = NULL;
    }

    sp->numitems = 0;
}


/***************************************
 * Adds a line to the menu item.
 ***************************************/

static void
addto_menu( FL_OBJECT  * ob,
            const char * str,
            ... )
{
    FLI_MENU_SPEC *sp = ob->spec;
    int n;
    char *p;

    if (    ISPUP( sp )
         || sp->numitems >= FL_MENU_MAXITEMS
         || sp->cur_val == INT_MAX )
        return;

    n = ++sp->numitems;

    sp->items[ n ]    = fl_strdup( str );
    sp->shortcut[ n ] = fl_strdup( "" );
    sp->mode[ n ]     = FL_PUP_NONE;
    sp->cb[ n ]       = NULL;

    /* Check if a callback function needs to be set */

    if ( ( p = strstr( sp->items[ n ], "%f" ) ) )
    {
        va_list ap;

        va_start( ap, str );
        sp->cb[ n ] = va_arg( ap, FL_PUP_CB );
        va_end( ap );
        memmove( p, p + 2, strlen( p ) - 1 );
    }

    /* Set the value for the menu (either the index or extract it from "%xn" */

    if ( ! ( p = strstr( sp->items[ n ], "%x" ) ) )
        sp->mval[ n ] = ++sp->cur_val;
    else
    {
        if ( ! isdigit( ( unsigned char ) p[ 2 ] ) )
        {
            M_err( "addto_menu", "Missing number after %%x" );
            sp->mval[ n ] = ++sp->cur_val;
        }
        else
        {
            char *eptr;

            sp->mval[ n ] = strtol( p + 2, &eptr, 10 );
            while ( *eptr && isspace( ( unsigned char ) *eptr ) )
                eptr++;
            if ( *eptr )
                memmove( p, eptr, strlen( eptr ) + 1 );
            else
                *p = '\0';
        }
    }
}


/***************************************
 * Sets the menu to a particular menu string
 ***************************************/

void
fl_set_menu( FL_OBJECT  * ob,
             const char * menustr,
             ... )
{
    char *t,
         *c;
    va_list ap;
    FLI_MENU_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_set_menu", "%s is not Menu class", ob ? ob->label : "" );
        return;
    }
#endif

    fl_clear_menu( ob );

    /* Split up menu string at '|' chars and create an entry for each part */

    va_start( ap, menustr );

    t = fl_strdup( menustr );

    for ( c = strtok( t, "|" );
          c && sp->numitems < FL_CHOICE_MAXITEMS;
          c = strtok( NULL, "|" ) )
    {
        FL_PUP_CB cb;

        if ( strstr( c, "%f" ) )
        {
            cb = va_arg( ap, FL_PUP_CB );
            addto_menu( ob, c, cb );
        }
        else
            addto_menu( ob, c );
    }

    if ( t )
        fl_free( t );

    va_end( ap );
}


/***************************************
 * Adds a line to the menu item.
 ***************************************/

int
fl_addto_menu( FL_OBJECT  * ob,
               const char * menustr,
               ... )
{
    FLI_MENU_SPEC *sp= ob->spec;
    char *t,
         *c;
    va_list ap;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_addto_menu", "%s is not Menu class", ob ? ob->label : "" );
        return 0;
    }
#endif

    /* Split up menu string at '|' chars and create an entry for each part */

    va_start( ap, menustr );

    t = fl_strdup( menustr );

    for ( c = strtok( t, "|" );
          c && sp->numitems < FL_CHOICE_MAXITEMS;
          c = strtok( NULL, "|" ) )
    {
        FL_PUP_CB cb;

        if ( strstr( c, "%f" ) )
        {
            cb = va_arg( ap, FL_PUP_CB );
            addto_menu( ob, c, cb );
        }
        else
            addto_menu( ob, c );
    }

    if ( t )
        fl_free( t );

    va_end( ap );

    return sp->numitems;
}


/***************************************
 * Replaces a line in the menu item.
 ***************************************/

void
fl_replace_menu_item( FL_OBJECT  * ob,
                      int          numb,
                      const char * str,
                      ... )
{
    FLI_MENU_SPEC *sp = ob->spec;
    char *s,
         *p,
         *eptr;
         
    if ( ISPUP( sp ) )
    {
        fli_replacepup_text( sp->extern_menu, numb, str );
        return;
    }

    if ( ( numb = val_to_index( ob, numb ) ) <= 0 )
        return;

    if ( sp->items[ numb ] )
        fl_free( sp->items[ numb ] );
    sp->cb[ numb ] = NULL;

    s = strdup( str );

    if ( ( p = strstr( s, "%f" ) ) )
    {
        va_list ap;

        va_start( ap, str );
        sp->cb[ numb ] = va_arg( ap, FL_PUP_CB );
        va_end( ap );
        memmove( p, p + 2, strlen( p ) - 1 );
    }

    if ( ( p = strstr( s, "%x" ) ) )
    {
        if ( isdigit( ( unsigned char ) p[ 2 ] ) )
        {
            sp->mval[ numb ] = strtol( p + 2, &eptr, 10 );
            while ( *eptr && isspace( ( unsigned char ) *eptr ) )
                eptr++;
            if ( *eptr )
                memmove( p, eptr, strlen( eptr ) + 1 );
            else
                *p = '\0';
        }
        else
        {
            M_err( "fl_replace_menu_item", "Missing number after %%x" );
            memmove( p, p + 2, strlen( p ) - 1 );
        }
    }

    sp->items[ numb ] = s;
}


/***************************************
 * Removes a line from the menu item.
 ***************************************/

void
fl_delete_menu_item( FL_OBJECT * ob,
                     int         numb )
{
    int i;
    FLI_MENU_SPEC *sp = ob->spec;

    if ( ISPUP( sp ) || ( numb = val_to_index( ob, numb ) ) <= 0 )
        return;

    fli_safe_free( sp->items[ numb ] );
    fli_safe_free( sp->shortcut[ numb ] );

    for ( i = numb; i < sp->numitems; i++ )
    {
        sp->items[ i ]      = sp->items[ i + 1 ];
        sp->mode[ i ]       = sp->mode[ i + 1 ];
        sp->modechange[ i ] = sp->modechange[ i + 1 ];
        sp->mval[ i ]       = sp->mval[ i + 1 ];
        sp->shortcut[ i ]   = sp->shortcut[ i + 1 ];
        sp->cb[ i ]         = sp->cb[ i + 1 ];
    }

    if ( sp->val == numb )
        sp->val = -1;

    sp->items[ sp->numitems ]      = NULL;
    sp->shortcut[ sp->numitems ]   = NULL;
    sp->mode[ sp->numitems ]       = FL_PUP_NONE;
    sp->modechange[ sp->numitems ] = 0;
    sp->mval[ sp->numitems ]       = 0;
    sp->cb[ sp->numitems ]         = NULL;

    sp->numitems--;
}


/***************************************
 * Sets a callback function for a menu item
 ***************************************/

FL_PUP_CB
fl_set_menu_item_callback( FL_OBJECT * ob,
                           int         numb,
                           FL_PUP_CB   cb )
{
    FLI_MENU_SPEC *sp = ob->spec;
    FL_PUP_CB old_cb;

    if ( ISPUP( sp ) || ( numb = val_to_index( ob, numb ) ) <= 0 )
        return NULL;

    old_cb = sp->cb[ numb ];
    sp->cb[ numb ] = cb;
    return old_cb;
}


/***************************************
 * Sets a shortcut for a menu item
 ***************************************/

void
fl_set_menu_item_shortcut( FL_OBJECT  * ob,
                           int          numb,
                           const char * str )
{
    FLI_MENU_SPEC *sp = ob->spec;

    if ( ISPUP( sp ) || ( numb = val_to_index( ob, numb ) ) <= 0 )
        return;

    fli_safe_free( sp->shortcut[ numb ] );
    sp->shortcut[ numb ] = fl_strdup( str ? str : "" );
}


/***************************************
 * Sets the display mode for the menu item
 ***************************************/

void
fl_set_menu_item_mode( FL_OBJECT    * ob,
                       int            numb,
                       unsigned int   mode )
{
    FLI_MENU_SPEC *sp = ob->spec;

    if ( ISPUP( sp ) )
        fl_setpup_mode( sp->extern_menu, numb, mode );
    else
    {
        if ( ( numb = val_to_index( ob, numb ) ) <= 0 )
            return;

        sp->mode[ numb ] = mode;
        sp->modechange[ numb ] = 1;

        if ( mode & FL_PUP_CHECK )
            sp->val = numb;
    }
}


/***************************************
 * Sets the display mode for the menu item
 ***************************************/

int
fl_set_menu_item_id( FL_OBJECT * ob,
                     int         index,
                     int         id )
{
    FLI_MENU_SPEC *sp = ob->spec;
    int old_id;

    if ( ISPUP( sp ) || id < 1 || index < 1 || index > sp->numitems )
        return -1;

    old_id = sp->mval[ index ];
    sp->mval[ index ] = id;
    return old_id;
}


/***************************************
 * Makes the menu symbol visible or not
 ***************************************/

void
fl_show_menu_symbol( FL_OBJECT * ob,
                     int         show )
{
    FLI_MENU_SPEC *sp = ob->spec;

    if ( ISPUP( sp ) )
         return;

    sp->showsymbol = show;
    fl_redraw_object( ob );
}


/***************************************
 * Returns the number of the menu item selected.
 ***************************************/

int
fl_get_menu( FL_OBJECT * ob )
{
    FLI_MENU_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_get_menu", "%s is not Menu class", ob ? ob->label : "" );
        return 0;
    }
#endif

    if ( ISPUP( sp ) )
        return sp->val;

    return sp->val > 0 && sp->val <= sp->numitems ? sp->mval[ sp->val ] : -1;
}


/***************************************
 * Returns rhe number of items in a menu
 ***************************************/

int
fl_get_menu_maxitems( FL_OBJECT * ob )
{
    FLI_MENU_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_get_menu_maxitems", "%s is not Menu class",
               ob ? ob->label : "" );
        return 0;
    }
#endif

    return ISPUP( sp ) ? fl_getpup_items( sp->extern_menu ) : sp->numitems;
}


/***************************************
 * Returns the text of the menu item selected.
 ***************************************/

const char *
fl_get_menu_text( FL_OBJECT * ob )
{
    FLI_MENU_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_get_menu_text", "%s is not Menu class",
               ob ? ob->label : "" );
        return NULL;
    }
#endif

    if ( ISPUP( sp ) )
        return fl_getpup_text( sp->extern_menu, sp->val );

    return ( sp->val < 1 || sp->val > sp->numitems ) ?
            NULL : sp->items[ sp->val ];
}


/***************************************
 * Returns a string with the menu items text
 ***************************************/

const char *
fl_get_menu_item_text( FL_OBJECT * ob,
                       int         numb )
{
    FLI_MENU_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_get_menu_item_text", "%s is not Menu class",
               ob ? ob->label : "" );
        return NULL;
    }
#endif

    if ( ISPUP(sp ) )
        return fl_getpup_text( sp->extern_menu, numb );

    numb = val_to_index( ob, numb );

    return numb <= 0 ? NULL : sp->items[ numb ];
}


/***************************************
 * Returns the mode of a menu item
 ***************************************/

unsigned int
fl_get_menu_item_mode( FL_OBJECT * ob,
                       int         numb )
{
    FLI_MENU_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_get_menu_item_mode", "%s is not Menu class",
               ob ? ob->label : "" );
        return 0;
    }
#endif

    if ( ISPUP( sp ) )
        return fl_getpup_mode( sp->extern_menu, numb );

    numb = val_to_index( ob, numb );

    return numb <= 0 ? 0 : sp->mode[ numb ];
}


/***************************************
 * Makes an already existing popup a menu
 ***************************************/

void
fl_set_menu_popup( FL_OBJECT * ob,
                   int         pup )
{
#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_MENU ) )
    {
        M_err( "fl_set_menu_popup", "%s is not Menu class",
               ob ? ob->label : "" );
        return;
    }
#endif

    ( ( FLI_MENU_SPEC * ) ob->spec )->extern_menu = pup;

    if ( ob->type == FL_PULLDOWN_MENU )
        fl_setpup_shadow( pup, 0 );
}


/***************************************
 * Creates a popup and makes that a menu
 ***************************************/

int
fl_set_menu_entries( FL_OBJECT    * ob,
                     FL_PUP_ENTRY * ent )
{
    int n;

    fl_clear_menu( ob );

    n = fl_newpup( FL_ObjWin( ob ) );
    fl_set_menu_popup( ob, fl_setpup_entries( n, ent ) );

    if ( ob->type == FL_PULLDOWN_MENU )
    {
        fl_setpup_bw( n, ob->bw );
        fl_setpup_shadow( n, 0 );
    }

    return n;
}


/***************************************
 * If the menu is really a popup in disguise returns the popups number
 ***************************************/

int
fl_get_menu_popup( FL_OBJECT * ob )
{
    FLI_MENU_SPEC *sp = ob->spec;

    return ISPUP( sp ) ? sp->extern_menu : -1;
}


/***************************************
 * Allows to change the no-title attribute of a menu
 ***************************************/

int
fl_set_menu_notitle( FL_OBJECT * ob,
                     int         off )
{
    FLI_MENU_SPEC *sp = ob->spec;
    int old = sp->no_title;

    sp->no_title = off;
    return old;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
