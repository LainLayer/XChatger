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
 * \file button.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  All Buttons. Additional button class can be added via
 *  fl_add_button_class and fl_create_generic_button
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <sys/types.h>

#define ISTABBOX( t )   (    t == FL_TOPTAB_UPBOX                  \
                          || t == FL_SELECTED_TOPTAB_UPBOX         \
                          || t == FL_BOTTOMTAB_UPBOX               \
                          || t == FL_SELECTED_BOTTOMTAB_UPBOX    )

#define WITHIN( obj, mx, my )   (    ( mx ) >= ( obj )->x                 \
                                  && ( mx ) <  ( obj )->x + ( obj )->w    \
                                  && ( my ) >= ( obj )->y                 \
                                  && ( my ) <  ( obj )->y + ( obj )->h )


/***************************************
 ***************************************/

static void
free_pixmap( FL_BUTTON_STRUCT * sp )
{
    if ( sp->pixmap )
    {
        XFreePixmap( flx->display, sp->pixmap );
        sp->pixmap = None;
    }
}


/********** DRAWING *************/

/***************************************
 * Draws a button object
 ***************************************/

void
fli_draw_button( FL_OBJECT * obj )
{
    FL_Coord dh,
             dw,
             ww,
             absbw = FL_abs( obj->bw );
    int off2 = 0;
    FL_BUTTON_STRUCT *sp = obj->spec;
    FL_COLOR col = sp->val ? obj->col2 : obj->col1;

    if ( obj->belowmouse && obj->active )
    {
        if ( col == FL_BUTTON_COL1 )
            col = FL_BUTTON_MCOL1;
        else if ( col == FL_BUTTON_COL2 )
            col = FL_BUTTON_MCOL2;
    }

    if ( FL_IS_UPBOX( obj->boxtype ) && ( sp->val || sp->is_pushed ) )
        fl_draw_box( FL_TO_DOWNBOX( obj->boxtype ), obj->x, obj->y, obj->w,
                     obj->h, col, obj->bw );
    else
        fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h, col,
                     obj->bw );

    dh = FL_crnd( 0.6 * obj->h );
    dw = FL_crnd( FL_min( 0.6 * obj->w, dh ) );

    ww = FL_crnd( 0.75 * obj->h );
    if ( ww < dw + absbw + 1 + ( obj->bw > 0 ) )
        ww = dw + absbw + 1 + ( obj->bw > 0 );

    if ( obj->type == FL_RETURN_BUTTON )
    {
        fl_draw_text( 0, obj->x + obj->w - ww, FL_crnd( obj->y + 0.2 * obj->h ),
                      dw, dh, obj->lcol, 0, 0, "@returnarrow" );
        off2 = dw - 2;
    }

    if ( obj->type == FL_MENU_BUTTON && obj->boxtype == FL_UP_BOX )
    {
        int dbh = FL_max( absbw - 1, 1 );

        dw = FL_max( 0.11 * obj->w, 13 );
        dh = FL_max( 6 + (obj->bw > 0 ), obj->h * 0.1 );

        fl_draw_box( FL_UP_BOX, obj->x + obj->w - dw - absbw - 2,
                     obj->y + ( obj->h - dh ) / 2, dw, dh, obj->col1, -dbh );
        off2 = dw - 1;
    }

    if ( obj->type == FL_MENU_BUTTON || obj->type == FL_RETURN_BUTTON )
    {
        obj->w -= off2;
        fl_draw_object_label( obj );
        obj->w += off2;
    }
    else if ( obj->boxtype & FLI_BROKEN_BOX || ISTABBOX( obj->boxtype ) )
    {
        fl_set_text_clipping( obj->x + 3, obj->y, obj->w - 6, obj->h );
        fl_draw_object_label( obj );
        fl_unset_text_clipping( );
    }
    else
        fl_draw_object_label( obj );
}


/***************************************
 * All button classes differ only in the way they are drawn, so we
 * separate this info out from generic button handlers
 ***************************************/

#define MAX_BUTTON_CLASS 12

typedef struct
{
    FL_DrawButton    drawbutton;
    FL_CleanupButton cleanup;
    int              bclass;            /* button class */
} ButtonRec;


static ButtonRec how_draw[ MAX_BUTTON_CLASS ];


/***************************************
 * Look up a drawing function given a button class ID
 ***************************************/

static FL_DrawButton
lookup_drawfunc( int bclass )
{
    ButtonRec *db  = how_draw,
              *dbs = how_draw + MAX_BUTTON_CLASS;

    for ( ; db < dbs; db++ )
        if ( db->bclass == bclass )
            return db->drawbutton;

    return NULL;
}


/***************************************
 ***************************************/

static FL_CleanupButton
lookup_cleanupfunc( int bclass )
{
    ButtonRec *db  = how_draw,
              *dbs = how_draw + MAX_BUTTON_CLASS;

    for ( ; db < dbs; db++ )
        if ( db->bclass == bclass )
            return db->cleanup;

    return NULL;
}


/***************************************
 * Associates a button class with a drawing function
 ***************************************/

void
fl_add_button_class( int              bclass,
                     FL_DrawButton    drawit,
                     FL_CleanupButton cleanup )
{
    static int initialized;
    ButtonRec *db = how_draw,
              *dbs = how_draw + MAX_BUTTON_CLASS,
              *first_avail;

    if ( ! initialized )
    {
        for ( ; db < dbs; db++ )
            db->bclass = -1;

        initialized = 1;
    }

    for ( db = how_draw, first_avail = NULL; db < dbs; db++ )
        if ( db->bclass == bclass )
        {
            db->drawbutton = drawit;
            db->cleanup    = cleanup;
            return;
        }
        else if ( db->bclass < 0 && ! first_avail )
            first_avail = db;

    /* If we get here, the class is not defined yet */

    if ( first_avail )
    {
        first_avail->bclass     = bclass;
        first_avail->drawbutton = drawit;
        first_avail->cleanup    = cleanup;
    }
    else
        M_err( "fl_add_button_class", "Exceeding limit: %d", MAX_BUTTON_CLASS );
}


/***************************************
 ***************************************/

static void
wait_for_release( XKeyEvent * ev )
{
    KeySym ksm;

    if ( ( ksm = XLookupKeysym( ev, 0 ) ) == NoSymbol )
        return;

    while ( fl_keysym_pressed( ksm ) )
    {
        XSync( flx->display, 0 );
        fl_msleep( 15 );
    }
}


/***************************************
 * Handles an event for a button object
 ***************************************/

static int
handle_button( FL_OBJECT * obj,
               int         event,
               FL_Coord    mx,
               FL_Coord    my,
               int         key,
               void      * ev )
{
    static int oldval;
    int newval;
    FL_BUTTON_STRUCT *sp = obj->spec;
    FL_DrawButton drawit;
    FL_CleanupButton cleanup;
    int ret = FL_RETURN_NONE;

    switch ( event )
    {
        case FL_DRAW :
            sp->event = FL_DRAW;
            if (    obj->type != FL_HIDDEN_BUTTON
                 && obj->type != FL_HIDDEN_RET_BUTTON )
            {
                if ( ( drawit = lookup_drawfunc( obj->objclass ) ) )
                    drawit( obj );
                else
                    M_err( "handle_button", "Unknown button class: %d",
                           obj->objclass );
            }
            break;

        case FL_DRAWLABEL :
            sp->event = FL_DRAWLABEL;
            break;          /* TODO. Missing labels */

        case FL_LEAVE:
            /* FL_MENU_BUTTON objects never get a FL_RELEASE event,
               so we have to "fake" one */

            if ( obj->type == FL_MENU_BUTTON )
            {
                sp->event = FL_RELEASE;
                sp->is_pushed = 0;
                sp->val = 0;
            }
            /* fall through */

        case FL_ENTER :
            /* Keep active radio buttons from reacting */

            if ( obj->type == FL_RADIO_BUTTON && sp->val == 1 )
                obj->belowmouse = 0;

            sp->event = event;
            fl_redraw_object( obj );
            break;

        case FL_PUSH :
            /* Don't accept pushes for an already pushed button (e.g. if the
               user pushes another mouse button) or for mouse buttons the
               button isn't set up to react to */

            if (    sp->is_pushed )
                break;

            if (    key < FL_MBUTTON1
                 || key > FL_MBUTTON5
                 || ! sp->react_to[ key - 1 ] )
            {
                fli_int.pushobj = NULL;
                break;
            }

            sp->event = FL_PUSH;

            if ( obj->type == FL_RADIO_BUTTON )
            {
                obj->belowmouse = 0;
                sp->val = 1;
                fl_redraw_object( obj );
                return FL_RETURN_CHANGED | FL_RETURN_END;
            }

            oldval        = sp->val;
            sp->val       = ! sp->val;
            sp->is_pushed = 1;
            sp->mousebut  = key;
            sp->timdel    = 1;
            fl_redraw_object( obj );

            if ( obj->type == FL_MENU_BUTTON )
                ret |= FL_RETURN_END;

            if (    obj->type == FL_INOUT_BUTTON
                 || obj->type == FL_MENU_BUTTON
                 || obj->type == FL_TOUCH_BUTTON )
                ret |= FL_RETURN_CHANGED;
            break;

        case FL_MOTION :
            if (    obj->type == FL_RADIO_BUTTON
                 || obj->type == FL_INOUT_BUTTON
                 || obj->type == FL_MENU_BUTTON )
                break;

            newval = sp->val;

            if ( WITHIN( obj, mx, my ) )
            {
                obj->belowmouse = 1;
                if ( sp->react_to[ key - 1 ] )
                    newval = ! oldval;
            }
            else
            {
                obj->belowmouse = 0;
                if ( sp->react_to[ key - 1 ] )
                    newval = oldval;
            }

            if ( sp->val != newval )
            {
                sp->val = newval;
                fl_redraw_object( obj );
            }
            break;

        case FL_RELEASE :
            if ( key != sp->mousebut && obj->type != FL_RADIO_BUTTON )
            {
                fli_int.pushobj = obj;
                break;
            }

            sp->event = FL_RELEASE;
            sp->is_pushed = 0;

            if ( obj->type == FL_INOUT_BUTTON && ! WITHIN( obj, mx, my ) )
                obj->belowmouse = 0;

            if ( obj->type == FL_PUSH_BUTTON )
            {
                fl_redraw_object( obj );
                if ( sp->val != oldval )
                    ret |= FL_RETURN_END | FL_RETURN_CHANGED;
            }
            else if ( sp->val == 0 && obj->type != FL_MENU_BUTTON )
                fl_redraw_object( obj );
            else
            {
                sp->val = 0;
                fl_redraw_object( obj );

                if (    obj->type != FL_MENU_BUTTON
                     && obj->type != FL_TOUCH_BUTTON )
                    ret |= FL_RETURN_END | FL_RETURN_CHANGED;

                if ( obj->type == FL_TOUCH_BUTTON )
                    ret |= FL_RETURN_END;
            }

            break;

        case FL_UPDATE :                /* only FL_TOUCH_BUTTON receives it */
            sp->event = FL_UPDATE;
            if (    sp->val
                 && sp->timdel++ > 10
                 && ( sp->timdel & 1 ) == 0 )
                ret |= FL_RETURN_CHANGED;
            break;

        case FL_SHORTCUT :
            sp->event = FL_SHORTCUT;

            /* This is a horrible hack */

            if ( obj->type == FL_PUSH_BUTTON || obj->type == FL_RADIO_BUTTON )
            {
                sp->val = ! sp->val;
                obj->pushed = obj->type == FL_RADIO_BUTTON;
                fl_redraw_object( obj );
                wait_for_release( ev );
            }
            else if (    obj->type == FL_NORMAL_BUTTON
                      || obj->type == FL_RETURN_BUTTON )
            {
                int obl = obj->belowmouse;

                sp->val = obj->belowmouse = 1;
                fl_redraw_object( obj );
                wait_for_release( ev );
                sp->val = 0;
                obj->belowmouse = obl;
                fl_redraw_object( obj );
            }
            sp->mousebut = FL_SHORTCUT + key;
            ret |= FL_RETURN_END | FL_RETURN_CHANGED;
            break;

        case FL_FREEMEM :
            if ( ( cleanup = lookup_cleanupfunc( obj->objclass ) ) )
                cleanup( sp );
            free_pixmap( sp );
            fli_safe_free( obj->spec );
            break;
    }

    return ret;
}


/***************************************
 * Creates a (generic) button object
 ***************************************/

FL_OBJECT *
fl_create_generic_button( int          objclass,
                          int          type,
                          FL_Coord     x,
                          FL_Coord     y,
                          FL_Coord     w,
                          FL_Coord     h,
                          const char * label )
{
    FL_OBJECT *obj;
    FL_BUTTON_STRUCT *sp;
    int i;

    obj = fl_make_object( objclass, type, x, y, w, h, label, handle_button );
    if ( type == FL_RADIO_BUTTON )
        obj->radio = 1;

    if ( type == FL_RETURN_BUTTON || type == FL_HIDDEN_RET_BUTTON )
        fl_set_object_shortcut( obj, "^M", 0 );

    if ( type == FL_HIDDEN_BUTTON || type == FL_HIDDEN_RET_BUTTON )
        obj->boxtype = FL_NO_BOX;

    if ( obj->type == FL_TOUCH_BUTTON )
    {
        obj->want_update = 1;
        obj->how_return = FL_RETURN_CHANGED;
    }

    sp = obj->spec = fl_calloc( 1, sizeof *sp );

    sp->event     = FL_DRAW;
    sp->is_pushed = 0;
    sp->pixmap    = sp->mask = sp->focus_pixmap = sp->focus_mask = None;
    sp->cspecv    = NULL;
    sp-> filename = sp->focus_filename = NULL;
    sp->is_pushed = 0;
    sp->mousebut  = 0;

    /* Per default a button (unfortunately) reacts to all mouse buttons */

    for ( i = 0; i < 5; i++ )
        sp->react_to[ i ] = 1;

    if ( fli_cntl.buttonLabelSize )
        obj->lsize = fli_cntl.buttonLabelSize;

    return obj;
}


/***************************************
 * Sets the buttons state
 ***************************************/

void
fl_set_button( FL_OBJECT * obj,
               int         pushed )
{
    FL_BUTTON_STRUCT *sp = obj->spec;

    pushed = pushed ? 1 : 0;     /* button can only be on or off */

    /* Nothing to do if the new state is already what the button is set to */

    if ( sp->val == pushed )
        return;

    /* If this is a radio button to be shown as switched on unset other
       radio button in its group */

    if ( obj->type == FL_RADIO_BUTTON && pushed )
        fli_do_radio_push( obj, obj->x, obj->y, FL_MBUTTON1, NULL, 1 );

    /* Set new state and redraw the button */

    sp->val = pushed;
    fl_redraw_object( obj );
}


/***************************************
 * Returns the value of the button
 ***************************************/

int
fl_get_button( FL_OBJECT * obj )
{
    return ( ( FL_BUTTON_STRUCT * ) obj->spec )->val;
}


/***************************************
 * Returns the number of the last used mouse button.
 * fl_mouse_button will also return the mouse number
 ***************************************/

int
fl_get_button_numb( FL_OBJECT * obj )
{
    return ( ( FL_BUTTON_STRUCT * ) obj->spec )->mousebut;
}


/***************************************
 * Creates a button
 ***************************************/

FL_OBJECT *
fl_create_button( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    FL_OBJECT *obj;

    fl_add_button_class( FL_BUTTON, fli_draw_button, 0 );
    obj = fl_create_generic_button( FL_BUTTON, type, x, y, w, h, label );
    obj->boxtype = FL_BUTTON_BOXTYPE;
    obj->col1    = FL_BUTTON_COL1;
    obj->col2    = FL_BUTTON_COL2;
    obj->align   = FL_BUTTON_ALIGN;
    obj->lcol    = FL_BUTTON_LCOL;

    return obj;
}


/***************************************
 * Adds a button to the current form
 ***************************************/

FL_OBJECT *
fl_add_button( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label)
{
    FL_OBJECT *obj = fl_create_button( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );
    return obj;
}


/***************************************
 * Function allows to set up to which mouse
 * buttons the button object will react.
 ***************************************/

void
fl_set_button_mouse_buttons( FL_OBJECT    * obj,
                             unsigned int   mouse_buttons )
{
    FL_BUTTON_STRUCT *sp = obj->spec;
    unsigned int i;

    for ( i = 0; i < 5; i++, mouse_buttons >>= 1 )
        sp->react_to[ i ] = mouse_buttons & 1;
}


/***************************************
 * Function returns a value via 'mouse_buttons', indicating
 * which mouse buttons the button object will react to.
 ***************************************/

void
fl_get_button_mouse_buttons( FL_OBJECT    * obj,
                             unsigned int * mouse_buttons )
{
    FL_BUTTON_STRUCT *sp;
    int i;
    unsigned int k;

    if ( ! obj )
    {
        M_err( "fl_get_button_mouse_buttons", "NULL object" );
        return;
    }

    if ( ! mouse_buttons )
        return;

    sp = obj->spec;

    *mouse_buttons = 0;
    for ( i = 0, k = 1; i < 5; i++, k <<= 1 )
        *mouse_buttons |= sp->react_to[ i ] ? k : 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
