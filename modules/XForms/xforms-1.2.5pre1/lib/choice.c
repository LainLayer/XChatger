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
 * \file choice.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * FL_CHOICE class
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pchoice.h"
#include "private/flvasprintf.h"
#include <string.h>
#include <stdlib.h>


#define NO_TITLE_MASK      1
#define ALIGN_BOTTOM_MASK  2



/***************************************
 ***************************************/

static void
free_choice( FLI_CHOICE_SPEC * sp )
{
    int i;

    for ( i = 1; i <= FL_CHOICE_MAXITEMS; i++ )
    {
        if ( sp->items[ i ] )
            fli_safe_free( sp->items[ i ] );
        if ( sp->shortcut[ i ] )
            fli_safe_free( sp->shortcut[ i ] );
    }
}


/***************************************
 * Draws a choice object
 ***************************************/

static void
draw_choice( FL_OBJECT * ob )
{
    FL_COLOR c1;
    FLI_CHOICE_SPEC *sp = ob->spec;
    int absbw = FL_abs(ob->bw);
    int off1 = 0,
        off2 = 0;

    c1 = ob->belowmouse ? FL_CHOICE_MCOL : ob->col1;

    fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, c1, ob->bw );

    if ( ob->type == FL_NORMAL_CHOICE2 )
    {
        int dh = FL_max( 6 + ( ob->bw > 0 ), ob->h * 0.1 );
        int dw = FL_max( 0.11 * ob->w, 13 );
        int dbh = FL_max( absbw - 1, 1 );
        int align = fl_to_outside_lalign( sp->align );

        fl_draw_box( FL_UP_BOX,
                     ob->x + ob->w - dw - absbw - 2,
                     ob->y + ( ob->h - dh ) / 2,
                     dw, dh, ob->col1, - dbh );

        off1 = fl_is_center_lalign( align ) ? ( dw / 2 ) : 0;
        off2 = align == FL_ALIGN_RIGHT ? dw : 0;
    }

    fl_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h, ob->lcol,
                         ob->lstyle, ob->lsize, ob->label );

    /* String can conceivably contain "type flags". need to get rid of them
       on the fly */

    if ( sp->val > 0 && sp->val <= sp->numitems )
    {
        char *str = fl_strdup( sp->items[ sp->val ] ),
             *cc  = strchr( str, '%' );

        if ( cc )
        {
            if ( cc[ 1 ] == '%' )
                cc[ 1 ] = '\0';
            else
                cc[ 0 ] = '\0';
        }

        fl_set_text_clipping( ob->x + absbw, ob->y,
                              ob->w - 2 * absbw, ob->h );
        fl_draw_text( sp->align, ob->x - off1, ob->y, ob->w - off2,
                      ob->h, ob->col2, sp->fontstyle, sp->fontsize,
                      str + ( str && ( *str == '\010' ) ) );
        fl_unset_text_clipping( );
        fl_free( str );
    }
}


/***************************************
 ***************************************/

static void
draw_droplist_choice( FL_OBJECT * ob )
{
    FL_COLOR c1;
    FLI_CHOICE_SPEC *sp = ob->spec;
    FL_Coord dw = ob->h,
             dx = ob->w - dw,
             bw;

    c1 = sp->below ? FL_CHOICE_MCOL : ob->col1;
    bw = ob->bw;
    if ( bw > 0 )
        bw -= ob->bw > 1;

    /* Arrows */

    fl_draw_box( sp->pushed ? FL_DOWN_BOX : FL_UP_BOX, ob->x + dx, ob->y,
                 dw, ob->h, c1, bw );
    if ( sp->no_title & ALIGN_BOTTOM_MASK )
        fl_draw_text( FL_ALIGN_CENTER, ob->x + dx + 2, ob->y + 2,
                      dw - 4, ob->h - 4,
                      FL_BLACK, 0, 0, "@#8->" );
    else
        fl_draw_text( FL_ALIGN_CENTER, ob->x + dx + 2, ob->y + 2,
                      dw - 4, ob->h - 4,
                      FL_BLACK, 0, 0, "@#2->" );

    /* Choice box */

    fl_draw_box( ob->boxtype, ob->x, ob->y, dx, ob->h, ob->col1, ob->bw );
    fl_draw_text_beside( ob->align, ob->x, ob->y, dx, ob->h, ob->lcol,
                         ob->lstyle, ob->lsize, ob->label );

    /* String can conceivably contain "type flags", need to get rid of them
       on the fly */

    if ( sp->val > 0 && sp->val <= sp->numitems )
    {
        char *str = fl_strdup( sp->items[ sp->val ] ),
             *cc = strchr( str, '%' );

        if ( cc )
        {
            if ( cc[ 1 ] == '%')
                cc[ 1 ] = '\0';
            else
                cc[ 0 ] = '\0';
        }

        fl_set_text_clipping( ob->x + FL_abs( ob->bw ), ob->y,
                              ob->w - 2 * FL_abs( ob->bw ), ob->h );
        fl_draw_text( sp->align, ob->x, ob->y, dx, ob->h, ob->col2,
                      sp->fontstyle, sp->fontsize,
                      str + ( str && ( *str == '\010' ) ) );
        fl_unset_text_clipping( );
        fl_free( str );
    }
}


/***************************************
 * Due to grayout, need to find out which one is valid
 ***************************************/

static int
set_next_entry( FLI_CHOICE_SPEC * sp,
                int               dir )
{
    int target = 0;
    int min = 1,
        max = sp->numitems;

    if ( sp->numitems == 0 )
        return -1;

    while ( sp->mode[ min ] & FL_PUP_GREY && min < max )
        min++;

    while ( sp->mode[ max ] & FL_PUP_GREY && max > min )
        max--;

    if ( min == max )
        return -1;

    if ( dir > 0 )
    {
        target = sp->val + 1;
        if ( target > max )
            target = min;
    }
    else if ( dir < 0 )
    {
        target = sp->val - 1;
        if ( target < min )
            target = max;
    }

    for ( ; target >= min && target <= max; target += dir )
        if ( ! ( sp->mode[ target ] & FL_PUP_GREY ) )
            return sp->val = target;

    M_err( "set_next_entry", "No valid entries" );
    return -1;
}


/***************************************
 ***************************************/

static int
do_pup( FL_OBJECT * ob )
{
    int popup_id;
    FLI_CHOICE_SPEC *sp = ob->spec;
    int i,
        val;

    popup_id = fl_newpup( FL_ObjWin( ob ) );

    /* Fake a title */

    if (    ob->label
         && ob->label[ 0 ]
         && ob->type != FL_DROPLIST_CHOICE
         && ! ( sp->no_title & NO_TITLE_MASK ) )
    {
        char *t = fl_malloc( strlen( ob->label ) + 3 );

        strcpy( t, ob->label );
        strcat( t, "%t" );
        fl_addtopup( popup_id, t );
        fl_free( t );
    }

    for ( i = 1; i <= sp->numitems; i++ )
    {
        fl_addtopup( popup_id, sp->items[ i ] );

        if ( sp->modechange[ i ] || sp->mode[ i ] != FL_PUP_NONE )
        {
            fl_setpup( popup_id, i, sp->mode[ i ] );
            sp->modechange[ i ] = 0;
        }

        fl_setpup_shortcut( popup_id, i, sp->shortcut[ i ] );
    }

    fl_setpup_shadow( popup_id, ob->type != FL_DROPLIST_CHOICE );
    fl_setpup_selection( popup_id, sp->val );

    fl_setpup_softedge( popup_id, ob->bw < 0 );

    if ( sp->no_title & ALIGN_BOTTOM_MASK )
        fl_setpup_align_bottom( );

    val = fl_dopup( popup_id );

    if ( val > 0 )
    {
        sp->mode[ val ] = fl_getpup_mode( popup_id, i );
        sp->modechange[ val ] = 1;
        sp->val = val;
    }

    fl_freepup( popup_id );
    return val;
}


#define Within( x, y, w, h )   (    mx >= ( x )              \
                                 && mx <= ( ( x ) + ( w ) )  \
                                 && my >= ( y )              \
                                 && my <= ( ( y ) + ( h ) ) )


/***************************************
 * Handles an event, returns whether value has changed.
 ***************************************/

static int
handle_choice( FL_OBJECT * ob,
               int         event,
               FL_Coord    mx,
               FL_Coord    my,
               int         key,
               void *      ev   FL_UNUSED_ARG )
{
    FLI_CHOICE_SPEC *sp = ob->spec;
    int val;
    int ret = FL_RETURN_NONE;

#if FL_DEBUG >= ML_DEBUG
    M_info2( "handle_choice", fli_event_name( event ) );
#endif

    switch ( event )
    {
        case FL_ATTRIB :
            /* always force outside alignment */

            ob->align = fl_to_outside_lalign( ob->align );
            break;

        case FL_DRAW:
            if ( ob->type == FL_DROPLIST_CHOICE )
                draw_droplist_choice( ob );
            else
                draw_choice( ob );
            break;

        case FL_DRAWLABEL:
            fl_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                                 ob->lcol, ob->lstyle, ob->lsize, ob->label );
            break;

        case FL_PUSH:
            if ( key == FL_MBUTTON2 || key == FL_MBUTTON3 )
            {
                sp->counter = 0;
                val = set_next_entry( sp, key == FL_MBUTTON3 ? 1 : -1 );
                sp->pushed = 0;
                fl_redraw_object( ob );
                if ( val > 0 )
                    ret |= FL_RETURN_CHANGED;
                break;
            }

            if ( key != FL_MBUTTON1 || sp->numitems == 0 )
                break;

            if ( ob->type != FL_DROPLIST_CHOICE )
            {
                if ( do_pup( ob ) > 0 )
                    ret |= FL_RETURN_CHANGED;
                break;
            }

            /* Droplist choices only become active when the mouse button
               has been released */

            if ( Within( ob->x + ob->w - ob->h, ob->y, ob->h, ob->h ) )
            {
                sp->pushed = 1;
                draw_droplist_choice( ob );
            }
            break;

        case FL_UPDATE:
            if (    ( key == FL_MBUTTON2 || key == FL_MBUTTON3 )
                 && ++sp->counter % 15 == 0 )
            {
                sp->counter = 0;
                val = set_next_entry( sp, key == FL_MBUTTON3 ? 1 : -1 );
                sp->pushed = 0;
                fl_redraw_object( ob );
                if ( val > 0 )
                    ret |= FL_RETURN_CHANGED;
            }
            break;

        case FL_MOTION:
            if ( sp->numitems == 0 || ob->type != FL_DROPLIST_CHOICE )
                break;

            if ( Within( ob->x + ob->w - ob->h, ob->y, ob->h, ob->h ) )
            {
                if ( ! sp->below )
                {
                    sp->below = 1;
                    draw_droplist_choice( ob );
                }
            }
            else if ( sp->below )
            {
                sp->below = 0;
                draw_droplist_choice( ob );
            }
            break;
                
        case FL_RELEASE:
            if ( sp->numitems == 0 )
                break;

            if (    key == FL_MBUTTON4
                 || key == FL_MBUTTON5 )
            {
                val = set_next_entry( sp, key == FL_MBUTTON5 ? 1 : -1 );
                sp->pushed = 0;
                fl_redraw_object( ob );
                if ( val > 0 )
                    ret |= FL_RETURN_CHANGED | FL_RETURN_END;
                break;
            }

            if ( ob->type != FL_DROPLIST_CHOICE || ! sp->pushed )
                break;

            if ( ! Within( ob->x + ob->w - ob->h, ob->y, ob->h, ob->h ) )
            {
                sp->pushed = 0;
                fl_redraw_object( ob );
                break;
            }

            if ( sp->no_title & ALIGN_BOTTOM_MASK )
                fl_setpup_position( - ( ob->form->x + ob->x + ob->w ),
                                    ob->form->y + ob->y - FL_PUP_PADH );
            else
                fl_setpup_position( - ( ob->form->x + ob->x + ob->w ),
                                    ob->form->y + ob->y + ob->h + FL_PUP_PADH );
            sp->pushed = 0;
            if ( do_pup( ob ) > 0 )
                ret |= FL_RETURN_CHANGED | FL_RETURN_END;
            break;

        case FL_LEAVE:
            sp->below = 0;
            fl_redraw_object( ob );
            break;

        case FL_ENTER:
            if ( sp->numitems == 0 )
                break;

            if (    (    ob->type == FL_DROPLIST_CHOICE
                      && Within( ob->x + ob->w - ob->h, ob->y, ob->h, ob->h ) )
                 || ob->type != FL_DROPLIST_CHOICE )
            {
                sp->below = 1;
                fl_redraw_object( ob );
            }
            break;

        case FL_SHORTCUT:
            if ( sp->numitems == 0 )
                break;

            fl_setpup_position( ob->form->x + ob->x + 10,
                                ob->form->y + ob->y + ob->h / 2 );
            val = do_pup( ob );
            fl_redraw_object( ob );
            if ( val > 0 )
                ret |= FL_RETURN_CHANGED | FL_RETURN_END;
            break;

        case FL_FREEMEM:
            free_choice( ob->spec );
            fl_free( ob->spec );
            break;
    }

    return ret;
}


/***************************************
 * Creates an object
 ***************************************/

FL_OBJECT *
fl_create_choice( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    FL_OBJECT *obj;
    int i;
    FLI_CHOICE_SPEC *sp;

    obj = fl_make_object( FL_CHOICE, type, x, y, w, h, label, handle_choice );

    obj->boxtype     = type == FL_NORMAL_CHOICE2 ? FL_UP_BOX : FL_CHOICE_BOXTYPE;
    obj->col1        = FL_CHOICE_COL1;
    obj->col2        = FL_CHOICE_COL2;
    obj->lcol        = FL_CHOICE_LCOL;
    obj->align       = FL_CHOICE_ALIGN;
    obj->want_update = 1;
    obj->spec = sp   = fl_calloc( 1, sizeof *sp );

    sp->fontsize  = fli_cntl.choiceFontSize ?
                    fli_cntl.choiceFontSize : FL_DEFAULT_SIZE;
    sp->fontstyle = FL_NORMAL_STYLE;
    sp->align     = FL_ALIGN_CENTER;

    for ( i = 0; i <= FL_CHOICE_MAXITEMS; i++ )
    {
        sp->items[ i ] = NULL;
        sp->shortcut[ i ] = NULL;
    }

    fl_set_object_return( obj, FL_RETURN_CHANGED );

    return obj;
}


/***************************************
 * Adds an object
 ***************************************/

FL_OBJECT *
fl_add_choice( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * l )
{
    FL_OBJECT *ob;

    ob = fl_create_choice( type, x, y, w, h, l );
    fl_add_object( fl_current_form, ob );
    return ob;
}


/***************************************
 * Clears the choice object
 ***************************************/

void
fl_clear_choice( FL_OBJECT * ob )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHOICE ) )
    {
        M_err( "fl_clear_choice", "%s is not choice class",
               ob ? ob->label : "" );
        return;
    }
#endif

    free_choice( sp );

    sp->val = 0;
    sp->numitems = 0;
    fl_redraw_object( ob );
}


/***************************************
 * Add a single choice item
 ***************************************/

static void
addto_choice( FL_OBJECT *  ob,
              const char * str )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( sp->numitems >= FL_CHOICE_MAXITEMS )
        return;

    sp->items[ ++sp->numitems ] = fl_strdup( str );

    sp->shortcut[ sp->numitems ] = fl_strdup( "" );

    sp->mode[ sp->numitems ] = FL_PUP_NONE;
    sp->modechange[ sp->numitems ] = 0;

    if ( sp->val == 0 )
    {
        sp->val = 1;
        fl_redraw_object( ob );
    }
}


/***************************************
 * User interface routine.
 ***************************************/

int
fl_addto_choice( FL_OBJECT *  ob,
                 const char * str )
{
    FLI_CHOICE_SPEC *sp = ob->spec;
    char *t,
         *c;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHOICE ) )
    {
        M_err( "fl_addto_choice", "%s is not choice class",
               ob ? ob->label : "" );
        return 0;
    }
#endif

    if ( sp->numitems >= FL_CHOICE_MAXITEMS )
        return sp->numitems;

    /* Split up string at '|' chars and create an entry for each part */

    t = fl_strdup( str );

    for ( c = strtok( t, "|" );
          c && sp->numitems < FL_CHOICE_MAXITEMS;
          c = strtok( NULL, "|" ) )
        addto_choice( ob, c );

    if ( t )
        fl_free( t );

    return sp->numitems;
}


/***************************************
 ***************************************/

int
fl_addto_choice_f( FL_OBJECT *  ob,
                   const char * fmt,
                   ... )
{
    int n;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    n = fl_addto_choice( ob, buf );
    fl_free( buf );
    return n;
}


/***************************************
 * Replaces a line to the choice item.
 ***************************************/

void
fl_replace_choice( FL_OBJECT *  ob,
                   int          numb,
                   const char * str )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( numb < 1 || numb > sp->numitems )
        return;

    if ( sp->items[ numb ] )
        fl_free( sp->items[ numb ] );
    sp->items[ numb ] = fl_strdup( str );

    if ( sp->val == numb )
        fl_redraw_object( ob );
}


/***************************************
 ***************************************/

void
fl_replace_choice_f( FL_OBJECT *  ob,
                     int          numb,
                     const char * fmt,
                     ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_replace_choice( ob, numb, buf );
    fl_free( buf );
}


/***************************************
 * Removes a line from the choice item.
 ***************************************/

void
fl_delete_choice( FL_OBJECT * ob,
                  int         numb )
{
    int i;
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( numb < 1 || numb > sp->numitems )
        return;

    if ( sp->items[ numb ] )
        fl_free( sp->items[ numb ] );
    if ( sp->shortcut[ numb ] )
        fl_free( sp->shortcut[ numb ] );

    for ( i = numb; i < sp->numitems; i++ )
    {
        sp->items[ i ] = sp->items[ i + 1 ];
        sp->shortcut[ i ] = sp->shortcut[ i + 1 ];
    }

    sp->items[ sp->numitems ] = NULL;
    sp->shortcut[ sp->numitems ] = NULL;
    sp->numitems--;

    if ( sp->val == numb )
    {
        if ( sp->val > sp->numitems )
            sp->val = sp->numitems;
        fl_redraw_object( ob );
    }
    else if ( sp->val > numb )
        sp->val--;
}


/***************************************
 * Sets the number of the choice.
 ***************************************/

void
fl_set_choice( FL_OBJECT * ob,
               int         choice )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if (    choice < 1
         || choice > sp->numitems
         || sp->mode[ choice ] & FL_PUP_GREY )
        sp->val = 0;
    else
        sp->val = choice;
    fl_redraw_object( ob );
}


/***************************************
 * Similar to set_choice, except we use txt
 ***************************************/

void
fl_set_choice_text( FL_OBJECT *  ob,
                    const char * txt )
{
    FLI_CHOICE_SPEC *sp;
    int i;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHOICE ) )
    {
        M_err( "fl_set_choice_text", "%s not choice class",
               ob ? ob->label : "" );
        return;
    }
#endif
    sp = ob->spec;

    for ( i = 1; i <= sp->numitems; i++ )
        if ( strcmp( txt, sp->items[ i ] ) == 0 )
        {
            fl_set_choice( ob, i );
            return;
        }

    M_err( "fl_set_choice_text", "%s not found", txt );
}


/***************************************
 ***************************************/

void
fl_set_choice_text_f( FL_OBJECT *  ob,
                      const char * fmt,
                      ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_set_choice_text( ob, buf );
    fl_free( buf );
}


/***************************************
 ***************************************/

int
fl_get_choice_item_mode( FL_OBJECT *  ob,
                         int          item )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( item < 1 || item > sp->numitems )
    {
        M_err( "fl_get_choice_item_mode", "Bad item index %d", item );
        return -1;
    }

    return sp->mode[ item ];
}



/***************************************
 * Set the mode of an item in a choice object
 ***************************************/

void
fl_set_choice_item_mode( FL_OBJECT *  ob,
                         int          item,
                         unsigned int mode )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( item < 1 || item > sp->numitems )
    {
        M_err( "fl_set_choice_item_mode", "Bad item index %d", item );
        return;
    }

    sp->mode[ item ] = mode;
    sp->modechange[ item ] = 1;
}


/***************************************
 ***************************************/

void
fl_set_choice_item_shortcut( FL_OBJECT *  ob,
                             int          item,
                             const char * sc )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( item < 1 || item > sp->numitems )
    {
        M_err( "fl_set_choice_item_shortcut", "Bad item index %d", item );
        return;
    }

    if ( sp->shortcut[ item ] )
        fl_free( sp->shortcut[ item ] );

    sp->shortcut[ item ] = fl_strdup( sc ? sc : "" );
}


/***************************************
 * Returns the number of the choice.
 ***************************************/

int
fl_get_choice( FL_OBJECT * ob )
{
#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHOICE ) )
    {
        M_err( "fl_get_choice", "%s is not choice class", ob ? ob->label : "" );
        return 0;
    }
#endif

    return ( ( FLI_CHOICE_SPEC * ) ob->spec )->val;
}


/***************************************
 ***************************************/

int
fl_get_choice_maxitems( FL_OBJECT * ob )
{
    return ( ( FLI_CHOICE_SPEC * ) ob->spec )->numitems;
}


/***************************************
 * Returns the text of the choice.
 ***************************************/

const char *
fl_get_choice_text( FL_OBJECT * ob )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHOICE ) )
    {
        M_err( "fl_get_choice_text", "%s is not choice class",
               ob ? ob->label : "" );
        return 0;
    }
#endif

    if ( sp->val == 0 )
        return NULL;
    return sp->items[ sp->val ];
}


/***************************************
 ***************************************/

const char *
fl_get_choice_item_text( FL_OBJECT * ob,
                         int         n )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( n < 1 || n > sp->numitems )
        return NULL;

    return sp->items[ n ];
}


/***************************************
 * Sets the font size inside the choice.
 ***************************************/

void
fl_set_choice_fontsize( FL_OBJECT * ob,
                        int         size )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( sp->fontsize != size )
    {
        sp->fontsize = size;
        fl_redraw_object( ob );
    }
}


/***************************************
 * Sets the font style inside the choice.
 ***************************************/

void
fl_set_choice_fontstyle( FL_OBJECT * ob,
                         int         style )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( sp->fontstyle != style )
    {
        sp->fontstyle = style;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_choice_align( FL_OBJECT * ob,
                     int         align )
{
    FLI_CHOICE_SPEC *sp = ob->spec;

    if ( sp->align != align )
    {
        sp->align = align;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_set_choice_entries(FL_OBJECT * ob, FL_PUP_ENTRY * ent )
{
    int i,
        k;

    fl_clear_choice( ob );

    for ( k = 0; ent && ent->text; ent++, k++ )
    {
        i = fl_addto_choice( ob, ent->text );
        if ( ent->mode == FL_PUP_GRAY )
            fl_set_choice_item_mode( ob, i, ent->mode );
        if ( ent->shortcut && *ent->shortcut )
            fl_set_choice_item_shortcut( ob, i, ent->shortcut );
    }

    return k;
}


/***************************************
 ***************************************/

int
fl_set_choice_notitle( FL_OBJECT * ob,
                       int         n )
{
    FLI_CHOICE_SPEC *sp = ob->spec;
    int old = sp->no_title & NO_TITLE_MASK ? 1 : 0;

    if ( n )
        sp->no_title |= NO_TITLE_MASK;
    else
        sp->no_title &= ~ NO_TITLE_MASK;

    return old;
}


/***************************************
 ***************************************/

int
fl_set_choice_align_bottom( FL_OBJECT * ob,
                            int         n )
{
    FLI_CHOICE_SPEC *sp = ob->spec;
    int old = sp->no_title & ALIGN_BOTTOM_MASK ? 1 : 0;

    if ( n )
        sp->no_title |= ALIGN_BOTTOM_MASK;
    else
        sp->no_title &= ~ ALIGN_BOTTOM_MASK;

    return old;
}




/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
