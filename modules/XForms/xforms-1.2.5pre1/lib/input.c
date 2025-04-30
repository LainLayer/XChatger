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
 * \file input.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  XForms Class FL_INPUT
 *     handle normal user inputs and exchange data with other
 *     applications via the X Selection machnism.
 *
 *  Data structure is grossly wrong and very inefficient.
 *  Need to complete overhaul this someday.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include "private/pinput.h"
#include "private/flvasprintf.h"


enum {
    COMPLETE = 0,
    PARTIAL  = 1,
    VSLIDER  = 2,
    HSLIDER  = 4
};


static void correct_topline( FLI_INPUT_SPEC *,
                             int * );

static void redraw_scrollbar( FL_OBJECT * );

static int make_line_visible( FL_OBJECT * obj,
                              int         ypos );

static int make_char_visible( FL_OBJECT * obj,
                              int         xpos );

static void copy_attributes( FL_OBJECT       * dest,
                             const FL_OBJECT * src );

static int date_validator( FL_OBJECT *,
                           const char *,
                           const char *,
                           int );

static int int_validator( FL_OBJECT *,
                          const char *,
                          const char *,
                          int );

static int float_validator( FL_OBJECT *,
                            const char *,
                            const char *,
                            int );

static int xytopos( FLI_INPUT_SPEC * sp,
                    int              xpos,
                    int              ypos );

enum {
    NORMAL_SELECT,
    WORD_SELECT,
    LINE_SELECT
};


static int Input_Mode = FL_NORMAL_INPUT_MODE;


/***************************************
 ***************************************/

static void
get_margin( int        btype,
            int        bw,
            FL_Coord * xm,
            FL_Coord * ym )
{
    if (    btype == FL_FLAT_BOX
         || btype == FL_NO_BOX
         || btype == FL_FRAME_BOX
         || btype == FL_EMBOSSED_BOX )
    {
        *xm = bw + 1;
        *ym = 0.7 * bw + 1;
    }
    else
    {
        *xm = 2 * bw + ( bw == 1 );
        *ym = bw + 1 + ( bw == 1 );
    }
}


/***************************************
 * Checks the size of scrollbars and input field.  No drawing is allowed
 ***************************************/

static void
check_scrollbar_size( FL_OBJECT * obj )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    FL_Coord xmargin,
             ymargin;
    int bw = FL_abs( obj->bw );
    int delta;
    int h_on = sp->h_on,
        v_on = sp->v_on;
    int max_pixels = sp->max_pixels;

    /* The test for sp->vscroll and sp->hscroll being set is only for
       fdesign which might change the object type of a normal input to
       a multiline input without creating them */

    if (    sp->input->type != FL_MULTILINE_INPUT
         || ! ( sp->vscroll && sp->hscroll ) )
        return;

    /* Compute the real input box size */

    sp->input->x = sp->dummy->x;
    sp->input->y = sp->dummy->y;

    get_margin( sp->input->boxtype, bw, &xmargin, &ymargin );
    sp->charh = fl_get_char_height( sp->input->lstyle, sp->input->lsize, 0, 0 );

    /* See how many lines would fit in */

    sp->screenlines = ( sp->dummy->h - 2.0 * ymargin ) / sp->charh + 0.001;

    sp->v_on =    sp->v_pref == FL_ON
               || (    sp->screenlines && sp->screenlines < sp->lines
                    && sp->v_pref != FL_OFF );

    if ( sp->v_on )
    {
        sp->vw = sp->vw_def;
        sp->vscroll->x = sp->input->x + sp->dummy->w - sp->vw;
        sp->vscroll->y = sp->input->y;
        sp->vscroll->w = sp->vw;
        fli_set_object_visibility( sp->vscroll, FL_VISIBLE );
    }
    else
    {
        sp->vw = 0;
        fli_set_object_visibility( sp->vscroll, FL_INVISIBLE );
    }

    sp->input->w = sp->dummy->w - sp->vw;

    sp->h_on =    sp->h_pref == FL_ON
               || (    max_pixels > sp->w
                    && sp->h_pref != FL_OFF );

    if ( sp->h_on )
    {
        sp->h_on = 1;
        sp->hh = sp->hh_def;
        sp->hscroll->x = sp->input->x;
        sp->hscroll->y = sp->input->y + sp->dummy->h - sp->hh;
        sp->hscroll->h = sp->hh;
        fli_set_object_visibility( sp->hscroll, FL_VISIBLE );

        if ( ( delta = max_pixels - sp->w ) > 0 )
        {
            sp->hsize = ( double ) sp->w / max_pixels;
            sp->hval  = ( double ) sp->xoffset / delta;
            sp->hinc1 = 8.0 * sp->charh / delta;
            sp->hinc2 = ( sp->charh - 2.0 ) / delta;
        }
        else
            sp->hsize = 1.0;
    }
    else
    {
        sp->hh = 0;
        fli_set_object_visibility( sp->hscroll, FL_INVISIBLE );
    }

    sp->input->h = sp->dummy->h - sp->hh;
    sp->h = sp->input->h - 2 * ymargin;

    sp->screenlines = ( double ) sp->h / sp->charh + 0.001;

    if ( ! sp->v_on && sp->screenlines < sp->lines && sp->h_pref != FL_OFF )
    {
        sp->v_on = 1;
        sp->vw = sp->vw_def;
        sp->vscroll->x = sp->input->x + sp->dummy->w - sp->vw;
        sp->vscroll->y = sp->input->y;
        sp->vscroll->visible = 1;
        sp->input->w = sp->dummy->w - sp->vw;
    }

    if ( sp->v_on && ( delta = sp->lines - sp->screenlines ) > 0 )
    {
        sp->vval = ( sp->topline - 1.0 ) / delta;
        sp->vsize = ( double ) sp->screenlines / sp->lines;
        sp->vinc1 = ( sp->screenlines - 0.99 ) / delta;
        sp->vinc2 = 1.01 / delta;
    }
    else
        sp->vsize = 1.0;

    sp->hscroll->w = sp->input->w;
    fli_notify_object( sp->hscroll, FL_RESIZED );
    sp->vscroll->h = sp->input->h;
    fli_notify_object( sp->vscroll, FL_RESIZED );
    sp->w = sp->input->w - 2 * xmargin;

    if ( h_on != sp->h_on || v_on != sp->v_on )
    {
        sp->attrib = 1;
        sp->dead_area = ! ( sp->h_on ^ sp->v_on );
    }
}


/***************************************
 ***************************************/

static void
draw_input( FL_OBJECT * obj )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    FL_COLOR col;
    FL_COLOR curscol = fli_dithered( fl_vmode ) ? FL_BLACK : sp->curscol;
    FL_Coord xmargin,
             ymargin;
    int bw = FL_abs( obj->bw );
    int cx,
        cy;
    int max_pixels,
        max_pixels_line;
    static char *saved;

    get_margin( obj->boxtype, bw, &xmargin, &ymargin );
    sp->w = sp->input->w - 2 * xmargin;
    sp->h = sp->input->h - 2 * ymargin;

    col = obj->focus ? obj->col2 : obj->col1;

    if ( sp->drawtype == COMPLETE )
    {
        fl_draw_box( obj->boxtype, sp->input->x, sp->input->y,
                     sp->input->w, sp->input->h, col, obj->bw );
        fl_draw_object_label_outside( obj );
    }

    if ( obj->type == FL_SECRET_INPUT )
    {
        saved = sp->str;
        sp->str = fl_strdup( sp->str );
        memset( sp->str, sp->field_char, strlen( saved ) );
    }

    cx = sp->input->x + xmargin;
    cy = sp->input->y + ymargin;

    fl_set_text_clipping( cx, cy, sp->w, sp->h );
    fl_set_clipping( cx, cy, sp->w, sp->h );

    max_pixels = fli_draw_string( obj->type == FL_MULTILINE_INPUT ?
                                  FL_ALIGN_LEFT_TOP : FL_ALIGN_LEFT,
                                  cx - sp->xoffset,      /* Bounding box */
                                  cy - sp->yoffset,
                                  sp->w + sp->xoffset,
                                  sp->h + sp->yoffset,
                                 -1,               /* Clipping is already set */
                                  col, sp->textcol, curscol,
                                  obj->lstyle, obj->lsize,
                                  (    sp->cursor_visible
                                    && obj->focus
                                    && sp->beginrange >= sp->endrange ) ?
                                  sp->position : -1,
                                  sp->beginrange, sp->endrange,
                                  sp->str, sp->drawtype != COMPLETE,
                                  sp->topline,
                                  sp->topline + sp->screenlines, 0 );

    max_pixels_line = fli_get_max_pixels_line( ) + 1;
    sp->charh = fl_get_char_height( obj->lstyle, obj->lsize, 0, 0 );

    if (    max_pixels > sp->max_pixels
         || (    sp->max_pixels_line >= sp->topline
              && sp->max_pixels_line <= sp->topline + sp->screenlines ) )
    {
        sp->max_pixels = max_pixels;
        sp->max_pixels_line = max_pixels_line;
    }

    fl_unset_clipping( );
    fl_unset_text_clipping( );

    if ( obj->type == FL_SECRET_INPUT )
    {
        fli_safe_free( sp->str );
        sp->str = saved;
    }

    sp->drawtype = COMPLETE;
}


#define DELIM( c )  ( c == ' ' || c == ',' || c == '.' || c == '\n' )


/***************************************
 * Figures out selection region of mouse, returns whether anything changed
 ***************************************/

static int
handle_select( FL_Coord    mx,
               FL_Coord    my,
               FL_OBJECT * obj,
               int         movement,
               int         mode )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int thepos,
        n,
        dummy;
    int oldpos = sp->position,
        oldbeg = sp->beginrange,
        oldend = sp->endrange;
    int bw = FL_abs( obj->bw );
    FL_Coord xmargin,
             ymargin;

    if ( obj->type == FL_HIDDEN_INPUT )
        return 0;

    /* Compute the mouse position in the string */

    get_margin( obj->boxtype, bw, &xmargin, &ymargin );

    thepos = fli_get_pos_in_string( obj->type == FL_MULTILINE_INPUT ?
                                    FL_ALIGN_LEFT_TOP : FL_ALIGN_LEFT,
                                    sp->input->x + xmargin - sp->xoffset,
                                    sp->input->y + ymargin - sp->yoffset,
                                    sp->w + sp->xoffset,
                                    sp->h + sp->yoffset,
                                    obj->lstyle, obj->lsize,
                                    mx, my, sp->str,
                                    &sp->xpos, &sp->ypos, &dummy );

    if ( mode == WORD_SELECT )
    {
#if defined USE_CLASSIC_EDITKEYS
        if ( sp->str[ thepos ] == ' ' )
            return 0;

        for ( n = thepos; sp->str[ n ] && ! DELIM( sp->str[ n ] ); n++ )
            /* empty */ ;
        sp->endrange = n;

        for ( n = thepos; n >= 0 && ! DELIM( sp->str[ n ] ); n-- )
            /* empty */ ;

        sp->beginrange = n + 1;
#else
        if (    ! isalnum( ( unsigned char ) sp->str[ thepos ] )
             && sp->str[ thepos ] != '_' )
        {
            for ( n = thepos;
                     sp->str[ n ]
                  && ! isalnum( ( unsigned char ) sp->str[ n ] )
                  && sp->str[ n ] != '_'
                  && sp->str[ n ] != '\n';
                  n++ )
                /* empty */ ;
            sp->endrange = n;

            for ( n = thepos;
                     n
                  && ! isalnum( ( unsigned char ) sp->str[ n ] )
                  && sp->str[ n ] != '_'
                  && sp->str[ n ] != '\n';
                  n-- )
                /* empty */ ;
            if ( n > 0 )
                ++n;
            sp->beginrange = n;
        }
        else
        {
            for ( n = thepos;
                     sp->str[ n ]
                  && (    isalnum( ( unsigned char ) sp->str[ n ] )
                       || sp->str[ n ] == '_' );
                  n++ )
                /* empty */ ;
            sp->endrange = n;

            for ( n = thepos;
                  n && (    isalnum( ( unsigned char ) sp->str[ n ] )
                         || sp->str[ n ] == '_' );
                  n-- )
                /* empty */ ;
            if ( n > 0 )
                ++n;
            sp->beginrange = n;
        }
#endif
    }
    else if ( mode == LINE_SELECT )
    {
        for ( n = thepos; sp->str[ n ] && sp->str[ n ] != '\n'; n++ )
            /* empty */ ;
        sp->endrange = n;

        for ( n = thepos; n >= 0 && sp->str[ n ] != '\n'; n-- )
            /* empty */ ;
        sp->beginrange = n + 1;
    }
    else
    {
        /* Adapt the range */

        if ( movement )
        {
            fl_freeze_form( obj->form );
            make_line_visible( obj, sp->ypos );
            make_char_visible( obj, sp->xpos );
            fl_unfreeze_form( obj->form );

            if ( thepos < sp->position )
            {
                sp->endrange = sp->position;
                sp->beginrange = thepos;
            }
            else
            {
                sp->beginrange = sp->position;
                sp->endrange = thepos;
            }
        }
        else
        {
            sp->position = sp->beginrange = thepos;
            sp->endrange = -1;
        }
    }

    if ( sp->beginrange == sp->endrange )
        sp->endrange = -1;

    if ( sp->beginrange < 0 )
        sp->beginrange = 0;

    return    oldpos != sp->position
           || oldbeg != sp->beginrange
           || oldend != sp->endrange;
}


/***************************************
 * This is not XCUTBUFFER. It is generated by ^K and can be
 * recalled by ^Y
 ***************************************/

#define MAXCBLEN   512
static char cutbuf[ MAXCBLEN ];


/***************************************
 * Delete a single char. dir =1 for next, dir -1 for prev
 ***************************************/

static void
delete_char( FLI_INPUT_SPEC * sp,
             int              dir,
             int              slen )
{
    int i = sp->position - ( dir < 0 );

    if ( sp->str[ i ] == '\n' )
    {
        sp->lines--;
        sp->ypos -= dir < 0;
    }

    memmove( sp->str + i, sp->str + i + 1, slen - i );
    sp->position -= dir < 0;
}


/***************************************
 * Removes a piece of the string 
 ***************************************/

static void
delete_piece( FL_OBJECT * obj,
              int         start,
              int         end )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    memmove( sp->str + start, sp->str + end + 1, strlen( sp->str + end ) );
    sp->position = start;

    /* This can be expensive TODO */

    sp->lines = fl_get_input_numberoflines( obj );
    fl_get_input_cursorpos( obj, &sp->xpos, &sp->ypos );
}


#define get_substring_width( o, b, e )                                       \
    fl_get_string_width( ( o )->lstyle, ( o )->lsize,                        \
                         ( ( FLI_INPUT_SPEC * ) ( o )->spec )->str + ( b ),  \
                         ( e ) - ( b ) )

#define IsRegular( k )  (    ( k ) == '\n'                                \
                          || ( key >= 32 && key <= 255 && key != 127 ) )


/***************************************
 * Editing command. Need 4 bytes. Byte1 for normal ASCII, byte2 for
 * special keysyms, such as PageUP etc. Byte 3 is used by Latin3 etc.
 * Byte 4 will be used to indicate modifiers.
 ***************************************/

static FL_EditKeymap kmap;

static int paste_it( FL_OBJECT *,
                     const unsigned char *,
                     int );

static void set_default_keymap( int );

#define set_to_eol( p )  while ( ( p ) < slen && sp->str[ p ] != '\n' ) ( p )++


/***************************************
 * Cursor moved. No editing.
 ***************************************/

static void
handle_movement( FL_OBJECT * obj,
                 int         key,
                 int         slen,
                 int         startpos,
                 int         kmask )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int ready,
        width,
        i,
        oldwidth,
        tt;

    if ( IsHome( key ) )
    {
        fl_set_input_topline( obj, 1 );
        sp->position = 0;
        sp->ypos = 1;
    }
    else if ( IsPageDown( key ) )
        fl_set_input_topline( obj, sp->topline + sp->screenlines );
    else if ( IsHalfPageDown( key ) )
        fl_set_input_topline( obj, sp->topline + sp->screenlines / 2 );
    else if ( Is1LineDown( key ) )
        fl_set_input_topline( obj, sp->topline + 1 );
    else if ( IsPageUp( key ) )
        fl_set_input_topline( obj, sp->topline - sp->screenlines );
    else if ( IsHalfPageUp( key ) )
        fl_set_input_topline( obj, sp->topline - sp->screenlines / 2 );
    else if ( Is1LineUp( key ) )
        fl_set_input_topline( obj, sp->topline - 1 );
    else if ( key == '\t' || key == '\f' )
        /* empty */ ;
    else if ( IsEnd( key ) )
    {
        fl_set_input_topline( obj, sp->lines );
        sp->position = slen;
        fl_get_input_cursorpos( obj, &sp->xpos, &sp->ypos );
    }
    else if ( IsLeft( key ) )   /* Left key */
    {
        if ( shiftkey_down( kmask ) )
            sp->position = startpos;
        else if ( sp->position > 0 )
            sp->position--;

        if ( sp->str[ sp->position ] == '\n' )
        {
            sp->ypos--;

            /* Compute starting position of current line */

            startpos = sp->position;
            while ( startpos > 0 && sp->str[ startpos - 1 ] != '\n' )
                startpos--;
        }
    }
    else if ( IsRight( key ) || key == kmap.moveto_eol )
    {
        if ( shiftkey_down( kmask ) || key == kmap.moveto_eol )
            set_to_eol( sp->position );
        else if ( sp->position < slen )
        {
            if ( sp->str[ sp->position ] == '\n' )
            {
                sp->ypos++;
                startpos = sp->position + 1;
            }
            sp->position++;
        }
    }
    else if ( IsUp( key ) )     /* Up key */
    {
        if ( startpos != 0 )
        {
            width = get_substring_width( obj, startpos, sp->position );
            i = startpos - 1;

            while ( i > 0 && sp->str[ i - 1 ] != '\n' )
                i--;

            oldwidth = 0.0;
            sp->position = i;

            ready = sp->str[ sp->position ] == '\n';

            while ( ! ready )
            {
                tt = get_substring_width( obj, i, sp->position + 1 );
                ready = 0.5 * ( oldwidth + tt ) >= width;
                oldwidth = tt;

                if ( ! ready )
                    sp->position++;

                if ( sp->str[ sp->position ] == '\n' )
                    ready = 1;
            }

            if ( --sp->ypos < 1 )
                sp->ypos = 1;
        }
    }
    else if ( IsDown( key ) )   /* Down key */
    {
        width = get_substring_width( obj, startpos, sp->position );
        i = sp->position + 1;

        while ( i < slen && sp->str[ i - 1 ] != '\n' )
            i++;

        if ( i < slen )
        {
            oldwidth = 0.0;
            sp->position = i;
            ready = sp->position == slen || sp->str[ sp->position ] == '\n';

            while ( ! ready )
            {
                tt = get_substring_width( obj, i, sp->position + 1 );
                ready = 0.5 * ( oldwidth + tt ) >= width;
                oldwidth = tt;

                if ( ! ready )
                    sp->position++;

                if ( sp->position == slen || sp->str[ sp->position ] == '\n' )
                    ready = 1;
            }
        }
        else
            sp->position = slen;

        if ( ++sp->ypos > sp->lines )
            sp->ypos = sp->lines;
    }
    else if ( key == kmap.moveto_bol )
        sp->position = startpos;
    else if ( key == kmap.moveto_prev_word )
    {
#if defined USE_CLASSIC_EDITKEYS
        if ( sp->position > 0 )
            sp->position--;

        while (    sp->position > 0
                && (    sp->str[ sp->position ] == ' '
                     || sp->str[ sp->position ] == '\n' ) )
        {
            if ( sp->str[ sp->position ] == '\n' )
                sp->ypos--;

            sp->position--;
        }

        while (    sp->position > 0
                && sp->str[ sp->position ] != ' '
                && sp->str[ sp->position ] != '\n' )
            sp->position--;
#else
        if ( sp->position > 0 )
            sp->position--;

        if (     ! isalnum( ( unsigned char ) sp->str[ sp->position ] )
              && sp->str[ sp->position ] != '_' )
            while (    sp->position > 0
                    && ! (    isalnum( ( unsigned char )
                                       sp->str[ sp->position ] )
                           || sp->str[ sp->position ] == '_' ) )
                --sp->position;
        else
            while (    sp->position > 0
                    && (    isalnum( ( unsigned char ) sp->str[ sp->position ] )
                         || sp->str[ sp->position ] == '_' ) )
                --sp->position;
#endif

        if ( sp->position > 0 )
            sp->position++;
    }
    else if ( key == kmap.moveto_next_word )
    {
        i = sp->position;

#if defined USE_CLASSIC_EDITKEYS
        while ( i < slen && ( sp->str[ i ] == ' ' || sp->str[ i ] == '\n' ) )
        {
            if ( sp->str[ i ] == '\n' )
                sp->ypos++;
            i++;
        }

        while ( i < slen && sp->str[ i ] != ' ' && sp->str[ i ] != '\n' )
            i++;
#else
        if (    ! isalnum( ( unsigned char ) sp->str[ i ] )
             && sp->str[ i ] != '_' )
            while (    i < slen
                    && ! isalnum( ( unsigned char ) sp->str[ i ] )
                    && sp->str[ i ] != '_' )
                ++i;
        else
            while (    i < slen
                    && (    isalnum( ( unsigned char ) sp->str[ i ] )
                         || sp->str[ i ] == '_' ) )
                ++i;
#endif
        sp->position = i;
    }
}


/***************************************
 * Editing
 ***************************************/

static int
handle_edit( FL_OBJECT * obj,
             int         key,
             int         slen )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int ret = FL_RETURN_CHANGED,
        i;

    if ( key == kmap.del_prev_char || key == kmap.backspace )
    {
        if ( sp->endrange >= 0 )
            delete_piece( obj, sp->beginrange, sp->endrange - 1 );
        else if ( sp->position > 0 )
            delete_char( sp, -1, slen );
        else
            ret = FL_RETURN_NONE;
    }
    else if ( key == kmap.del_next_char )
    {
        if ( sp->endrange >= 0 )
            delete_piece( obj, sp->beginrange, sp->endrange - 1 );
        else if ( sp->position < slen )
            delete_char( sp, 1, slen );
        else
            ret = FL_RETURN_NONE;
    }
    else if ( key == kmap.del_next_word )
    {
        if ( obj->type == FL_SECRET_INPUT || ( i = sp->position ) == slen )
            ret = FL_RETURN_NONE;
        else
        {
#if defined USE_CLASSIC_EDITKEYS
            while (    i < slen
                    && ( sp->str[ i ] == ' ' || sp->str[ i ] == '\n' ) )
                i++;
            while ( i < slen && sp->str[ i ] != ' ' && sp->str[ i ] != '\n' )
                i++;
#else
            /* If the first character is neiter a letter nor a digit nor an
               underscore delete it and all other characters of the same kind.
               Otherwise delete all charaters that are letters. digit or
               underscores. This is the same behaviour as in e.g. Qt.
            */

            if (    ! isalnum( ( unsigned char ) sp->str[ i ] )
                 && sp->str[ i ] != '_' )
                while (    i < slen
                        && ! isalnum( ( unsigned char ) sp->str[ i ] )
                        && sp->str[ i ] != '_' )
                    i++;
            else
                while (    i < slen
                        && (    isalnum( ( unsigned char ) sp->str[ i ] )
                             || sp->str[ i ] == '_' ) )
                    i++;
#endif
            if ( i - sp->position > 1 )
                fli_sstrcpy( cutbuf, sp->str + sp->position,
                             FL_min( i - sp->position + 1, MAXCBLEN ) );

            delete_piece( obj, sp->position, i - 1 );
        }
    }
    else if ( key == kmap.del_prev_word )
    {
        int j = sp->position;

        if ( obj->type == FL_SECRET_INPUT || j == 0 )
            ret = FL_RETURN_NONE;
        else
        {

#if defined USE_CLASSIC_EDITKEYS
            sp->position--;
            while (    sp->position > 0
                    && (    sp->str[ sp->position ] == ' '
                         || sp->str[ sp->position ] == '\n' ) )
                sp->position--;
            while (    sp->position > 0
                    && sp->str[ sp->position ] != ' '
                    && sp->str[ sp->position ] != '\n' )
                sp->position--;
#else
            --sp->position;
            if (    ! isalnum( ( unsigned char ) sp->str[ sp->position ] ) 
                 && sp->str[ sp->position ] != '_' )
                while (    sp->position > 0
                        && ! isalnum( ( unsigned char )
                                      sp->str[ sp->position ] ) 
                        && sp->str[ sp->position ] != '_' )
                    --sp->position;
            else
                while (    sp->position > 0
                        && (    isalnum( ( unsigned char )
                                         sp->str[ sp->position ] ) 
                             || sp->str[ sp->position ] == '_' ) )
                    --sp->position;

            if ( sp->position )
                ++sp->position;
#endif
            if ( sp->position != j )
            {
                if ( j - sp->position > 1 )
                    fli_sstrcpy( cutbuf, sp->str + sp->position,
                                 FL_min( j - sp->position + 1, MAXCBLEN ) );
                delete_piece( obj, sp->position, j - 1 );
            }
            else
                ret = FL_RETURN_NONE;
        }
    }
    else if ( key == kmap.clear_field )
    {
        if ( slen > 0 )
        {
            if ( slen > 1 )
                fli_sstrcpy( cutbuf, sp->str, FL_min( slen, MAXCBLEN ) );
            delete_piece( obj, 0, slen - 1 );
        }
        else
            ret = FL_RETURN_NONE;
    }
    else if ( key == kmap.del_to_eol )
    {
        if ( slen > sp->position )
        {
            if ( sp->str[ sp->position ] != '\n' )
                for ( i = sp->position; i < slen && sp->str[ i ] != '\n'; i++ )
                    /* empty */ ;
            else
                i = sp->position + 1;

            /* Save buffer */

            if ( i - sp->position > 1 )
                fli_sstrcpy( cutbuf, sp->str + sp->position,
                             FL_min( i - sp->position + 1, MAXCBLEN ) );

            delete_piece( obj, sp->position, i - 1 );
        }
        else
            ret = FL_RETURN_NONE;
    }
#if ! defined USE_CLASSIC_EDITKEYS
    else if ( key == kmap.del_to_bol )
    {
        int j = sp->position;

        if ( j == 0 )
            ret = FL_RETURN_NONE;
        else
        {
            if ( sp->str[ --sp->position ] != '\n' )
            {
                while ( sp->position > 0 && sp->str[ --sp->position ] != '\n' )
                    /* empty */;
                if ( sp->str[ sp->position ] == '\n' )
                    ++sp->position;
            }

            if ( j - sp->position > 1 )
                fli_sstrcpy( cutbuf, sp->str + sp->position,
                             FL_min( j - sp->position + 1, MAXCBLEN ) );

            delete_piece( obj, sp->position, j - 1 );
        }
    }
#endif
    else if ( key == kmap.paste )
        paste_it( obj, ( unsigned char * ) cutbuf, strlen( cutbuf ) );
    else if ( key == kmap.transpose && sp->position > 0 )
    {
        char t;

        if ( sp->position < slen && sp->str[ sp->position ] != '\n' )
        {
            t = sp->str[ sp->position - 1 ];
            sp->str[ sp->position - 1 ] = sp->str[ sp->position ];
            sp->str[ sp->position ] = t;
            sp->position++;
        }
        else
        {
            t = sp->str[ sp->position - 2 ];
            sp->str[ sp->position - 2 ] = sp->str[ sp->position - 1 ];
            sp->str[ sp->position - 1 ] = t;
        }
    }

    return ret;
}


/***************************************
 * Handles a key press, returns whether something has changed
 ***************************************/

static int
handle_normal_key( FL_OBJECT    * obj,
                   int            key,
                   int            slen )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    char *tmpbuf = NULL;
    int tmppos = 0;
    int ret = FL_RETURN_CHANGED;

    /* Check that there's still room for a new character */

    if (    sp->maxchars > 0
         && slen >= sp->maxchars
         && (    Input_Mode == FL_NORMAL_INPUT_MODE
              || slen == sp->position ) )
    {
        fl_ringbell( 0 );
        return FL_RETURN_NONE;
    }

    if ( sp->validate )
    {
        tmpbuf = fl_strdup( sp->str );
        tmppos = sp->position;
    }

    /* If a range is marked remove it, it's replaced by the new character */

    if ( sp->endrange >= 0 )
    {
        delete_piece( obj, sp->beginrange, sp->endrange - 1 );
        slen = strlen( sp->str );
    }

    /* Merge the new character */

    if (    Input_Mode == FL_DOS_INPUT_MODE
        && sp->maxchars > 0
        && slen == sp->maxchars )
    {
        memmove( sp->str + sp->position + 1, sp->str + sp->position,
                 slen - sp->position );
        sp->str[ sp->maxchars ] = '\0';
    }
    else
        memmove( sp->str + sp->position + 1, sp->str + sp->position,
                 slen - sp->position + 1 );
    sp->str[ sp->position++ ] = key;

    if ( key == '\n' )
    {
        sp->lines++;
        sp->ypos++;
    }

    if ( sp->validate )
    {
        int ok = sp->validate( obj, tmpbuf, sp->str, key );

        if ( ( ok & ~ FL_RINGBELL ) != FL_VALID )
        {
            ret = FL_RETURN_NONE;
            strcpy( sp->str, tmpbuf );
            sp->position = tmppos;

            if ( key == '\n' )
            {
                sp->lines--;
                sp->ypos--;
            }
        }

        if ( ok & FL_RINGBELL )
            fl_ringbell( 0 );
        fl_free( tmpbuf );
    }

    return ret;
}



/***************************************
 * Handles a key press, returns whether the content of the input field
 * was changed
 ***************************************/

static int
handle_key( FL_OBJECT    * obj,
            int            key,
            unsigned int   kmask )
{
    int ret = FL_RETURN_NONE;
    FLI_INPUT_SPEC *sp = obj->spec;
    int slen;                  /* length of the string */
    int oldy = sp->ypos;
    int oldl = sp->lines;
    int oldx = sp->xoffset;
    int oldmax = sp->max_pixels;

    /* Increase the size of the buffer for the text if it's full */

    slen = strlen( sp->str );

    if ( sp->size == slen + 1 )
    {
        sp->size += 8;
        sp->str = fl_realloc( sp->str, sp->size );
    }

    /* Silently translate carriage return to line feed */

    if ( obj->type == FL_MULTILINE_INPUT && key == '\r' )
        key = '\n';

#if defined USE_CLASSIC_EDITKEYS
    if ( controlkey_down( kmask ) && key > 255 )
        key |= FL_CONTROL_MASK;
#else
    if ( controlkey_down( kmask ) )
        key |= FL_CONTROL_MASK;
#endif

    if ( metakey_down( kmask ) )
        key |= FL_ALT_MASK;

    if ( shiftkey_down( kmask ) )
    {
        if ( key == XK_Up )
            key = XK_Home;
        else if ( key == XK_Down )
            key = XK_End;
    }

    /* Translate all move keys to cursor keys so we can distinguish edit/move
       keys more easily */

    if ( key == kmap.moveto_next_line )
        key = XK_Down;
    else if ( key == kmap.moveto_prev_line )
        key = XK_Up;
    else if ( key == kmap.moveto_prev_char )
        key = XK_Left;
    else if ( key == kmap.moveto_next_char )
        key = XK_Right;
    else if ( key == kmap.moveto_bof )
        key = XK_Home;
    else if ( key == kmap.moveto_eof )
        key = XK_End;
    else if ( key == kmap.moveto_next_page )
        key = XK_PageDn;
    else if ( key == kmap.moveto_prev_page )
        key = XK_PageUp;

    if ( IsRegular( key ) )     /* Normal keys and new line */
        ret = handle_normal_key( obj, key, slen );
    else if (    IsCursorKey( key )
              || key == kmap.moveto_eol
              || key == kmap.moveto_bol
              || key == kmap.moveto_prev_word
              || key == kmap.moveto_next_word
              || Is1LineUp( key )
              || Is1LineDown( key )
              || IsHalfPageUp( key )
              || IsHalfPageDown( key ) )
    {
        int startpos = 0;

        if ( obj->type == FL_MULTILINE_INPUT )
        {
            startpos = sp->position;
            while ( startpos > 0 && sp->str[ startpos - 1 ] != '\n' )
                startpos--;
        }

        handle_movement( obj, key, slen, startpos, kmask );

        if ( sp->endrange != -1 )
        {
            make_line_visible( obj, sp->ypos );
            make_char_visible( obj, sp->xpos );
        }
    }
    else
        ret = handle_edit( obj, key, slen );

    sp->endrange = -1;

    if ( ret != FL_RETURN_NONE )
    {
        int junk;

        fl_get_string_dimension( obj->lstyle, obj->lsize, sp->str,
                                 strlen( sp->str ), &sp->max_pixels, &junk );
    }

    if ( sp->noscroll )
    {
        sp->xoffset = sp->yoffset = 0;
        sp->topline = sp->ypos = 1;
        oldmax = sp->max_pixels;
    }
    else
    {
        int startpos = 0;
        int width;

        if ( obj->type == FL_MULTILINE_INPUT )
        {
            startpos = sp->position;
            while ( startpos > 0 && sp->str[ startpos - 1 ] != '\n' )
                startpos--;
        }

        width = fl_get_string_width( obj->lstyle, obj->lsize,
                                     sp->str + startpos,
                                     sp->position - startpos );

        if ( width < sp->w - 4 )
            sp->xoffset = 0;
        else
        {
            if ( width - oldx > sp->w - 4 )
                sp->xoffset = width - sp->w + 4;
            else
            {
                int cw = fl_get_char_width( obj->lstyle, obj->lsize );
                if ( width - oldx < cw )
                sp->xoffset = width - cw;
                else
                    sp->xoffset = oldx;
            }
        }
    }

    fl_freeze_form( obj->form );

    if (    oldl   != sp->lines
         || oldy   != sp->ypos
         || oldx   != sp->xoffset
         || oldmax != sp->max_pixels )
    {
        check_scrollbar_size( obj );
        make_line_visible( obj, sp->ypos );
        redraw_scrollbar( obj );
    }

    fl_redraw_object( sp->input );
    fl_unfreeze_form( obj->form );

    return ret;
}


/***************************************
 * Given nb bytes of stuff, paste it into the input field.
 ***************************************/

static int
paste_it( FL_OBJECT           * obj,
          const unsigned char * thebytes,
          int                   nb )
{
    int ret = FL_RETURN_NONE;

    while ( nb-- )
        ret |= handle_key( obj, *thebytes++, 0 );

    return ret;
}


/***************************************
 * Callback for handling selection. It might be called only after
 * handling the input object is done and in that case we have to
 * insert the object into the onject queue manually...
 ***************************************/

/* handle X cut & paste ******************************* */

static int selection_hack = 0;

static int
gotit_cb( FL_OBJECT  * obj,
          long         type  FL_UNUSED_ARG,
          const void * buf,
          long         nb )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    sp->changed |= paste_it( obj, ( unsigned char * ) buf, nb );
    fl_update_display( 0 );

    if ( selection_hack && sp->changed )
    {
        selection_hack = sp->changed = 0;
        obj->returned = FL_RETURN_CHANGED;
        fli_object_qenter( obj, FL_PASTE );
    }

    return 0;
}


/***************************************
 * Paste request is handled here. If we do not own the selection,
 * this will result in an SelectionNotify event that gets handled
 * by handle_clipboard_event(). And in that case we can't report
 * the object to have changed back to the application since all
 * that will happen some time later. Thus we set 'selection_hack'
 * to indicate to the getit_cb() function to artificially enter
 * the object into the object queue.
 ***************************************/

static int
do_XPaste( FL_OBJECT * obj )
{
    int ret = fl_request_clipboard( obj, XA_STRING, gotit_cb );

    if ( ret == -1 && obj->how_return == FL_RETURN_CHANGED )
        selection_hack = 1;
    return ret > 0 ? FL_RETURN_CHANGED : FL_RETURN_NONE;
}


/***************************************
 ***************************************/

static int
lose_selection( FL_OBJECT * obj,
                long        type  FL_UNUSED_ARG )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    sp->beginrange = sp->endrange = -1;
    if ( ! obj->focus )
        sp->position = -1;
    else if ( sp->position < 0 )
        sp->position = sp->str ? strlen( sp->str ) : 0;
    fl_redraw_object( sp->input );
    fl_update_display( 0 );
    return 0;
}


/***************************************
 ***************************************/

static void
do_XCut( FL_OBJECT * obj,
         int         beginrange,
         int         endrange )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    char *buff;
    int nc = endrange - beginrange + 1;

    if ( nc <= 0 )
        return;

    buff = fl_malloc( nc + 1 );

    strncpy( buff, sp->str + beginrange, nc );
    buff[ nc ] = '\0';

    fl_stuff_clipboard( obj, XA_STRING, buff, nc, lose_selection );

    fl_free( buff );
}


/***************************************
 * Handles an event
 ***************************************/

static int
handle_input( FL_OBJECT * obj,
              int         event,
              FL_Coord    mx,
              FL_Coord    my,
              int         key,
              void      * ev )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    static int motion,
               lx = INT_MAX,
               ly = INT_MAX,
               paste;
    int ret = FL_RETURN_NONE,
        val,
        state = 0;

    /* Convert scroll wheel events to up or down arrow key events */

    if ( event == FL_KEYPRESS )
        state = ( ( XKeyEvent * ) ev )->state;

    if ( event == FL_PUSH )
    {
        if ( key == FL_MBUTTON4 )
        {
            event = FL_KEYPRESS;
            key = XK_Up;
        }
        else if ( key == FL_MBUTTON5 )
        {
            event = FL_KEYPRESS;
            key = XK_Down;
        }
    }

    switch ( event )
    {
        case FL_ATTRIB :
            obj->align = fl_to_outside_lalign( obj->align );
            break;

        case FL_RESIZED :
            check_scrollbar_size( obj );
            break;

        case FL_DRAW:
            /* We always force label outside */

            if ( sp->input->type != FL_MULTILINE_INPUT )
            {
                if ( sp->dummy != obj ) /* this can only happen with fdesign */
                    sp->dummy = sp->input = obj;
            }

            sp->dummy->align = fl_to_outside_lalign( sp->dummy->align );
            copy_attributes( sp->input, sp->dummy );
            if ( sp->input->type != FL_HIDDEN_INPUT )
                draw_input( sp->input );
            /* fall through */

        case FL_DRAWLABEL:
            if ( sp->input->type != FL_MULTILINE_INPUT )
                fl_draw_object_label_outside( sp->input );
            else
                fl_draw_text_beside( sp->dummy->align,
                                     sp->input->x, sp->input->y,
                                     sp->input->w + sp->vw,
                                     sp->input->h + sp->hh,
                                     sp->input->lcol, sp->input->lstyle,
                                     sp->input->lsize, sp->dummy->label );
            break;

        case FL_FOCUS:
            if ( obj->type == FL_MULTILINE_INPUT )
            {
                if ( sp->dummy->focus )
                    break;
                sp->dummy->focus = 1;
            }

            // Put the cursor back into the position where it was (except
            // for DOS mode where it's always positioned at the start)

            if ( sp->str && Input_Mode != FL_DOS_INPUT_MODE )
            {
                if ( sp->position < 0 )
                    sp->position = - sp->position - 1;
                if ( sp->position > ( int ) strlen( sp->str ) )
                    sp->position = strlen( sp->str );
            }
            else
                sp->position = 0;

            sp->changed = 0;
            fl_redraw_object( sp->input );
            break;

        case FL_UNFOCUS:
            if ( obj->type == FL_MULTILINE_INPUT )
                sp->dummy->focus = 0;

            if ( sp->position >= 0 )
                sp->position = - sp->position - 1;
            sp->endrange = -1;
            fl_redraw_object( sp->input );

            /* If the event is set to NULL don't validate or report
               any changes - the call came from either closing the
               form or from the user changing the focus with the
               fl_set_focus_object() function - never use the event,
               it may be invalid */

            if ( ev )
                ret =   ( sp->changed ? FL_RETURN_CHANGED : FL_RETURN_NONE )
                      | FL_RETURN_END;

            break;

        case FL_UPDATE:
            if ( ! obj->focus )
                break;
            motion = ( mx != lx || my != ly ) && ! paste;
            if ( motion && handle_select( mx, my, obj, 1, NORMAL_SELECT ) )
                fl_redraw_object( sp->input );
            break;

        case FL_PUSH:
            paste = 0;
            lx = mx;
            ly = my;
            if ( key == FL_MBUTTON2 && ( sp->changed = do_XPaste( obj ) ) )
            {
                if ( obj->how_return == FL_RETURN_CHANGED )
                    sp->changed = 0;
                ret = FL_RETURN_CHANGED;
                paste = 1;
            }
            else if ( handle_select( mx, my, obj, 0, NORMAL_SELECT ) )
                fl_redraw_object( sp->input );
            break;

        case FL_RELEASE:
            if ( key == FL_MBUTTON4 || key == FL_MBUTTON5 )
                break;
            if ( key == FL_MBUTTON1 && motion )
                do_XCut( obj, sp->beginrange, sp->endrange - 1 );
            motion = 0;
            break;

        case FL_DBLCLICK:
        case FL_TRPLCLICK:
            if ( key == FL_MBUTTON4 || key == FL_MBUTTON5 )
                break;
            if ( handle_select( mx, my, obj, 0,
                                event == FL_DBLCLICK ?
                                WORD_SELECT : LINE_SELECT ) )
            {
                fl_redraw_object( sp->input );
                do_XCut( obj, sp->beginrange, sp->endrange );
            }
            break;

        case FL_KEYPRESS :
            if ( ( ret = handle_key( obj, key, state ) ) )
            {
                sp->changed = 1;
                if ( obj->how_return == FL_RETURN_CHANGED )
                    sp->changed = 0;
            }
            break;

        case FL_FREEMEM:
            fli_safe_free( ( ( FLI_INPUT_SPEC * ) obj->spec )->str );
            fli_safe_free( obj->spec );
            return ret;
    }

    if (    ret
         && sp
         && sp->validate
         && event == FL_UNFOCUS
         && ( val = sp->validate( obj, sp->str, sp->str, 0 ) ) != FL_VALID )
    {
        ret = FL_RETURN_NONE;
        if ( val & FL_RINGBELL )
        {
            fl_ringbell( 0 );
            fl_reset_focus_object( obj );
        }
    }

    /* In some places the x- and y-coordinates (column and row) of the cursor
       aren't set consistently, so repair it here... */

    if ( obj->spec )
    fl_get_input_cursorpos( obj, &sp->xpos, &sp->ypos );

    return ret;
}


/***************************************
 * Callback for the vertical scrollbar of multi-line input objects
 ***************************************/

static void
vsl_cb( FL_OBJECT * obj,
        long        data  FL_UNUSED_ARG )
{
    FLI_INPUT_SPEC *sp = obj->parent->spec;

    double val = fl_get_scrollbar_value( obj );
    int top = FL_nint( val * ( sp->lines - sp->screenlines ) ) + 1;

    sp->endrange = -1;          /* switch off selection */
    sp->drawtype = VSLIDER;
    fl_set_input_topline( sp->input, top );
}


/***************************************
 * Callback for the horizontal scrollbar of multi-line input objects
 ***************************************/

static void
hsl_cb( FL_OBJECT * obj,
        long        data  FL_UNUSED_ARG )
{
    FLI_INPUT_SPEC *sp = obj->parent->spec;
    double val = fl_get_scrollbar_value( obj );
    int xoff = val * ( sp->max_pixels - sp->w ) + 0.1;

    sp->drawtype = HSLIDER;
    fl_set_input_xoffset( sp->input, xoff );
}


/***************************************
* Pre- and post- handlers
 ***************************************/

static int
input_pre( FL_OBJECT * obj,
           int         ev,
           FL_Coord    mx,
           FL_Coord    my,
           int         key,
           void      * xev )
{
    FL_OBJECT *ext = obj->parent;

    return ( ext && ext->prehandle ) ?
           ext->prehandle( ext, ev, mx, my, key, xev ) : 0;
}


/***************************************
 ***************************************/

static int
input_post( FL_OBJECT * obj,
            int         ev,
            FL_Coord    mx,
            FL_Coord    my,
            int         key,
            void      * xev )
{
    FL_OBJECT *ext = obj->parent;

    return ( ext && ext->posthandle ) ?
           ext->posthandle( ext, ev, mx, my, key, xev ) : 0;
}


/***************************************
 ***************************************/

static void
input_cb( FL_OBJECT * obj,
          long        data  FL_UNUSED_ARG )
{
    obj->parent->returned = obj->returned;
}


/***************************************
 * Creates an input object
 ***************************************/

FL_OBJECT *
fl_create_input( int          type,
                 FL_Coord     x,
                 FL_Coord     y,
                 FL_Coord     w,
                 FL_Coord     h,
                 const char * label )
{
    FL_OBJECT *obj;
    FLI_INPUT_SPEC *sp;

    set_default_keymap( 0 );

    obj = fl_make_object( FL_INPUT, type, x, y, w, h, label, handle_input );
    obj->boxtype    = FL_INPUT_BOXTYPE;
    obj->col1       = FL_INPUT_COL1;
    obj->col2       = FL_INPUT_COL2;
    obj->align      = FL_INPUT_ALIGN;
    obj->lcol       = FL_INPUT_LCOL;
    obj->lsize      = fli_cntl.inputFontSize ?
                      fli_cntl.inputFontSize : FL_DEFAULT_SIZE;
    obj->set_return = fl_set_input_return;

    fl_set_object_prehandler( obj, input_pre );
    fl_set_object_posthandler( obj, input_post );

    obj->wantkey       = obj->type == FL_MULTILINE_INPUT ?
                         FL_KEY_ALL : FL_KEY_NORMAL;
    obj->want_update   = 1;
    obj->input         = 1;
    obj->click_timeout = FL_CLICK_TIMEOUT;
    obj->spec = sp     = fl_calloc( 1, sizeof *sp );

    sp->textcol        = FL_INPUT_TCOL;
    sp->curscol        = FL_INPUT_CCOL;
    sp->position       = -1;
    sp->endrange       = -1;
    sp->size           = 8;
    sp->lines          = sp->ypos = 1;
    sp->str            = fl_malloc( sp->size );
    *sp->str           = '\0';
    sp->cursor_visible = 1;

    switch ( obj->type )
    {
        case FL_DATE_INPUT :
            sp->maxchars = 10;
            break;

        case FL_SECRET_INPUT :
            sp->maxchars = 16;
            break;

        default :
            sp->maxchars = 0;
    }

    sp->dummy      = obj;
    sp->input      = obj;
    sp->field_char = ' ';

    if ( obj->type == FL_INT_INPUT )
        sp->validate = int_validator;
    else if ( obj->type == FL_FLOAT_INPUT )
        sp->validate = float_validator;
    else if ( obj->type == FL_DATE_INPUT )
    {
        fl_set_input_format( obj, FL_INPUT_MMDD, '/' );
        sp->validate = date_validator;
    }

    obj->how_return = FL_RETURN_END_CHANGED;
    fl_set_object_dblbuffer( obj, type != FL_HIDDEN_INPUT );

    return obj;
}


/***************************************
 ***************************************/

static int
fake_handle( FL_OBJECT * obj,
             int         event,
             FL_Coord    mx   FL_UNUSED_ARG,
             FL_Coord    my   FL_UNUSED_ARG,
             int         key  FL_UNUSED_ARG,
             void      * ev   FL_UNUSED_ARG )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    switch ( event )
    {
        case FL_ATTRIB:
            if ( sp->dummy != obj ) /* this can only happen with fdesign */
                sp->dummy = obj;
            copy_attributes( sp->input, sp->dummy );
            /* fall through */

        case FL_DRAW:
        case FL_DRAWLABEL:
            check_scrollbar_size( obj );
            break;
    }

    return 0;
}


/***************************************
 * Adds an input object
 ***************************************/

FL_OBJECT *
fl_add_input( int          type,
              FL_Coord     x,
              FL_Coord     y,
              FL_Coord     w,
              FL_Coord     h,
              const char * label )
{
    FL_OBJECT *obj;
    FLI_INPUT_SPEC *sp;
    int oldu = fl_get_coordunit( );

    obj = fl_create_input( type, x, y, w, h, label );
    sp = obj->spec;

    fl_set_coordunit( FL_COORD_PIXEL );

    x = obj->x;
    y = obj->y;
    w = obj->w;
    h = obj->h;

    if ( obj->type == FL_MULTILINE_INPUT )
    {
        fl_set_object_label( obj, NULL );
        sp->dummy = fl_create_box( FL_NO_BOX, x, y, w, h, label );
        sp->dummy->objclass   = FL_INPUT;
        sp->dummy->type       = FL_MULTILINE_INPUT;
        copy_attributes( sp->dummy, obj );
        sp->dummy->handle     = fake_handle;
        sp->dummy->spec       = sp;
        sp->dummy->set_return = fl_set_input_return;

        fl_add_child( sp->dummy, obj );

        sp->hh_def = sp->vw_def = fli_get_default_scrollbarsize( obj );
        sp->h_pref = sp->v_pref = FL_AUTO;
        sp->vscroll = fl_create_scrollbar( fli_context->vscb,
                                           x + w - sp->vw_def,
                                           y, sp->vw_def, h, NULL );
        fl_set_scrollbar_value( sp->vscroll, 0.0 );
        fl_set_object_callback( sp->vscroll, vsl_cb, 0 );
        fl_set_object_resize( sp->vscroll, FL_RESIZE_NONE );
        fl_add_child( sp->dummy, sp->vscroll );

        sp->hscroll = fl_create_scrollbar( fli_context->hscb, x,
                                           y + h - sp->hh_def,
                                           w, sp->hh_def, NULL );
        fl_set_scrollbar_value( sp->hscroll, 0.0 );
        fl_set_object_callback( sp->hscroll, hsl_cb, 0 );
        fl_set_object_resize( sp->hscroll, FL_RESIZE_NONE );
        fl_add_child( sp->dummy, sp->hscroll );

        fl_set_object_callback( sp->input, input_cb, 0 );
        fl_set_object_return( sp->dummy, FL_RETURN_END_CHANGED );
    }

    fl_add_object( fl_current_form, sp->dummy );

    fl_set_coordunit( oldu );

    /* Set default return policy for the new object */

    fl_set_object_return( obj, FL_RETURN_END_CHANGED );

    return sp->dummy;
}


/***************************************
 * Sets the input string. Only printable character and, for multi-line
 * inputs new-lines are accepted.
 ***************************************/

#define IS_VALID_INPUT_CHAR( c )   \
       isprint( ( unsigned char ) ( c ) )    \
    || ( obj->type == FL_MULTILINE_INPUT && ( c ) == '\n' )

void
fl_set_input( FL_OBJECT  * obj,
              const char * str )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int len;
    char *p;
    const char *q;

    if ( ! str )
        str = "";

    for ( len = 0, q = str; *q; ++q )
        if ( IS_VALID_INPUT_CHAR( *q ) )
            ++len;

    if ( sp->size < len + 1 )
    {
        sp->size = len + 9;
        sp->str = fl_realloc( sp->str, sp->size );
    }

    for ( p = sp->str, q = str; *q; ++q )
        if ( IS_VALID_INPUT_CHAR( *q ) )
            *p++ = *q;
    *p = '\0';

    /* Set position of cursor in string to the end (if object doesn't has
       focus must be negative of length of strig minus one) */

    if ( sp->position >= 0 )
        sp->position = len;
    else
        sp->position = - len - 1;

    sp->endrange = -1;

    sp->lines = fl_get_input_numberoflines( obj );
    fl_get_input_cursorpos( obj, &sp->xpos, &sp->ypos );

    /* Get max string width - it's possible that fl_set_input() is used before
       the form is show, draw_object is a no-op, thus we end up with a wrong
       string size */

    fl_get_string_dimension( obj->lstyle, obj->lsize,
                             sp->str, len, &sp->max_pixels, &len );

    if ( obj->form )
        fl_freeze_form( obj->form );

    check_scrollbar_size( obj );
    make_line_visible( obj, sp->ypos );
    fl_redraw_object( sp->input );
    sp->xoffset = 0;
    check_scrollbar_size( obj );
    if ( sp->v_on || sp->h_on )
        redraw_scrollbar( obj );

    if ( obj->form )
        fl_unfreeze_form( obj->form );
}


/***************************************
 * Sets the input string using a format string and an appropriate number
 * of (unspecified) arguments
 ***************************************/

void
fl_set_input_f( FL_OBJECT  * obj,
                const char * fmt,
                ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_set_input( obj, buf );
    fl_free( buf );
}


/***************************************
 * Sets the color of the input string
 ***************************************/

void
fl_set_input_color( FL_OBJECT * obj,
                    FL_COLOR    textcol,
                    FL_COLOR    curscol )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    sp->textcol = textcol;
    sp->curscol = curscol;
    fl_redraw_object( sp->input );
}


/***************************************
 * Returns the color of the input string
 ***************************************/

void
fl_get_input_color( FL_OBJECT * obj,
                    FL_COLOR  * textcol,
                    FL_COLOR  * curscol )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    *textcol = sp->textcol;
    *curscol = sp->curscol;
}


/***************************************
 ***************************************/

int
fl_set_input_fieldchar( FL_OBJECT * obj,
                        int         fchar )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int ochar = sp->field_char;

    if ( obj->objclass != FL_INPUT )
    {
        M_err( "fl_set_input_fieldchar", "%s isn't an input object",
               obj ? obj->label : "null" );
        return 0;
    }

    sp->field_char = fchar;
    return ochar;
}


/***************************************
 * Returns a pointer to the text string
 ***************************************/

const char *
fl_get_input( FL_OBJECT * obj )
{
    return ( ( FLI_INPUT_SPEC * ) obj->spec )->str;
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function should be regarded as for internal use
 * only and fl_set_object_return() should be used instead (which then
 * will call this function).
 ***************************************/

void
fl_set_input_return( FL_OBJECT    * obj,
                     unsigned int   when )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( when & FL_RETURN_END_CHANGED )
        when &= ~ ( FL_RETURN_END | FL_RETURN_CHANGED );

    obj->how_return = sp->input->how_return = when;
    fl_set_object_return( sp->vscroll, FL_RETURN_CHANGED );
    fl_set_object_return( sp->hscroll, FL_RETURN_CHANGED );
}


/***************************************
 ***************************************/

void
fl_set_input_scroll( FL_OBJECT * obj,
                     int         yes )
{
    ( ( FLI_INPUT_SPEC * ) obj->spec )->noscroll = ! yes;
}


/***************************************
 * Makes a part of an input string selected or deselected
 ***************************************/

void
fl_set_input_selected_range( FL_OBJECT * obj,
                             int         begin,
                             int         end )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int len;

    if ( obj->type == FL_HIDDEN_INPUT )
        return;

    len = strlen( sp->str );

    if ( begin < 0 )
        sp->beginrange = 0;
    else if ( begin > len )
        sp->beginrange = len;
    else
        sp->beginrange = begin;

    if ( end < 0 )
        sp->endrange = -1;
    else if ( end > len )
        sp->endrange = len;
    else
        sp->endrange = end;

    /* move cursor to the head */

    sp->position = sp->beginrange;
    fl_redraw_object( sp->input );
}


/***************************************
 ***************************************/

const char *
fl_get_input_selected_range( FL_OBJECT * obj,
                             int       * begin,
                             int       * end )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    static char *selbuf;
    static int nselbuf;
    int n;

    n = sp->endrange - sp->beginrange;

    if ( n < 1 )
    {
        if ( begin )
            *begin = -1;
        if ( end )
            *end = -1;
        return NULL;
    }

    if ( begin )
        *begin = sp->beginrange;

    if ( end )
        *end = sp->endrange;

    if ( n != nselbuf )
    {
        selbuf = fl_realloc( selbuf, n + 1 );
        nselbuf = n;
    }

    fli_sstrcpy( selbuf, sp->str + sp->beginrange, n );

    return selbuf;
}


/***************************************
 * Selects the current input programmatically without moving
 * the cursor
 ***************************************/

void
fl_set_input_selected( FL_OBJECT * obj,
                       int         yes )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( obj->type == FL_HIDDEN_INPUT )
        return;

    if ( yes )
    {
        sp->position = sp->endrange = strlen( sp->str );
        sp->beginrange = 0;
    }
    else
        sp->endrange = -1;

    fl_redraw_object( sp->input );
}


/***************************************
 * Given an (x,y) location returns the string position in chars
 ***************************************/

static int
xytopos( FLI_INPUT_SPEC * sp,
         int              xpos,
         int              ypos )
{
    int newp = 0;
    char *s = sp->str,
         *se = s + strlen( s );

    if ( ypos < 1 )
        ypos = 1;
    else if ( ypos > sp->lines )
        ypos = sp->lines;

    if ( xpos < 0 )
        xpos = 0;

    sp->ypos = 1;
    while ( sp->ypos < ypos && ( s = strchr( s, '\n' ) ) )
    {
        sp->ypos++;
        s++;
        newp = s - sp->str;
    }

    s = sp->str + newp;
    for ( sp->xpos = 0; sp->xpos < xpos && s < se; sp->xpos++, newp++ )
        if (  *++s == '\n' )
            break;

    return sp->position = newp;
}


/***************************************
 * Move cursor within the input field, cursor position is measured in chars
 ***************************************/

void
fl_set_input_cursorpos( FL_OBJECT * obj,
                        int         xpos,
                        int         ypos )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int oldp = sp->position;

    if ( obj->type == FL_HIDDEN_INPUT )
        return;

    if ( oldp != xytopos( sp, xpos, ypos ) )
    {
        fl_freeze_form( obj->form );
        make_line_visible( obj, sp->ypos );
        make_char_visible( obj, sp->xpos );
        fl_redraw_object( obj );
        fl_unfreeze_form( obj->form );
    }
}


/***************************************
 ***************************************/

int
fl_get_input_cursorpos( FL_OBJECT * obj,
                        int       * x,
                        int       * y )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    char *s = sp->str;
    int cnt = 0;

    if ( ! obj->focus )
        return sp->position = *x = -1;

    *y = 1;
    *x = 0;

    for ( ; s && *s && cnt < sp->position; s++, cnt++ )
        if ( *s == '\n' )
        {
            *y += 1;
            *x = 0;
        }
        else
            *x += 1;

    return sp->position;
}


/***************************************
 * Reverts to the default keymap for edit keys
 ***************************************/

void
fl_set_default_editkeymap( void )
{
    set_default_keymap( 1 );
}


#define Ctrl( c ) \
( ( tolower( ( unsigned char ) c ) - 'a' + 1 ) | FL_CONTROL_MASK )
#define Meta( c ) ( tolower( ( unsigned char ) c ) | FL_ALT_MASK )

/***************************************
 ***************************************/

static void
set_default_keymap( int force )
{
    static int initialized = 0;

    if ( ! force && initialized )
        return;

    initialized = 1;

    /* Emacs defaults */

    kmap.moveto_next_char = Ctrl( 'f' );
    kmap.moveto_prev_char = Ctrl( 'b' );
    kmap.moveto_prev_word = Meta( 'b' );
    kmap.moveto_next_word = Meta( 'f' );

    kmap.moveto_bol       = Ctrl( 'a' );
    kmap.moveto_eol       = Ctrl( 'e' );

    kmap.moveto_next_line = Ctrl( 'n' );
    kmap.moveto_prev_line = Ctrl( 'p' );

    kmap.moveto_bof       = Meta( '<' );
    kmap.moveto_eof       = Meta( '>' );

    kmap.del_next_char    = Ctrl( 'd' );
    kmap.del_prev_char    = Ctrl( 'h' );
    kmap.del_next_word    = Meta( 'd' );
    kmap.del_prev_word    = Meta( '\b' );

    kmap.del_to_eol       = Ctrl( 'k' );
    kmap.del_to_bol       = Meta( 'k' );

    kmap.backspace        = '\b';
    kmap.transpose        = Ctrl( 't' );
    kmap.paste            = Ctrl( 'y' );
    kmap.clear_field      = Ctrl( 'u' );
}


/***************************************
 ***************************************/

void
fl_set_input_maxchars( FL_OBJECT * obj,
                       int         maxchars )
{
    ( ( FLI_INPUT_SPEC * ) obj->spec )->maxchars = maxchars;
}


/***************************************
 ***************************************/

FL_INPUT_VALIDATOR
fl_set_input_filter( FL_OBJECT          * obj,
                     FL_INPUT_VALIDATOR   validate )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    FL_INPUT_VALIDATOR old = sp->validate;

    sp->validate = validate;
    return old;
}


/***************************************
 ***************************************/

void
fl_set_input_format( FL_OBJECT * obj,
                     int         fmt,
                     int         sep )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if (    ! isprint( ( unsigned char ) sep )
         || isdigit( ( unsigned char ) sep ) )
        sep = '/';
    sp->attrib1 = fmt;
    sp->attrib2 = sep;
}


/***************************************
 ***************************************/

void
fl_get_input_format( FL_OBJECT * obj,
                     int       * fmt,
                     int       * sep )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    *fmt = sp->attrib1;
    *sep = sp->attrib2;
}


/***************************************
 ***************************************/

int
fl_validate_input( FL_OBJECT *obj )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    return (    ! sp->validate
             || sp->validate( obj, sp->str, sp->str, 0 ) == FL_VALID ) ?
           FL_VALID : FL_INVALID;
}


/***************************************
 * Validator for date
 ***************************************/

#define IS_LEAP_YEAR( y )   \
    ( ( y ) % 4 == 0 && ( ( y ) % 100 != 0 || ( y ) % 400 == 0 ) )

static int
date_validator( FL_OBJECT  * obj,
                const char * oldstr  FL_UNUSED_ARG,
                const char * newstr,
                int          newc )
{
    char *val,
         *s,
         sepsep[ 3 ];
    char ssep[ 2 ] = "";
    int i,
        len,
        ival[ ] = { 1, 1, 1 };
    int fmt,
        sep;
    int invalid = FL_RINGBELL | FL_INVALID;
    int m,
        d;

    /* Consider empty valid */

    if ( ( len = strlen( newstr ) ) == 0 )
        return FL_VALID;

    fl_get_input_format( obj, &fmt, &sep );

    *ssep = sep;
    strcat( strcpy( sepsep, ssep ), ssep );


    /* Allow only separator or digit, but no separator at the very start or
       two separators in a row */

    if (    (    newc != sep
              && newc != '\0'
              && ! isdigit( ( unsigned char ) newc ) )
         || *newstr == sep || strstr( newstr, sepsep ) )
        return invalid;

    s = fl_strdup( newstr );

    /* Split up the date string at the separators and convert to ints and
       check that there aren't more than 2 digits for day and month and 4
       for the year */

    for ( i = 0, val = strtok( s, ssep ); i < 3 && val;
          val = strtok( NULL, ssep ) )
    {
        if ( ( i < 2 && strlen( val ) > 2 ) || ( i == 2 && strlen( val ) > 4 ) )
             return invalid;

        ival[ i++ ] = atoi( val );

        if ( i <= 2 && strlen( val ) == 2 && ival[ i - 1 ] == 0 )
            return invalid;
    }

    fl_free( s );

    /* Allow one or more '0' at the start of the day pr month (but not as
       the only digit, i.e. when the new character is the separator) */

    if (    newc == sep
         && (    ( i == 1 && ival[ 0 ] == 0 )
              || ( i == 2 && ival[ 1 ] == 0 ) ) )
        return invalid;

    /* Don't allow another separator when we already got 3 items */

    if ( i == 3 && newstr[ len - 1 ] == sep )
       return invalid;

    /* Always require 3 items when the user tries to leave the field
       and make sure that day or month aren't 0 */

    if (    newc == '\0'
         && ( i != 3 || ival[ 0 ] == 0 || ival[ 1 ] == 0 ) )
        return invalid;

    m = fmt == FL_INPUT_MMDD ? 0 : 1;
    d = ! m;

    /* Basic check for upper limits of day and month */

    if ( ival[ m ] > 12 || ival[ d ] > 31 )
        return invalid;

    /* More precise check for days in month */

    if (    ( ival[ d ] > 30 && ( ival[ m ] % 2 ) == 0 && ival[ m ] < 8 )
         || ( ival[ d ] > 30 && ( ival[ m ] % 2 ) != 0 && ival[ m ] > 8 ) )
        return invalid;

    /* Take care: check for leap year can only be done when leaving */

    if (    ival[ m ] == 2
         && (    ival[ d ] > 29
              || (    i == 3
                   && newc == 0
                   && ival[ d ] > 28
                   && ! IS_LEAP_YEAR( ival[ 2 ] ) ) ) )
        return invalid;

    return FL_VALID;
}


/***************************************
 * Validator for integer fields
 ***************************************/

static int
int_validator( FL_OBJECT  * obj     FL_UNUSED_ARG,
               const char * oldstr  FL_UNUSED_ARG,
               const char * str,
               int          newc )
{
    char *eptr = NULL;
    long dummy;

    /* The empty string is considered to be valid */

    if ( ! *str )
        return FL_VALID;

    /* If there was a new character and all we got is a '+' or '-' this is ok */

    if ( ! str[ 1 ] && ( newc == '+' || newc == '-' ) )
        return FL_VALID;

    dummy = strtol( str, &eptr, 10 );

    if (    ( ( dummy == LONG_MAX || dummy == LONG_MIN ) && errno == ERANGE )
         || *eptr )
        return FL_INVALID | FL_RINGBELL;

    return FL_VALID;
}


/***************************************
 * Validator for floating point fields
 ***************************************/

static int
float_validator( FL_OBJECT  * obj     FL_UNUSED_ARG,
                 const char * oldstr  FL_UNUSED_ARG,
                 const char * str,
                 int          newc )
{
    char *eptr = NULL;
    size_t len;
    double dummy;

    /* The empty string is considered valid */

    if ( ! *str )
        return FL_VALID;

    /* Try strtod() an the string*/

    dummy = strtod( str, &eptr );

    /* If it reports no problem were done */

    if (    ! ( ( dummy == HUGE_VAL || dummy == -HUGE_VAL ) && errno == ERANGE )
         && ! *eptr )
        return FL_VALID;

    /* Otherwise, if there's no new character the input must be invalid */

    if ( ! newc )
        return FL_INVALID | FL_RINGBELL;
            
    /* Now we handle cases that strtod() flagged as bad but which we need to
       accept while editing is still underway. If there's only a single char
       it should be a dot or a sign */

    len = strlen( str );

    if ( len == 1 )
        return ( newc == '+' || newc == '-' || newc == '.' ) ?
            FL_VALID : FL_INVALID | FL_RINGBELL;

    /* If there are two characters accept a sequence of a sign and a decimal
       point or a number followed by 'e' or 'E' */

    if ( len == 2 )
        return (    ! strcmp( str, "+." )
                 || ! strcmp( str, "-." )
                 || *eptr == 'e'
                 || *eptr == 'E' ) ?
               FL_VALID : ( FL_INVALID | FL_RINGBELL );

    /* Accept an 'e' or 'E' in the last position, or, if it's in the second last
       position, when it's followed by a sign - but only if it's the first 'e'
       or 'E' in the string */

    if ( ( *eptr == 'e' || *eptr == 'E' )
         && strchr( str, *eptr ) == eptr
         && (    eptr == str + len - 1
              || (    eptr == str + len - 2
                   && ( eptr[ 1 ] == '+' || eptr[ 1 ] == '-' ) ) ) )
         return FL_VALID;

    return FL_INVALID | FL_RINGBELL;
}


/***************************************
 ***************************************/

void
fl_set_input_xoffset( FL_OBJECT * obj,
                      int         xoff )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->xoffset != xoff )
    {
        sp->xoffset = xoff;
        if ( sp->drawtype != HSLIDER )
        {
            check_scrollbar_size( obj );
            redraw_scrollbar( obj );
        }
        sp->drawtype = COMPLETE;
        fl_redraw_object( sp->input );
    }
}


/***************************************
 ***************************************/

int
fl_get_input_xoffset( FL_OBJECT * obj )
{
    return ( ( FLI_INPUT_SPEC * ) obj->spec )->xoffset;
}


/***************************************
 * Corrects, if necessary, the value of 'top' (the topmost line to be
 * shown in a FL_MULTILINE_INPUT object, count is starting at 1) so
 * that the value is at least 1 and, if there are less lines below
 * 'top' then fit into the input field, adjusts 'top' that the
 * complete field is used (i.e. there are no empty lines at the end).
 ***************************************/

static void
correct_topline( FLI_INPUT_SPEC * sp,
                 int            * top )
{
    if ( sp->lines > sp->screenlines )
    {
        if ( sp->lines < *top + sp->screenlines - 1 )
            *top = sp->lines - sp->screenlines + 1;
        if ( *top < 1 )
            *top = 1;
    }
    else
        *top = 1;
}


/***************************************
 ***************************************/

int
fl_get_input_numberoflines( FL_OBJECT * obj )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int count;
    const char *s = sp->str;

    if ( ! s )
        return sp->lines = 0;

    for ( count = 1; *s; s++ )
        if ( *s == '\n' )
            count++;

    return sp->lines = count;
}


/***************************************
 * Makes the requested line 'top' (starting at 1) the topmost line
 * shown in a FL_MULTILINE_INPUT object.
 ***************************************/

void
fl_set_input_topline( FL_OBJECT * obj,
                      int         top )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->input->type != FL_MULTILINE_INPUT )
        return;

    correct_topline( sp, &top );

    if ( sp->topline == top )
        return;

    /* Make sure the cursor remains in a visible line */

    if ( sp->ypos < top || sp->ypos >= top + sp->screenlines )
    {
        if ( sp->ypos < top )
            xytopos( sp, sp->xpos, top );
        else
            xytopos( sp, sp->xpos, top + sp->screenlines - 1 );
        make_char_visible( obj, sp->xpos );
    }

    sp->topline = top;
    if ( sp->drawtype != VSLIDER )
    {
        check_scrollbar_size( obj );
        redraw_scrollbar( obj );
    }

    sp->drawtype = COMPLETE;
    sp->yoffset = ( sp->topline - 1 ) * sp->charh;
    fl_redraw_object( sp->input );
}


/***************************************
 * Line number 'n' is numbered from 1.
 ***************************************/

static int
make_line_visible( FL_OBJECT * obj,
                   int         ypos )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int oldtop = sp->topline;

    if ( obj->type != FL_MULTILINE_INPUT )
        return 0;

    if ( ypos < sp->topline )
        fl_set_input_topline( obj, ypos );
    else if ( ypos > sp->topline + sp->screenlines - 1 )
        fl_set_input_topline( obj, ypos - sp->screenlines + 1 );
    else if ( sp->lines < sp->screenlines )
        fl_set_input_topline( obj, 1 );

    return oldtop != sp->topline;
}


/***************************************
 ***************************************/

static int
make_char_visible( FL_OBJECT * obj,
                   int         xpos )
{
    FLI_INPUT_SPEC *sp = obj->spec;
    int start_of_line = sp->position;
    int oldxoffset = sp->xoffset;
    int tmp;

    if ( xpos < 0 )
        return 0;

    while ( start_of_line > 0 && sp->str[ start_of_line - 1 ] != '\n' )
        start_of_line--;

    tmp = get_substring_width( obj, start_of_line, start_of_line + xpos );

    if ( tmp < sp->xoffset )
        sp->xoffset = tmp;
    else if ( tmp - sp->xoffset > sp->w )
        sp->xoffset = tmp - sp->w;

    if ( sp->xoffset != oldxoffset )
    {
        check_scrollbar_size( obj );
        redraw_scrollbar( obj );
        fl_redraw_object( sp->input );
        return 1;
    }

    return 0;
}


/***************************************
 ***************************************/

void
fl_set_input_vscrollbar( FL_OBJECT * obj,
                         int         pref )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->v_pref != pref )
    {
        sp->v_pref = pref;
        check_scrollbar_size( obj );
        redraw_scrollbar( obj );
        fl_redraw_object( sp->input );
    }
}


/***************************************
 ***************************************/

void
fl_set_input_hscrollbar( FL_OBJECT * obj,
                         int         pref )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->h_pref != pref )
    {
        sp->h_pref = pref;
        check_scrollbar_size( obj );
        redraw_scrollbar( obj );
        fl_redraw_object( sp->input );
    }
}


/***************************************
 ***************************************/

void
fl_set_input_scrollbarsize( FL_OBJECT * obj,
                            int         hh,
                            int         vw )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->hh_def != hh || sp->vw_def != vw )
    {
        sp->hh_def = hh;
        sp->vw_def = vw;
        check_scrollbar_size( obj );
        redraw_scrollbar( obj );
        fl_redraw_object( sp->input );
    }
}


/***************************************
 ***************************************/

void
fl_get_input_scrollbarsize( FL_OBJECT * obj,
                            int       * hh,
                            int       * vw )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    *hh = sp->hh_def;
    *vw = sp->vw_def;
}


/***************************************
 ***************************************/

int
fl_get_input_topline( FL_OBJECT * obj )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->input->type != FL_MULTILINE_INPUT )
        return 1;

    return sp->topline;
}


/***************************************
 ***************************************/

int
fl_get_input_screenlines( FL_OBJECT * obj )
{
    return ( ( FLI_INPUT_SPEC * ) obj->spec )->screenlines;
}


#define SetKey( m )  if ( keymap->m ) kmap.m = keymap->m


/***************************************
 ***************************************/

void
fl_set_input_editkeymap( const FL_EditKeymap * keymap )
{
    /* If keymap is Null force default */

    if ( ! keymap )
    {
        set_default_keymap( 1 );
        return;
    }

    set_default_keymap( 0 );

    SetKey( del_prev_char );
    SetKey( del_next_char );
    SetKey( del_prev_word );
    SetKey( del_next_word );

    SetKey( moveto_prev_char );
    SetKey( moveto_next_char );
    SetKey( moveto_prev_word );
    SetKey( moveto_next_word );
    SetKey( moveto_prev_line );
    SetKey( moveto_next_line );
    SetKey( moveto_bof );
    SetKey( moveto_eof );
    SetKey( moveto_bol );
    SetKey( moveto_eol );

    SetKey( backspace );
    SetKey( clear_field );
    SetKey( paste );
    SetKey( transpose );
    SetKey( del_to_eos );
    SetKey( del_to_eol );
    SetKey( del_to_bol );
}


/***************************************
 ***************************************/

void
fl_get_input_editkeymap( FL_EditKeymap * keymap )
{
    /* Don't do anything if we got a NULL pointer */

    if ( ! keymap )
        return;

    /* Make sure the keymap is set up */

    set_default_keymap( 0 );

    /* Copy the current keymap to the user supplied buffer */

    memcpy( keymap, &kmap, sizeof kmap );
}


/***************************************
 ***************************************/

static void
copy_attributes( FL_OBJECT       * dest,
                 const FL_OBJECT * src )
{
    if ( src == dest )
        return;

    dest->col1    = src->col1;
    dest->col2    = src->col2;
    dest->align   = src->align;
    dest->boxtype = src->boxtype;
    dest->lcol    = src->lcol;
    dest->lstyle  = src->lstyle;
    dest->lsize   = src->lsize;
}


/***************************************
 ***************************************/

static void
redraw_scrollbar( FL_OBJECT * obj )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    fl_freeze_form( obj->form );

    if ( sp->v_on )
    {
        fl_set_scrollbar_size( sp->vscroll, sp->vsize );
        fl_set_scrollbar_value( sp->vscroll, sp->vval );
        if ( sp->vsize != 1.0 )
            fl_set_scrollbar_increment( sp->vscroll, sp->vinc1, sp->vinc2 );
        fl_redraw_object( sp->vscroll );
    }

    if ( sp->h_on )
    {
        fl_set_scrollbar_size( sp->hscroll, sp->hsize );
        fl_set_scrollbar_value( sp->hscroll, sp->hval );
        if ( sp->hsize != 1.0 )
            fl_set_scrollbar_increment( sp->hscroll, sp->hinc1, sp->hinc2 );
        fl_redraw_object( sp->hscroll );
    }

    if ( sp->attrib )
    {
        fl_redraw_object( sp->input );
        sp->attrib = 0;
    }

    if ( sp->dead_area && FL_ObjWin( obj ) )
    {
        sp->dead_area = 0;
        fl_winset( FL_ObjWin( obj ) );
        fl_draw_box( FL_FLAT_BOX, sp->dummy->x + sp->dummy->w - sp->vw,
                     sp->dummy->y + sp->dummy->h - sp->hh, sp->vw,
                     sp->hh, sp->hscroll->col1, 1 );
    }

    fl_unfreeze_form( obj->form );
}


/***************************************
 ***************************************/

void
fl_set_input_cursor_visible( FL_OBJECT * obj,
                             int         visible )
{
    FLI_INPUT_SPEC *sp = obj->spec;

    if ( sp->cursor_visible != visible )
    {
        sp->cursor_visible = visible;
        fl_redraw_object( obj );
    }
}


/***************************************
 ***************************************/

int
fl_input_changed( FL_OBJECT * obj )
{
    return ( ( FLI_INPUT_SPEC * ) obj->spec )->changed;
}


/***************************************
 ***************************************/

int
fl_set_input_mode( int mode )
{
    int old_mode = Input_Mode;

    Input_Mode = mode == FL_DOS_INPUT_MODE ?
                 FL_DOS_INPUT_MODE : FL_NORMAL_INPUT_MODE;

    return old_mode;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
