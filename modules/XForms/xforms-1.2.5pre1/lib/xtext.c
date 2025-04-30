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
 * \file xtext.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * All text routines. There are rooms for speed ups. For one, font
 * switching can be reduced somewhat.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"

#include <string.h>
#include <ctype.h>


static int UL_thickness = -1;
static int UL_propwidth = 1;    /* 1 for proportional, 0 for constant */

static void do_underline( FL_Coord,
                          FL_Coord,
                          const char *,
                          int );

static void do_underline_all( FL_Coord,
                              FL_Coord,
                              const char *,
                              int,
                              unsigned long *,
                              unsigned long * );

#define NUM_LINES_INCREMENT  64

static struct LINE_INFO {
    char * str;
    int    len;
    int    index;
    int    underline_index;
    int    x;
    int    y;
} * lines = NULL;
    
static int nlines;

static int max_pixelline = 0;


/***************************************
 ***************************************/

static int
extend_workmem( int nl )
{
    lines = fl_realloc( lines, nl * sizeof *lines );
    return nlines = nl;
}


/***************************************
 ***************************************/

void
fli_free_xtext_workmem( void )
{
    fli_safe_free( lines );
    nlines = 0;
}


/***************************************
 * Returns the index of the widest line drawn in a previous
 * call of fli_draw_string() (only used by input.c)
 ***************************************/

int
fli_get_max_pixels_line( void )
{
    return max_pixelline;
}


/* type fitting both XDrawString() and XDrawImageString() */

typedef int ( * DrawString )( Display    * display,
                              Drawable     d,
                              GC           gc,
                              int          x,
                              int          y,
                              const char * string,
                              int          length );


/***************************************
 * Major text drawing routine. It draws text (possibly consisting of several
 * lines) into the box specified via the coordinates and using the given
 * alignment relative to that box. Also a cursor is drawn. For lines that
 * contain a special character indicating underlining this is also handled.
 * Finally, parts of the text can be shown as selected.
 *
 * Arguments:
 *  align       Alignment of the text relative to the box
 *  x, ym w, h  postion and size of box
 *  clip        0 = no clipping is to be used at all
 *              1 = clipping is to be done by this function
 *              -1 = clipping is done but already has been set externally
 *  backcol     color to be used for selected text
 *  forecol     color for (unselected) text
 *  curscol     color for cursor
 *  style       text font style
 *  size        text font size
 *  curspos     index into string where cursor is to be drawn (if negative or
 *              non-zero and there's no text no cursor is drawn)
 *  selstart    index into string where selection starts
 *  selend      index into string where selection ends (to get selection this
 *              must be larger than 'selstart')
 *  istr        pointer to the text to be drawn
 *  img         if non-zero also draw background (use XDrawImageString()
 *              instead of XDrawString() to draw the text)
 *  topline     first line of the text to be actually shown (counting starts
 *              at 1)
 *  endline     last line to be shown (if less than 1 or too large is replaced
 *              by the number of lines in the text)
 *  bkcol       background color (used when 'img' is true)
 *
 * Returns the width (in pixel) of the widest line of the text drawn.
 ***************************************/

int
fli_draw_string( int           align,
                 FL_Coord      x,
                 FL_Coord      y,
                 FL_Coord      w,
                 FL_Coord      h,
                 int           clip,
                 FL_COLOR      backcol,
                 FL_COLOR      forecol,
                 FL_COLOR      curscol,
                 int           style,
                 int           size,
                 int           curspos,
                 int           selstart,
                 int           selend,
                 const char *  istr,
                 int           img,
                 int           topline,
                 int           endline,
                 FL_COLOR      bkcol )
{
    int i;
    int lnumb = 0;           /* number of lines in string */
    int max_pixels = 0;
    int horalign,
        vertalign;
    char * str = NULL,
         * p = NULL;
    DrawString drawIt = img ? XDrawImageString : XDrawString;

    /* Check if anything has to be drawn at all - do nothing if we either
       have no window or the cursor is to be drawn somewhere else than in
       the very first position and there's no string to output. It would
       be tempting to also bail out if the height 'h' is 0 or even negative
       but there are some code paths were this actually may happen and we
       wouldn't output a string even though it is needed (I know, it's a
       bloody mess but fixing it right now would probably take a few weeks
       and even might break existing code...) */

    if (    flx->win == None
         || ( curspos > 0 && ! ( istr && *istr ) ) )
        return 0;

    /* We operate only on a copy of the input string */

    if ( istr && *istr )
        p = str = fl_strdup( istr );

    /* Split the string into lines, store the index where each of them begins
       in the original string as well as the length */

    while ( p )
    {
        /* Make sure we have enough memory */

        if ( lnumb >= nlines )
            extend_workmem( nlines + NUM_LINES_INCREMENT );

        /* Get pointer to the start of the line and it's index in the
           complete string */

        lines[ lnumb ].str = p;
        lines[ lnumb ].index = p - str;   /* where line begins in str */

        /* Try to find the next new line and replace the '\n' with '\0' */

        if ( ( p = strchr( p, '\n' ) ) )
            *p++ = '\0';

        /* Calculate the length of the string */

        lines[ lnumb ].len = p ? ( p - lines[ lnumb ].str - 1 ) :
                                 ( int ) strlen( lines[ lnumb ].str );
        ++lnumb;
    }

    /* Correct values for the top and end line to be shown (they are given
       starting at 1) */

    if ( --topline < 0 || topline >= lnumb )
        topline = 0;

    if ( --endline >= lnumb || endline < 0 )
        endline = lnumb;

    /* Calculate coordinates of all lines (for y the baseline position),
     for that make sure the correct font is set up */

    fl_set_font( style, size );
    fli_get_hv_align( align, &horalign, &vertalign );

    for ( i = topline; i < endline; i++ )
    {
        struct LINE_INFO *line = lines + i;
        int width;

        /* Check for the special character which indicates underlining (all
           the line if it's in the very first position, otherwise just after
           the character to underline), remove it from the string but remember
           were it was and correct the selection positions if necessary (i.e.
           if they are in the line after the character to be underlined).
           Same for the cursor position if it's in the line. */

        if ( ( p = strchr( line->str, *fl_ul_magic_char ) ) )
        {
            line->underline_index = p - line->str;

            if (    selstart < line->index + line->len
                 && selstart > line->index + line->underline_index )
                --selstart;
            if (    selend < line->index + line->len
                 && selend > line->index + line->underline_index )
                --selend;
            if (    curspos >= line->index + line->underline_index
                 && selstart < line->index + line->len )
                --curspos;

            memmove( p, p + 1, line->len-- - line->underline_index );
        }
        else
            line->underline_index = -1;

        /* Determine the width (in pixel) of the line) */

        width = XTextWidth( flx->fs, line->str, line->len );

        if ( width > max_pixels )
        {
            max_pixels = width;
            max_pixelline = i;
        }

        /* Calculate the x- and y- positon of where to print the text */

        switch ( horalign )
        {
            case  FL_ALIGN_LEFT :
                line->x = x;
                break;

            case FL_ALIGN_CENTER :
                line->x = x + 0.5 * ( w - width );
                break;

            case FL_ALIGN_RIGHT :
                line->x = x + w - width;
                break;

            default :
                M_err( "fli_draw_string", "This is impossible" );
                return 0;
        }

        switch ( vertalign )
        {
            case FL_ALIGN_TOP :
                line->y = y + i * flx->fheight + flx->fasc;
                break;

            case FL_ALIGN_CENTER :
                line->y =   y + 0.5 * h + ( i - 0.5 * lnumb ) * flx->fheight
                          + flx->fasc;
                break;

            case FL_ALIGN_BOTTOM :
                line->y = y + h - 1 + ( i - lnumb ) * flx->fheight + flx->fasc;
                break;

            default :
                M_err( "fli_draw_string", "This is impossible" );
                return 0;
        }
    }

    /* Set clipping if we got asked to */

    if ( clip > 0 )
        fl_set_text_clipping( x, y, w, h );

    /* Set foreground and background color for text */

    fli_textcolor( forecol );
    fli_bk_textcolor( bkcol );

    /* Draw all the lines requested */

    for ( i = topline; i < endline; i++ )
    {
        struct LINE_INFO *line = lines + i;
        FL_COLOR underline_col = forecol;
        int xsel = 0,       /* start position of selected text */
            wsel = 0;       /* and its length (in pixel) */

        /* Skip lines that can't be visile due to clipping */

        if ( clip != 0 )
        {
            if ( line->y + flx->fdesc < y )
                continue;
            if ( line->y - flx->fasc >= y + h )
                break;
        }

        /* Draw the text */

        drawIt( flx->display, flx->win, flx->textgc,
                line->x, line->y, line->str, line->len );

        /* Draw selection area if required - for this we need to draw
           the selection background and then redraw the text in this
           region (in the clor that was used for the background before).
           Of course all this only needs to be done if the selection started
           before or in this line and didn't end before it. */

        if (    selstart <  selend
             && selstart <= line->index + line->len
             && selend   >  line->index )
        {
            int start,     /* start index of selected text */
                end,       /* end index */
                len;       /* its length (in chars) */

            /* The selection may have started before the line we're just
               dealing with and may end after it. Find the start and end
               position in this line */

            if ( selstart <= line->index )
                start = 0;
            else
                start = selstart - line->index;

            if ( selend >= line->index + line->len )
                end = line->len;
            else
                end = selend - line->index;

            len = end - start;

            /* Get the start position and width (in pixels) of the selected
               region (the -1 in the calculation  of wsel is a fudge factor
               to make it look a bit better) */

            xsel = line->x + XTextWidth( flx->fs, line->str, start );

            wsel = XTextWidth( flx->fs, line->str + start, len ) - 1;
            if ( xsel + wsel > x + w )
                wsel = x + w - xsel;

            /* Draw in the selection color */

            fl_rectf( xsel, line->y - flx->fasc, wsel,
                      flx->fheight, forecol );

            fli_textcolor( backcol );
            drawIt( flx->display, flx->win, flx->textgc, xsel,
                    line->y, line->str + start, len );
            fli_textcolor( forecol );

            if ( line->underline_index > 0 )
                underline_col = backcol;
        }

        /* Next do underlining */

        if ( line->underline_index > 0 )
        {
            fl_color( underline_col );
            do_underline( line->x, line->y, line->str,
                          line->underline_index - 1 );
        }
        else if ( line->underline_index == 0 )
        {
            unsigned long offset,
                          thickness;

            fl_color( forecol );
            do_underline_all( line->x, line->y, line->str,
                              line->len, &offset, &thickness );

            /* If wsel is larger than 0 some part of the underlined
               string is selected and then we need to draw underine of
               the part of the string that is selected in the color used
               for drawing that part of the string. */

            if ( wsel > 0 && thickness > 0 )
            {
                fl_color( underline_col );
                XFillRectangle( flx->display, flx->win, flx->gc, xsel,
                                line->y + offset, wsel, thickness);
            }
        }

        /* Finally, we also may have to draw a cursor */

        if (    curspos >= line->index
             && curspos <= line->index + line->len )
        {
            int tt = XTextWidth( flx->fs, line->str,
                                 curspos - line->index );

            fl_rectf( line->x + tt, line->y - flx->fasc,
                      2, flx->fheight, curscol );
        }
    }

    /* One possiblity remains: there's no text but the cursor is to be set
       at the very first position */

    if ( curspos == 0 && lnumb == 0 && w >= 2 )
    {
        int xc,
            yc;

        if ( horalign == FL_ALIGN_LEFT )
            xc = x;
        else if ( horalign == FL_ALIGN_CENTER )
            xc = x + 0.5 * w - 1;
        else
            xc = x + w - 2;

        if ( vertalign == FL_ALIGN_BOTTOM )
            yc = y + h - 1 - flx->fasc;
        else if ( vertalign == FL_ALIGN_CENTER )
            yc = y + 0.5 * ( h - flx->fheight );
        else
            yc = y;

        fl_rectf( xc, yc, 2, flx->fheight, curscol );
    }

    /* Free our copy of the string */

    fli_safe_free( str );

    /* Reset clipping if required */

    if ( clip > 0 )
        fl_unset_text_clipping( );

    return max_pixels;
}


/***************************************
 * Function returns the index of the character in the label of the object
 * the mouse is over or -1 if it's not over the label. Note that the function
 * has some limitations: it can only be used on labels inside of the object
 * and the label string may not contain underline characters (and the label
 * can't be a symbol) - if you try to use it on labels that don't satisfy
 * these requirements -1 is returned. 
 ***************************************/

int
fl_get_label_char_at_mouse( FL_OBJECT * obj )
{
    int x,
        y,
        xp,
        yp,
        pos,
        outside;
    unsigned int dummy;

    if (    ! obj
         || ! obj->form
         || ! fl_is_inside_lalign( obj->align )
         || ! obj->label || ! *obj->label
         || strchr( obj->label, *fl_ul_magic_char )
         || ( obj->label[ 0 ] == '@' && obj->label[ 1 ] != '@' ) )
        return -1;

    if (    fl_get_form_mouse( obj->form, &x, &y, &dummy ) != obj->form->window
         || x < obj->x || x >= obj->x + obj->w
         || y < obj->y || y >= obj->y + obj->h )
        return -1;

    x += 2;

    pos = fli_get_pos_in_string( obj->align, obj->x, obj->y, obj->w, obj->h,
                                 obj->lstyle, obj->lsize, x, y, obj->label,
                                 &xp, &yp, &outside ) - 1;

    if ( outside )
        return -1;

    return pos;
}


/***************************************
 * Routine returns the index of the character the mouse is on in a string
 * via the return value and the line number and character position in the
 * line via 'yp' and 'xp' (note: they count starting at 1, 0 indicates the
 * mouse is to the left of the start of the line)
 * The function expects a string that doesn't contain mon-printable characters
 * (except '\n' for starts a new lines)
 * This function is supposed to work on text drawn using fli_draw_string()
 * using the same relevant arguments (alignment, box, font style and size
 * and string) as passed to this function.
 *
 * Arguments:
 *  align:       alignment of the text in the box
 *  x, y, w, h:  box the text is to be found in
 *  style:       font style used when drawing the text
 *  size:        font size used when drawing the text
 *  xpos:        x-position of the mouse
 *  ypos:        y-position of the mouse
 *  str:         pointer to the text itself
 *  xp:          pointer for returning the index in the line where the mouse is
 *               (tarts at 1 with 0 meaning before the start of the string)
 *  yp:          pointer for returning the line number (starting at 1)
 *  outside:     set if the mouse wasn't directly within the string
 ***************************************/

int
fli_get_pos_in_string( int          align,
                       FL_Coord     x,
                       FL_Coord     y,
                       FL_Coord     w,
                       FL_Coord     h,
                       int          style,
                       int          size,
                       FL_Coord     xpos,
                       FL_Coord     ypos,
                       const char * str,
                       int        * xp,
                       int        * yp,
                       int        * outside )
{
    int lnumb = 0;             /* number of lines  */
    int horalign,
        vertalign;
    struct LINE_INFO * line;
    int width;                 /* string width of that line... */
    int xstart;                /* start x-coordinate of this line  */
    int toppos;                /* y-coord of the top line  */
    const char *p = str;
    int xlen;
    int fheight;
    int dummy;

    /* Give the user some slack in hitting the mark - he might try to place
       the cursor between two characters and accidentally has the mouse a
       bit too far to the right. */

    xpos -= 2;
    *outside = 0;

    /* Nothing to be done if there's no string */

    if ( ! str || ! *str )
        return 0;

    /* No need to actually set the font (we're not drawing anything), all
       required is its height */

    fheight = fl_get_char_height( style, size, &dummy, &dummy );

    /* Find all the lines starts etc. in the string */

    while ( p )
    {
        if ( lnumb + 1 >= nlines )
            extend_workmem( nlines + NUM_LINES_INCREMENT );

        lines[ lnumb ].str = ( char * ) p;
        lines[ lnumb++ ].index = p - str;
        if ( ( p = strchr( p, '\n' ) ) )
            ++p;
    }

    /* Find the line in which the mouse is  */

    fli_get_hv_align( align, &horalign, &vertalign );

    switch ( vertalign )
    {
        case FL_ALIGN_TOP :
            toppos = y;
            break;

        case FL_ALIGN_CENTER :
            toppos = y + 0.5 * ( h - lnumb * fheight );
            break;

        case FL_ALIGN_BOTTOM :
            toppos = y + h - 1 - fheight;
            break;

        default :
            M_err( "fli_get_pos_in_string", "This is impossible" );
            return 0;
    }

    *yp = ( ypos - toppos ) / fheight;

    if ( *yp < 0 )
    {
        *outside = 1;
        *yp = 0;
    }
    else if ( *yp >= lnumb )
    {
        *outside = 1;
        *yp = lnumb - 1;
    }

    line = lines + *yp;

    if ( *yp == lnumb - 1 )
        line->len = strlen( line->str );
    else
        line->len = lines[ *yp + 1 ].str - line->str - 1;

    /* Calculate width and start x-coordinate of the line */

    width = XTextWidth( flx->fs, line->str, line->len );

    switch ( horalign )
    {
        case FL_ALIGN_LEFT :
            xstart = x;
            break;

        case FL_ALIGN_CENTER :
            xstart = x + 0.5 * ( w - width );
            break;

        case FL_ALIGN_RIGHT :
            xstart = x + w - width;
            break;

        default :
            M_err( "fli_get_pos_in_string", "This is impossible" );
            return 0;
    }

    xpos -= xstart;

    /* If the mouse is before or behind the string things are simple.... */

    if ( xpos <= 0 )
    {
        *xp = 0;
        *yp += 1;
        *outside = 1;
        return line->index;
    }
    else if ( xpos >= width )
    {
        *xp = line->len;
        *yp += 1;
        *outside = 1;
        return line->index + line->len;
    }

    /* ...otherwise take a guess at the offset in the string where the mouse
       is, assuming all chars have the same width */

    *xp = ( double ) ( xpos * line->len ) / width;

    xlen = XTextWidth( flx->fs, line->str, ++*xp );

    /* If we don't have hit it directly search to the left or right */

    if ( xlen > xpos )
    {
        do
        {
            *xp -= 1;
            xlen = XTextWidth( flx->fs, line->str, *xp );
        }
        while ( *xp > 0 && xlen > xpos );
        *xp += 1;
    }
    else if ( xlen < xpos )
        do
        {
            *xp += 1;
            xlen = XTextWidth( flx->fs, line->str, *xp );
        }
        while ( *xp < lines->len && xlen < xpos );

    *yp += 1;

    return line->index + *xp;
}


/***
  Miscellaneous text drawing routines
***/

/***************************************
 * Draw text with cursor and, if 'bk' is set, also the background
 * (but with no highlighting)
 ***************************************/

static void
fli_draw_text_cursor( int          align,   /* alignment in box */
                      FL_Coord     x,       /* box geometry */
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * str,     /* string to draw */
                      int          style,   /* font style and size */
                      int          size,
                      FL_COLOR     c,       /* color for text */
                      FL_COLOR     bc,      /* background color */
                      FL_COLOR     cc,      /* color for cursor */
                      int          bk,      /* draws background when set */
                      int          pos )    /* index of cursor position */
{
    fli_draw_string( align, x, y, w, h, 0, FL_NOCOLOR, c, cc,
                     style, size, pos, 0, -1, str, bk, 0, 0, bc );
}


/***************************************
 * Draws a (multi-line) text with a cursor (no background, no highlighting)
 ***************************************/

void
fl_draw_text_cursor( int          align,   /* alignment in box */
                     FL_Coord     x,       /* box geometry */
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     FL_COLOR     c,       /* text color */
                     int          style,   /* font style and size */
                     int          size,
                     const char * str,     /* the text to draw */
                     FL_COLOR     cc,      /* cursor color */
                     int          pos )    /* cursor position */
{
    fli_draw_text_cursor( align, x, y, w, h, str, style, size,
                          c, FL_NOCOLOR, cc, 0, pos );
}


/***************************************
 ***************************************/

#define D( x, y, c )                                      \
    fli_draw_text_cursor( align, x, y, w, h, str,         \
                          style,size, c, bc, 0, bk, -1 )

void
fli_draw_text_inside( int          align,
                      FL_Coord     x,
                      FL_Coord     y,
                      FL_Coord     w,
                      FL_Coord     h,
                      const char * str,
                      int          style,
                      int          size,
                      FL_COLOR     c,
                      FL_COLOR     bc,
                      int          bk )
{
    int special = 0;
    int xoff,
        yoff;
    int sw = w,
        sh = h,
        sx = x,
        sy = y;

    if ( ! str || ! *str )
        return;

    if ( str[ 0 ] == '@' && str[ 1 ] != '@' )
    {
        if ( w < 5 && h < 5 )
        {
            sw = sh = 6 + 1.1 * size;
            sx -= sw / 2;
            sy -= sh / 2;
        }

        if ( fl_draw_symbol( str, sx, sy, sw, sh, c ) )
            return;
        else
            str++;
    }
    else if ( str[ 0 ] == '@' && str[ 1 ] == '@' )
        str++;

    xoff = 5;
    yoff = 4;

    x += xoff;
    w -= 2 * xoff;
    y += yoff;
    h -= 2 * yoff;

    if ( special_style( style ) )
    {
        special = ( style / FL_SHADOW_STYLE ) * FL_SHADOW_STYLE;
        style %= FL_SHADOW_STYLE;
    }

    /* Take care of special effects stuff  */

    if ( special == FL_SHADOW_STYLE )
        D( x + 2, y + 2, FL_BOTTOM_BCOL );
    else if ( special == FL_ENGRAVED_STYLE )
    {
        D( x - 1, y,     FL_RIGHT_BCOL );
        D( x,     y - 1, FL_RIGHT_BCOL );
        D( x - 1, y - 1, FL_RIGHT_BCOL );
        D( x + 1, y,     FL_TOP_BCOL );
        D( x,     y + 1, FL_TOP_BCOL );
        D( x + 1, y + 1, FL_TOP_BCOL );
    }
    else if ( special == FL_EMBOSSED_STYLE )
    {
        D( x - 1, y,     FL_TOP_BCOL );
        D( x,     y - 1, FL_TOP_BCOL );
        D( x - 1, y - 1, FL_TOP_BCOL );
        D( x + 1, y,     FL_RIGHT_BCOL );
        D( x,     y + 1, FL_RIGHT_BCOL );
        D( x + 1, y + 1, FL_RIGHT_BCOL );
    }

    fli_draw_text_cursor( align, x, y, w, h, str, style, size,
                          c, bc, FL_NOCOLOR, special ? 0 : bk, -1 );
}


/***************************************
 * Draws a text inside a box.
 ***************************************/

void
fl_draw_text( int          align,
              FL_Coord     x,
              FL_Coord     y,
              FL_Coord     w,
              FL_Coord     h,
              FL_COLOR     c,
              int          style,
              int          size,
              const char * str )
{
    fli_draw_text_inside( align, x, y, w, h, str, style, size, c, 0, 0 );
}


/***************************************
 ***************************************/

void
fl_draw_text_beside( int          align,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     FL_COLOR     c,
                     int          style,
                     int          size,
                     const char * str )
{
    int newa,
        newx,
        newy,
        dx = 0,
        dy = 0;

    if ( ! str || ! *str || w <= 0 || h <= 0 )
        return;

    if ( fl_is_inside_lalign( align ) && ! fl_is_center_lalign( align ) )
        M_warn( "drw_text_beside", "align request is inside" );

    if ( align & FL_ALIGN_LEFT )
    {
        if ( align & FL_ALIGN_BOTTOM || align & FL_ALIGN_TOP )
            dx = - 4;
        else
            dx = 1;
    }
    else if ( align & FL_ALIGN_RIGHT )
    {
        if ( align & FL_ALIGN_BOTTOM || align & FL_ALIGN_TOP )
            dx = 4;
        else
            dx = - 1;
    }

    if ( align & FL_ALIGN_BOTTOM )
        dy = - 2;
    else if ( align & FL_ALIGN_TOP )
        dy = 2;

    x += dx;
    y += dy;

    fli_get_outside_align( align, x, y, w, h, &newa, &newx, &newy );
    fl_draw_text( newa, newx, newy, w, h, c, style, size, str );
}


/***************************************
 * Do underlined text, single character only
 * if underline width to be proportional or fixed width
 ***************************************/

void
fli_set_ul_property( int prop,
                     int thickness )
{
    UL_propwidth = prop;
    if ( thickness > 0 )
        UL_thickness = thickness;
}


#define DESC( c )   ( c == 'g' || c == 'j' || c == 'q' || c == 'y' || c == 'p' )
#define NARROW( c ) ( c == 'i' || c == 'j' || c == 'l' || c == 'f' || c == '1' )

/***************************************
 ***************************************/

XRectangle *
fli_get_underline_rect( XFontStruct * fs,
                        FL_Coord      x,
                        FL_Coord      y,
                        const char  * cstr,
                        int           n )
{
    static XRectangle xr;
    int ul_width,
        ul_rwidth,
        xoff;
    unsigned long ul_pos,
                  ul_thickness = 0;
    char *str = ( char * ) cstr;
    int ch = *( str + n );
    int pre;                /* stuff in front of the string, such as ^H */

    if ( UL_thickness < 0 )
        XGetFontProperty( flx->fs, XA_UNDERLINE_THICKNESS, &ul_thickness );
    else
        ul_thickness = UL_thickness;

    if ( ul_thickness == 0 || ul_thickness > 100 )
        ul_thickness = strstr( fli_curfnt, "bold" ) ? 2 : 1;

    if ( ! XGetFontProperty( fs, XA_UNDERLINE_POSITION, &ul_pos ) )
        ul_pos = DESC( ch ) ? ( 1 + flx->fdesc ) : 1;

    /* If the character is narrow, use the width of g otherwise use the width
       of D. Of course, if UL_width == proportional, this really does not
       matter */

    ul_width = XTextWidth( fs, NARROW( ch ) ? "h" : "D", 1 );
    ul_rwidth = XTextWidth( fs, str + n, 1 );

    pre = str[ 0 ] == *fl_ul_magic_char;

    xoff = fli_get_string_widthTABfs( fs, str + pre, n - pre );

    /* Try to center the underline on the correct character */

    if ( UL_propwidth )
        x = x + xoff;
    else
        x = x + xoff + ( ul_rwidth - ul_width ) / 2;

    xr.x = x;
    xr.y = y + ul_pos;
    xr.width = UL_propwidth ? ul_rwidth : ul_width;
    xr.height = ul_thickness;
    return &xr;
}


/***************************************
 ***************************************/

static void
do_underline( FL_Coord     x,
              FL_Coord     y,
              const char * cstr,
              int          n )
{
    XRectangle *xr = fli_get_underline_rect( flx->fs, x, y, cstr, n );

    if ( flx->win == None || xr->width <= 0 ||  xr->height <= 0 )
        return;

    XFillRectangle( flx->display, flx->win, flx->gc, xr->x, xr->y,
                    xr->width, xr->height );
}


#define has_desc( s )    (    strchr( s, 'g' )  \
                           || strchr( s, 'j' )  \
                           || strchr( s, 'q' )  \
                           || strchr( s, 'y' )  \
                           || strchr( s, 'p' ) )


/***************************************
 * Underline whole string
 ***************************************/

static void
do_underline_all( FL_Coord        x,
                  FL_Coord        y,
                  const char    * str,
                  int             n,
                  unsigned long * ul_pos,
                  unsigned long * ul_thickness )
{
    int ul_width;

    if ( flx->win == None )
        return;

    if ( UL_thickness < 0 )
        XGetFontProperty( flx->fs, XA_UNDERLINE_THICKNESS, ul_thickness );
    else
        *ul_thickness = UL_thickness;

    if ( *ul_thickness == 0 || *ul_thickness > 100 )
        *ul_thickness = strstr( fli_curfnt, "bold" ) ? 2 : 1;

    if ( ! XGetFontProperty( flx->fs, XA_UNDERLINE_POSITION, ul_pos ) )
        *ul_pos = has_desc( str ) ? ( 1 + flx->fdesc ) : 1;

    ul_width = XTextWidth( flx->fs, str, n );

    /* Draw it */

    if ( ul_width > 0 && *ul_thickness > 0 )
        XFillRectangle( flx->display, flx->win, flx->gc, x, y + *ul_pos,
                        ul_width, *ul_thickness );
}


/***************************************
 * Draw a single line string possibly with embedded tabs
 ***************************************/

int
fli_draw_stringTAB( Window       win,
                    GC           gc,
                    int          x,
                    int          y,
                    int          style,
                    int          size,
                    const char * s,
                    int          len,
                    int          img )
{
    int w, tab;
    const char *p,
               *q;
    XFontStruct *fs = fl_get_font_struct( style, size );
    DrawString drawIt = img ? XDrawImageString : XDrawString;

    if ( win == 0 )
        return 0;

    tab = fli_get_tabpixels( fs );

    XSetFont( flx->display, gc, fs->fid );

    for ( w = 0, q = s; *q && ( p = strchr( q, '\t' ) ) && p - s < len;
          q = p + 1 )
    {
        drawIt( flx->display, win, gc, x + w, y, ( char * ) q, p - q );
        w += XTextWidth( fs, q, p - q );
        w = ( w / tab + 1 ) * tab;
    }

    drawIt( flx->display, win, gc, x + w, y, ( char * ) q, s - q + len );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
