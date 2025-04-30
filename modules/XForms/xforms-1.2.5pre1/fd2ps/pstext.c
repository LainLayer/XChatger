/*
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file pstext.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd2ps.h"
#include <stdlib.h>

char *ul_magic_char = "\010";


/***************************************
 ***************************************/

void
ps_text_init( void )
{
    ps_output( "/point {SX SY add 2 div div} BD\n" );
    ps_output( "/SetFont {findfont exch scalefont setfont} BD\n" );
    ps_output( "/Lshow {show} BD\n" );
    ps_output( "/Cshow {dup stringwidth pop -2 div 0 rmoveto show} BD\n" );
    ps_output( "/Rshow {dup stringwidth pop neg 0 rmoveto show} BD\n" );
    ps_output( "/CP {currentpoint} bind def /SW {stringwidth} BD\n" );
}


/*
 * Text stuff. Default fonts follows the XFORM built-in
 */

static const char *fnts[ FL_MAXFONTS ] =
{
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-Oblique",
    "Helvetica-BoldOblique",
    "Courier",
    "Courier-Bold",
    "Courier-Oblique",
    "Courier-BoldOblique",
    "Times-Roman",
    "Times-Bold",
    "Times-Italic",
    "Times-BoldItalic",

 /* xforms users charter */
    "Times-Roman",
    "Times-Bold",
    "Times-Italic",
    "Times-BoldItalic",

    "Symbol"
};

static int cur_style = -1, cur_size = -1;


/***************************************
 ***************************************/

void
ps_invalidate_font_cache( void )
{
    cur_style = cur_size = -1;
}


/***************************************
 ***************************************/

void
ps_set_font( int style,
             int size )
{
    if ( style >= FL_SHADOW_STYLE )
        style %= FL_SHADOW_STYLE;

    if ( style == cur_style && cur_size == size )
        return;

    ps_output( "%d point /%s SetFont\n", size, fnts[ style ] );
    ps_output( "/H %d point def\n", size );
    cur_style = style;
    cur_size = size;
}


#define has_desc(s)    (strchr(s,'g')||strchr(s,'j')||\
                        strchr(s,'q')||strchr(s,'y')||strchr(s,'p'))
#define is_desc(c)     (c=='g'||(c=='j')||(c=='q')||(c=='y')||(c=='p'))


/***************************************
 ***************************************/

static void
do_underline( const char * s,
              int          n )
{
    ps_output( "/len (%s) SW pop def\n", s );

    if ( n == -1 )
    {
        ps_output( "/ty CP exch pop %d sub def ", 1 + has_desc( s ) * 2 );
        ps_output( "/tx CP pop len sub def " );
        ps_output( "tx ty M len tx add ty LT S\n" );
    }
    else
    {
        char *t = fl_strdup( s );
        *( t + n ) = '\0';
        ps_output( "/ul (%c) SW pop def\n", *( s + n ) );
        ps_output( "/ty CP exch pop %d sub def ", 1 + is_desc(s[ n ] ) * 2 );
        ps_output( "/tx CP pop len sub (%s) SW pop add def\n", t );
        ps_output( "tx ty M ul tx add ty LT S\n" );
        free( t );
    }
}


/***************************************
 ***************************************/

#define Quote( c )  ( c == '(' || c == ')' || c == '%' )

static char *
ps_quote( char *str )
{
    static char buf[ 1024 ];
    char *s, *q = buf;

    for ( s = str; *s; s++ )
    {
        if ( Quote( *s ) )
            *q++ = '\\';
        *q++ = *s;
    }
    *q = '\0';
    return buf;
}


/***************************************
 * This routine is always called by other routines. Once we get here,
 * the text would always remain within the box specified by
 * {x,y,w,h}.
 ***************************************/

static void
ps_drw_text( int          align,
             float        x,
             float        y,
             float        w,
             float        h,
             long         c,
             int          style,
             int          size,
             const char * sstr )
{
    int ulpos = -1, lnumb;
    int i;
    char *lines[ 512 ];
    char *str;
    char newlabel[ 255 ], *p;
    float bw = 2;
    int halign, valign;

    ps_color( c );
    ps_set_font( style, size );

    str = fl_strdup( sstr );

    lines[ 0 ] = str;

    /* Split (multi-line)string into lines */

    for ( i = 0, lnumb = 1; str[ i ] != '\0'; i++ )
        if ( str[ i ] == '\n' )
        {
            str[ i ] = '\0';
            lines[ lnumb ] = str + i + 1;
            lnumb++;
        }

    fl_get_hv_align( align, &halign, &valign );

    /* Figure out where the starting point is */

    switch ( halign )
    {
        case FL_ALIGN_CENTER:
            ps_output( "/x %.1f def ", x + 0.5 * w );
            break;

        case FL_ALIGN_LEFT:
            ps_output( "/x %.1f def ", bw + x );
            break;

        case FL_ALIGN_RIGHT:
            ps_output( "/x %.1f def ", x + w - 1 - bw );
            break;
    }

    switch ( valign )
    {
        case FL_ALIGN_TOP:
            ps_output( "/y %.1f H sub def\n", y + h - bw );
            break;

        case FL_ALIGN_BOTTOM:
            ps_output( "/y %.1f %.1f H mul add def\n",
                       y + bw, lnumb - 0.9 );
            break;

        case FL_ALIGN_CENTER:
            ps_output( "/y %.1f %.1f H mul add def\n",
                       y + 0.5 * h, 0.5 * lnumb - 0.9 );
            break;
    }

    for ( i = 0; i < lnumb; i++ )
    {
        /* Check if have underline request */

        if ( ( p = strchr( lines[ i ], *ul_magic_char ) ) )
        {
            char *q;

            ulpos = p - lines[ i ];
            q = newlabel;
            p = lines[ i ];
            for ( ; *p; p++ )
                if ( *p != *ul_magic_char )
                    *q++ = *p;
            *q = 0;
            lines[ i ] = newlabel;
        }

        ps_output( "x y M " );

        switch ( halign )
        {
            case FL_ALIGN_CENTER:
                ps_output( "(%s) Cshow\n", ps_quote( lines[ i ] ) );
                break;

            case FL_ALIGN_LEFT:
                ps_output( "(%s) Lshow\n", ps_quote( lines[ i ] ) );
                break;

            case FL_ALIGN_RIGHT:
                ps_output( "(%s) Rshow\n", ps_quote( lines[ i ] ) );
                break;
        }

        if ( ulpos >= 0 )
            do_underline( lines[ i ], ulpos - 1 );
        ulpos = -1;
        if ( i != lnumb - 1 )
            ps_output( "/y y H sub def\n" );
    }

    free( str );
}


/***************************************
 ***************************************/

#define D( x, y, c )  ps_drw_text( align, x, y, w, h, c, style, size, str )

void
ps_draw_text( int          align,
              float        x,
              float        y,
              float        w,
              float        h,
              long         col,
              int          style,
              int          size,
              const char * str)
{
    int special = FL_INVALID_STYLE;

    if ( ! str || ! *str )
        return;

    if ( *str == '@' )
    {
        ps_draw_symbol( str, x, y, w, h, col );
        return;
    }

    if ( special_style( style ) )
    {
        special = ( style / FL_SHADOW_STYLE ) * FL_SHADOW_STYLE;
        style %= FL_SHADOW_STYLE;
    }

    if ( special == FL_SHADOW_STYLE )
        D( x + 2, y - 2, FL_BOTTOM_BCOL );
    else if ( special == FL_ENGRAVED_STYLE )
    {
        D( x - 1, y,     FL_RIGHT_BCOL );
        D( x,     y + 1, FL_RIGHT_BCOL );
        D( x - 1, y + 1, FL_RIGHT_BCOL );
        D( x + 1, y,     FL_LEFT_BCOL );
        D( x,     y - 1, FL_LEFT_BCOL );
        D( x + 1, y - 1, FL_LEFT_BCOL );
    }
    else if ( special == FL_EMBOSSED_STYLE )
    {
        D( x - 1, y,     FL_TOP_BCOL );
        D( x,     y + 1, FL_TOP_BCOL );
        D( x - 1, y + 1, FL_TOP_BCOL );
        D( x + 1, y,     FL_RIGHT_BCOL );
        D( x,     y - 1, FL_RIGHT_BCOL );
        D( x + 1, y - 1, FL_RIGHT_BCOL );
    }

    ps_drw_text( align, x, y, w, h, col, style, size, str );
}


/***************************************
 ***************************************/

void
ps_draw_text_beside( int          align,
                     float        x,
                     float        y,
                     float        w,
                     float        h,
                     long         col,
                     int          style,
                     int          size,
                     const char * str )
{
    int newa, newx, newy;

    if ( ! str || ! *str )
        return;

    align = fl_to_outside_lalign( align );

#if 1
    fl_get_outside_align( align, x, y, w, h, &newa, &newx, &newy );
    ps_draw_text( newa, newx, newy, w, h, col, style, size, str );
#else
    if ( align == FL_ALIGN_LEFT )
        ps_draw_text( FL_ALIGN_RIGHT, x - h, y, h, h, col, style, size, str );
    else if ( align == FL_ALIGN_RIGHT )
        ps_draw_text( FL_ALIGN_LEFT, x + w, y, h, h, col, style, size, str );
    else if ( align == FL_ALIGN_TOP )
        ps_draw_text( FL_ALIGN_BOTTOM, x, y + h, w, h, col, style, size, str );
    else if ( align == FL_ALIGN_BOTTOM )
        ps_draw_text( FL_ALIGN_TOP, x, y - h, w, h, col, style, size, str );
    else
        ps_draw_text( FL_ALIGN_CENTER, x, y, w, h, col, style, size, str );
#endif
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
