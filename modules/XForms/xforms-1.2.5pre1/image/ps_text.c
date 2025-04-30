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
 *  along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/*
 *  This file is part of the XForms library package.
 *  Copyright (c) 1997-2002  by T.C. Zhao
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pflps.h"
#include <stdlib.h>

extern char *fl_ul_magic_char;

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


/***************************************
 ***************************************/

void
flps_invalidate_font_cache( void )
{
    flps->cur_style = flps->cur_size = -1;
}


/***************************************
 ***************************************/

void
flps_set_font( int style,
               int size )
{

    if ( style >= FL_SHADOW_STYLE )
        style %= FL_SHADOW_STYLE;

    if ( style == flps->cur_style && size == flps->cur_size )
        return;

    if ( flps->scale_text )
        size = 0.5 * ( flps->final_xscale + flps->final_yscale );

    flps_output( "%d point /%s SetFont\n", size, fnts[ style ] );
    flps_output( "/H %d point def\n", size );

    flps->cur_style = style;
    flps->cur_size = size;
}


#define has_desc( s )    (    strchr( s, 'g' )    \
                           || strchr( s, 'j' )    \
                           || strchr( s, 'q' )    \
                           || strchr( s, 'y' )    \
                           || strchr( s, 'p' ) )

#define is_desc( c )     (    c == 'g'    \
                           || c == 'j'    \
                           || c == 'q'    \
                           || c == 'y'    \
                           || c == 'p' )


/***************************************
 ***************************************/

static void
do_underline( const char * s,
              int          n )
{

    flps_output( "/len (%s) SW pop def\n", s );

    if ( n == -1 )
    {
        flps_output( "/ty CP exch pop %d sub def ", 1 + has_desc( s ) * 2 );
        flps_output( "/tx CP pop len sub def " );
        flps_output( "tx ty M len tx add ty LT S\n" );
    }
    else
    {
        char *t = fl_strdup( s );

        t[ n ] = '\0';
        flps_output( "/ul (%c) SW pop def\n", s[ n ] );
        flps_output( "/ty CP exch pop %d sub def ",
                     1 + is_desc( s [ n ] ) * 2 );
        flps_output( "/tx CP pop len sub (%s) SW pop add def\n", t );
        flps_output( "tx ty M ul tx add ty LT S\n" );
        fl_free( t );
    }
}


#define Quote( c )   ( c == '(' || c == ')' || c == '%')


/***************************************
 ***************************************/

static char *
ps_quote( char * str )
{
    static char buf[ 1024 ];
    char *s,
         *q = buf;

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
flps_drw_text( int          align,
               float        x,
               float        y,
               float        w,
               float        h,
               FL_COLOR     c,
               int          style,
               int          size,
               const char * sstr )
{
    int ulpos = -1, lnumb;
    int i;
    char *lines[ 512 ];
    char *str;
    char newlabel[ 255 ],
         *p;
    float bw = 2;
    int halign,
        valign;
    int is_vert;

    flps_color( c );
    flps_set_font( style, size );

    str = fl_strdup( sstr );

    lines[ 0 ] = str;

    if ( ( is_vert = align & FL_ALIGN_VERT ) )
    {
        align &= ~ FL_ALIGN_VERT;
        flps_output( "gsave %.1f %.1f translate 90 rotate\n", x, y );
        x = y = 0;
    }

    /* this is a hack to get arbitary rotation for image_postscript */

    if ( flps->rotation )
    {
        flps_output( "gsave %.1f %.1f translate %g rotate\n", x, y,
                     flps->rotation * 0.1 );
        x = y = 0;
    }

    /* split (multi-line)string into lines */

    for ( i = 0, lnumb = 1; str[ i ] != '\0'; i++ )
    {
        if ( str[ i ] == '\n')
        {
            str[ i ] = '\0';
            lines[ lnumb ] = str + i + 1;
            lnumb++;
        }
    }

    fli_get_hv_align( align, &halign, &valign );

    /* figure out where the starting point is */

    switch ( halign )
    {
        case FL_ALIGN_CENTER :
            flps_output( "/x %.1f def ", x + 0.5 * w );
            break;

        case FL_ALIGN_LEFT :
            flps_output( "/x %.1f def ", bw + x );
            break;

        case FL_ALIGN_RIGHT :
            flps_output( "/x %.1f def ", x + w - 1 - bw );
            break;
    }

    switch ( valign )
    {
        case FL_ALIGN_TOP :
            flps_output( "/y %.1f H sub def\n", y + h - bw );
            break;

        case FL_ALIGN_BOTTOM :
            flps_output( "/y %.1f %.1f H mul add def\n",
                         y + bw, lnumb - 0.9 );
            break;

        case FL_ALIGN_CENTER :
            flps_output( "/y %.1f %.1f H mul add def\n",
                         y + 0.5 * h, 0.5 * lnumb - 0.9 );
            break;
    }

    for ( i = 0; i < lnumb; i++ )
    {
        /* check if have underline request */

        if ( ( p = strchr( lines[ i ], *fl_ul_magic_char ) ) )
        {
            char *q;

            ulpos = p - lines[ i ];
            q = newlabel;
            p = lines[ i ];
            for ( ;  *p; p++ )
                if ( *p != *fl_ul_magic_char )
                    *q++ = *p;
            *q = 0;
            lines[ i ] = newlabel;
        }

        flps_output( "x y M " );

        switch ( halign )
        {
            case FL_ALIGN_CENTER :
                flps_output( "(%s) Cshow\n", ps_quote( lines[ i ] ) );
                break;

            case FL_ALIGN_LEFT :
                flps_output( "(%s) Lshow\n", ps_quote( lines[ i ] ) );
                break;

            case FL_ALIGN_RIGHT :
                flps_output( "(%s) Rshow\n", ps_quote( lines[ i ] ) );
                break;
        }

        if ( ulpos >= 0 )
            do_underline( lines[ i ], ulpos - 1 );

        ulpos = -1;

        if ( i != lnumb - 1 )
            flps_output( "/y y H sub def\n" );
    }

    fl_free( str );

    if ( is_vert || flps->rotation )
        flps_output( "grestore\n" );
}


#define D( x, y, c )   flps_drw_text( align, x, y, w, h, c, style, size, str )


/***************************************
 ***************************************/

void
flps_draw_text( int         align,
                int         x,
                int         y,
                int         w,
                int         h,
                FL_COLOR    col,
                int         style,
                int         size,
                const char * istr )
{
    int special = FL_INVALID_STYLE;
    const char *str = istr;

    if ( ! str || ! *str )
        return;

    if ( *str == '@' && str[ 1 ] != '@' )
    {
        if ( w < 3 || h < 3 )
        {
            w = h = size + 4;
            x -= w / 2;
            y -= h / 2;
        }

        flps_draw_symbol( str, x, y, w, h, col );
        return;
    }

    str += str[ 1 ] == '@';

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
        D( x, y + 1,     FL_RIGHT_BCOL );
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

    flps_drw_text( align, x, y, w, h, col, style, size, str );
}


/***************************************
 ***************************************/

void
flps_draw_text_beside( int          align,
                       int          x,
                       int          y,
                       int          w,
                       int          h,
                       FL_COLOR     col,
                       int          style,
                       int          size,
                       const char * str )
{
    if ( ! str || ! *str )
        return;

    switch( fl_to_outside_lalign( align ) )
    {
        case FL_ALIGN_LEFT :
            flps_draw_text( FL_ALIGN_RIGHT, x - h, y, h, h, col, style, size,
                            str );
            break;

        case FL_ALIGN_RIGHT :
            flps_draw_text( FL_ALIGN_LEFT, x + w, y, h, h, col, style, size,
                            str );
            break;

        case FL_ALIGN_TOP :
            flps_draw_text( FL_ALIGN_BOTTOM, x, y + h, w, h, col, style, size,
                            str );
            break;

        case FL_ALIGN_BOTTOM :
            flps_draw_text( FL_ALIGN_TOP, x, y - h, w, h, col, style, size,
                            str );
            break;

        case FL_ALIGN_LEFT_BOTTOM :
            flps_draw_text( FL_ALIGN_LEFT_TOP, x, y - h, w, h, col, style,
                            size, str );
            break;

        case FL_ALIGN_RIGHT_BOTTOM :
            flps_draw_text( FL_ALIGN_RIGHT_TOP, x, y - h, w, h, col, style,
                            size, str );
            break;

        case FL_ALIGN_LEFT_TOP :
            flps_draw_text( FL_ALIGN_LEFT_BOTTOM, x, y + h, w, h, col, style,
                            size, str );
            break;

        case FL_ALIGN_RIGHT_TOP :
            flps_draw_text( FL_ALIGN_RIGHT_BOTTOM, x, y + h, w, h, col, style,
                            size, str );
            break;

        case FL_ALIGN_CENTER :
            flps_draw_text( FL_ALIGN_CENTER, x, y, w, h, col, style, size,
                            str );
            break;

        default :
            flps_draw_text( FL_ALIGN_TOP, x, y - h, w, h, col, style, size,
                            str );
            break;
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
