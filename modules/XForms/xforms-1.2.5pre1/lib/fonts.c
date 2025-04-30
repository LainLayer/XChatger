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
 * \file fonts.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * All font and string size query routines. There are rooms for speed ups.
 * For one, font switching can be reduced somewhat.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"
#include <string.h>
#include <ctype.h>

static XFontStruct * defaultfs;

static XFontStruct * try_get_font_struct( int,
                                          int,
                                          int );
static char * get_fname( const char *,
                         int );


/*
 * Question marks indicate the sizes in tenth of a point. It will be
 * replaced on the fly by the font requesting routines. Depending on
 * the availability of the fonts and capabilities of the server, the
 * font may or may not be scalable.
 *
 * Resolution field is left blank on purpose as the resolution reported
 * by the server is not reliable thus the program can't force the
 * resolution. This way the admins can set the proper font path.
 *
 * Order is important as it has to agree with FL_TIMES_STYLE etc
 * defined in Basic.h
 *
 */

/* These default fonts may not be the most beuatiful X11 fonts available
   on the system but they are part of X11 distributions since at least
   20 years, so we can be rather sure that they're available everywhere.
   (And, remember, these fonts must be available on the machine where the
   X server is running on, which is not necessarily the machine where the
   program using XForms is executed.) */

static const char *default_fonts[ ] =
{
    "-*-helvetica-medium-r-*-*-*-?-*-*-p-*-*-*",
    "-*-helvetica-bold-r-*-*-*-?-*-*-p-*-*-*",
    "-*-helvetica-medium-o-*-*-*-?-*-*-p-*-*-*",
    "-*-helvetica-bold-o-*-*-*-?-*-*-p-*-*-*",

    "-*-courier-medium-r-*-*-*-?-*-*-*-*-*-*",
    "-*-courier-bold-r-*-*-*-?-*-*-*-*-*-*",
    "-*-courier-medium-o-*-*-*-?-*-*-*-*-*-*",
    "-*-courier-bold-o-*-*-*-?-*-*-*-*-*-*",

    "-*-times-medium-r-*-*-*-?-*-*-p-*-*-*",
    "-*-times-bold-r-*-*-*-?-*-*-p-*-*-*",
    "-*-times-medium-i-*-*-*-?-*-*-p-*-*-*",
    "-*-times-bold-i-*-*-*-?-*-*-p-*-*-*",

    "-*-charter-medium-r-*-*-*-?-*-*-*-*-*-*",
    "-*-charter-bold-r-*-*-*-?-*-*-*-*-*-*",
    "-*-charter-medium-i-*-*-*-?-*-*-*-*-*-*",
    "-*-charter-bold-i-*-*-*-?-*-*-*-*-*-*",

    NULL
};

static FL_FONT fl_fonts[ FL_MAXFONTS ];

static const char *cv_fname( const char * );

#define DEFAULTF1  "fixed"
#define DEFAULTF2  "6x13"


/***************************************
 * Global initialization routine. Must be called before any font
 * routine can be used. We can place fli_init_font in all font switching
 * and string size query routines so a seperate initialization is not
 * needed, and it has the added bonus that startup *may* be faster,
 * but we pay a function call overhead in every call to any of these
 * font related routines.
 ***************************************/

void
fli_init_font( void )
{
    FL_FONT *flf;
    const char *const *f = default_fonts;
    static int initialized;

    if ( initialized )
        return;

    initialized = 1;

    /* If fl_set_font_name() has been called before fl_initialize() we need
       to keep the changes */

    for ( flf = fl_fonts, f = default_fonts; *f; f++, flf++ )
        if ( ! *flf->fname )
            strcpy( flf->fname, *f );

    /* Load a default font */

    if (    ! defaultfs
         && ! ( defaultfs = XLoadQueryFont( flx->display, DEFAULTF1 ) ) )
        defaultfs = XLoadQueryFont( flx->display, DEFAULTF2 );

    /* Load a couple of fonts at normal size to prevent the caching code from
       using bad looking replacement if strange sizes are requested */

    fl_get_font_struct( FL_NORMAL_STYLE, FL_DEFAULT_SIZE );
    fl_get_font_struct( FL_BOLD_STYLE,   FL_DEFAULT_SIZE );
    fl_get_font_struct( FL_FIXED_STYLE,  FL_DEFAULT_SIZE );
}


/***************************************
 * In addition to get the font handle, we also make the font current
 * in default GC
 ***************************************/

void
fl_set_font( int numb,
             int size )
{
    int dh;
    XCharStruct overall;
    XFontStruct *fs;

    fs = fl_get_font_struct( numb, size );

    /* cur_font is always the one in current GC */

    if ( fl_state[ fl_vmode ].cur_fnt == fs )
    {
#if FL_DEBUG >= ML_DEBUG
        M_debug( "fl_set_font", "current", fli_curfnt );
#endif
        return;
    }

    fl_state[ fl_vmode ].cur_fnt = flx->fs = fs;

    /* Basic font info (no need to send a string, we just want the maximum
       ascent and descent) */

    XTextExtents( flx->fs, "", 0, &dh, &flx->fasc, &flx->fdesc, &overall );
    flx->fheight = flx->fasc + flx->fdesc;

    XSetFont( flx->display, flx->textgc, flx->fs->fid );

    if ( fli_cntl.debug > 1 )
    {
        unsigned long res = 0;

        if ( XGetFontProperty( flx->fs, XA_RESOLUTION, &res ) )
            M_info2( "fl_set_font", "FontResolution: %lu", res );
    }
}


/***************************************
 * Add a new font (indexed by n) or change an existing font.
 * Preferably the font name constains a '?' in the size
 * position so different sizes can be used.
 ***************************************/

int
fl_set_font_name( int          n,
                  const char * name )
{
    FL_FONT *flf;

    if ( n < 0 || n >= FL_MAXFONTS )
    {
        M_warn( "fl_set_font_name", "Bad font number (%d)", n );
        return -1;
    }

    if ( ! name || ! *name )
    {
        M_warn( "fl_set_font_name", "Bad font name" );
        return -1;
    }

    if ( strlen( name ) > FL_MAX_FONTNAME_LENGTH )
    {
        M_warn( "fl_set_font_name", "Font name too long" );
        return -1;
    }

    flf = fl_fonts + n;

    if ( *flf->fname )
    {
        int i;

        for ( i = 0; i < flf->nsize; i++ )
            if ( flf->size[ i ] > 0 )
                XFreeFont( flx->display, flf->fs[ i ] );
        *flf->fname = '\0';
    }

    flf->nsize = 0;
    strcpy( flf->fname, name );

    if ( ! flx || ! flx->display )
        return 1;

    return try_get_font_struct( n, FL_DEFAULT_SIZE, 1 ) ? 0 : -1;
}


/***************************************
 * Add a new font (indexed by n) or change an existing font.
 ***************************************/

int
fl_set_font_name_f( int          n,
                    const char * fmt,
                    ... )
{
    char *buf;
    int ret;

    EXPAND_FORMAT_STRING( buf, fmt );
    ret = fl_set_font_name( n, buf );
    fl_free( buf );
    return ret;
}


/***************************************
 * Returns the name of the indexed font
 ***************************************/

const char *
fl_get_font_name( int n )
{
    if ( n < 0 || n >= FL_MAXFONTS )
        return NULL;

    return fl_fonts[ n ].fname;
}


/***************************************
 * List built-in fonts
 ***************************************/

int
fl_enumerate_fonts( void ( * output )( const char *s ),
                    int  shortform )
{
    FL_FONT *flf = fl_fonts,
            *fe  = flf + FL_MAXFONTS;
    int n = 0;

    for ( ; output && flf < fe; flf++ )
        if ( *flf->fname )
        {
            output( shortform ? cv_fname( flf->fname ) : flf->fname );
            n++;
        }

    return n;
}


/***************************************
 * All font changes go through this routine. If with_fail is false,
 * this routine will not fail even if requested font can't be loaded.
 * A substitution will be made.
 ***************************************/

static XFontStruct *
try_get_font_struct( int numb,
                     int size,
                     int with_fail )
{
    FL_FONT *flf = fl_fonts;
    XFontStruct *fs = NULL;
    int i,
        is_subst = 0;

    if ( special_style( numb ) )
        numb %= FL_SHADOW_STYLE;

    /* Avoid trying to use negative or zero font size */

    if ( size <= 0 )
    {
        M_info( "try_get_font_struct",
                "Bad font size requested (%d), using %d istead",
                size, size < 0 ? -size : 1 );
        size = size < 0 ? -size : 1;
    }
 
    flf = fl_fonts + numb;

    if ( numb < 0 || numb >= FL_MAXFONTS || ! *flf->fname )
    {
        if ( ! fli_no_connection ) {

            /* This function is typically used to test whether a font is
               loadable or not, so it's not a fatal error if it fails. Issue
               a message for information therefore. */

            M_info( "try_get_font_struct", "Bad FontStyle requested: %d: %s",
                    numb, flf->fname );
        }

        if ( ! fl_state[ fl_vmode ].cur_fnt )
            M_warn( "try_get_font_struct", "bad font returned" );

        return fl_state[ fl_vmode ].cur_fnt;
    }

    strcpy( fli_curfnt, get_fname( flf->fname, size ) );

    /* Search for requested size in the cached fonts - fonts with "negative
       sizes" are replacement fonts found before */

    for ( fs = NULL, i = 0; ! fs && i < flf->nsize; i++ )
        if ( size == abs( flf->size[ i ] ) )
            fs = flf->fs[ i ];

    /* Return it if font has already been loaded (i.e. is in the cache) */

    if ( fs )
        return fs;

    /* Try to load the font */

    fs = XLoadQueryFont( flx->display, fli_curfnt );

    /* If that didn't work try to find a replacement font, i.e. an already
       loaded font with the nearest size or, if there's none, the very most
       basic font. */

    if ( ! fs )
    {
       int mdiff = INT_MAX,
           k;

        if ( with_fail )
            return NULL;

        M_warn( "try_get_font_struct", "Can't load %s, using subsitute",
                fli_curfnt );

        /* Search for a replacement with the nearest size */

        for ( k = -1, i = 0; i < flf->nsize; i++ )
        {
            if ( mdiff > FL_abs( size - flf->size[ i ] ) )
            {
                mdiff = FL_abs( size - flf->size[ i ] );
                k = i;
            }
        }

        if ( k != -1 )
            fs = flf->fs[ k ];
        else
            fs = flx->fs ? flx->fs : defaultfs;

        is_subst = 1;
    }

    /* If cache is full make space at the end */

    if ( flf->nsize == FL_MAX_FONTSIZES )
    {
        if ( flf->size[ FL_MAX_FONTSIZES - 1 ] > 0 )
            XFreeFont( flx->display, flf->fs[ FL_MAX_FONTSIZES - 1 ] );
        flf->nsize--;
    }

    flf->fs[ flf->nsize ] = fs;
    flf->size[ flf->nsize++ ] = is_subst ? - size : size;

    /* Here we are guranteed a valid font handle although there is no
       gurantee the font handle corresponds to the font requested */

    return fs;
}


/***************************************
 ***************************************/

XFontStruct *
fl_get_font_struct( int style,
                    int size )
{
    return try_get_font_struct( style, size, 0 );
}


/***************************************
 * Similar to fl_get_string_xxxGC except that there is no side effects.
 * Must not free the fontstruct as structure FL_FONT caches the
 * structure for possible future use.
 ***************************************/

int
fl_get_string_width( int          style,
                     int          size,
                     const char * s,
                     int          len )
{
    XFontStruct *fs = fl_get_font_struct( style, size );

    return fli_no_connection ? ( len * size ) : XTextWidth( fs, s, len );
}


/***************************************
 ***************************************/

int
fli_get_string_widthTABfs( XFontStruct * fs,
                           const char *  s,
                           int           len )
{
    int w,
        tab;
    const char *p,
               *q;

    if ( fli_no_connection )
        return 12 * len;

    tab = fli_get_tabpixels( fs );

    for ( w = 0, q = s; *q && ( p = strchr( q, '\t' ) ) && ( p - s ) < len;
          q = p + 1 )
    {
        w += XTextWidth( fs, q, p - q );
        w = ( ( w / tab ) + 1 ) * tab;
    }

    return w += XTextWidth( fs, q, len - ( q - s ) );
}


/***************************************
 ***************************************/

int
fl_get_string_widthTAB( int          style,
                        int          size,
                        const char * s,
                        int          len )
{
    XFontStruct *fs = fl_get_font_struct( style, size );

    return fli_get_string_widthTABfs( fs, s, len );
}


/***************************************
 * Function returns the height of the string, calculated from adding the
 * largest ascent and descent of all its characters in the string, via 'asc'
 * and 'desc' (but which both can be NULL pointers), the maximum ascent
 * and descent.
 ***************************************/

int
fl_get_string_height( int          style,
                      int          size,
                      const char * s,
                      int          len,
                      int *        asc,
                      int *        desc )
{
    int a, d;

    if ( fli_no_connection )
        a = d = size / 2;
    else
    {
        XFontStruct *fs = fl_get_font_struct( style, size );
        XCharStruct overall;
        int dh;

        XTextExtents( fs, s, len, &dh, &a, &d, &overall );
    }

    if ( asc )
        *asc = a;
    if ( desc )
        *desc = d;

    return a + d;
}


/***************************************
 * Returns font height and, via 'asc' and 'desc' (but which both can be NULL
 * pointers), the fonts ascent and descent.
 ***************************************/

int
fl_get_char_height( int   style,
                    int   size,
                    int * asc,
                    int * desc )
{
    int a, d;

    if ( fli_no_connection )
        a = d = size / 2;
    else
    {
        XFontStruct *fs = fl_get_font_struct( style, size );

        a = fs->ascent;
        d = fs->descent;

        if ( asc )
            *asc = a;
        if ( desc )
            *desc = d;
    }

    return a + d;
}


/***************************************
 * Function returns the width of the widest character in the requested font
 ***************************************/

int
fl_get_char_width( int style,
                   int size )
{
    XFontStruct *fs = fl_get_font_struct( style, size );

    return fs->max_bounds.width;
}


/***************************************
 ***************************************/

void
fl_get_string_dimension( int          fntstyle,
                         int          fntsize,
                         const char * s,
                         int          len,
                         int *        width,
                         int *        height )
{
    const char *p,
               *q;
    int h,
        maxw = 0,
        maxh = 0;

    h = fl_get_char_height( fntstyle, fntsize, NULL, NULL );

    for ( q = s; *q && ( p = strchr( q, '\n' ) ); q = p + 1 )
    {
        maxw = FL_max( maxw,
                       fl_get_string_width( fntstyle, fntsize, q, p - q ) );
        maxh += h;
    }

    maxw = FL_max( maxw, fl_get_string_width( fntstyle, fntsize,
                                              q, len - ( q - s ) ) );
    maxh += h;

    *width  = maxw;
    *height = maxh;
}


/*
 * Tab handling. Currently only one tab
 */

#define  MaxTabs   5

static char *tabstop[ MaxTabs ] = { "aaaaaaaa", 0 };
static int tabstopNchar[ MaxTabs ] = { 7 };


/***************************************
 ***************************************/

void
fl_set_tabstop( const char *s )
{
    static int set;

    if ( s )
    {
        if ( set )
            fl_free( *tabstop );
        *tabstop = fl_strdup( s );
        *tabstopNchar = strlen( *tabstop );
        set = 1;
    }
}


/***************************************
 ***************************************/

int
fli_get_tabpixels( XFontStruct * fs )
{
    return   XTextWidth( fs, *tabstop, *tabstopNchar )
           + XTextWidth( fs, " ", 1 );
}


/***************************************
 * Convert X font names to more conventional names by stripping the
 * auxiliary info.
 ***************************************/

static const char *
cv_fname( const char *f )
{
    static char fname[ FL_MAX_FONTNAME_LENGTH + 1 ];
    char *q,
         *p;

    /* Remove all the garbages from head */

    for ( q = strcpy( fname, f ); *q && ! isalnum( ( unsigned char ) *q ); q++ )
        /* empty */ ;

    /* Remove all the garbage from the end, starting from '?' */

    if ( ( p = strchr( fname, '?' ) ) )
        *--p = '\0';

    /* Remove all remaining garbages */

    for ( p = fname + strlen( fname ) - 1;
          p > q && ! isalnum( ( unsigned char ) *p ); p-- )
        /* empty */ ;

    *++p = '\0';

    return q;
}


/***************************************
 * Given a font name and a size (in points), assemble the complete name
 ***************************************/

static char *
get_fname( const char * str,
           int          size )
{
    static char fname[ sizeof fli_curfnt ];
    char len_str[ 50 ];    /* should be enough for all ints */
    char *p;

    /* If necessary truncate font names that are too long, the caller
       expects a real string */

    strncpy( fname, str, sizeof fname - 1 );
    fname[ sizeof fname - 1 ] = '\0';

    if ( ( p = strchr( fname, '?' ) ) )
    {
        int len = sprintf( len_str, "%d0", size );

        if ( len + strlen( str ) <= sizeof fname - 1 )
        {
            memmove( p + len, p + 1, strlen( p ) );
            strncpy( p, len_str, len );
        }
    }

    return fname;
}


/***************************************
 * Some compatibility stuff, i.e. functions that were never documented
 * and were removed from V0.89, but apparently this broke some applications
 * that were using them. Put back in 10/22/00.
 ***************************************/

int
fl_fdesc_( void )
{
    return flx->fdesc;
}


/***************************************
 ***************************************/

int
fl_fheight_( void )
{
    return flx->fheight;
}


/***************************************
 ***************************************/

GC
fl_gc_( void )
{
    return flx->gc;
}


/***************************************
 ***************************************/

GC
fl_textgc_( void )
{
    return flx->textgc;
}


/***************************************
 ***************************************/

Window
fl_cur_win_( void )
{
    return flx->win;
}


/***************************************
 ***************************************/

XFontStruct *
fl_cur_fs_( void )
{
    return flx->fs;
}


/***************************************
 ***************************************/

Display *
fl_display_( void )
{
    return flx->display;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
