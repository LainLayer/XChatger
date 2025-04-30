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
 * \file xpopup.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 * Implementation of pop-up menus in Xlib. Not quite fit the
 * model of forms library, but it is needed to make other things
 * work.
 *
 * These functionalities should be someday rewritten using
 * forms construct rather than Xlib.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>


#define FL_MAXPUP  32            /* default maximum pups */
#define PADH       FL_PUP_PADH   /* space between items */
#define PADW       8             /* space on each side */
#define PADTITLE   14            /* extran space for title  */
#define CHECKW     6             /* check box size */

#define M_TITLE    1
#define M_ERR      2


/****************************************************************
 * pop up menu structure and some defaults
 ****************************************************************/

#define NSC          8      /* max hotkeys   */

typedef struct
{
    char         * str;             /* label                        */
    FL_PUP_CB      icb;             /* callback                     */
    long         * shortcut;        /* shortcut keys                */
    int            subm;            /* sub menu                     */
    unsigned int   mode;            /* various attributes           */
    int            ret;             /* %x stuff                     */
    short          ulpos;           /* hotkeys in label             */
    short          radio;           /* radio entry. 0 mean no radio */
    short          len;
} MenuItem;


typedef struct
{
    int              used;
    char           * title;         /* Menu title                   */
    Window           win;           /* menu window                  */
    Cursor           cursor;        /* cursor for the pup           */
    GC               gc_active;     /* GC for main text             */
    GC               gc_inactive;   /* GC for inactive text         */
    MenuItem       * item[ FL_MAXPUPI + 1 ];
    FL_PUP_CB        menu_cb;       /* callback routine             */
    FL_PUP_ENTERCB   enter_cb;      /* enter callback routine       */
    void           * enter_data;
    FL_PUP_ENTERCB   leave_cb;      /* leave callback routine       */
    void           * leave_data;
    unsigned long    event_mask;
    int              x,             /* origin relative to root      */
                     y;
    unsigned int     w,             /* total dimension              */
                     h;
    short            titleh;
    short            nitems;        /* no. of item in menu          */
    short            title_width;   /* title width                  */
    short            maxw;
    short            bw;
    short            lpad;
    short            rpad;
    short            padh;
    short            cellh;
    short            isEntry;       /* true if menu is setup via entry struct */
    int              par_y;
    FL_FORM        * form;
} PopUP;


static void grab_both( PopUP * );
static void reset_radio( PopUP *,
                         MenuItem * );

/* Resources that control the fontsize and other things */

static int pup_font_style = FL_NORMAL_STYLE;
static int pup_title_font_style = FL_NORMAL_STYLE;


#ifdef __sgi
static int pup_font_size = FL_SMALL_SIZE,
           pup_title_font_size = FL_SMALL_SIZE;
#else
static int pup_font_size = FL_NORMAL_SIZE,
           pup_title_font_size = FL_NORMAL_SIZE;
#endif

static FL_COLOR pup_color         = FL_COL1;
static FL_COLOR pup_text_color    = FL_BLACK;
static FL_COLOR pup_checked_color = FL_BLUE;

static int pup_level = 0;
static int fl_maxpup = FL_MAXPUP;

static int pup_bw = -1;
static int pup_bw_is_set = 0;

static PopUP *menu_rec = NULL;

static XFontStruct *pup_font_struct = NULL;        /* popup main text font */
static int pup_ascent = 0,                         /* font properties */
           pup_desc = 0;
static XFontStruct *pup_title_font_struct = NULL;  /* popup title text font */
static int pup_title_ascent = 0,
           pup_title_desc   = 0;
static Cursor pup_defcursor = 0;

static int pup_subreturn;

static int pup_using_keys = 0;
static int pup_internal_showpup_call = 0;


/************ data struct maintanance ******************{**/

/***************************************
 ***************************************/

static void
init_pupfont( void )
{
    XCharStruct chs;
    int junk;

    if ( ! pup_title_font_struct )
    {
        pup_title_font_struct = fl_get_fntstruct( pup_title_font_style,
                                                  pup_title_font_size );
        XTextExtents( pup_title_font_struct, "qjQb", 4, &junk,
                      &pup_title_ascent, &pup_title_desc, &chs );
    }

    if ( ! pup_font_struct )
    {
        pup_font_struct = fl_get_fntstruct( pup_font_style, pup_font_size );
        XTextExtents( pup_font_struct, "qjQb", 4, &junk, &pup_ascent,
                      &pup_desc, &chs );
    }
}


/***************************************
 * Initialize a particular menu
 ***************************************/

static void
init_pup( PopUP * m )
{
    m->menu_cb     = NULL;
    m->enter_cb    = m->leave_cb = NULL;
    m->w = m->h    = m->maxw = 0;
    m->nitems       = 0;
    m->title_width  = 0;
    m->win          = None;
    m->gc_active    = m->gc_inactive = None;
    m->bw           = pup_bw;
    m->title        = NULL;
    m->item[ 0 ]    = NULL;
    m->padh         = PADH;
    if ( ! pup_defcursor )
        pup_defcursor = fli_get_cursor_byname( XC_sb_right_arrow );
    m->cursor       = pup_defcursor;
    m->lpad         = m->rpad = PADW;
    init_pupfont( );
    m->cellh        = pup_ascent + pup_desc + 2 * m->padh;
    m->isEntry      = 0;
    m->form         = NULL;
}


/***************************************
 ***************************************/

static int
find_empty_index( Window win )
{
    PopUP *p;

    for ( p = menu_rec; p < menu_rec + fl_maxpup; p++ )
        if ( ! p->used )
        {
            init_pup( p );
            p->used = 1;
            p->form = win != None ? fl_win_to_form( win ) : NULL;
            return p - menu_rec;
        }

    M_err( "find_empty_index", "Too many popups (maximum is %d)", fl_maxpup );
    return -1;
}


static void convert_shortcut( const char *,
                              const char *,
                              MenuItem *,
                              int );


static void wait_for_close( Window );


/***************************************
 ***************************************/

static void
reset_max_width( PopUP * m )
{
    int i;
    MenuItem **item = m->item;
    char *t,
         *b;


    if ( ! m->used || m->nitems <= 0 )
        return;

    m->maxw = 0;

    for ( i = 0; i < m->nitems; i++ )
    {
        b = t = fl_strdup( item[ i ]->str );
        while ( ( b = strchr( b, '\b' ) ) )
            memmove( b, b + 1, strlen( b ) );
        m->maxw = FL_max( m->maxw,
                          fl_get_string_widthTAB( pup_font_style, pup_font_size,
                                                  t, strlen( t ) ) );
        fl_free( t );
    }

    if ( m->title && *m->title )
    {
        b = t = fl_strdup( m->title );
        while ( ( b = strchr( b, '\b' ) ) )
            memmove( b, b + 1, strlen( b ) );
        m->title_width = XTextWidth( pup_title_font_struct, t, strlen( t ) );
        fl_free( t );
    }
    else
        m->title_width = 0;

    m->cellh = pup_ascent + pup_desc + 2 * m->padh;
}


/***************************************
 * Parse the menu entries
 ***************************************/

#define MV( d, s )   memmove( ( d ), ( s ), strlen( s ) + 1 )

static int
parse_entry( int          n,
             const char * str,
             va_list      ap )
{
    PopUP *m = menu_rec + n;
    MenuItem *item;
    char *s,
         *c,
         *p,
         *e,
         *sc = NULL;
    unsigned int flags = 0;
    long num;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used || ! str )
        return -1;

    s = fl_strdup( str );

    for ( c = strtok( s, "|" );
          c && m->nitems < FL_MAXPUPI;
          c = strtok( NULL, "|" ) )
    {
        flags = 0;
        m->item[ m->nitems ] = item = fl_malloc( sizeof *item );
        item->str      = NULL;
        item->icb      = NULL;
        item->shortcut = NULL;
        item->subm     = -1;
        item->mode     = 0;
        item->ret      = m->nitems + 1;
        item->ulpos    = -1;
        item->radio    = 0;
        item->len      = 0;

        p = c;
        while ( ( p = strchr( p, '%' ) ) && ! ( flags & M_ERR ) )
        {
            switch ( p[ 1 ] )
            {
                case '%' :
                    MV( p, p + 1 );
                    p = p + 1;
                    break;

                case 't' :
                    flags |= M_TITLE;
                    MV( p, p + 2 );
                    break;

                case 'f' :
                    item->icb = va_arg( ap, FL_PUP_CB );
                    MV( p, p + 2 );
                    break;

                case 'F' :
                    m->menu_cb = va_arg( ap, FL_PUP_CB );
                    MV( p, p + 2 );
                    break;

                case 'm' :
                    item->subm = va_arg( ap, int );
                    MV( p, p + 2 );
                    break;

                case 'l' :
                    MV( p, p + 2 );
                    MV( c + 1, c );
                    *c = '\010';
                    p = p + 1;
                    break;

                case 'i' :
                case 'd' :
                    item->mode |= FL_PUP_GREY;
                    MV( p, p + 2 );
                    break;

                case 'x' :
                    num = strtol( p + 2, &e, 10 );
                    if ( e == p + 2 )
                    {
                        flags |= M_ERR;
                        M_err( "parse_entry", "Missing number after %%x" );
                        break;
                    }
                    if ( num <= 0 )
                    {
                        flags |= M_ERR;
                        M_err( "parse_entry", "Invalid zero or negative "
                               "number after %%x" );
                        break;
                    }
                    item->ret = num;
                    while ( isspace( ( unsigned char ) *e ) )
                        e++;
                    MV( p, e );
                    break;

                case 'B' :
                    item->mode |= FL_PUP_CHECK;
                    /* fall through */

                case 'b' :
                    item->mode |= FL_PUP_BOX;
                    MV( p, p + 2 );
                    break;

                case 'R' :
                    item->mode |= FL_PUP_CHECK;
                    /* fall through */

                case 'r' :
                    item->mode |= FL_PUP_BOX;
                    num = strtol( p + 2, &e, 10 );
                    if ( num <= 0 )
                    {
                        flags |= M_ERR;
                        M_err( "parse_entry", "Zero or negative group number" );
                        break;
                    }
                    if ( e == p + 2 )
                    {
                        flags |= M_ERR;
                        M_err( "parse_entry", "Missing number after %%%c",
                               p + 1 );
                        break;
                    }
                    item->radio = num;
                    while ( isspace( ( unsigned char ) *e ) )
                        e++;

                    /* If the item is to be in on state all other items
                       belonging to the same group must be in off state */

                    if ( p[ 1 ] == 'R' )
                    {
                        int k;

                        for ( k = m->nitems - 1; k >= 0; k-- )
                            if ( m->item[ k ]->radio == item->radio )
                                m->item[ k ]->mode &= ~ FL_PUP_CHECK;
                    }

                    MV( p, e );
                    break;

                case 'h' :
                case 's' :
                    sc = va_arg( ap, char * );
                    MV( p, p + 2 );
                    break;

                default :
                    flags |= M_ERR;
                    M_err( "parse_entry", "Unknown sequence %%%c", p[ 1 ] );
                    break;
            }
        }

        if ( flags & M_ERR )
        {
            fl_free( item );
            m->item[ m->nitems ] = NULL;
            break;
        }

        if ( sc )
        {
            M_info( "parse_entry", "shortcut = %s for %s", sc, c );
            convert_shortcut( sc, c, item, NSC );
        }

        if ( item->mode & FL_PUP_BOX )
            m->lpad = PADW + CHECKW + 2;

        if ( item->subm >= 0 )
            m->rpad = PADW + 16;

        if ( flags & M_TITLE )
        {
            char *t,
                 *b;

            m->title = fl_strdup( c );
            b = t = fl_strdup( c );
            while ( ( b = strchr( b, '\b' ) ) )
                memmove( b, b + 1, strlen( b ) );
            m->title_width = XTextWidth( pup_title_font_struct,
                                         t, strlen( t ) );
            fl_free( t );
            fl_free( item );
            m->item[ m->nitems ] = NULL;
        }
        else
        {
            char *t,
                 *b;

            item->str = fl_strdup( c );
            item->len = strlen( item->str );

            b = t = fl_strdup( item->str );
            while ( ( b = strchr( b, '\b' ) ) )
                memmove( b, b + 1, strlen( b ) );
            m->maxw = FL_max( m->maxw,
                              fl_get_string_widthTAB( pup_font_style,
                                                      pup_font_size,
                                                      t, strlen( t ) ) );
            fl_free( t );
            m->nitems++;
        }
    }

    if ( c )
        M_err( "parse_entry", "Too many menu items, max is %d", FL_MAXPUPI );

    fl_free( s );

    return ( flags & M_ERR ) ? -1 : 0;
}


/***************************************
 ***************************************/

static void
close_pupwin( PopUP * pup )
{
    if ( pup->win )
    {
        XDestroyWindow( flx->display, pup->win );
        wait_for_close( pup->win );
        pup->win = None;
    }
}


/***************************************
 * initialize the menu system. Must be called first. Made defpup/newpup
 * etc. auto call fli_init_pup (instead of letting fl_initialize to call
 * it) and we save about ~25k in exe size for app not using pups
 ***************************************/

void
fli_init_pup( void )
{
    PopUP *mr;
    size_t i;

    if ( menu_rec )
        return;

    menu_rec = fl_calloc( fl_maxpup, sizeof *menu_rec );

    for ( mr = menu_rec; mr < menu_rec + fl_maxpup; mr++ )
    {
        mr->used       = 0;
        mr->title      = NULL;
        mr->win        = None;
        mr->cursor     = None;
        mr->gc_active  = mr->gc_inactive = None;
        mr->menu_cb    = NULL;
        mr->enter_cb   = mr->leave_cb = NULL;
        mr->enter_data = mr->leave_data = NULL;

        for ( i = 0; i <= FL_MAXPUPI; i++ )
            mr->item[ i ] = NULL;
    }

    fl_setpup_default_fontsize( fli_cntl.pupFontSize ?
                                fli_cntl.pupFontSize : -2 );
}


/***************************************
 ***************************************/

int
fl_setpup_default_fontsize( int size )
{
    int i;
    int old_pup_font_size = pup_font_size;

    if ( size <= 0 )
        return old_pup_font_size;

    fli_init_pup( );

    pup_font_size = size;
    pup_title_font_size = size;

    pup_font_struct = pup_title_font_struct = NULL;

    if ( ! flx->display )
        return old_pup_font_size;

    init_pupfont( );

    for ( i = 0; i < fl_maxpup; i++ )
    {
        reset_max_width( menu_rec + i );
        close_pupwin( menu_rec + i );
    }

    return old_pup_font_size;
}


/***************************************
 ***************************************/

int
fl_setpup_default_fontstyle( int style )
{
    int i;
    int old_pup_font_style = pup_font_style;

    if ( ! flx->display )
        return old_pup_font_style;

    if ( style < 0 )
        return pup_font_style;

    fli_init_pup( );

    pup_font_style       = style;
    pup_title_font_style = style;
    pup_font_struct      = pup_title_font_struct = NULL;

    init_pupfont( );

    for ( i = 0; i < fl_maxpup; i++ )
        reset_max_width( menu_rec + i );

    return old_pup_font_style;
}


/***************************************
 ***************************************/

void
fl_setpup_default_color( FL_COLOR fg,
                         FL_COLOR bg )
{
    pup_color      = fg;
    pup_text_color = bg;
}


/***************************************
 ***************************************/

void
fl_setpup_default_pup_checked_color( FL_COLOR col )
{
    pup_checked_color = col;
}


/********************************************************************
 * Public routines
 ****************************************************************{***/

/***************************************
 * Allocate a new PopUP ID
 ***************************************/

int
fl_newpup( Window win )
{
    fli_init_pup( );

    if ( pup_level )
    {
        M_warn( "fl_newpup", "Inconsistent pup_level %d", pup_level );
        pup_level = 0;
    }

    if ( ! pup_bw_is_set )
    {
        pup_bw = fli_cntl.borderWidth ? fli_cntl.borderWidth : -2;
        pup_bw_is_set = 1;
    }

    return find_empty_index( win == None ? fl_root : win );
}


/***************************************
 * Add pop-up entries
 ***************************************/

int
fl_addtopup( int          n,
             const char * str,
             ... )
{
    va_list ap;
    int ret;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
        return -1;

    va_start( ap, str );
    ret = parse_entry( n, str, ap );
    va_end( ap );

    return ret == 0 ? n : -1;
}


/***************************************
 * Allocate PopUP ID and optionally set all entries
 ***************************************/

int
fl_defpup( Window       win,
           const char * str,
           ... )
{
    int n;
    int ret;
    va_list ap;

    if ( ( n = fl_newpup( win ) ) < 0 )
        return -1;

    if ( str == 0 )
        return n;

    va_start( ap, str );
    ret = parse_entry( n, str, ap );
    va_end( ap );

    return ret == 0 ? n : -1;
}


/***************************************
 * Check to see if the requested value exists in popup m
 ***************************************/

static MenuItem *
ind_is_valid( PopUP * m,
              int     ind )
{
    MenuItem **is = m->item,
             **ise,
             *item = NULL;

    for ( ise = is + m->nitems; is < ise && !item; is++ )
    {
        if ( ( *is )->ret == ind )
            item = *is;
        else if ( ( *is )->subm >= 0 )
            item = ind_is_valid( menu_rec + ( *is )->subm, ind );
    }

    return item;
}


/***************************************
 ***************************************/

static MenuItem *
requested_item_is_valid( const char * where,
                         int          nm,
                         int          ni )
{
    if ( nm < 0 || nm >= fl_maxpup || ! menu_rec[ nm ].used )
    {
        M_err( where, "Bad popup index %d", nm );
        return NULL;
    }

    return ind_is_valid( menu_rec + nm, ni );
}


/***************************************
 * Change attributes of a popup item
 ***************************************/

int
fl_setpup_mode( int          nm,
                int          ni,
                unsigned int mode )
{
    MenuItem *item;

    if ( ! ( item = requested_item_is_valid( "fl_setpup_mode", nm, ni ) ) )
        return -1;

    if ( ( item->mode = mode ) & FL_PUP_CHECK )
        item->mode |= FL_PUP_BOX;

    if ( item->mode & FL_PUP_RADIO )
    {
        item->mode |= FL_PUP_BOX;
        if ( ! item->radio )
            item->radio = -1;
    }

    if ( item->mode & FL_PUP_BOX )
        menu_rec[ nm ].lpad = PADW + CHECKW + 2;

    return 0;
}


#define AltMask  FL_ALT_MASK

/***************************************
 ***************************************/

static void
convert_shortcut( const char * sc,
                  const char * str,
                  MenuItem   * item,
                  int          n     FL_UNUSED_ARG )
{
    if ( ! item->shortcut )
        item->shortcut = fl_calloc( 1, NSC * sizeof *item->shortcut );

    item->ulpos = fli_get_underline_pos( str, sc ) - 1;
    fli_convert_shortcut( sc, item->shortcut );
    if ( sc[ 0 ] == '&' )
        M_info( "convert_shortcut", "sc = %s keysym = %ld\n",
                sc, item->shortcut[ 0 ] );
}


static void draw_popup( PopUP * );
static void draw_item( PopUP *,
                       int,
                       int );


/***************************************
 ***************************************/

static void
wait_for_close( Window win )
{
    long emask = AllEventsMask;
    XEvent xev;

    /* Drop all events for the window. We need to do sync before to be
       sure all events are already in the event queue */

    XSync( flx->display, False );

    while ( XCheckWindowEvent( flx->display, win, emask, &xev ) )
        /* empty */ ;
}


/****************************************************************
 * Global routine of doing pop-ups. Never returns unless user
 * does something with the pointer. For "hanging" pop-ups, a
 * pointer & focus grab will be activated and released upon returning.
 * Since requested item might be inactive, search for next active
 * item if current one is not
 ****************************************************************/

static int
get_valid_entry( PopUP * m,
                 int     target,
                 int     dir )
{
    if ( target < 1 )
        target = dir < 0 ? m->nitems : 1;
    if ( target > m->nitems )
        target = dir < 0 ? m->nitems : 1;

    for ( ; target > 0 && target <= m->nitems; target += dir )
        if ( ! ( m->item[ target - 1 ]->mode & FL_PUP_GREY ) )
            return target;

    /* wrap */

    if ( target < 1 )
        target = dir < 0 ? m->nitems : 1;
    if ( target > m->nitems )
        target = dir < 0 ? m->nitems : 1;

    for ( ; target > 0 && target <= m->nitems; target += dir )
        if ( ! ( m->item[ target - 1 ]->mode & FL_PUP_GREY ) )
            return target;

    M_err( "get_valid_entry", "No valid entries among total of %d", m->nitems );
    return 0;
}


#define alt_down    ( metakey_down( keymask ) != 0 )

/***************************************
 ***************************************/

static int
handle_shortcut( PopUP        * m,
                 KeySym         keysym,
                 unsigned int   keymask )
{
    MenuItem **mi = m->item;
    int i,
        j;
    int sc,
        alt;

    for ( i = 0; i < m->nitems; i++ )
    {
        if ( ! ( mi[ i ]->mode & FL_PUP_GREY ) && mi[ i ]->shortcut )
            for ( j = 0; j < NSC && mi[ i ]->shortcut[ j ]; j++ )
            {
                sc = mi[ i ]->shortcut[ j ];
                alt = ( sc & AltMask ) == AltMask;
                sc &= ~ AltMask;
                if ( sc == ( int ) keysym && ! ( alt ^ alt_down ) )
                    return i + 1;
            }
    }
    return 0;
}


/***************************************
 ***************************************/

static int
handle_submenu( PopUP    * m,
                MenuItem * item,
                int      * val )
{
    if ( ! ( item->mode & ( FL_PUP_GREY | FL_INACTIVE ) ) && item->subm >= 0 )
    {
        /* Set up the position for the new window (it should appear so
           that it's top line is flush with the line of the parent menu
           it was started from). Please note: the new window has to overlap
           the parent window at least in a single point - otherwise drawing
           artefacts often appear! */

        fl_setpup_position( m->x + m->w - 3,
                            m->y + m->cellh * ( *val - 1 )
                            + ( ( m->title && *m->title ) ?
                                m->titleh - m->padh : 0 ) );

        /* Draw and deal with the submenu */

        if ( ( pup_subreturn = *val = fl_dopup( item->subm ) ) <= 0 )
            grab_both( m );
        else
            return 1;
    }

    return 0;
}


/***************************************
 * Keyboard handling. Also checks shortcut
 ***************************************/

static int
pup_keyboard( XKeyEvent * xev,
              PopUP     * m,
              int       * val )
{
    KeySym keysym = NoSymbol;
    char buf[ 16 ];
    int oldval = *val;

    XLookupString( xev, buf, sizeof buf, &keysym, 0 );

    if ( IsHome( keysym ) )
    {
        draw_item( m, *val, FL_FLAT_BOX );
        *val = get_valid_entry( m, 1, -1 );
        draw_item( m, *val, FL_UP_BOX );
    }
    else if ( IsEnd( keysym ) )
    {
        draw_item( m, *val, FL_FLAT_BOX );
        *val = get_valid_entry( m, m->nitems, 1 );
        draw_item( m, *val, FL_UP_BOX );
    }
    else if ( IsUp( keysym ) )
    {
        draw_item( m, *val, FL_FLAT_BOX );
        *val = get_valid_entry( m, *val - 1, -1 );
        draw_item( m, *val, FL_UP_BOX );
    }
    else if ( IsDown( keysym ) )
    {
        draw_item( m, *val, FL_FLAT_BOX );
        *val = get_valid_entry( m, *val + 1, 1 );
        draw_item( m, *val, FL_UP_BOX );
    }
    else if ( IsRight( keysym ) )
    {
        if ( *val > 0 && *val <= m->nitems && m->item[ *val - 1 ]->subm )
        {
            oldval = *val;
            if ( handle_submenu( m, m->item[ *val - 1 ], val ) )
                keysym = XK_Return;
            else
                *val = oldval;
        }
    }
    else if ( IsLeft( keysym ) )
    {
        *val = -1;
        keysym = XK_Escape;
    }
    else if ( keysym == XK_Escape || keysym == XK_Cancel )
    {
        draw_item( m, *val, FL_FLAT_BOX );
        *val = -1;
    }
    else if ( keysym == XK_Return )
    {
        if ( *val > 0 && *val <= m->nitems && m->item[ *val - 1 ]->subm )
            handle_submenu( m, m->item[ *val - 1 ], val );
    }
    else
    {
        int i;

        if ( ( i = handle_shortcut( m, keysym, xev->state ) ) )
        {
            *val = i;
            handle_submenu( m, m->item[ *val - 1 ], val );
            keysym = XK_Return;
        }
        else
            pup_using_keys = 0;
    }

    if ( oldval != *val && ( m->enter_cb || m->leave_cb ) )
    {
        if ( oldval > 0 && oldval <= m->nitems && m->leave_cb )
            m->leave_cb( m->item[ oldval - 1 ]->ret, m->leave_data );
        if ( *val > 0 && *val <= m->nitems && m->enter_cb )
            m->enter_cb( m->item[ *val - 1 ]->ret, m->enter_data );
    }

    return keysym == XK_Escape || keysym == XK_Return || keysym == XK_Cancel;
}


/***************************************
 * Mouse moved - val is set to the item number (not value) upon return
 ***************************************/

static MenuItem *
handle_motion( PopUP * m,
               int     mx,
               int     my,
               int   * val )
{
    int cval = -1;
    MenuItem *item = NULL;
    static MenuItem *lastitem = NULL;
    static PopUP *lastm = NULL;

    if (    mx >= 0 && mx <= ( int ) m->w
         && my >= 0 && my <= ( int ) m->h - ( FL_abs( m->bw ) > 2 )
                             - ( m->padh > 1 ) )
    {
        cval = m->nitems - ( m->h - ( FL_abs( m->bw ) > 2 )
                             - ( m->padh > 1 ) - my ) / m->cellh;
        if ( cval > 0 )
            item = m->item[ cval - 1 ];
    }

    if ( cval != *val || m != lastm )
    {
        draw_item( m, *val, FL_FLAT_BOX );
        draw_item( m, cval, FL_UP_BOX );
        *val = cval;
    }

    if ( item && item->mode & FL_PUP_GREY )
        item = NULL;

    if ( lastitem && item != lastitem && m->leave_cb )
        m->leave_cb( lastitem->ret, m->leave_data );

    if ( item && item != lastitem  && m->enter_cb )
        m->enter_cb( item->ret, m->enter_data );

    lastitem = item;
    lastm = m;

    return item;
}


/***************************************
 * Interaction routine. If mouse is released on the title bar,
 * consider its a "hanging" pop-up request else return
 ***************************************/

static int
pup_interact( PopUP * m )
{
    XEvent ev;
    int val       = 0,
        done      = 0,
        timer_cnt = 0;
    MenuItem *item;

    m->event_mask |= KeyPressMask;
    ev.xmotion.time = 0;

    /* If the new popup was opened due to a key press mark the first active
       entry as currently selected */

    if ( pup_using_keys )
    {
        int i;

        for ( i = 1; i < m->nitems; i++ )
        {
            if ( m->item[ i - 1 ]->mode & FL_PUP_GREY )
                continue;
            draw_item( m, i, FL_UP_BOX );
            val = i;
            break;
        }
    }

    while ( ! done )
    {
        long msec = fli_context->idle_delta;

        if ( fli_context->timeout_rec )
            fli_handle_timeouts( &msec );

        if ( ! XCheckWindowEvent( flx->display, m->win, m->event_mask, &ev ) )
        {
            /* If the mouse button was released or pressed not within the
               popup's window we're through with the popup */

            if (    XCheckTypedEvent( flx->display, ButtonPress, &ev )
                 || XCheckTypedEvent( flx->display, ButtonRelease, &ev ) )
            {
                val = -1;
                break;
            }

            if ( timer_cnt++ % 10 == 0 )
            {
                timer_cnt = 0;
                fli_handle_idling( &ev, msec, 1 );
                fl_winset( m->win );
            }
            continue;
        }

        timer_cnt = 0;
        fli_int.query_age++;

        switch ( ev.type )
        {
            case Expose:
                draw_popup( m );
                XSync( flx->display, 0 );
                break;

            case MotionNotify:
                fli_compress_event( &ev, ButtonMotionMask );
                /* fall through */

            case ButtonPress:
                /* taking adv. of xbutton.x == xcrossing.x */

                fli_int.mousex  = ev.xmotion.x;
                fli_int.mousey  = ev.xmotion.y;
                fli_int.keymask = ev.xmotion.state;
                fli_int.query_age = 0;

                pup_using_keys = 0;
                item = handle_motion( m, ev.xbutton.x, ev.xbutton.y, &val );

                if ( item && item->subm >= 0 && ev.xbutton.x >= 0 )
                {
                    unsigned int keymask;
                    int old_val = val;

                    done = handle_submenu( m, item, &val );
                    fl_get_win_mouse( m->win, &ev.xbutton.x, &ev.xbutton.y,
                                      &keymask );
                    if ( ! ( done = keymask ? done : 1 ) )
                        draw_item( m, old_val, FL_FLAT_BOX );
                }
                else if ( pup_level > 1 && val < 0 )
                    done =    ev.xbutton.x < 0
                           && (    ev.xbutton.y <= m->par_y
                                || ev.xbutton.y > m->par_y + m->cellh );
                break;

            case ButtonRelease:
                fli_int.mousex  = ev.xbutton.x;
                fli_int.mousey  = ev.xbutton.y;
                fli_int.keymask = ev.xbutton.state;
                fli_int.query_age = 0;

                item = handle_motion( m, ev.xbutton.x, ev.xbutton.y, &val );
                if ( item && item->subm >= 0 && val != -1 )
                    done = handle_submenu( m, item, &val );
                else
                    done = val != 0;
                break;

            case KeyPress:
                fli_int.mousex  = ev.xkey.x;
                fli_int.mousey  = ev.xkey.y;
                fli_int.keymask = ev.xkey.state;
                fli_int.query_age = 0;

                pup_using_keys = 1;
                done = pup_keyboard( ( XKeyEvent * ) &ev, m, &val );
                break;

            case UnmapNotify:   /* must be by external routine */
                done = 1;
                val = -1;
                break;
        }
    }

    return val;
}


/***************************************
 ***************************************/

static void
grab_both( PopUP * m )
{
    unsigned int evmask = m->event_mask;

    /* Set the window we're using */

    fl_winset( m->win );

    /* Get rid of all non-pointer events in event_mask */

    evmask &= ~ ( ExposureMask | KeyPressMask );
    XSync( flx->display, 0 );
    fl_msleep( 30 );
    XChangeActivePointerGrab( flx->display, evmask, m->cursor, CurrentTime );

    /* Do pointer and keyboard grab */

    if ( XGrabPointer( flx->display, m->win, False, evmask, GrabModeAsync,
                       GrabModeAsync, None, m->cursor, CurrentTime )
                                                                != GrabSuccess )
        M_err( "grab_both", "Can't grab pointer" );

    if ( XGrabKeyboard( flx->display, m->win, False, GrabModeAsync,
                        GrabModeAsync, CurrentTime ) != GrabSuccess )
    {
        M_err( "grab_both", "Can't grab keyboard" );
        XUngrabPointer( flx->display, CurrentTime );
    }
}


/***************************************
 * Main routine for creating, doing interaction and removing a popup window
 ***************************************/

int
fl_dopup( int n )
{
    PopUP *m = menu_rec + n;
    int val = 0;
    MenuItem *item = 0;
    XEvent xev;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
    {
        M_err( "fl_dopup", "bad pupID: %d\n", n );
        return -1;
    }

    if ( pup_level == 0 )
        fli_context->pup_id = n;

    pup_subreturn = -1;

    pup_level++;
    pup_internal_showpup_call = 1;
    fl_showpup( n );

    /* If one opens a touch menu and is fast enough to move the mouse out
       of the window before the grab is active an extra EnterNotify event
       comes in that results in the touch menu getting opened again after
       closing it, so delete all such events for the form the touch menu
       belongs to. */

    if ( m->form && m->form->window )
        while ( XCheckWindowEvent( flx->display, m->form->window,
                                   EnterWindowMask, &xev ) )
            /* empty */ ;

    /* pup_interact() returns the item number */

    val = pup_interact( m );

    if ( m->win )
    {
        XUnmapWindow( flx->display, m->win );
        wait_for_close( m->win );
    }
    else
        M_err( "fl_dopup", "Window already closed" );

    /* The following is necessary because 'save_under' may not be supported.
       Both the forms under the closed popup window and higher level popup
       window may require a redraw if the had become (partially) hidden. */

    if (    pup_level > 1
         && ! DoesSaveUnders( ScreenOfDisplay( flx->display, fl_screen ) ) )
    {
        FL_FORM *form;

        while ( XCheckMaskEvent( flx->display, ExposureMask, &xev ) != False )
            if ( ( form = fl_win_to_form( ( ( XAnyEvent * ) &xev )->window ) )
                                                                       != NULL )
            {
                fl_winset( form->window );
                fl_redraw_form( form );
            }
            else
            {
                int i;

                for ( i = 0; i < fl_maxpup; i++ )
                    if ( menu_rec[ i ].win == ( ( XAnyEvent * ) &xev )->window )
                    {
                        fl_winset( menu_rec[ i ].win );
                        draw_popup( menu_rec + i );
                    }
            }
    }

    if ( pup_level > 1 )
    {
        /* Need to remove all MotionNotify otherwise wrong coord */

        while ( XCheckMaskEvent( flx->display, ButtonMotionMask, &xev ) )
            /* empty */ ;
    }

    /* Handle callback if any  */

    pup_level--;
    if (    val > 0
         && val <= m->nitems
         && ( pup_subreturn < 0 || ( pup_subreturn > 0 && pup_level > 0 ) ) )
    {
        item = m->item[ val - 1 ];

        /* If we ended up on a disabled item or one that points to a
           submenu return -1 to indicate nothing got selected */

        if (    item->mode & FL_PUP_GREY
             || item->subm >= 0 )
        {
            fli_context->pup_id = -1;
            return -1;
        }

        if ( item->radio )
            reset_radio( m, item );
        else if ( item->mode & FL_PUP_CHECK )
        {
            item->mode &= ~ FL_PUP_CHECK;
            item->mode |= FL_PUP_BOX;
        }
        else if ( item->mode & FL_PUP_BOX )
            item->mode |= FL_PUP_CHECK;

        val = item->ret;
        if ( item->icb )
            val = item->icb( val );
        if ( val > 0 && m->menu_cb )
            val = m->menu_cb( val );
    }

    if ( pup_level <= 0 )
        fli_context->pup_id = -1;

    if ( pup_subreturn > 0 )
        val = pup_subreturn;

    return val;
}


/***************************************
 ***************************************/

void
fl_freepup( int n )
{
    PopUP *p = menu_rec + n;
    int i;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
        return;

    if ( ! p->used )
    {
        M_warn( "freepup", "freeing an unallocated/free'ed popup %d\n", n );
        return;
    }

    for ( i = 0; i < p->nitems; i++ )
    {
        if ( p->item[ i ] )
        {
            if ( p->item[ i ]->subm >= 0 && p->isEntry )
                fl_freepup( p->item[ i ]->subm );
            fli_safe_free( p->item[ i ]->str );
            fli_safe_free( p->item[ i ]->shortcut );
        }

        fli_safe_free( p->item[ i ] );
    }

    p->used = 0;

    if ( p->gc_active != None )
        XFreeGC( flx->display, p->gc_active );
    if ( p->gc_inactive != None )
        XFreeGC( flx->display, p->gc_inactive );

    fli_safe_free( p->title );

    close_pupwin( p );
}


/*
 * Some convenience functions
 */

/***************************************
 ***************************************/

void
fl_setpup_shortcut( int          nm,
                    int          ni,
                    const char * sc )
{
    MenuItem *item;

    if ( sc && ( item = requested_item_is_valid( "pupshortcut", nm, ni ) ) )
        convert_shortcut( sc, item->str, item, NSC );
}


/***************************************
 * 
 ***************************************/

FL_PUP_CB
fl_setpup_menucb( int       nm,
                  FL_PUP_CB cb )
{
    PopUP *m;
    FL_PUP_CB oldcb;

    if ( nm < 0 || nm >= fl_maxpup || ! menu_rec[ nm ].used )
        return NULL;

    m = menu_rec + nm;
    oldcb = m->menu_cb;
    m->menu_cb = cb;
    return oldcb;
}


/***************************************
 ***************************************/

FL_PUP_ENTERCB
fl_setpup_entercb( int              nm,
                   FL_PUP_ENTERCB   cb,
                   void           * data )
{
    FL_PUP_ENTERCB oldcb;
    PopUP *m;
    int n,
        subm;

    if ( nm < 0 || nm >= fl_maxpup || ! menu_rec[ nm ].used )
        return NULL;

    m = menu_rec + nm;
    oldcb = m->enter_cb;
    m->enter_cb = cb;
    m->enter_data = data;
    for ( n = 0; n < m->nitems; n++ )
        if ( ( subm = m->item[ n ]->subm ) >= 0 && ! menu_rec[ subm ].enter_cb )
            fl_setpup_entercb( subm, cb, data );

    return oldcb;
}


/***************************************
 ***************************************/

FL_PUP_LEAVECB
fl_setpup_leavecb( int              nm,
                   FL_PUP_LEAVECB   cb,
                   void           * data )
{
    FL_PUP_LEAVECB oldcb;
    PopUP *m;
    int n,
        subm;

    if ( nm < 0 || nm >= fl_maxpup || ! menu_rec[ nm ].used )
        return NULL;

    m = menu_rec + nm;
    oldcb = m->leave_cb;
    m->leave_cb = cb;
    m->leave_data = data;
    for ( n = 0; n < m->nitems; n++ )
        if ( ( subm = m->item[ n ]->subm ) >= 0 && ! menu_rec[ subm ].enter_cb )
            fl_setpup_leavecb( subm, cb, data );

    return oldcb;
}


/***************************************
 ***************************************/

FL_PUP_CB
fl_setpup_itemcb( int       nm,
                  int       ni,
                  FL_PUP_CB cb )
{
    MenuItem *item;
    FL_PUP_CB oldcb = NULL;

    if ( ( item = requested_item_is_valid( "fl_setpup_itemcb", nm, ni ) ) )
    {
        oldcb = item->icb;
        item->icb = cb;
    }

    return oldcb;
}


/***************************************
 ***************************************/

void
fl_setpup_title( int          nm,
                 const char * title )
{
    PopUP *m = menu_rec + nm;
    char *t,
         *b;

    if ( nm < 0 || nm >= fl_maxpup || ! menu_rec[ nm ].used || ! title )
        return;

    fli_safe_free( m->title );
    m->title = fl_strdup( title ? title : "" );
    b = t = fl_strdup( title ? title : "" );
    while ( ( b = strchr( b, '\b' ) ) )
        memmove( b, b + 1, strlen( b ) );
    m->title_width = XTextWidth( pup_title_font_struct, t, strlen( t ) );
    fl_free( t );
}


/***************************************
 ***************************************/

void
fl_setpup_title_f( int          nm,
                   const char * fmt,
                   ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_setpup_title( nm, buf );
    fl_free( buf );
}


/***************************************
 ***************************************/

Cursor
fl_setpup_cursor( int nm,
                  int cursor )
{
    PopUP *m;
    Cursor old;

    if ( nm < 0 || nm >= fl_maxpup || ! menu_rec[ nm ].used )
        return None;

    m = menu_rec + nm;
    old = m->cursor;
    m->cursor = cursor ? fli_get_cursor_byname( cursor ) : pup_defcursor;

    return old;
}


/***************************************
 ***************************************/

Cursor
fl_setpup_default_cursor( int cursor )
{
    Cursor old_defcursor = pup_defcursor;

    pup_defcursor = fli_get_cursor_byname( cursor );
    return old_defcursor;
}


/***************************************
 ***************************************/

void
fl_setpup_pad( int n,
               int padw,
               int padh )
{
    PopUP *m;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
        return;

    m = menu_rec + n;
    m->padh = padh;
    m->rpad = m->lpad = padw;
    m->cellh = pup_ascent + pup_desc + 2 * m->padh;
}


/***************************************
 ***************************************/

static void
recurse( PopUP * m,
         void    ( * set )( int, int ),
         int     val )
{
    int i;

    for ( i = 0; i < m->nitems; i++ )
        if ( m->item[ i ]->subm )
            set( m->item[ i ]->subm, val );
}


/***************************************
 ***************************************/

void
fl_setpup_shadow( int n,
                  int y  FL_UNUSED_ARG )
{
    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
        return;
}


/***************************************
 ***************************************/

void
fl_setpup_bw( int n,
              int bw )
{
    PopUP *m = menu_rec + n;
    int i;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
        return;

    m->bw = bw;
    for ( i = 0; i < m->nitems; i++ )
        if ( m->item[ i ]->subm )
            fl_setpup_bw( m->item[ i ]->subm, bw );
}


/***************************************
 ***************************************/

void
fl_setpup_softedge( int n,
                    int y )
{
    PopUP *m;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
        return;

    m = menu_rec + n;
    m->bw = y ? - FL_abs( m->bw ) : FL_abs( m->bw );
    recurse( m, fl_setpup_softedge, y );
}


/***************************************
 ***************************************/

static void
reset_radio( PopUP    * m,
             MenuItem * item )
{
    MenuItem **ii;

    for ( ii = m->item; ii < m->item + m->nitems; ii++ )
        if ( ( *ii )->radio == item->radio )
            ( *ii )->mode &= ~ FL_PUP_CHECK;
    item->mode |= FL_PUP_CHECK;
}


/***************************************
 ***************************************/

void
fl_setpup_selection( int nm,
                     int ni )
{
    MenuItem *item;

    if (    ( item = requested_item_is_valid( "fl_setpup_selection", nm, ni ) )
         && item->radio )
        reset_radio( menu_rec + nm, item );
}


/***************************************
 ***************************************/

void
fl_setpup_submenu( int m,
                   int i,
                   int subm )
{
    MenuItem *item;

    if ( ( item = requested_item_is_valid( "fl_setpup_submenu", m, i ) ) )
    {
        menu_rec[ m ].rpad = PADW + 16;
        item->subm = subm;
    }
}


/**** End of PUBLIC routines for pop-ups *******************}*/


/**** ALL drawing routines */


/***************************************
 * draw item. Index starts from 1
 ***************************************/

static void
draw_item( PopUP * m,
           int     i,
           int     style )
{
    int j = i - 1;
    int bw = FL_abs( m->bw );
    int x = bw,
        w = m->w - 2 * bw,
        y = m->titleh + m->cellh * j,
        h = m->cellh;
    char *str;
    MenuItem *item;
    GC gc;

    if ( j < 0 || j >= m->nitems )
        return;

    item = m->item[ j ];
    gc = ( item->mode & FL_PUP_GREY ) ? m->gc_inactive : m->gc_active;
    str = item->str;

    if ( ! ( item->mode & FL_PUP_GREY ) )
        fl_draw_box( style, x + 1, y, w - 2, h - 1,
                     pup_color, m->bw == -1 ? -1 : -2 );

    if ( item->mode & FL_PUP_BOX && ! ( item->mode & FL_PUP_CHECK ) )
    {
        int w = CHECKW + ( item->radio ? 0 : 2 );
        int bbw = item->radio ? -2 : -1;

        ( item->radio ? fli_draw_checkbox : fl_draw_box )
            ( FL_UP_BOX, 2 * bw + ( m->lpad - w ) / 2,
              y + ( h - CHECKW ) / 2 - 2,
              w, w, pup_color, bbw );
    }

    if ( item->mode & FL_PUP_CHECK )
    {
        int w = CHECKW + ( item->radio ? 0 : 2 );
        int bbw = item->radio ? -3 : -2;

        ( item->radio ? fli_draw_checkbox : fl_draw_box )
            ( FL_DOWN_BOX, 2 * bw + ( m->lpad - w ) / 2,
              y + ( h - CHECKW ) / 2 - 2, w, w,
              fli_depth( fl_vmode ) == 1 ? FL_BLACK : pup_checked_color, bbw );
    }

    /* show text */

    j = str[ 0 ] == '\010';
    fli_draw_stringTAB( m->win, gc,
                        m->lpad + 2 * bw, y + m->padh + pup_ascent,
                        pup_font_style, pup_font_size, str + j,
                        strlen( str ) - j, 0 );

    /* do underline */

    if ( item->ulpos >= 0 )
    {
        XRectangle *xr;

        xr = fli_get_underline_rect( pup_font_struct, m->lpad + 2 * bw,
                                     y + m->padh + pup_ascent,
                                     str, item->ulpos );
        XFillRectangle( flx->display, m->win, gc,
                        xr->x, xr->y, xr->width, xr->height );
    }

    if ( j )
        fl_draw_symbol( "@DnLine", 2 * bw, y + h - 2, m->w - 4 * bw, 1,
                        FL_COL1 );

    if ( item->subm >= 0 )
        fl_draw_symbol( (    style == FL_UP_BOX
                          && ! ( item->mode & FL_PUP_GREY ) ) ?
                        "@DnArrow" : "@UpArrow",
                        m->w - 2 * bw - 9 - m->rpad / 2,
                        y + h / 2 - 8,
                        16, 16, FL_BLACK );
}


/***************************************
 ***************************************/

static void
draw_title( Display  * d,
            Drawable   w,
            int        x,
            int        y,
            char     * s )
{
    char *t, *b;
    int n;

    if ( ! s || ! * s )
        return;
    b = t = fl_strdup( s );
    while ( ( b = strchr( b, '\b' ) ) )
        memmove( b, b + 1, strlen( b ) );

    n = strlen( t );

    fl_set_font( pup_title_font_style, pup_title_font_size );
    fli_textcolor( pup_text_color );
    XDrawString( d, w, flx->textgc, x - 1, y - 1, t, n );
    XDrawString( d, w, flx->textgc, x, y - 1, t, n );
    XDrawString( d, w, flx->textgc, x + 1, y - 1, t, n );
    XDrawString( d, w, flx->textgc, x - 1, y, t, n );
    XDrawString( d, w, flx->textgc, x + 1, y, t, n );
    XDrawString( d, w, flx->textgc, x - 1, y + 1, t, n );
    XDrawString( d, w, flx->textgc, x, y + 1, t, n );
    XDrawString( d, w, flx->textgc, x + 1, y + 1, t, n );
    fli_textcolor( FL_WHITE );
    XDrawString( d, w, flx->textgc, x, y, t, n );

    fl_free( t );
}


/***************************************
 * Instead of popping up the menu at mouse location, use externally
 * set position. Good for programmatical pop-ups
 ***************************************/

static int extpos = 0;
static FL_Coord extx = 0,
                exty = 0;
static int align_bottom = 0;


/***************************************
 ***************************************/

void
fl_setpup_position( int x,
                    int y )
{
    extpos = 1;
    extx   = x;
    exty   = y;
}


/***************************************
 ***************************************/

void
fl_setpup_align_bottom( void )
{
    align_bottom = 1;
}


/***************************************
 ***************************************/

static void
draw_popup( PopUP * m )
{
    int i;

    if ( m->title && *m->title )
        m->titleh = pup_title_ascent + pup_title_desc + PADTITLE;
    else
        m->titleh = m->padh;

    /* make the popup box  */

    fl_draw_box( FL_UP_BOX, 0, 0, m->w, m->h, pup_color, m->bw );

    /* title box */

    if ( m->title && *m->title )
    {
        fl_draw_box( FL_FRAME_BOX, 3, 3, m->w - 6, m->titleh - 6,
                     pup_color, 1 );

        draw_title( flx->display, m->win, ( m->w - m->title_width ) / 2,
                    PADTITLE / 2 + pup_title_ascent, m->title );
    }

    for ( i = 1; i <= m->nitems; i++ )
        draw_item( m, i, FL_FLAT_BOX );
}


/***************************************
 ***************************************/

void
fl_showpup( int n )
{
    PopUP *m = menu_rec + n;
    int req_y = exty;
    unsigned int dummy;

    if ( n < 0 || n >= fl_maxpup || ! menu_rec[ n ].used )
    {
        M_err( "fl_showpup", "bad pupID: %d\n", n );
        return;
    }

    /* Calculate the height of the title */

    if ( m->title )
        m->titleh = pup_title_ascent + pup_title_desc + PADTITLE;
    else
        m->titleh = m->padh;

    /* Calculate the total width and height of the popup */

    m->maxw = FL_max( m->title_width, m->maxw );
    m->w = m->maxw + m->rpad + m->lpad + 4 * FL_abs( m->bw );
    m->h =   m->nitems * m->cellh + m->titleh + 1 + ( m->padh > 1 )
           + 2 * ( FL_abs( m->bw ) > 2 );

    /* If no external coordinates are set open the popup at the mouse
       position, otherwise take care that negative coordinates specify
       the lower right hand corner of the popup */

    if ( ! extpos )
        fl_get_mouse( &m->x, &m->y, &dummy );
    else
    {
        if ( extx >= 0 )
            m->x = extx;
        else
            m->x = - extx - m->w;

        if ( exty >= 0 )
            m->y = exty;
        else
            m->y = - exty - m->h;
    }

    if ( align_bottom )
        m->y -= m->h;

    /* Try to make sure the popup is within the root window */

    if ( m->x + m->w > ( unsigned int ) fl_scrw )
        m->x = fl_scrw - m->w;
    if ( m->y + m->h > ( unsigned int ) fl_scrh )
        m->y = fl_scrh - m->h;

    /* If the root window is too small show whatever we can */

    if ( m->x < 0 )
        m->x = 0;
    if ( m->y < 0 )
        m->y = 0;

    /* Warp the mouse to the upper left hand corner of the popup unless
       external coordinates are specified */

    if ( ! extpos && ( m->x != extx || m->y != exty ) )
        XWarpPointer( flx->display, None, fl_root, 0, 0, 0, 0,
                      m->x + FL_abs( m->bw ), m->y + FL_abs( m->bw ) );

    /* Forget that an external position had been set so it won't get
       reused for another popup */

    extpos = 0;
    align_bottom = 0;

    /* If the window doesn't exist yet create it, otherwise move it to the
       requested position and, if necessary, resize it */

    if ( m->win == None)
    {
        XSetWindowAttributes xswa;
        unsigned long int vmask;

        m->event_mask =   ExposureMask
                        | ButtonPressMask
                        | ButtonReleaseMask
                        | ButtonMotionMask
                        | OwnerGrabButtonMask
                        | PointerMotionHintMask
                        | StructureNotifyMask   /* for UnmapNotify */
                        | EnterWindowMask
                        | KeyPressMask;

        xswa.event_mask            = m->event_mask;
        xswa.save_under            = True;
        xswa.backing_store         = WhenMapped;
        xswa.override_redirect     = True;
        xswa.cursor                = m->cursor;
        xswa.border_pixel          = 0;
        xswa.colormap              = fli_colormap( fl_vmode );
        xswa.do_not_propagate_mask = ButtonPress | ButtonRelease | KeyPress;

        vmask =   CWEventMask     | CWSaveUnder   | CWBackingStore
                | CWCursor        | CWBorderPixel | CWColormap
                | CWDontPropagate | CWOverrideRedirect;

        m->win = XCreateWindow( flx->display, fl_root,
                                m->x, m->y, m->w, m->h, 0,
                                fli_depth( fl_vmode ), InputOutput,
                                fli_visual( fl_vmode ), vmask, &xswa );

        XSetTransientForHint( flx->display, m->win, fl_root );
        XStoreName( flx->display, m->win, m->title );

        if ( ! m->gc_active && ! m->gc_inactive )
        {
            XGCValues xgcv;

            xgcv.foreground     = fl_get_flcolor( pup_text_color );
            xgcv.font           = pup_font_struct->fid;
            xgcv.stipple        = FLI_INACTIVE_PATTERN;
            vmask               = GCForeground | GCFont | GCStipple;

            /* GC for main text */

            m->gc_active = XCreateGC( flx->display, m->win, vmask, &xgcv );

            /* GC for inactive text */

            xgcv.foreground = fl_get_flcolor( FL_INACTIVE );
            m->gc_inactive = XCreateGC( flx->display, m->win, vmask, &xgcv );

            /* Special hack for B&W */

            if ( fli_dithered( fl_vmode ) )
                XSetFillStyle( flx->display, m->gc_inactive, FillStippled );
        }

        XSetWMColormapWindows( flx->display, fl_root, &m->win, 1 );
    }
    else
    {
        Window r;
        int ax,
            ay;
        unsigned int aw,
                     ah;

        XGetGeometry( flx->display, m->win, &r, &ax, &ay, &aw, &ah,
                      &dummy, &dummy );

        if ( m->x != ax || m->y != ay || m->w != aw || m->h != ah )
            XMoveResizeWindow( flx->display, m->win, m->x, m->y, m->w, m->h );
    }

    XMapRaised( flx->display, m->win );

    /* The function gets either called directly from a user program or via
       the fl_dopup() function. In the first case we need to draw the pupup
       and then remove all events the creation of the window produced (after
       a sync so that we can be sure all events are already on the event
       queue). */

    if ( ! pup_internal_showpup_call )
    {
        XEvent ev;

        fl_winset( m->win );
        XSync( flx->display, False );

        while ( XCheckWindowEvent( flx->display, m->win, AllEventsMask, &ev) )
            /* empty */ ;
    }
    else
    {
        m->par_y = m->padh + req_y - m->y;
        grab_both( m );
        pup_internal_showpup_call = 0;
    }

    draw_popup( m );
}


/***************************************
 ***************************************/

void
fl_hidepup( int n )
{
    if ( n >= 0 && n < fl_maxpup )
        close_pupwin( menu_rec + n );
    if ( n == fli_context->pup_id )
        fli_context->pup_id = -1;
}


/***************************************
 ***************************************/

unsigned int
fl_getpup_mode( int nm,
                int ni )
{
    MenuItem *item;

    if ( ( item = requested_item_is_valid( "fl_getpup_mode", nm, ni ) ) )
        return item->mode;

    return 0;
}


/***************************************
 ***************************************/

const char *
fl_getpup_text( int nm,
                int ni )
{
    MenuItem *item;

    if ( ( item = requested_item_is_valid( "fl_getpup_text", nm, ni ) ) )
        return item->str;

    return NULL;
}


/***************************************
 ***************************************/

void
fli_replacepup_text( int          nm,
                     int          ni,
                     const char * nt )
{
    MenuItem *item;

    if ( ! nt )
        nt = "";

    if ( ( item = requested_item_is_valid( "fli_replacepup_text", nm, ni ) ) )
    {
        fli_safe_free( item->str );
        item->str = fl_strdup( nt );
    }
}


/***************************************
 ***************************************/

int
fl_setpup_maxpup( int n )
{
    int i,
        j;

    if ( n < FL_MAXPUP )
        return FL_MAXPUP;

    fli_init_pup( );

    menu_rec = fl_realloc( menu_rec, n * sizeof *menu_rec );
    for ( i = fl_maxpup; i < n; i++ )
    {
        menu_rec[ i ].used   = 0;
        menu_rec[ i ].title  = NULL;
        menu_rec[ i ].win    = None;
        menu_rec[ i ].cursor = None;

        menu_rec[ i ].gc_active = menu_rec[ i ].gc_inactive = None;

        for ( j = 0; j <= FL_MAXPUPI; j++ )
            menu_rec[ i ].item[ j ] = NULL;

        menu_rec[ i ].menu_cb = NULL;
        menu_rec[ i ].enter_cb = menu_rec[ i ].leave_cb = NULL;
        menu_rec[ i ].enter_data = menu_rec[ i ].leave_data = NULL;
    }

    return fl_maxpup = n;
}


/***************************************
 * Build the menu using low-level pup support
 ***************************************/

static int
generate_menu( int                  n,
               const FL_PUP_ENTRY * pup,
               int                  top )
{
    static const FL_PUP_ENTRY *p = NULL;
    static PopUP *menu = NULL;
    static int val = 0;

    if ( top )
    {
        val = 1;
        menu = menu_rec + n;
        menu->isEntry = 1;
        p = pup;
    }

    if ( ! p || ! p->text )
        return n;

    for ( ; p && p->text; p++, val++ )
    {
        int cnt = 0;
        char *t,
             *w;

        /* Count number of '%' */

        for ( w = ( char * ) p->text; *w; w++ )
            if ( *w == '%' )
                cnt++;

        /* Get copy of the string with enough room for all further additions */

        w = t = fl_malloc( strlen( p->text ) + cnt + 6 + log10( INT_MAX ) );
        strcpy( t, p->text );

        /* Double all '%' */

        while ( *w && ( w = strchr( w, '%' ) ) )
        {
            memmove( w + 1, w, strlen( w ) + 1 );
            w += 2;
        }

        if ( *t != '/' )          /* regular entry */
        {
            if ( *t == '_' )
                *t = '\010';

            sprintf( t + strlen( t ), "%%x%d", val );

            fl_addtopup( n, t );

            if ( p->mode )
                fl_setpup_mode( n, val, p->mode );

            if ( p->shortcut && *p->shortcut )
                fl_setpup_shortcut( n, val, p->shortcut );

            if ( p->callback )
                fl_setpup_itemcb( n, val, p->callback );
        }
        else                      /* start of submenu */
        {
            int m = fl_newpup( menu->form ? menu->form->window : None );

            if ( t[ 1 ] == '_' )
                t[ 1 ] = '\010';

            sprintf( t + strlen( t ), "%%x%d%%m", val );

            fl_addtopup( n, t + 1, m );

            if ( p->shortcut && *p->shortcut )
                fl_setpup_shortcut( n, val, p->shortcut );

            if ( p->mode & FL_PUP_GREY )
                fl_setpup_mode( n, val, p->mode & FL_PUP_GREY );

            val++;
            generate_menu( m, ++p, 0 );
            menu_rec[ m ].isEntry = 1;
        }

        fl_free( t );
    }

    return n;
}


/***************************************
 ***************************************/

int
fl_setpup_entries( int            n,
                   FL_PUP_ENTRY * entries )
{
    return generate_menu( n, entries, 1 );
}


/***************************************
 ***************************************/

int
fl_getpup_items( int n )
{
    int m = 0;

    if ( n >= 0 && n < fl_maxpup && menu_rec[ n ].used )
    {
        int k,
            i;

        k = m = menu_rec[ n ].nitems;

        for ( i = 0; i < k; i++ )
            if ( menu_rec[ n ].item[ i ]->subm >= 0 )
                m += fl_getpup_items( menu_rec[ n ].item[ i ]->subm );
    }

    return m;
}


/***************************************
 ***************************************/

int
fl_current_pup( void )
{
    return fli_context->pup_id;
}


/***************************************
 ***************************************/

int
fl_setpup_default_bw( int bw )
{
    int ori = pup_bw;

    pup_bw = bw;
    pup_bw_is_set = 1;

    return ori;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
