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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file pixmap.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 * Pixmap support. In order to take advantage of Xpm3.4g features,
 * we need both XpmRevision and XpmLibraryVersion check
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include XPM_H_LOCATION


#if FL_DEBUG >= ML_ERR
#define CHECK( obj, f )                                                 \
    if (    ! IsValidClass( ( obj ), FL_PIXMAP )                        \
         && ! IsValidClass( ( obj ), FL_PIXMAPBUTTON ) )                \
    {                                                                   \
        M_err( f, "%s is not Pixmap/pixmapbutton class",                \
               ( ( obj ) && ( obj )->label ) ? ( obj )->label : "" );   \
        return;                                                         \
    }
#else
#define CHECK( obj, f )
#endif


typedef struct {
    XpmAttributes * xpma;
    GC              gc;
    int             align;
    int             dx,
                    dy;
    int             show_focus;
    unsigned int    focus_w,    /* these should be in button_spec */
                    focus_h;
} PixmapSPEC;

static XpmAttributes *xpmattrib;


/***************************************
 * Part of pixmap cleanup
 ***************************************/

static void
cleanup_xpma_struct( XpmAttributes * xpma )
{
    /* Only versions >= 3.4g have alloc_pixels. We always compile with 3.4g
       but have to re-act to dynamic libraries, which may be older */

    if ( ! xpma || ! xpma->colormap )
        return;

    /* do we use at least libXpm 3.4g? */

#if XpmFormat >= 3 && XpmVersion >= 4 && XpmRevision >= 7
    M_warn( "cleanup_xpma_struct", "Using 3.4g features" );
    XFreeColors( flx->display, xpma->colormap,
                 xpma->alloc_pixels, xpma->nalloc_pixels, 0 );
#else
    /* somewhat dangerous */

    M_warn( "cleanup_xpma_struct", "Using old xpm libs" );
    XFreeColors( flx->display, xpma->colormap,
                 xpma->pixels, xpma->npixels, 0 );
#endif

    xpma->colormap = None;

    XpmFreeAttributes( xpma );
    fl_free( xpma );
}


/***************************************
 * Free pixmaps associated with an object
 ***************************************/

static void
free_pixmap( FL_BUTTON_STRUCT * sp )
{
    PixmapSPEC *psp = sp->cspecv;

    fl_free_pixmap( sp->pixmap );
    fl_free_pixmap( sp->mask );
    cleanup_xpma_struct( psp->xpma );

    psp->xpma  = NULL;
    sp->pixmap = None;
    sp->mask   = None;
}


/***************************************
 ***************************************/

static void
free_focuspixmap( FL_BUTTON_STRUCT * sp )
{
    fl_free_pixmap( sp->focus_pixmap );
    fl_free_pixmap( sp->focus_mask );

    sp->focus_pixmap = None;
    sp->focus_mask   = None;
}


/***************************************
 * Change pixmap/mask. del==true means we want to destroy old pixmaps
 ***************************************/

static void
change_pixmap( FL_BUTTON_STRUCT * sp,
               Window             win,
               Pixmap             p,
               Pixmap             shape_mask,
               int                del )
{
    PixmapSPEC *psp = sp->cspecv;

    if ( p == None || win == None )
        return;

    if ( del )
        free_pixmap( sp );
    else
    {
        cleanup_xpma_struct( psp->xpma );
        psp->xpma = NULL;
    }

    sp->pixmap = p;
    sp->mask = shape_mask;

    M_warn( "change_pixmap", "Pixmap = %ld mask = %ld win = %ld",
            p, shape_mask, win );

    if ( psp->gc == None )
    {
        psp->gc = XCreateGC( flx->display, win, 0, NULL );
        XSetGraphicsExposures( flx->display, psp->gc, False );
    }

    XSetClipMask( flx->display, psp->gc, sp->mask );
}


/***************************************
 * Change pixmap/mask. If 'del' is set destroy teh old pixmaps
 ***************************************/

static void
change_focuspixmap( FL_BUTTON_STRUCT * sp,
                    Window             win  FL_UNUSED_ARG,
                    Pixmap             p,
                    Pixmap             shape_mask,
                    int                del )
{
    if ( del )
        free_focuspixmap( sp );

    sp->focus_pixmap = p;
    sp->focus_mask   = shape_mask;
}


/***************************************
 ***************************************/

static void
show_pixmap( FL_OBJECT * obj,
             int         focus )
{
    FL_BUTTON_STRUCT *sp = obj->spec;
    PixmapSPEC *psp = sp->cspecv;
    int dest_x,
        dest_y,
        dest_w,
        dest_h,
        src_x,
        src_y,
        m_dest_x,
        m_dest_y;
    FL_Coord clip_x,
             clip_y,
             clip_w,
             clip_h;
    Pixmap pixmap,
           mask;
    int bits_w,
        bits_h,
        is_focus = focus && sp->focus_pixmap && psp->show_focus;
    int bw = FL_abs( obj->bw );

    pixmap = is_focus ? sp->focus_pixmap : sp->pixmap;
    mask   = is_focus ? sp->focus_mask   : sp->mask;
    bits_w = is_focus ? psp->focus_w     : sp->bits_w;
    bits_h = is_focus ? psp->focus_h     : sp->bits_h;

    /* Do nothing if pixmap does not exist or has zero size */

    if ( pixmap == None || bits_w == 0 || bits_h == 0 )
    {
        fl_draw_text( FL_ALIGN_CENTER, obj->x, obj->y, obj->w, obj->h,
                      obj->lcol, obj->lstyle, FL_TINY_SIZE, "p" );
        return;
    }

    m_dest_x = dest_x = obj->x + bw + psp->dx;
    m_dest_y = dest_y = obj->y + bw + psp->dy;
    dest_w = obj->w - 2 * bw - 2 * psp->dx;
    dest_h = obj->h - 2 * bw - 2 * psp->dy;

    src_x = 0;
    src_y = 0;

    if ( dest_w > bits_w )
    {
        if ( ! ( psp->align & ( FL_ALIGN_LEFT | FL_ALIGN_RIGHT ) ) )
            m_dest_x = dest_x += ( dest_w - bits_w ) / 2;
        else if ( psp->align & FL_ALIGN_RIGHT )
            m_dest_x = dest_x += dest_w - bits_w;
        dest_w = bits_w;
    }
    else
    {
        if ( ! ( psp->align & ( FL_ALIGN_LEFT | FL_ALIGN_RIGHT ) ) )
            src_x = ( bits_w - dest_w ) / 2;
        else if ( psp->align & FL_ALIGN_RIGHT )
            src_x = bits_w - dest_w;
        m_dest_x -= src_x;
    }

    if ( dest_h > bits_h )
    {
        if ( ! ( psp->align & ( FL_ALIGN_TOP | FL_ALIGN_BOTTOM ) ) )
            m_dest_y = dest_y += ( dest_h - bits_h ) / 2;
        else if ( psp->align & FL_ALIGN_BOTTOM )
            m_dest_y = dest_y += dest_h - bits_h;
        dest_h = bits_h;
    }
    else
    {
        if ( ! ( psp->align & ( FL_ALIGN_TOP | FL_ALIGN_BOTTOM ) ) )
            src_y = ( bits_h - dest_h ) / 2;
        else if ( psp->align & FL_ALIGN_BOTTOM )
            src_y = bits_h - dest_h;
        m_dest_y -= src_y;
    }

    /* Get the currently set clipping */

    if ( fl_get_clipping( 1, &clip_x, &clip_y, &clip_w, &clip_h ) )
    {
        if ( clip_w <= 0 || clip_h <= 0 )
            return;

        /* If the pixmap is not within the clipping region nothing is
           to be drawn */

        if (    dest_x + dest_w < clip_x
             || dest_x > clip_x + clip_w
             || dest_y + dest_h < clip_y
             || dest_y > clip_y + clip_h )
            return;

        /* If the pixmap isn't completely within the clipping region
           recalculate what to draw */

        if (    dest_x <= clip_x
             || dest_x + dest_w >= clip_x + clip_w
             || dest_y <= clip_y
             || dest_y + dest_h >= clip_y + clip_h )
        {
            if ( dest_x < clip_x )
            {
                src_x  += clip_x - dest_x;
                dest_w -= clip_x - dest_x;
                dest_x = clip_x;
            }

            if ( dest_x + dest_w > clip_x + clip_w )
                dest_w = clip_x + clip_w - dest_x;

            if ( dest_y < clip_y )
            {
                src_y  += clip_y - dest_y;
                dest_h -= clip_y - dest_y;
                dest_y = clip_y;
            }

            if ( dest_y + dest_h > clip_y + clip_h )
                dest_h = clip_y + clip_h - dest_y;
        }
    }

    /* Hopefully, XSetClipMask is smart */

    XSetClipMask( flx->display, psp->gc, mask );
    XSetClipOrigin( flx->display, psp->gc, m_dest_x, m_dest_y );

    XCopyArea( flx->display, pixmap, FL_ObjWin( obj ),
               psp->gc, src_x, src_y, dest_w, dest_h, dest_x, dest_y );
}


static int red_closeness   = 40000;
static int green_closeness = 30000;
static int blue_closeness  = 50000;


/***************************************
 * Basic attributes
 ***************************************/

static void
init_xpm_attributes( Window          win,
                     XpmAttributes * xpma,
                     FL_COLOR        tran )
{
    XWindowAttributes xwa;

    XGetWindowAttributes( flx->display, win, &xwa );
    xpma->valuemask = XpmVisual | XpmDepth | XpmColormap;
    xpma->depth = xwa.depth;
    xpma->visual = xwa.visual;
    xpma->colormap = xwa.colormap;

    xpma->valuemask |= XpmRGBCloseness;
    xpma->red_closeness = red_closeness;
    xpma->green_closeness = green_closeness;
    xpma->blue_closeness = blue_closeness;

#if XpmRevision >= 7
    xpma->valuemask |= XpmReturnPixels | XpmReturnAllocPixels;
#else
    xpma->valuemask |= XpmReturnPixels;
#endif

    {
        static XpmColorSymbol xpcm[ 2 ];

        xpcm[ 0 ].name  = "None";
        xpcm[ 0 ].value = 0;
        xpcm[ 0 ].pixel = fl_get_flcolor( tran );
        xpcm[ 1 ].name  = "opaque";
        xpcm[ 1 ].value = 0;
        xpcm[ 1 ].pixel = fl_get_flcolor( FL_BLACK );

        xpma->valuemask   |= XpmColorSymbols;
        xpma->colorsymbols = xpcm;
        xpma->numsymbols   = 2;
    }
}


/**********************************************************************
 * Static PIXMAP
 ******************************************************************{**/


static void
draw_pixmap( FL_OBJECT * obj )
{
    /* Draw the box */

    fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h,
                 obj->col2, obj->bw );
    show_pixmap( obj, 0 );
}


/***************************************
 ***************************************/

static int
handle_pixmap( FL_OBJECT * obj,
               int         event,
               FL_Coord    mx   FL_UNUSED_ARG,
               FL_Coord    my   FL_UNUSED_ARG,
               int         key  FL_UNUSED_ARG,
               void      * ev   FL_UNUSED_ARG )
{
    FL_BUTTON_STRUCT *sp = obj->spec;

#if FL_DEBUG >= ML_DEBUG
    M_info( "handle_pixmap", fli_event_name( event ) );
#endif

    switch ( event )
    {
        case FL_DRAW:
            draw_pixmap( obj );
            /* fall through */

        case FL_DRAWLABEL:
            fl_draw_object_label( obj );
            break;

        case FL_FREEMEM:
            free_pixmap( obj->spec );
            if ( ( ( PixmapSPEC * ) sp->cspecv )->gc )
                XFreeGC( flx->display, ( ( PixmapSPEC * ) sp->cspecv )->gc );
            fli_safe_free( sp->cspecv );
            fli_safe_free( obj->spec );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * Creates a pixmap object
 ***************************************/

FL_OBJECT *
fl_create_pixmap( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    FL_OBJECT *obj;
    FL_BUTTON_STRUCT *sp;
    PixmapSPEC *psp;

    obj = fl_make_object( FL_PIXMAP, type, x, y, w, h, label, handle_pixmap );

    obj->boxtype = FL_BITMAP_BOXTYPE;
    obj->col1    = FL_BITMAP_COL1;
    obj->col2    = FL_BITMAP_COL2;
    obj->lcol    = FL_BITMAP_LCOL;
    obj->align   = FL_BITMAP_ALIGN;
    obj->active  = type != FL_NORMAL_BITMAP;
    obj->spec    = sp = fl_calloc( 1, sizeof *sp );

    sp->bits_w = 0;
    sp->cspecv = psp = fl_calloc( 1, sizeof *psp );

    psp->dx    = psp->dy = 0;
    psp->align = FL_ALIGN_CENTER;

    return obj;
}


/***************************************
 * Adds a pixmap object
 ***************************************/

FL_OBJECT *
fl_add_pixmap( int          type,
               FL_Coord      x,
               FL_Coord      y,
               FL_Coord      w,
               FL_Coord      h,
               const char * label )
{
    FL_OBJECT *obj = fl_create_pixmap( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 ***************************************/

Pixmap
fl_create_from_pixmapdata( Window          win,
                           char         ** data,
                           unsigned int  * w,
                           unsigned int  * h,
                           Pixmap        * sm,
                           int           * hotx,
                           int           * hoty,
                           FL_COLOR        tran )
{
    Pixmap p = None;
    int s;

    /* This ensures we do not depend on the header/dl having the same size */

    xpmattrib = fl_calloc( 1, XpmAttributesSize( ) );
    init_xpm_attributes( win, xpmattrib, tran );

    s = XpmCreatePixmapFromData( flx->display, win, data, &p, sm, xpmattrib );

    if ( s != XpmSuccess )
    {
        errno = 0;
        M_err( "fl_create_from_pixmapdata", "error converting: %s",
               ( s == XpmOpenFailed ? "(Can't open)" :
                 ( s == XpmFileInvalid ? "(Invalid file)" :
                   ( s == XpmColorFailed ? "(Can't get color)" : "" ) ) ) );

        if ( s < 0 )
        {
            fl_free( xpmattrib );
            return None;
        }
    }

    if ( p != None )
    {
        *w = xpmattrib->width;
        *h = xpmattrib->height;
        if ( hotx )
            *hotx = xpmattrib->x_hotspot;
        if ( hoty )
            *hoty = xpmattrib->y_hotspot;
    }
    else
        fl_free( xpmattrib );

    return p;
}


/***************************************
 ***************************************/

void
fl_set_pixmap_pixmap( FL_OBJECT * obj,
                      Pixmap      id,
                      Pixmap      mask )
{
    FL_BUTTON_STRUCT *sp;
    FL_Coord w = 0,
             h = 0;

    CHECK( obj, "fl_set_pixmap_pixmap" );

    sp = obj->spec;
    change_pixmap( sp, FL_ObjWin( obj ), id, mask, 0 ); /* 0 don't free old */

    if ( sp->pixmap != None )
        fl_get_winsize( sp->pixmap, &w, &h );

    sp->bits_w = w;
    sp->bits_h = h;

    fl_redraw_object( obj );
}


/***************************************
 ***************************************/

Pixmap
fl_get_pixmap_pixmap( FL_OBJECT * obj,
                      Pixmap    * p,
                      Pixmap    * m )
{
    FL_BUTTON_STRUCT *sp;

    if (    ! IsValidClass( obj, FL_PIXMAP )
         && ! IsValidClass( obj, FL_PIXMAPBUTTON ) )
    {
        M_err( "fl_get_pixmap_pixmap", "%s is not Pixmap/pixmapbutton class",
               ( obj && obj->label ) ? obj->label : "" );
        return None;
    }

    sp = obj->spec;

    /* pixmapbutton and pixmap use the same structure */

    *p = sp->pixmap;
    if ( m )
        *m = sp->mask;

    return sp->pixmap;
}


/***************************************
 * Generic routine to read a pixmap file.
 ***************************************/

Pixmap
fl_read_pixmapfile( Window         win,
                    const char   * file,
                    unsigned int * w,
                    unsigned int * h,
                    Pixmap       * shape_mask,
                    int          * hotx,
                    int          * hoty,
                    FL_COLOR       tran )
{
    Pixmap p = None;
    int s;

    xpmattrib = fl_calloc( 1, XpmAttributesSize( ) );
    init_xpm_attributes( win, xpmattrib, tran );

    s = XpmReadFileToPixmap( flx->display, win, ( char * ) file,
                             &p, shape_mask, xpmattrib );

    if ( s != XpmSuccess )
    {
        errno = 0;
        M_err( "fl_read_pixmapfile", "error reading %s %s", file,
               ( s == XpmOpenFailed ? "(Can't open)" :
                 ( s == XpmFileInvalid ? "(Invalid file)" :
                   ( s == XpmColorFailed ? "(Can't get color)" : "" ) ) ) );

        if ( s < 0 )
        {
            fl_free( xpmattrib );
            return None;
        }
    }

    if ( p != None )
    {
        *w = xpmattrib->width;
        *h = xpmattrib->height;

        if ( hotx )
            *hotx = xpmattrib->x_hotspot;
        if ( hoty )
            *hoty = xpmattrib->y_hotspot;
    }
    else
        fl_free( xpmattrib );

    return p;
}


/***************************************
 ***************************************/

void
fl_set_pixmap_file( FL_OBJECT  * obj,
                    const char * fname )
{
    Pixmap p = None,
           shape_mask = None;
    FL_BUTTON_STRUCT *sp;
    int hotx, hoty;
    Window win;

    if ( ! flx || ! flx->display )
        return;

    CHECK( obj, "fl_set_pixmap_file" );

    sp = obj->spec;
    win = FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_default_win( );
    p = fl_read_pixmapfile( win, fname, &sp->bits_w, &sp->bits_h,
                            &shape_mask, &hotx, &hoty, obj->col1 );

    if ( p != None )
    {
        change_pixmap( sp, win, p, shape_mask, 0 );
        ( ( PixmapSPEC * ) sp->cspecv )->xpma = xpmattrib;
        fl_redraw_object( obj );
    }
}


/******** End of static pixmap ************************}*/


/*****************************************************************
 * Pixmap button
 ***********************************************************{****/

#define IsFlat( t ) (    ( t ) == FL_FLAT_BOX       \
                      || ( t ) == FL_FRAME_BOX      \
                      || ( t ) == FL_BORDER_BOX )


/***************************************
 ***************************************/

static void
draw_pixmapbutton( FL_OBJECT * obj )
{
    FL_BUTTON_STRUCT *sp = obj->spec;
    PixmapSPEC *psp = sp->cspecv;

    /* Draw it like a "normal button */

    fli_draw_button( obj );

    /* Add the pixmap on top of it */

    switch ( sp->event )
    {
        case FL_ENTER:
            if ( psp->show_focus )
                show_pixmap( obj, 1 );
            else
                show_pixmap( obj, 0 );
            break;

        case FL_LEAVE:
            show_pixmap( obj, 0 );
            break;

        default:
            show_pixmap( obj, obj->belowmouse && psp->show_focus );
            break;
    }

    fl_draw_object_label( obj );
}


/***************************************
 * button driver will clean up spec after this function returns
 ***************************************/

static void
cleanup_pixmapbutton( FL_BUTTON_STRUCT *sp )
{
    PixmapSPEC *psp = sp->cspecv;

    if ( psp->gc )
    {
        XFreeGC( flx->display, psp->gc );
        psp->gc = None;
    }

    if ( psp->xpma )
    {
        cleanup_xpma_struct( psp->xpma );
        psp->xpma = NULL;
    }

    if ( sp->cspecv )
    {
        fl_free( sp->cspecv );
        sp->cspecv = NULL;
    }
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_pixmapbutton( int          type,
                        FL_Coord     x,
                        FL_Coord     y,
                        FL_Coord     w,
                        FL_Coord     h,
                        const char * label )
{
    FL_OBJECT *obj;
    static int class_init;
    FL_BUTTON_STRUCT *sp;
    PixmapSPEC *psp;

    if ( ! class_init )
    {
        fl_add_button_class( FL_PIXMAPBUTTON,
                             draw_pixmapbutton, cleanup_pixmapbutton );
        class_init = 1;
    }

    obj = fl_create_generic_button( FL_PIXMAPBUTTON, type, x, y, w, h, label );

    obj->boxtype = FL_PIXMAPBUTTON_BOXTYPE;
    obj->col1    = FL_PIXMAPBUTTON_COL1;
    obj->col2    = FL_PIXMAPBUTTON_COL2;
    obj->align   = FL_PIXMAPBUTTON_ALIGN;
    obj->lcol    = FL_PIXMAPBUTTON_LCOL;

    sp = obj->spec;   /* allocated in fl_create_generic_button() */

    sp->cspecv = psp = fl_calloc( 1, sizeof *psp );

    psp->show_focus = 1;
    psp->align      = FL_ALIGN_CENTER;
    psp->dx         = psp->dy = 3;

    return obj;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_pixmapbutton( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * label )
{
    FL_OBJECT *obj;

    obj = fl_create_pixmapbutton( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 ***************************************/

void
fl_set_pixmap_data( FL_OBJECT   * obj,
                    char       ** bits )
{
    FL_BUTTON_STRUCT *sp;
    Window win;
    Pixmap p,
           shape_mask = None;
    int hx, hy;

    CHECK( obj, "fl_set_pixmap_data" );

    if ( ! flx->display )
        return;

    sp = obj->spec;
    win = FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_default_win( );
    p = fl_create_from_pixmapdata( win, bits, &sp->bits_w, &sp->bits_h,
                                   &shape_mask, &hx, &hy, obj->col1 );

    if ( p != None )
    {
        change_pixmap( sp, win, p, shape_mask, 0 );
        ( ( PixmapSPEC * ) sp->cspecv )->xpma = xpmattrib;
        fl_redraw_object( obj );
    }

}


/***************************************
 ***************************************/

void
fl_set_pixmap_colorcloseness( int red,
                              int green,
                              int blue )
{
    red_closeness   = red;
    green_closeness = green;
    blue_closeness  = blue;
}


/****************** End of pixmap stuff ************}**/


/***************************************
 ***************************************/

void
fl_set_pixmap_align( FL_OBJECT * obj,
                     int         align,
                     int         xmargin,
                     int         ymargin )
{
    FL_BUTTON_STRUCT *sp;
    PixmapSPEC *psp;

    CHECK( obj, "fl_set_pixmap_align" );

    sp = obj->spec;
    psp = sp->cspecv;
    if ( align != psp->align || xmargin != psp->dx || ymargin != psp->dy )
    {
        psp->align = align;
        psp->dx = xmargin;
        psp->dy = ymargin;
        fl_redraw_object( obj );
    }
}


/***************************************
 ***************************************/

void
fl_set_pixmapbutton_focus_pixmap( FL_OBJECT * obj,
                                  Pixmap      id,
                                  Pixmap      mask )
{
    FL_BUTTON_STRUCT *sp = obj->spec;
    PixmapSPEC *psp = sp->cspecv;
    int w,
        h;

    CHECK( obj, "fl_set_pixmapbutton_focus_pixmap" );

    change_focuspixmap( sp, FL_ObjWin( obj ), id, mask, 0 );
    if ( sp->focus_pixmap != None )
    {
        fl_get_winsize( sp->focus_pixmap, &w, &h );
        psp->focus_w = w;
        psp->focus_h = h;
    }
}


/***************************************
 ***************************************/

void
fl_set_pixmapbutton_focus_data( FL_OBJECT  * obj,
                                char      ** bits )
{
    FL_BUTTON_STRUCT *sp;
    PixmapSPEC *psp;
    Window win;
    Pixmap p,
           shape_mask = None;
    int hx,
        hy;

    CHECK( obj, "fl_set_pixmapbutton_focus_data" );

    if ( ! flx->display )
        return;

    sp = obj->spec;
    psp = sp->cspecv;
    win = FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_default_win( );
    p = fl_create_from_pixmapdata( win, bits, &psp->focus_w, &psp->focus_h,
                                   &shape_mask, &hx, &hy, obj->col1 );

    if ( p != None )
    {
        change_focuspixmap( sp, win, p, shape_mask, 0 );
        ( ( PixmapSPEC * ) sp->cspecv )->xpma = xpmattrib;
    }
}


/***************************************
 ***************************************/

void
fl_set_pixmapbutton_focus_file( FL_OBJECT  * obj,
                                const char * fname )
{
    Pixmap p,
           shape_mask = None;
    FL_BUTTON_STRUCT *sp;
    int hotx,
        hoty;
    Window win;
    PixmapSPEC *psp;

    if ( ! flx->display )
        return;

    sp = obj->spec;
    psp = sp->cspecv;
    win = FL_ObjWin( obj ) ? FL_ObjWin( obj ) : fl_default_win( );
    p = fl_read_pixmapfile( win, fname, &psp->focus_w, &psp->focus_h,
                            &shape_mask, &hotx, &hoty, obj->col1 );

    if ( p != None )
    {
        change_focuspixmap( sp, win, p, shape_mask, 0 );
        fl_free( xpmattrib );
    }
}


/***************************************
 ***************************************/

void
fl_set_pixmapbutton_focus_outline( FL_OBJECT * obj,
                                   int         yes_no )
{
    FL_BUTTON_STRUCT *sp;
    PixmapSPEC *psp;

    CHECK( obj, "fl_set_pixmapbutton_focus_outline" );

    sp = obj->spec;
    psp = sp->cspecv;
    psp->show_focus = yes_no;
}


/***************************************
 ***************************************/

void
fl_free_pixmap_pixmap( FL_OBJECT * obj )
{
    CHECK( obj, "fl_free_pixmap_pixmap" );

    free_pixmap( obj->spec );
}


/***************************************
 ***************************************/

void
fl_free_pixmap_focus_pixmap( FL_OBJECT * obj )
{
    CHECK( obj, "fl_free_pixmap_focus_pixmap" );

    free_focuspixmap( obj->spec );
}


/***************************************
 * This can't go into forms.c as it will pull xpm into
 * programs that don't need it
 ***************************************/

void
fli_set_form_icon_data( FL_FORM  * form,
                        char    ** data )
{
    Pixmap p,
           s = None;
    unsigned int j;

    p = fl_create_from_pixmapdata( fl_root, data, &j, &j, &s, NULL, NULL, 0 );

    if ( p != None )
    {
        fl_set_form_icon( form, p, s );
        fl_free( xpmattrib );
    }
}


/***************************************
 ***************************************/

void
fl_free_pixmap( Pixmap id )
{
    if ( id != None )
        XFreePixmap( fl_display, id );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
