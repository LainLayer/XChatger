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
 * \file xsupport.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Form initialization and Windowing support.
 *
 *  Further isolation of dependencies of FORMS on underlining window
 *  systems.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


static int xerror_detected = 0;


/***************************************
 * For debugging only
 ***************************************/

void
fli_check_key_focus( const char * s,
                     Window       win )
{
    int r;
    Window w;

    if ( fli_cntl.debug > 1 )
    {
        XGetInputFocus( flx->display, &w, &r );
        M_info( "fli_check_key_focus", "%s:%s FWin = %lu ReqW = %lu",
                s ? s : "", w == win ? "OK" : "Wrong", w, win );
    }
}


/*****************************************************************
 * Pointer query routines
 ***********************************************************{*****/

/***************************************
 * Return the window ID mouse currently is in and sets the mouse location
 * relative to root
 ***************************************/

Window
fl_get_mouse( FL_Coord     * x,
              FL_Coord     * y,
              unsigned int * keymask )
{
    Window rjunk,
           childwin;
    int cx,
        cy,
        xx,
        yy;

    XQueryPointer( flx->display, fl_root, &rjunk, &childwin,
                   &xx, &yy, &cx, &cy, keymask );
    *x = xx;
    *y = yy;

    return childwin;
}


/***************************************
 * Find the mouse position relative to win and return the child win
 * the mouse is currently in
 ***************************************/

Window
fl_get_win_mouse( Window         win,
                  FL_Coord     * x,
                  FL_Coord     * y,
                  unsigned int * keymask )
{
    Window rjunk,
           childwin;
    int dummy,
        ix,
        iy;

    XQueryPointer( flx->display, win, &rjunk, &childwin,
                   &dummy, &dummy, &ix, &iy, keymask );

    *x = ix;
    *y = iy;

    return childwin;
}


/***************************************
 ***************************************/

Window
fl_get_form_mouse( FL_FORM      * form,
                   FL_Coord     * x,
                   FL_Coord     * y,
                   unsigned int * keymask )
{
    Window win = None;

    if ( fli_get_visible_forms_index( form ) >= 0 )
    {
        FL_pixmap *flp = form->flpixmap;

        win = ( flp && flp->win != None ) ? flp->win : form->window;
        fl_get_win_mouse( win, x, y, keymask );
    }

    return win;
}


/***************************************
 * warp mouse to (mx, my) relative to root window
 ***************************************/

void
fl_set_mouse( FL_Coord mx,
              FL_Coord my )
{
    XWarpPointer( flx->display, None, fl_root, 0, 0, 0, 0, mx, my );
}


/*** End of pointer query routines ******************/


Pixmap fli_gray_pattern[ 3 ] = { None, None, None };
GC fli_bwgc[ 3 ];
GC fli_whitegc;
GC fl_drawgc[ 18 ];


static unsigned char gray40_bits[] =
{
    0xee, 0xbb, 0xee, 0xbb, 0xee, 0xbb, 0xee, 0xbb
};

static unsigned char gray50_bits[] =
{
    0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55
};

static unsigned char gray60_bits[] =
{
    0x11, 0x44, 0x11, 0x44, 0x11, 0x44, 0x11, 0x44
};


/***************************************
 ***************************************/

void
fli_init_stipples( void )
{
    if ( ! fli_gray_pattern[ 0 ] )
    {
        fli_gray_pattern[ 0 ] =
            XCreateBitmapFromData( flx->display, fl_root,
                                   ( char * ) gray40_bits, 8, 8 );
        fli_gray_pattern[ 1 ] =
            XCreateBitmapFromData( flx->display, fl_root,
                                   ( char * ) gray50_bits, 8, 8 );
        fli_gray_pattern[ 2 ] =
            XCreateBitmapFromData( flx->display, fl_root,
                                   ( char * ) gray60_bits, 8, 8 );
    }
}


/***************************************
 * Must NOT allow object pixmap and form pixmap active at the
 * same time
 ***************************************/

static void
change_object_drawable( FL_pixmap * p,
                        FL_OBJECT * obj )
{
    p->x = obj->x;
    p->y = obj->y;
    p->win = FL_ObjWin( obj );
    obj->form->window = p->pixmap;
    obj->x = 0;
    obj->y = 0;
    fl_winset( p->pixmap );
}


/***************************************
 ***************************************/

static void
change_form_drawable( FL_pixmap * p,
                      FL_FORM   * form )
{
    p->x = form->x;
    p->y = form->y;
    p->win = form->window;
    form->window = p->pixmap;
    form->x = 0;
    form->y = 0;
    fl_winset( p->pixmap );
}


/***************************************
 ***************************************/

static int
xerror_handler( Display     * d  FL_UNUSED_ARG,
                XErrorEvent * xev )
{
    if ( xev->error_code == BadAlloc )
        M_err( "xerror_handler", "XError: can't allocate - ignored " );
    else
        M_err( "xerror_handler", "XError: %d", xev->error_code );

    xerror_detected = 1;
    return 0;
}


/* non-square box can't be double buffered */

#define NON_SQB( a )  ( ( a )->boxtype == FL_NO_BOX )

/* Pixmap support   */


/***************************************
 ***************************************/

void
fli_create_object_pixmap( FL_OBJECT * obj )
{
    FL_pixmap *p = obj->flpixmap;
    int ( * oldhandler )( Display *, XErrorEvent * );

    /* Check to see if we need to create a pixmap. Don't do it for none-square
       boxes as it is not easy to figure out the object color beneath the
       object we are trying to paint. It also makes no sense to draw to
       a pixmap for the object if we're already been directed to draw to a
       pixmap for the form itself. */

    if (    ! obj->use_pixmap
         || ( obj->form->flpixmap && obj->form->flpixmap->win )
         || obj->w <= 0
         || obj->h <= 0
         || NON_SQB( obj ) )
        return;

    /* If we already got a pixmap that fits the objects properties just
       switch to it */

    if (    p
         && p->pixmap
         && p->w == obj->w
         && p->h == obj->h
         && p->depth == fli_depth( fl_vmode )
         && p->visual == fli_visual( fl_vmode )
         && p->dbl_background == obj->dbl_background
         && p->pixel == fl_get_pixel( obj->dbl_background ) )
    {
        change_object_drawable( p, obj );
        fl_rectf( 0, 0, obj->w, obj->h, obj->dbl_background );
        return;
    }

    if ( ! p )
        p = obj->flpixmap = fl_calloc( 1, sizeof *p );
    else if ( p->pixmap )
        XFreePixmap( flx->display, p->pixmap );

    oldhandler = XSetErrorHandler( xerror_handler );

    p->pixmap = XCreatePixmap( flx->display, FL_ObjWin( obj ), obj->w, obj->h,
                               fli_depth( fl_vmode ) );

    XSetErrorHandler( oldhandler );

    /* Test if creating the pixmap succeeded or we can't use one */

    if ( xerror_detected )
    {
        xerror_detected = 0;
        p->pixmap = None;
        return;
    }

    p->w = obj->w;
    p->h = obj->h;
    p->depth = fli_depth( fl_vmode );
    p->visual = fli_visual( fl_vmode );
    p->dbl_background = obj->dbl_background;
    p->pixel = fl_get_pixel( obj->dbl_background );
    change_object_drawable( p, obj );
    fl_rectf( 0, 0, obj->w, obj->h, obj->dbl_background );
}


/***************************************
 ***************************************/

void
fli_show_object_pixmap( FL_OBJECT * obj )
{
    FL_pixmap *p = obj->flpixmap;

    if (    ! p
         || ! p->pixmap
         || ! p->win
         || NON_SQB( obj ) )
        return;

    XCopyArea( flx->display, p->pixmap, p->win, flx->gc,
               0, 0, p->w, p->h, p->x, p->y );

    obj->x = p->x;
    obj->y = p->y;
    obj->form->window = p->win;
    p->win = None;
    fl_winset( obj->form->window );
}


/***************************************
 ***************************************/

void
fli_free_flpixmap( FL_pixmap * p )
{
    if ( p && p->pixmap )
    {
        XFreePixmap( flx->display, p->pixmap );
        p->pixmap = None;
    }
}


/***************************************
 ***************************************/

static int
form_pixmapable( FL_FORM * form )
{
    /* Check to see if we can use a pixmap. None-square boxes can't be used
       as it is not easy to figure out the object color beneath the form we're
       trying to paint. Take care, sometimes a form can have a fake NO_BOX as
       the first object */

    return    form->use_pixmap
           && (    form->first
                && (    ! NON_SQB( form->first )
                     || (    form->first->next
                          && ! NON_SQB( form->first->next ) ) ) );
}


/***************************************
 ***************************************/

void
fli_create_form_pixmap( FL_FORM * form )
{
    FL_pixmap *p = form->flpixmap;
    int ( * oldhandler )( Display *, XErrorEvent * );

    if ( form->w <= 0 || form->h <= 0 || ! form_pixmapable( form ) )
        return;

    if (    p
         && p->pixmap
         && p->w == form->w
         && p->h == form->h
         && p->depth == fli_depth( fl_vmode )
         && p->visual == fli_visual( fl_vmode ) )
    {
        change_form_drawable( p, form );
        return;
    }

    if ( ! p )
        p = form->flpixmap = fl_calloc( 1, sizeof *p );
    else if ( p->pixmap )
        XFreePixmap( flx->display, p->pixmap );

    oldhandler = XSetErrorHandler( xerror_handler );

    p->pixmap = XCreatePixmap( flx->display, form->window,
                               form->w, form->h,
                               fli_depth( fl_vmode ) );

    XSetErrorHandler( oldhandler );

    /* Test if creating a pixmap worked, otherwise we can't use one */

    if ( xerror_detected )
    {
        xerror_detected = 0;
        p->pixmap = None;
        return;
    }

    XSetErrorHandler( oldhandler );

    p->w = form->w;
    p->h = form->h;
    p->depth = fli_depth( fl_vmode );
    p->visual = fli_visual( fl_vmode );
    change_form_drawable( p, form );
}


/***************************************
 ***************************************/

void
fli_show_form_pixmap( FL_FORM * form )
{
    FL_pixmap *p = form->flpixmap;

    if (    ! form_pixmapable( form )
         || ! p
         || ! p->pixmap
         || ! p->win
         || p->w <= 0
         || p->h <= 0 )
        return;

    XCopyArea( flx->display, p->pixmap, p->win, flx->gc,
               0, 0, p->w, p->h, 0, 0 );

    form->x = p->x;
    form->y = p->y;
    form->window = p->win;
    p->win = None;
    fl_winset( form->window );
}


/********  VisualClass name **************/

#define VN( a )   { a, #a }

static FLI_VN_PAIR xvclass[ ] =
{
    VN( PseudoColor ),
    VN( TrueColor ),
    VN( DirectColor ),
    VN( StaticColor ),
    VN( GrayScale ),
    VN( GreyScale ),
    VN( StaticGray ),
    VN( StaticGrey ),
    { FL_DefaultVisual, "DefaultVisual" },
    { -1,               NULL            }
};


/***************************************
 ***************************************/

const char *
fli_vclass_name( int n )
{
    FLI_VN_PAIR *xc = xvclass;

    for ( ; xc->name; xc++ )
        if ( n == xc->val )
            return xc->name;

    return "InvalidVisual";
}


/***************************************
 * fli_get_vn_val can't be used. caller relies on the returning
 * of FL_IllegalVisual
 ***************************************/

int
fli_vclass_val( const char * v )
{
    FLI_VN_PAIR *vn;

    if ( ! v ) 
        return FL_IllegalVisual;

    for ( vn = xvclass; vn->name; vn++ )
        if ( ! strcmp( vn->name, v ) )
            return vn->val;

    return FL_IllegalVisual;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
