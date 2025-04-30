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
 * \file canvas.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *.
 * Class FL_CANVAS
 *
 *  Not too much different from an app_win except geometry is managed
 *  by forms and has one of the forms as its parent.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pcanvas.h"


/***************************************
 * If yield_to_shortcut is set, every key press will have to
 * be checked for all objects' shortcuts on the current form
 ***************************************/

static int
handle_keyboard_special( FL_OBJECT * ob,
                         XEvent    * xev )
{
    unsigned char keybuf[ 127 ],
                  *ch;
    KeySym keysym;
    int kbuflen;
    int ret = 0;

    kbuflen = XLookupString( ( XKeyEvent * ) xev, ( char * ) keybuf,
                             sizeof keybuf, &keysym, 0 );

    if ( IsModifierKey( keysym ) )
        /* empty */ ;
    else if ( kbuflen == 0 && keysym != None )
        ret = fli_do_shortcut( ob->form, keysym,
                               xev->xkey.x, xev->xkey.y, xev );
    else
        for ( ch = keybuf; ch < keybuf + kbuflen && ob->form; ch++ )
            ret = fli_do_shortcut( ob->form, *ch,
                                   xev->xkey.x, xev->xkey.y, xev ) || ret;


    return ret;
}


#define IsValidCanvas( ob )   ( ob && (    ob->objclass == FL_CANVAS       \
                                        || ob->objclass == FL_GLCANVAS ) )


/***************************************
 * We have to intercept all events destined for the canvas.
 * Must return 0 if canvas is used just like an arbitary application
 * window. event processing routine calls the preemptive routine
 * and continues dispatching events if preemptive handler returns 0.
 ***************************************/

static int
canvas_event_intercept( XEvent * xev,
                        void   * vob )
{
    FL_OBJECT *ob = vob;
    FLI_CANVAS_SPEC *sp = ob->spec;

    fli_xevent_name( "CanvasIntercept", xev );

    if ( ! sp )
    {
        /* Must be Destroy Event, which is generated after FREEMEM. Probably
           should block closewindow and handle the events there. Speed
           penalty? */

        return FL_PREEMPT;
    }

    if (    xev->type == DestroyNotify
         && ! sp->canvas_handler[ xev->type ]
         && sp->cleanup )
    {
        sp->cleanup( ob );
        sp->window = None;
    }

    if (    xev->type == KeyPress
         && sp->yield_to_shortcut
         && handle_keyboard_special( ob, xev ) )
        return FL_PREEMPT;

    if (    xev->type != Expose
         && xev->type != GraphicsExpose
         && xev->type != ClientMessage
         && ( ! ob->active || ob->form->deactivated ) )
        return FL_PREEMPT;

    if ( sp->canvas_handler[ xev->type ] )
    {
        if (    xev->type == Expose
             && sp->activate
             && ob->objclass == FL_GLCANVAS )
            sp->activate( ob );

        sp->canvas_handler[ xev->type ]( ob, sp->window, sp->w, sp->h,
                                         xev, sp->user_data[ xev->type ] );
        return FL_PREEMPT;
    }

    return FL_PREEMPT;
}


/********** Data Structure maint. ***************{ ***/

/***************************************
 ***************************************/

static void
free_canvas( FL_OBJECT * ob )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    fli_unmap_canvas_window( ob );

    /* Don't free the colormap if it is XForms' internal one */

    if ( ! sp->keep_colormap && sp->colormap != fli_colormap( fl_vmode ) )
        XFreeColormap( flx->display, sp->colormap );

    fli_safe_free( ob->spec );
}


/***************************************
 * Returns the window ID of the canvas window
 ***************************************/

Window
fl_get_canvas_id( FL_OBJECT * ob )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_DEBUG
    if ( ! IsValidCanvas( ob ) )
    {
        M_err( "fl_get_canvas_id", "%s not a canvas",
               ( ob && ob->label ) ? ob->label : "" );
        return None;
    }
#endif

    return sp->window;
}


/****** End of data struct. maint.*************  }********/


/***************************************
 ***************************************/

static void
BegWMColormap( FLI_CANVAS_SPEC * sp )
{

    /* Set WM_COLORMAP property. Seems some versions of tvtwm have problems
       with setting this property. This check simply works around the problem
       (for most cases). */

    if (    sp->colormap != fli_colormap( fl_vmode )
         && ! XSetWMColormapWindows( flx->display, sp->parent,
                                     &sp->window, 1 ) )
        M_err( "BegWMColormap", "WM choked" );
}


/***************************************
 ***************************************/

void
fl_set_canvas_attributes( FL_OBJECT            * ob,
                          unsigned int           mask,
                          XSetWindowAttributes * xswa )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    /* Must not allow adding/removing events. We take care of soliciting
       events via canvas handler registrations */

    if ( mask & CWEventMask )
    {
        M_err( "fl_set_canvas_attributes", "Changing Events not supported" );
        mask &= ~ CWEventMask;
    }

    sp->user_mask = mask;
    sp->user_xswa = *xswa;

    /* Check if canvas is already active */

    if ( sp->window )
    {
        XChangeWindowAttributes( flx->display, sp->window,
                                 sp->user_mask, &sp->user_xswa );

        if ( mask & CWColormap )
            BegWMColormap( sp );
    }
}


/***************************************
 ***************************************/

void
fl_set_canvas_colormap( FL_OBJECT * ob,
                        Colormap    colormap )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    sp->colormap = sp->xswa.colormap = colormap;
    sp->mask |= CWColormap;

    if ( sp->window )
    {
        M_warn( "fl_set_canvas_colormap",
                "Changing colormap for active window" );
        XChangeWindowAttributes( flx->display, sp->window, sp->mask,
                                 &sp->xswa );
        BegWMColormap( sp );
    }
}


/***************************************
 ***************************************/

void
fl_share_canvas_colormap( FL_OBJECT * ob,
                          Colormap    colormap )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    sp->keep_colormap = 1;
    fl_set_canvas_colormap( ob, colormap );
}


/***************************************
 ***************************************/

Colormap
fl_get_canvas_colormap( FL_OBJECT * ob )
{
    return ( ( FLI_CANVAS_SPEC * ) ( ob->spec ) )->colormap;
}


/***************************************
 ***************************************/

void
fl_set_canvas_visual( FL_OBJECT * obj,
                      Visual    * vi )
{
    ( ( FLI_CANVAS_SPEC * ) ( obj->spec ) )->visual = vi;
}


/***************************************
 ***************************************/

void
fl_set_canvas_depth( FL_OBJECT * obj,
                     int         depth )
{
    ( ( FLI_CANVAS_SPEC * ) ( obj->spec ) )->depth = depth;
}


/***************************************
 ***************************************/

int
fl_get_canvas_depth( FL_OBJECT * obj )
{
    return ( ( FLI_CANVAS_SPEC * ) ( obj->spec ) )->depth;
}


#define Moved( ob, sp )    ( ob->x != sp->x || ob->y != sp->y )
#define Resized( ob, sp )  ( ob->w != sp->w || ob->h != sp->h )


/***************************************
 ***************************************/

static void
init_canvas( FL_OBJECT * ob )
{
    FLI_CANVAS_SPEC *sp = ob->spec;
    static int nc;      /* number of canvases */
    char name[ 32 ];

    if ( ! sp->window || ! fl_winisvalid( sp->window ) )
    {
        /* Find the real parent of the canvas */

        sp->parent = fl_get_real_object_window( ob );
        sp->window = None;

        if ( sp->parent == None )
        {
            M_err( "init_canvas", "Internal Error" );
            exit( 0 );
        }

        if ( sp->init && sp->init( ob ) < 0 )
        {
            M_err( "init_canvas", "Unable to initialize canvas %s", ob->label );
            return;
        }

        /* Create the window */

        sp->window = XCreateWindow( flx->display, sp->parent,
                                    ob->x, ob->y, ob->w, ob->h, 0,
                                    sp->depth, InputOutput,
                                    sp->visual, sp->mask, &sp->xswa );

        if ( sp->user_mask )
            XChangeWindowAttributes( flx->display, sp->window,
                                     sp->user_mask, &sp->user_xswa );

#if FL_DEBUG >= ML_ERR
        M_warn( "init_canvas", "Depth = %d colormap = 0x%lx, WinID = %ld",
                sp->depth, sp->colormap, sp->window );
#endif

        /* Take over event handling */

        fli_set_preemptive_callback( sp->window, canvas_event_intercept, ob );

        if ( sp->activate && sp->activate( ob ) < 0 )
        {
            M_err( "init_canvas", "Can't initialize canvas %s", ob->label );
            return;
        }

        /* Record the name of the window */
        
        if ( *ob->label )
            XStoreName( flx->display, sp->window, ob->label );
        else
        {
            sprintf( name, "flcanvas%d", nc++ );
            XStoreName( flx->display, sp->window, name );
        }

        BegWMColormap( sp );

        XMapWindow( flx->display, sp->window );

        /* Save size */

        sp->x = ob->x;
        sp->y = ob->y;
        sp->w = ob->w;
        sp->h = ob->h;
    }

    /* Check if moved or resized */

    if ( Moved( ob, sp ) || Resized( ob, sp ) )
    {
        M_warn( "init_canvas", "Canvas: WinMoved\n" );
        XMoveResizeWindow( flx->display, sp->window, ob->x, ob->y,
                           ob->w, ob->h );
    }

    sp->x = ob->x;
    sp->y = ob->y;
    sp->w = ob->w;
    sp->h = ob->h;

    if ( ob->col1 != FL_NoColor )
        XClearWindow( flx->display, sp->window );

    sp->dec_type = fli_boxtype2frametype( ob->boxtype );
    fl_draw_frame( sp->dec_type, ob->x, ob->y, ob->w, ob->h, ob->col2, ob->bw );
}


/***************************************
 ***************************************/

FL_HANDLE_CANVAS
fl_add_canvas_handler( FL_OBJECT        * ob,
                       int                ev,
                       FL_HANDLE_CANVAS   h,
                       void             * udata )
{
    FL_HANDLE_CANVAS oldh = NULL;
    FLI_CANVAS_SPEC *sp = ob->spec;
    unsigned long emask = fli_xevent_to_mask( ev );

    if ( ! IsValidCanvas( ob ) )
    {
        M_err( "fl_add_canvas_handler", "%s not canvas class",
               ob ? ob->label : "" );
        return NULL;
    }

    if ( ev < KeyPress )
    {
        M_err( "fl_add_canvas_handler", "Invalid event %d", ev );
        return NULL;
    }

    if ( ev != 0 && ev < LASTEvent )
    {
        oldh = sp->canvas_handler[ ev ];
        sp->canvas_handler[ ev ] = h;
        sp->user_data[ ev ] = udata;
        if ( ! sp->window )
            sp->xswa.event_mask |= emask;
        else
            sp->xswa.event_mask = fl_addto_selected_xevent( sp->window, emask );
    }

    return oldh;
}


/***************************************
 * Remove a particular handler for event ev. If ev is invalid,
 * remove all handlers and their corresponding event mask
 ***************************************/

void
fl_remove_canvas_handler( FL_OBJECT        * ob,
                          int                ev,
                          FL_HANDLE_CANVAS   h  FL_UNUSED_ARG )
{
    FLI_CANVAS_SPEC *sp = ob->spec;
    unsigned long emask = fli_xevent_to_mask( ev );

    if ( ev < 0 || ev >= LASTEvent )
    {
        M_err( "fl_remove_canvas_handler", "Invalid event %d", ev );
        return;
    }

    sp->canvas_handler[ ev ] = NULL;

    if ( ! sp->window )
    {
        if ( emask != 0 )
        {
            sp->xswa.event_mask &= ~emask;
            sp->xswa.event_mask |= ExposureMask;
        }
        return;
    }

    /* Knock off the mask. Need to get Expose however */

    if ( emask != 0 )
        sp->xswa.event_mask = fl_remove_selected_xevent( sp->window, emask );
    else if ( ev < 2 )
        XSelectInput( flx->display, sp->window,
                      sp->xswa.event_mask = ExposureMask );

    if ( ev == 0 )
    {
        for ( ; ev < LASTEvent; ev++ )
            sp->canvas_handler[ ev ] = NULL;
    }
}


/***************************************
 * Handle canvas by calling registered handlers. There is not much
 * to do as FL_DRAW typically will be followd by Expose on the
 * canvas
 ***************************************/

static int
handle_canvas( FL_OBJECT * ob,
               int         event,
               FL_Coord    mx   FL_UNUSED_ARG,
               FL_Coord    my   FL_UNUSED_ARG,
               int         key  FL_UNUSED_ARG,
               void      * xev  FL_UNUSED_ARG )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    switch ( event )
    {
        case FL_ATTRIB :
            ob->align = fl_to_outside_lalign( ob->align );
            break;

        case FL_DRAW:
            if ( ob->col1 != FL_NoColor )
                sp->xswa.background_pixel = fl_get_pixel( ob->col1 );
            else
                sp->xswa.background_pixel = None;
            sp->mask |= CWBackPixel;
            init_canvas( ob );
            fl_draw_object_label_outside( ob );
            break;

        case FL_FREEMEM:
            fli_hide_canvas( ob );
            free_canvas( ob );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 ***************************************/

void
fli_hide_canvas( FL_OBJECT * ob )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    if ( sp->window && sp->cleanup )
        sp->cleanup( ob );

    /* If parent is unmapped, sp->window is also unmapped, must cleanup
       canvas specific stuff before closing window */

    if ( ob->visible && sp->window && ob->form && ob->form->window )
        fl_winclose( sp->window );

    sp->window = None;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_generic_canvas( int          canvas_class,
                          int          type,
                          FL_Coord     x,
                          FL_Coord     y,
                          FL_Coord     w,
                          FL_Coord     h,
                          const char * label )
{
    FL_OBJECT *ob;
    FLI_CANVAS_SPEC *sp;
    int vmode = fl_vmode;
    int i;

    ob = fl_make_object( canvas_class, type, x, y, w, h, label, handle_canvas );
    ob->boxtype = FL_CANVAS_BOXTYPE;
    ob->col1 = FL_NoColor;       /* indicates no background */
    ob->col2 = FL_BLACK;

    sp = ob->spec = fl_calloc( 1, sizeof *sp );
    sp->xswa.border_pixel = 0;
    sp->xswa.event_mask = ExposureMask | StructureNotifyMask;
    sp->xswa.do_not_propagate_mask = 0;
    sp->mask = CWColormap | CWEventMask | CWBorderPixel | CWDontPropagate;

    if ( ! fli_no_connection )
    {
        sp->visual = fli_visual( vmode );
        sp->depth = fli_depth( vmode );
        sp->colormap = sp->xswa.colormap = fli_colormap( vmode );
        sp->gc = fl_state[ vmode ].gc[ 7 ];     /* NOT USED */
    }

    sp->winname = NULL;
    sp->window = sp->parent = sp->swindow = None;
    sp->init = sp->activate = sp->cleanup = NULL;
    sp->last_active = NULL;
    sp->context = NULL;
    for ( i = 0; i < LASTEvent; i++ )
    {
        sp->canvas_handler[ i ] = NULL;
        sp->user_data[ i ] = NULL;
    }

    fl_canvas_yield_to_shortcut( ob, 1 );

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_canvas( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * label )
{
    return fl_create_generic_canvas( FL_CANVAS, type, x, y, w, h, label );
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_canvas( int          type,
               FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h,
               const char * label )
{
    FL_OBJECT *ob = fl_create_canvas( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/***************************************
 ***************************************/

void
fl_modify_canvas_prop( FL_OBJECT             * obj,
                       FL_MODIFY_CANVAS_PROP   init,
                       FL_MODIFY_CANVAS_PROP   activate,
                       FL_MODIFY_CANVAS_PROP   cleanup )
{
    FLI_CANVAS_SPEC *sp = obj->spec;

    sp->init     = init;
    sp->activate = activate;
    sp->cleanup  = cleanup;
}


/***************************************
 ***************************************/

void
fl_canvas_yield_to_shortcut( FL_OBJECT * ob,
                             int         yes )
{
    FLI_CANVAS_SPEC *sp = ob->spec;
    unsigned int emask = KeyPressMask;

    if ( ( sp->yield_to_shortcut = yes ) )
    {
        if ( ! sp->window )
            sp->xswa.event_mask |= emask;
        else
            sp->xswa.event_mask =
                               fl_addto_selected_xevent( sp->window, emask );
    }
    else if ( ! sp->canvas_handler[ KeyPress ] )
    {
        if ( ! sp->window )
            sp->xswa.event_mask &= ~emask;
        else
            sp->xswa.event_mask = 
                                fl_remove_selected_xevent( sp->window, emask );
    }
}


/***************************************
 * Clear the canvas to the background color. If no background is
 * defined use black.
 ***************************************/

void
fl_clear_canvas( FL_OBJECT * ob )
{
    Window win;

    if ( ! ob || ! ( win = FL_ObjWin( ob ) ) )
        return;

    if ( ob->col1 != FL_NoColor )
        XClearWindow( flx->display, win );
    else
    {
        fl_winset( win );
        fl_rectf( ob->x, ob->y, ob->w, ob->h, FL_BLACK );
    }
}


/***************************************
 * Called when a form that contains a canvas is getting hidden
 ***************************************/

void
fli_unmap_canvas_window( FL_OBJECT * ob )
{
    FLI_CANVAS_SPEC *sp = ob->spec;

    if ( ob->visible && sp->window && ob->form && ob->form->window )
        fl_winclose( sp->window );

    sp->window = None;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
