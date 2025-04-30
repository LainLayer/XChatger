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
 * \file formbrowser.c
 *
 *  This file is part of the XForms library package.
 *
 *  Copyright (c) 1997  By T.C. Zhao and Mark Overmars
 *  Copyright (c) 1998  By Steve Lamont of the National Center for
 *                      Microscopy and Imaging Research
 *  Copyright (c) 1999-2002  by T.C. Zhao and Steve Lamont
 *  All rights reserved.
 *
 * form browser.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/pformbrowser.h"


static void check_scrollbar( FL_OBJECT * ob );
static int canvas_cleanup( FL_OBJECT * ob );
static int canvas_handler( FL_OBJECT * ob,
                           Window      win,
                           int         w,
                           int         h,
                           XEvent    * ev,
                           void      * data );
static void delete_form( FLI_FORMBROWSER_SPEC * sp,
                     int                    f );
static void display_forms( FLI_FORMBROWSER_SPEC * sp );
static void form_cb( FL_OBJECT * ob,
                     void      * data );
static int handle_formbrowser( FL_OBJECT * ob,
                               int         event,
                               FL_Coord    mx,
                               FL_Coord    my,
                               int         key,
                               void      * ev );
static void hcb( FL_OBJECT * ob,
                 long        data );
static void parentize_form( FL_FORM   * form,
                            FL_OBJECT * ob );
static void set_form_position( FL_FORM * form,
                               int       x,
                               int       y );
static void vcb( FL_OBJECT * ob,
                 long        data );
static void set_formbrowser_return( FL_OBJECT    * obj,
                                    unsigned int   when );


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_formbrowser( int          type,
                       FL_Coord     x,
                       FL_Coord     y,
                       FL_Coord     w,
                       FL_Coord     h,
                       const char * label )
{
    FL_OBJECT *ob;
    FLI_FORMBROWSER_SPEC *sp;
    int absbw, oldu = fl_get_coordunit( );
    int D;

    ob = fl_make_object( FL_FORMBROWSER, type, x, y, w, h, label,
                         handle_formbrowser );
    fl_set_coordunit( FL_COORD_PIXEL );
    ob->boxtype    = FL_FORMBROWSER_BOXTYPE;
    ob->align      = FL_FORMBROWSER_ALIGN;
    ob->col1       = FL_FORMBROWSER_COL1;
    ob->col2       = FL_BLACK;
    ob->set_return = set_formbrowser_return;
    ob->spec       = sp = fl_calloc( 1, sizeof *sp );

    absbw = FL_abs( ob->bw );

    sp->form   = NULL;
    sp->parent = ob;
    sp->scroll = FL_SMOOTH_SCROLL;
    sp->vw_def = sp->hh_def = D = fli_get_default_scrollbarsize( ob );
    sp->canvas = fl_create_canvas( FL_CANVAS,
                                   ob->x + absbw, ob->y + absbw,
                                   ob->w - 2 * absbw - sp->vw_def,
                                   ob->h - 2 * absbw - sp->hh_def,
                                   label );

    sp->canvas->u_vdata = sp;

    fl_modify_canvas_prop( sp->canvas, NULL, NULL, canvas_cleanup );

    fl_set_object_color( sp->canvas, ob->col1, ob->col2 );
    fl_set_object_bw( sp->canvas, ob->bw );

    fl_set_object_boxtype( sp->canvas,
                           fli_boxtype2frametype( ob->boxtype ) );
    fl_add_canvas_handler( sp->canvas, Expose, canvas_handler, NULL );

    sp->v_pref = sp->h_pref = FL_AUTO;

    sp->hsl = fl_create_scrollbar( FL_HOR_THIN_SCROLLBAR, ob->x,
                                   y + h - D, w - D, D, "" );
    fl_set_scrollbar_value( sp->hsl, sp->old_hval = 0.0 );
    fl_set_object_boxtype( sp->hsl, ob->boxtype );
    sp->hsl->visible = sp->h_pref == FL_ON;
    sp->hsl->resize = FL_RESIZE_X;
    fl_set_object_callback( sp->hsl, hcb, 0 );

    sp->vsl = fl_create_scrollbar( FL_VERT_THIN_SCROLLBAR,
                                   x + w - D, y, D, h - D, "" );
    fl_set_object_boxtype( sp->vsl, ob->boxtype );
    sp->vsl->visible = sp->v_pref == FL_ON;
    fl_set_scrollbar_value( sp->vsl, sp->old_hval = 0.0 );
    sp->vsl->resize = FL_RESIZE_Y;
    fl_set_object_callback( sp->vsl, vcb, 0 );

    fl_add_child( ob, sp->canvas );
    fl_add_child( ob, sp->hsl );
    fl_add_child( ob, sp->vsl );

    fl_set_coordunit( oldu );

    /* Set default return policy for the object */

    fl_set_object_return( ob, FL_RETURN_NONE );

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_formbrowser( int          type,
                    FL_Coord     x,
                    FL_Coord     y,
                    FL_Coord     w,
                    FL_Coord     h,
                    const char * label )
{

    FL_OBJECT *obj = fl_create_formbrowser( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_formbrowser_topform( FL_OBJECT * ob )
{
    int topline;
    FLI_FORMBROWSER_SPEC *sp;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_get_formbrowser_topform", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;
    topline = sp->top_form + 1;

    return topline ? sp->form[ topline - 1 ] : NULL;
}


/***************************************
 ***************************************/

int
fl_set_formbrowser_topform( FL_OBJECT * ob,
                            FL_FORM   * form )
{
    int n = fl_find_formbrowser_form_number( ob, form );

    if ( n > 0 )
        fl_set_formbrowser_topform_bynumber( ob, n );

    return n;
}


/***************************************
 ***************************************/

FL_FORM *
fl_set_formbrowser_topform_bynumber( FL_OBJECT * ob,
                                     int         n )
{
    FLI_FORMBROWSER_SPEC *sp = ob->spec;
    FL_FORM *form = NULL;

    if ( n > 0 && n <= sp->nforms )
    {
        int h,
            f;

        sp->top_form = n - 1;
        sp->top_edge = 0;
        form = sp->form[ sp->top_form ];
        display_forms( sp );

        for ( h = f = 0; f < sp->top_form; f++ )
            h += sp->form[ f ]->h;

        sp->old_vval = ( double ) h / ( sp->max_height - sp->canvas->h );
        fl_set_scrollbar_value( sp->vsl, sp->old_vval );
    }

    return form;
}


/***************************************
 ***************************************/

int
fl_addto_formbrowser( FL_OBJECT * ob,
                      FL_FORM   * form )
{
    FLI_FORMBROWSER_SPEC *sp;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_addto_formbrowser", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    if ( ! form )
    {
        M_err( "fl_addto_formbrowser", "Invalid argument" );
        return 0;
    }

    if ( form->attached )
    {
        M_err( "fl_addto_formbrowser", "Already attached ?" );
        return 0;
    }

    sp = ob->spec;

    if ( form->visible == FL_VISIBLE )
        fl_hide_form( form );

    if ( ! form->form_callback )
        fl_set_form_callback( form, form_cb, NULL );

    parentize_form( form, ob );
    sp->form = fl_realloc( sp->form, ( sp->nforms + 1 ) * sizeof *sp->form );
    sp->form[ sp->nforms++ ] = form;
    form->attached = 1;

    if ( form->pre_attach )
        form->pre_attach( form );
        
    if ( sp->max_width < form->w )
        sp->max_width = form->w;
        
    sp->max_height += form->h;
    display_forms( sp );

    return sp->nforms;
}


/***************************************
 ***************************************/

int
fl_find_formbrowser_form_number( FL_OBJECT * ob,
                                 FL_FORM   * form )
{
    FLI_FORMBROWSER_SPEC *sp;
    int num;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_find_formbrowser_form_number", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    if ( ! form )
    {
        M_err( "fl_find_formbrowser_form_number", "Invalid argument" );
        return 0;
    }

    sp = ob->spec;

    for ( num = 0; num < sp->nforms; num++ )
        if ( sp->form[ num ] == form )
            break;

    return num == sp->nforms ? 0 : num + 1;
}


/***************************************
 ***************************************/

int
fl_delete_formbrowser( FL_OBJECT * ob,
                       FL_FORM   * form )
{
    FLI_FORMBROWSER_SPEC *sp;
    int f;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_delete_formbrowser", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return -1;
    }

    if ( ! form )
    {
        M_err( "fl_delete_formbrowser", "Invalid argument" );
        return -1;
    }

    sp = ob->spec;
    f = fl_find_formbrowser_form_number( ob, form );

    if ( f )
        delete_form( sp, f - 1 );

    return f ? sp->nforms : -1;
}


/***************************************
 ***************************************/

#if 0

FL_FORM *
fl_get_formbrowser_parent_form( FL_OBJECT * ob )
{
    return ob->form->parent;
}

#endif


/***************************************
 ***************************************/

FL_FORM *
fl_delete_formbrowser_bynumber( FL_OBJECT * ob,
                                int         num )
{
    FL_FORM *form;
    FLI_FORMBROWSER_SPEC *sp;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_delete_formbrowser_bynumber", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;

    if ( num <= 0 || num > sp->nforms )
    {
        M_err( "fl_delete_formbrowser_bynumber",
               "Invalid argument -- %d not between 1 and %d",
               num, sp->nforms );
        return NULL;
    }

    form = sp->form[ --num ];
    delete_form( sp, num );

    return form;
}


/***************************************
 ***************************************/

FL_FORM *
fl_replace_formbrowser( FL_OBJECT * ob,
                        int         num,
                        FL_FORM   * form )
{
    FL_FORM *old_form;
    FLI_FORMBROWSER_SPEC *sp;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_replace_formbrowser", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;

    if ( num <= 0 || num > sp->nforms )
    {
        M_err( "fl_replace_formbrowser",
               "Invalid argument -- %d not between 1 and %d",
               num, sp->nforms );
        return NULL;
    }


    old_form = sp->form[ --num ];
    fl_hide_form( old_form );
    sp->form[ num ] = form;
    display_forms( sp );

    return old_form;
}


/***************************************
 ***************************************/

int
fl_get_formbrowser_area( FL_OBJECT * ob,
                         int       * x,
                         int       * y,
                         int       * w,
                         int       * h )
{
    FLI_FORMBROWSER_SPEC *sp;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_get_formbrowser_area", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    sp = ob->spec;

    *x = sp->canvas->x;
    *y = sp->canvas->y;
    *w = sp->canvas->w;
    *h = sp->canvas->h;

    return 1;
}


/***************************************
 ***************************************/

int
fl_insert_formbrowser( FL_OBJECT * ob,
                       int         line,
                       FL_FORM   * new_form )
{
    FLI_FORMBROWSER_SPEC *sp;
    int nforms;
    FL_FORM **form;
    int n = line - 1;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_insert_formbrowser", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return -1;
    }

    sp = ob->spec;
    nforms = sp->nforms;

    if ( line <= 0 || line > nforms )
    {
        M_err( "fl_insert_formbrowser", "Invalid argument" );
        return -1;
    }

    form = fl_realloc( sp->form, ( nforms + 1 ) * sizeof *form );

    if ( ! form )
    {
        M_err( "fl_insert_formbrowser", "Running out of memory" );
        return -1;
    }

    parentize_form( new_form, ob );

    if ( n != nforms )
        memmove( form + n + 1, form + n, sizeof *form * ( nforms - n ) );
    form[ n ] = new_form;
    sp->form = form;
    sp->nforms++;
    display_forms( sp );

    return sp->nforms;
}


/***************************************
 ***************************************/

void
fl_set_formbrowser_hscrollbar( FL_OBJECT * ob,
                               int         how )
{
    FLI_FORMBROWSER_SPEC *sp = ob->spec;

    if ( sp->h_pref != how )
    {
        sp->h_pref = how;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_formbrowser_vscrollbar( FL_OBJECT * ob,
                               int         how )
{
    FLI_FORMBROWSER_SPEC *sp = ob->spec;

    if ( sp->v_pref != how )
    {
        sp->v_pref = how;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_formbrowser_scroll( FL_OBJECT * ob,
                           int         how )
{
    FLI_FORMBROWSER_SPEC *sp = ob->spec;

    if ( sp->scroll != how )
    {
        if ( ( sp->scroll = how ) == FL_JUMP_SCROLL )
            sp->top_edge = 0;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

int
fl_set_formbrowser_xoffset( FL_OBJECT * ob,
                            int         offset )
{
    FLI_FORMBROWSER_SPEC *sp;
    int current;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_set_formbrowser_xoffset", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    sp = ob->spec;
    current = sp->left_edge;

    if ( sp->max_width < sp->canvas->w )
        offset = 0;
    if ( offset < 0 )
        offset = 0;
    if ( offset > sp->max_width - sp->canvas->w )
        offset = sp->max_width - sp->canvas->w;

    sp->left_edge = offset;
    sp->old_hval = ( double ) sp->left_edge / ( sp->max_width - sp->canvas->w );
    fl_set_scrollbar_value( sp->hsl, sp->old_hval );

    return current;
}


/***************************************
 ***************************************/

int
fl_get_formbrowser_xoffset( FL_OBJECT * ob )
{
    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_get_formbrowser_xoffset", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    return ( ( FLI_FORMBROWSER_SPEC * ) ob->spec )->left_edge;
}


/***************************************
 ***************************************/

int
fl_set_formbrowser_yoffset( FL_OBJECT * ob,
                            int         offset )
{
    FLI_FORMBROWSER_SPEC *sp;
    int current;
    int h,
        f;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_set_formbrowser_yoffset", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    sp = ob->spec;
    current = fl_get_formbrowser_yoffset( ob );

    if ( sp->max_height < sp->canvas->h )
        offset = 0;
    if ( offset < 0 )
        offset = 0;
    if ( offset > sp->max_height - sp->canvas->h )
        offset = sp->max_height - sp->canvas->h;

    h = sp->max_height;
    for ( f = sp->nforms - 1; f >= 0 && offset < h; f-- )
        h -= sp->form[ f ]->h;

    sp->top_form = ++f;
    sp->top_edge = offset - h;

    sp->old_vval = ( double ) offset / ( sp->max_height - sp->canvas->h );
    fl_set_scrollbar_value( sp->vsl, sp->old_vval );

    return current;
}


/***************************************
 ***************************************/

int
fl_get_formbrowser_yoffset( FL_OBJECT * ob )
{
    FLI_FORMBROWSER_SPEC *sp;
    int h,
        f;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_get_formbrowser_yoffset", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return 0;
    }

    sp = ob->spec;
    for ( h = f = 0; f < sp->top_form; f++ )
        h += sp->form[ f ]->h;

    return h + sp->top_edge;
}


/***************************************
 ***************************************/

int
fl_get_formbrowser_numforms( FL_OBJECT * ob )
{
    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_get_formbrowser_numforms", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return -1;
    }

    return ( ( FLI_FORMBROWSER_SPEC * ) ob->spec )->nforms;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_formbrowser_form( FL_OBJECT * ob,
                         int         n )
{
    FL_FORM *form = NULL;
    FLI_FORMBROWSER_SPEC *sp;

    if ( ! IsFormBrowserClass( ob ) )
    {
        M_err( "fl_get_formbrowser_form", "%s not a formbrowser",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;

    if ( n >= 1 && n <= sp->nforms )
        form = sp->form[ n - 1 ];
    else
        M_err( "fl_get_formbrowser_form",
               "%d is not an allowable form number", n );

    return form;
}


/* Internals */

/***************************************
 ***************************************/

static void
display_forms( FLI_FORMBROWSER_SPEC * sp )
{
    int f;
    int y_pos;
    FL_OBJECT *canvas = sp->canvas;
    FL_FORM **form    = sp->form;
    int nforms        = sp->nforms;
    int top_form      = sp->top_form;
    int left_edge     = - sp->left_edge;
    int height        = canvas->h;           /* - (2 * absbw); */

    if ( ! FL_ObjWin( sp->canvas ) )
        return;

    fli_inherit_attributes( sp->parent, sp->canvas );

    for ( f = 0; f < top_form; f++ )
        if ( form[ f ]->visible )
            fl_hide_form( form[ f ] );

    fli_inherit_attributes( sp->parent, sp->vsl );
    fli_inherit_attributes( sp->parent, sp->hsl );

    /* I prefer to keep scrollbar unresizable */

    sp->vsl->resize = sp->hsl->resize = FL_RESIZE_NONE;

    y_pos = sp->scroll == FL_JUMP_SCROLL ? 0 : -sp->top_edge;

    for ( f = top_form; y_pos < height && f < nforms; f++ )
    {
        if ( form[ f ]->visible )
            set_form_position( form[ f ], left_edge, y_pos );
        else
        {
            fl_prepare_form_window( form[ f ], 0, FL_NOBORDER, "Formbrowser" );
            form[ f ]->parent_obj = sp->parent;
            XReparentWindow( fl_get_display( ),
                             form[ f ]->window,
                             FL_ObjWin( sp->canvas ),
                             left_edge, y_pos );
            fl_show_form_window( form[ f ] );
        }

        y_pos += form[ f ]->h;
    }

    for ( ; f < nforms; f++ )
        if ( form[ f ]->visible )
            fl_hide_form( form[ f ] );
}


/***************************************
 ***************************************/

static int
handle_formbrowser( FL_OBJECT * ob,
                    int         event,
                    FL_Coord    mx   FL_UNUSED_ARG,
                    FL_Coord    my   FL_UNUSED_ARG,
                    int         key  FL_UNUSED_ARG,
                    void      * ev   FL_UNUSED_ARG )
{
    FLI_FORMBROWSER_SPEC *sp = ob->spec;

    switch ( event )
    {
        case FL_RESIZED :
            fl_redraw_object( ob );
            break;

        case FL_DRAW :
            fl_set_object_boxtype( sp->canvas,
                                   fli_boxtype2frametype( ob->boxtype ) );
            sp->processing_destroy = 0;
            check_scrollbar( ob );
            if ( ! sp->in_draw && FL_ObjWin( sp->canvas ) )
            {
                sp->in_draw = 1;
                display_forms( sp );
                sp->in_draw = 0;
            }
            break;

        case FL_FREEMEM :
            fl_free( sp );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * Canvas expose handler.
 ***************************************/

static int
canvas_handler( FL_OBJECT * ob,
                Window      win   FL_UNUSED_ARG,
                int         w     FL_UNUSED_ARG,
                int         h     FL_UNUSED_ARG,
                XEvent    * ev    FL_UNUSED_ARG,
                void      * data  FL_UNUSED_ARG )
{
    display_forms( ( FLI_FORMBROWSER_SPEC * ) ob->u_vdata );
    return 0;
}


/***************************************
 * Before canvas is destroyed, this routine will be called.
 * we need to close the form that is attached to this canvas
 ***************************************/

static int
canvas_cleanup( FL_OBJECT * ob )
{

    FLI_FORMBROWSER_SPEC *sp = ob->u_vdata;
    int i;

    sp->processing_destroy = 1;

    sp->h_on = FL_OFF;
    sp->v_on = FL_OFF;

    for ( i = 0; i < sp->nforms; i++ )
    if ( sp->form[ i ]->visible )
        fl_hide_form( sp->form[ i ] );

    return 0;
}


/***************************************
 * Dummy
 ***************************************/

static void
form_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         void      * data  FL_UNUSED_ARG )
{
}


/***************************************
 ***************************************/

static void
hcb( FL_OBJECT * obj,
     long        data  FL_UNUSED_ARG )
{
    FLI_FORMBROWSER_SPEC *sp = obj->parent->spec;
    double nval = fl_get_scrollbar_value( sp->hsl );
    int old_left_edge = sp->left_edge;

    sp->left_edge = ( sp->max_width - sp->canvas->w ) * nval;
    if ( old_left_edge != sp->left_edge )
    {
        fl_freeze_form( obj->form );
        display_forms( sp );
        fl_unfreeze_form( obj->form );
    }

    if ( obj->returned & FL_RETURN_END )
        obj->parent->returned |= FL_RETURN_END;

    if ( nval != sp->old_hval )
        obj->parent->returned |= FL_RETURN_CHANGED;

    if (    obj->parent->how_return & FL_RETURN_END_CHANGED
         && ! (    obj->parent->returned & FL_RETURN_CHANGED
                && obj->parent->returned & FL_RETURN_END ) )
            obj->parent->returned = FL_RETURN_NONE;

    if ( obj->parent->returned & FL_RETURN_END )
        sp->old_hval = nval;
}


/***************************************
 ***************************************/

static void
vcb( FL_OBJECT * obj,
     long        data  FL_UNUSED_ARG )
{
    FLI_FORMBROWSER_SPEC *sp = obj->parent->spec;
    double nval = fl_get_scrollbar_value( sp->vsl );

    if ( sp->scroll == FL_JUMP_SCROLL )
        sp->top_form = ( sp->nforms - 1 ) * nval;
    else
    {
        /* do pixel based scrolling */

        int pos = ( sp->max_height - sp->canvas->h ) * nval;
        int h = 0,
            f;

        for ( f = 0; h <= pos && f < sp->nforms; f++ )
            h += sp->form[ f ]->h;

        sp->top_form = f ? ( f - 1 ) : f;
        sp->top_edge = sp->form[ sp->top_form ]->h - h + pos;
    }

    fl_freeze_form( obj->form );
    display_forms( sp );
    fl_unfreeze_form( obj->form );

    if ( obj->returned & FL_RETURN_END )
        obj->parent->returned |= FL_RETURN_END;

    if ( nval != sp->old_vval )
        obj->parent->returned |= FL_RETURN_CHANGED;

    if (    obj->parent->how_return & FL_RETURN_END_CHANGED
         && ! (    obj->parent->returned & FL_RETURN_CHANGED
                && obj->parent->returned & FL_RETURN_END ) )
            obj->parent->returned = FL_RETURN_NONE;

    if ( obj->parent->returned & FL_RETURN_END )
        sp->old_vval = nval;
}


/***************************************
 ***************************************/

static void
set_form_position( FL_FORM * form,
                   int       x,
                   int       y )
{
    XMoveWindow( fl_get_display( ), form->window, x, y );
}


/***************************************
 ***************************************/

static void
delete_form( FLI_FORMBROWSER_SPEC * sp,
             int                    f )
{
    fl_hide_form( sp->form[ f ] );
    sp->form[ f ]->attached = 0;
    sp->nforms--;
    sp->max_height -= sp->form[ f ]->h;
    for ( ; f < sp->nforms; f++ )
        sp->form[ f ] = sp->form[ f + 1 ];
    sp->form = fl_realloc( sp->form, sizeof *sp->form * sp->nforms );
    display_forms( sp );
}


/***************************************
 ***************************************/

static void
parentize_form( FL_FORM   * form,
                FL_OBJECT * ob )
{
    form->parent = ob->form;    /* This is probably the wrong way to do it. */
}


/***************************************
 ***************************************/

static void
check_scrollbar( FL_OBJECT * ob )
{
    FLI_FORMBROWSER_SPEC *sp = ob->spec;
    int absbw = FL_abs( ob->bw );
    int h_on = sp->h_on,
        v_on = sp->v_on;

    /* Inherit the boxtype of the parent */

    sp->hsl->boxtype = ob->boxtype;
    sp->vsl->boxtype = ob->boxtype;

    /* Gravity/resize may screw up the ratios. Recompute */

    sp->canvas->x = ob->x + absbw;
    sp->canvas->y = ob->y + absbw;
    sp->canvas->w = ob->w - 2 * absbw;
    sp->canvas->h = ob->h - 2 * absbw;

    sp->h_on =    sp->canvas->w - 2 * absbw - sp->vw_def > 0 
               && sp->canvas->h - 2 * absbw - sp->hh_def > 0
               && (    sp->h_pref == FL_ON
                    || (    sp->h_pref != FL_OFF
                         && sp->canvas->w < sp->max_width ) );

    sp->v_on =    sp->canvas->w - 2 * absbw - sp->vw_def > 0 
               && sp->canvas->h - 2 * absbw - sp->hh_def > 0
               && (    sp->v_pref == FL_ON
                    || (    sp->v_pref != FL_OFF
                         && sp->canvas->h < sp->max_height ) );

    if ( sp->h_on && ! sp->v_on )
        sp->v_on =    sp->canvas->w - 2 * absbw - sp->vw_def > 0
                   && sp->canvas->h - 2 * absbw - sp->hh_def > 0
                   && sp->v_pref != FL_OFF
                   && sp->canvas->h < sp->max_height + sp->hh_def;
    else if ( ! sp->h_on && sp->v_on )
        sp->h_on =    sp->canvas->w - 2 * absbw - sp->vw_def > 0
                   && sp->canvas->h - 2 * absbw - sp->hh_def > 0
                   && sp->h_pref != FL_OFF
                   && sp->canvas->w < sp->max_width + sp->vw_def;

    if ( sp->v_on )
    {
        sp->vw = sp->vw_def;
        sp->vsl->x = ob->x + ob->w - sp->vw;
        sp->vsl->y = ob->y;
        sp->vsl->w = sp->vw;
        fli_set_object_visibility( sp->vsl, FL_VISIBLE );
        fli_notify_object( sp->vsl, FL_RESIZED );
    }
    else
    {
        fli_set_object_visibility( sp->vsl, FL_HIDDEN );
        sp->vw = 0;
    }

    if ( sp->h_on )
    {
        sp->hh = sp->hh_def;
        sp->hsl->x = ob->x;
        sp->hsl->y = ob->y + ob->h - sp->hh;
        sp->hsl->h = sp->hh;
        fli_set_object_visibility( sp->hsl, FL_VISIBLE );
        fli_notify_object( sp->hsl, FL_RESIZED );
    }
    else
    {
        fli_set_object_visibility( sp->hsl, FL_HIDDEN );
        sp->hh = 0;
    }

    /* Recheck vertical */

    if (    ! sp->v_on
         && sp->canvas->w - 2 * absbw - sp->vw_def > 0
         && sp->canvas->h - 2 * absbw - sp->hh_def > 0
         && sp->v_pref != FL_OFF
         && sp->canvas->h < sp->max_height )
    {
        sp->v_on = 1;
        sp->vw = sp->vw_def;
        sp->vsl->x = ob->x + ob->w - sp->vw;
        sp->vsl->y = ob->y;
        sp->canvas->w = ob->w - 2 * absbw - sp->vw;
    }

    sp->canvas->w =    ob->w - 2 * absbw
                    - ( sp->v_on ? 2 * absbw + sp->vw_def : 0 );
    sp->canvas->h =    ob->h - 2 * absbw
                     - ( sp->h_on ? 2 * absbw + sp->hh_def : 0 );

    sp->hsl->w = sp->canvas->w + 2 * absbw;
    sp->vsl->h = sp->canvas->h + 2 * absbw;

    /* If scrollbars get turned off adjust the offsets. */

    if ( ! sp->v_on && v_on && sp->canvas->h >= sp->max_height )
    {
        sp->top_edge = 0;
        sp->top_form = 0;
        fl_set_scrollbar_value( sp->vsl, sp->old_vval = 0.0 );
    }

    if ( ! sp->h_on && h_on && sp->canvas->w >= sp->max_width )
    {
        sp->left_edge = 0;
        fl_set_scrollbar_value( sp->hsl, sp->old_hval = 0.0 );
    }

    if ( sp->h_on )
    {
        fl_set_scrollbar_size( sp->hsl,
                               ( double ) sp->canvas->w / sp->max_width );
        fl_set_formbrowser_xoffset( ob, fl_get_formbrowser_xoffset( ob ) );
    }

    if ( sp->v_on )
    {
        fl_set_scrollbar_size( sp->vsl,
                               ( double ) sp->canvas->h / sp->max_height );
        fl_set_formbrowser_yoffset( ob, fl_get_formbrowser_yoffset( ob ) );
    }

    if ( sp->canvas->w > 0 && sp->canvas->h > 0 )
        fl_winresize( FL_ObjWin( sp->canvas ), sp->canvas->w, sp->canvas->h );
}


/***************************************
 * Sets under which conditions the object is to be returned to the
 * application. This function is for interal use only, the user
 * must call fl_set_object_return() (which then will call this
 * function).
 ***************************************/

static void
set_formbrowser_return( FL_OBJECT    * obj,
                        unsigned int   when )
{
    FLI_FORMBROWSER_SPEC *sp = obj->spec;

    if ( when & FL_RETURN_END_CHANGED )
        when &= ~ ( FL_RETURN_NONE | FL_RETURN_CHANGED );

    obj->how_return = when;

    if ( when == FL_RETURN_NONE || when == FL_RETURN_CHANGED )
    {
        fl_set_scrollbar_return( sp->vsl, FL_RETURN_CHANGED );
        fl_set_scrollbar_return( sp->hsl, FL_RETURN_CHANGED );
    }
    else
    {
        fl_set_scrollbar_return( sp->vsl, FL_RETURN_ALWAYS );
        fl_set_scrollbar_return( sp->hsl, FL_RETURN_ALWAYS );
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
