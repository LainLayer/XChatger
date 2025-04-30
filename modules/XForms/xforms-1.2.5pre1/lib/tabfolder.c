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
 * \file tabfolder.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1997-2002  By T.C. Zhao
 *  All rights reserved.
 *
 * tabbed folder
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"

typedef struct {
    FL_OBJECT  * canvas;
    FL_OBJECT  * parent;            /* the tabfolder object         */
    FL_FORM   ** forms;             /* the folders                  */
    FL_OBJECT ** title;             /* the associted tab            */
    int          nforms;            /* number of folders            */
    int          active_folder;     /* current active folder        */
    int          last_active;       /* the previous active folder   */
    int          x,
                 y;
    int          max_h;
    int          h_pad,
                 v_pad;
    int          processing_destroy;
    int          auto_fit;
    int          offset;
    int          num_visible;
} FLI_TABFOLDER_SPEC;


static void compute_position( FL_OBJECT * );
static void switch_folder( FL_OBJECT *,
                           long );
static void program_switch( FL_OBJECT *,
                            int );
static void get_tabsize( FL_OBJECT *,
                         const char *,
                         int *,
                         int *,
                         int );
static void shift_tabs( FL_OBJECT *,
                        int left );

#define IsFolderClass( ob ) ( ( ob ) && ( ob )->objclass == FL_TABFOLDER )


/***************************************
 ***************************************/

static int
handle_tabfolder( FL_OBJECT * ob,
                  int         event,
                  FL_Coord    mx   FL_UNUSED_ARG,
                  FL_Coord    my   FL_UNUSED_ARG,
                  int         key  FL_UNUSED_ARG,
                  void      * ev )
{
    FL_FORM *folder;
    FLI_TABFOLDER_SPEC *sp = ob->spec;

    switch ( event )
    {
        case FL_RESIZED:
            if (    ( folder = fl_get_active_folder( ob ) )
                 && sp->auto_fit != FL_NO )
            {
                if ( sp->auto_fit == FL_FIT )
                    fl_set_form_size( folder, sp->canvas->w, sp->canvas->h );
                else if (    folder->w < sp->canvas->w
                          || folder->h < sp->canvas->h )
                    fl_set_form_size( folder, sp->canvas->w, sp->canvas->h );
            }
            break;

        case FL_MOVEORIGIN:
            if ( ( folder = fl_get_active_folder( ob ) ) )
            {
                fl_get_winorigin( folder->window, &folder->x, &folder->y );

                /* Don't forget nested folders */

                fli_handle_form( folder, FL_MOVEORIGIN, 0, ev );
            }
            break;

        case FL_DRAW:
            fl_set_object_boxtype( sp->canvas,
                                   fli_boxtype2frametype( ob->boxtype ) );
            sp->processing_destroy = 0;
            compute_position( ob );
            break;

        case FL_FREEMEM:
            fli_safe_free( sp->forms );
            fli_safe_free( sp->title );
            fl_free( sp );
            break;
    }

    return 0;
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
    FLI_TABFOLDER_SPEC *sp = ob->u_vdata;

    /* sp->nforms can be zero */

    if ( sp->nforms == 0 || sp->active_folder >= sp->nforms )
        return 0;

    if ( sp->active_folder >= 0 )   /* regular exposure, not first time */
        program_switch( sp->title[ sp->active_folder ], sp->active_folder );
    else if ( sp->last_active >= 0 && sp->last_active < sp->nforms )
        program_switch( sp->title[ sp->last_active ], sp->last_active );

    return 0;
}


/***************************************
 * Before canvas is destroyed this routine will be called where
 * we need to close the form that is attached to this canvas
 ***************************************/

static int
canvas_cleanup( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp = ob->u_vdata;

    if ( sp->active_folder >= 0 && sp->active_folder < sp->nforms )
    {
        sp->processing_destroy = 1;
        if ( sp->forms[ sp->active_folder ]->visible == FL_VISIBLE )
            fl_hide_form( sp->forms[ sp->active_folder ] );

        sp->last_active = sp->active_folder;

        if ( sp->active_folder >= 0 )
            fl_set_object_boxtype( sp->title[ sp->active_folder ],
                                   ob->parent->type != FL_BOTTOM_TABFOLDER ?
                                   FL_TOPTAB_UPBOX : FL_BOTTOMTAB_UPBOX );
        sp->active_folder = -1;
    }

    return 0;
}


/***************************************
 * For all the folders set a dummy form callback to prevent
 * the contained objects from leaking thru to fl_do_forms
 ***************************************/

static void
form_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         void      * data  FL_UNUSED_ARG )
{
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_tabfolder( int          type,
                     FL_Coord     x,
                     FL_Coord     y,
                     FL_Coord     w,
                     FL_Coord     h,
                     const char * label )
{
    FL_OBJECT *ob;
    FLI_TABFOLDER_SPEC *sp;
    int absbw,
        oldu = fl_get_coordunit( );;

    ob = fl_make_object( FL_TABFOLDER, type, x, y, w, h, label,
                         handle_tabfolder );
    fl_set_coordunit( FL_COORD_PIXEL );

    ob->boxtype = FL_UP_BOX;
    ob->spec    = sp  = fl_calloc( 1, sizeof *sp );

    absbw = FL_abs( ob->bw );

    sp->parent = ob;
    sp->forms = NULL;
    sp->title = NULL;
    sp->x = ob->x + absbw;
    sp->y = ob->y + absbw;
    sp->h_pad = 12;
    sp->v_pad = 5;
    sp->auto_fit = FL_NO;

    sp->canvas = fl_create_canvas( FL_SCROLLED_CANVAS, sp->x, sp->y,
                                   ob->w - 2 * absbw,
                                   ob->h - 2 * absbw, label ? label : "tab" );

    sp->canvas->u_vdata = sp;
    fl_modify_canvas_prop( sp->canvas, 0, 0, canvas_cleanup );
    fl_set_object_boxtype( sp->canvas,
                           fli_boxtype2frametype( ob->boxtype ) );
    fl_add_canvas_handler( sp->canvas, Expose, canvas_handler, 0 );

    fl_set_object_color( sp->canvas, ob->col1, ob->col2 );
    fl_set_object_bw( sp->canvas, ob->bw );
    fl_set_object_gravity( sp->canvas, ob->nwgravity, ob->segravity );
    fl_set_coordunit( oldu );

    fl_add_child( ob, sp->canvas );

    fl_set_object_return( ob, FL_RETURN_END_CHANGED );

    return ob;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_add_tabfolder( int          type,
                  FL_Coord     x,
                  FL_Coord     y,
                  FL_Coord     w,
                  FL_Coord     h,
                  const char * l )
{
    FL_OBJECT *obj = fl_create_tabfolder( type, x, y, w, h, l );

    /* Set the default return policy for the object */

    fl_add_object( fl_current_form, obj );
    return obj;
}


/***************************************
 ***************************************/

void
fli_detach_form( FL_FORM * form )
{
    form->attached = 0;
    if ( form->parent && form->parent->child == form )
        form->parent->child = 0;
    form->parent = NULL;
}


/***************************************
 ***************************************/

int
fl_get_tabfolder_numfolders( FL_OBJECT * ob )
{
    return ( ( FLI_TABFOLDER_SPEC * ) ob->spec )->nforms;
}


/***************************************
 * Tab is switched by the application, no need to invoke the callback
 * or report back to the user
 ***************************************/

static void
program_switch( FL_OBJECT * obj,
                int         folder )
{
    FLI_TABFOLDER_SPEC *sp;

    if ( folder >= 0 )
    {
        sp = obj->u_vdata;
        switch_folder( obj, folder );
        obj->parent->returned = FL_RETURN_NONE;

        /* This handles set_folder while hidden */

        if ( ! obj->visible || ! obj->form->visible == FL_VISIBLE )
            sp->last_active = folder;
    }
}


/***************************************
 ***************************************/

static void
switch_folder( FL_OBJECT * ob,
               long        data )
{
    FLI_TABFOLDER_SPEC *sp = ob->u_vdata;
    FL_FORM *form;
    Window win;
    FL_OBJECT *bkob;

    if ( data < 0 || data >= sp->nforms )
    {
        M_err( "switch_folder", "Invalid index");
        return;
    }

    form = sp->forms[ data ];

    if (    data == sp->active_folder
         && sp->active_folder >= 0
         && ! sp->processing_destroy
         && (    ob->parent->how_return == FL_RETURN_ALWAYS
              || ob->parent->how_return == FL_RETURN_END ) )
    {
        ob->parent->returned |= FL_RETURN_END;

#if USE_BWC_BS_HACK
        if ( ! ob->parent->object_callback )
            ob->parent->returned &= ~ FL_RETURN_END;
#endif
    }

    if ( data == sp->active_folder || sp->processing_destroy )
    {
        sp->processing_destroy = 0;
        return;
    }

    if ( ! ob->form->window || ! FL_ObjWin( sp->canvas ) )
        return;

    if ( sp->auto_fit != FL_NO )
    {
        if ( sp->auto_fit == FL_FIT )
            fl_set_form_size( form, sp->canvas->w, sp->canvas->h );
        else if ( form->w < sp->canvas->w || form->h < sp->canvas->h )
            fl_set_form_size( form, sp->canvas->w, sp->canvas->h );
    }

    /* We may have more tabs than can be shown */

    if ( sp->num_visible < sp->nforms - 1 || sp->offset )
    {
        if ( ( data && data == sp->offset ) || data > sp->num_visible )
        {
            int last;

            shift_tabs( ob, data == sp->offset ? -1 : 1 );
            sp->title[ data ]->boxtype &= ~ FLI_BROKEN_BOX;
            sp->title[ data ]->align = FL_ALIGN_CENTER;
            last = sp->num_visible + sp->offset + 1;
            last = FL_clamp( last, 0, sp->nforms - 1 );
            sp->title[ last ]->boxtype |= FLI_BROKEN_BOX;
            sp->title[ last ]->align = fl_to_inside_lalign( FL_ALIGN_LEFT );
            fl_redraw_form( ob->form );
        }
    }

    win = fl_prepare_form_window( form, 0, FL_NOBORDER, "Folder" );

    /* win reparent eats the reparent event */

    fl_winreparent( win, FL_ObjWin( sp->canvas ) );
    form->parent_obj = ob;
    fl_show_form_window( form );

    /* Need to redraw the last selected folder tab */

    if (    sp->active_folder >= 0
         && sp->forms[ sp->active_folder ]->visible == FL_VISIBLE )
    {
        FL_OBJECT *actobj;

        actobj = sp->title[ sp->active_folder ];
        actobj->col1 = sp->parent->col1;

        fl_set_object_boxtype( actobj,
                               ob->parent->type != FL_BOTTOM_TABFOLDER ?
                               FL_TOPTAB_UPBOX : FL_BOTTOMTAB_UPBOX );

        fl_draw_frame( FL_UP_FRAME, sp->canvas->x, sp->canvas->y, sp->canvas->w,
                       sp->canvas->h, sp->canvas->col1, sp->canvas->bw );
        fl_hide_form( sp->forms[ sp->active_folder ] );
        sp->forms[ sp->active_folder ]->parent_obj = NULL;
        sp->last_active = sp->active_folder;
    }

    form->parent = ob->form;
    ob->form->child = form;

    /* Find out the color of the new form */

    if ( ( bkob = form->first ) && bkob->type == FL_NO_BOX )
        bkob = bkob->next;

    if ( bkob )
        fl_set_object_color( ob, bkob->col1, ob->col2 );

    fl_set_object_boxtype( ob, ob->parent->type != FL_BOTTOM_TABFOLDER ?
                           FL_SELECTED_TOPTAB_UPBOX :
                           FL_SELECTED_BOTTOMTAB_UPBOX );

    if (    sp->active_folder >= 0 )
    {
        ob->parent->returned = FL_RETURN_END | FL_RETURN_CHANGED;

#if USE_BWC_BS_HACK
        if ( ! ob->parent->object_callback )
            ob->parent->returned &= ~ ( FL_RETURN_END | FL_RETURN_CHANGED );
#endif
    }

    sp->active_folder = data;
}


/***************************************
 * Add a new folder to the bunch
 ***************************************/

FL_OBJECT *
fl_addto_tabfolder( FL_OBJECT  * ob,
                    const char * title,
                    FL_FORM    * form )
{
    FLI_TABFOLDER_SPEC *sp = ob->spec;
    FL_OBJECT *tab;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_addto_tabfolder", "%s not a folder class",
               ob ? ob->label : "null" );
        return 0;
    }

    if ( ! form || ! title )
    {
        M_err( "fl_addto_tabfolder", "Invalid argument(s)" );
        return 0;
    }

    if ( form->attached )
    {
        M_err( "fl_addto_tabfolder",
               "Seems as if the form is already attached" );
        return 0;
    }

    if ( form->visible == FL_VISIBLE )
        fl_hide_form( form );

    sp->forms = fl_realloc( sp->forms, ( sp->nforms + 1 ) * sizeof *sp->forms );
    sp->title = fl_realloc( sp->title, ( sp->nforms + 1 ) * sizeof *sp->title );

    /* Plug the possible object leakage thru fl_do_forms */

    if ( ! form->form_callback )
        fl_set_form_callback( form, form_cb, NULL );

    sp->forms[ sp->nforms ] = form;
    form->attached = 1;

    if ( form->pre_attach )
        form->pre_attach( form );

    tab = sp->title[ sp->nforms ] = fl_create_button( FL_NORMAL_BUTTON,
                                                      0, 0, 10, 10, title );

    fli_inherit_attributes( ob, tab );
    fl_set_object_boxtype( tab, ob->type != FL_BOTTOM_TABFOLDER ?
                           FL_TOPTAB_UPBOX : FL_BOTTOMTAB_UPBOX );

    tab->u_vdata = sp;
    fl_set_object_callback( tab, switch_folder, sp->nforms );

    sp->nforms++;
    compute_position( ob );

    fl_add_child( ob, tab );

    tab->how_return = FL_RETURN_CHANGED;

    if ( sp->nforms == 1 )
    {
        sp->last_active = 0;
        sp->active_folder = -1;
        program_switch( sp->title[ sp->last_active ], sp->last_active );
    }

    /* If first time and the canvas is visible, refresh */

    if ( sp->nforms == 1 && ob->visible )
        fl_redraw_form( ob->form );

    return tab;
}


/***************************************
 ***************************************/

static void
get_tabsize( FL_OBJECT  * ob,
             const char * label,
             int        * ww,
             int        * hh,
             int          fudge )
{
    int w,
        h,
        absbw = FL_abs( ob->bw );
    FLI_TABFOLDER_SPEC *sp = ob->spec;

    fl_get_string_dimension( ob->lstyle, ob->lsize, label, strlen( label ),
                             &w, &h );
    w += sp->h_pad + 2 * absbw;
    h += sp->v_pad + 2 * absbw;

    *hh = h + fudge * absbw;
    *ww = w;

    return;
}


/***************************************
 ***************************************/

void
fl_delete_folder_byname( FL_OBJECT  * ob,
                         const char * name )
{
    FLI_TABFOLDER_SPEC *sp = ob->spec;
    int i,
        done;

    for ( done = i = 0; ! done && i < sp->nforms; i++ )
        if ( ! strcmp( sp->title[ i ]->label, name ) )
            done = i + 1;

    if ( done )
        fl_delete_folder_bynumber( ob, done );

}


/***************************************
 ***************************************/

void
fl_delete_folder_byname_f( FL_OBJECT  * ob,
                           const char * fmt,
                           ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_delete_folder_byname( ob, buf );
    fl_free( buf );
}


/***************************************
 ***************************************/

void
fl_delete_folder_bynumber( FL_OBJECT * ob,
                           int         num )
{
    int i = num - 1;
    FLI_TABFOLDER_SPEC *sp = ob->spec;
    FL_OBJECT *deleted = NULL;
    FL_FORM *theform = NULL;

    if ( i >= 0 && i < sp->nforms )
    {
        int j;

        deleted = sp->title[ i ];
        fli_detach_form( theform = sp->forms[ i ] );

        for ( j = i + 1; j < sp->nforms; j++ )
        {
            sp->title[ j - 1 ]           = sp->title[ j ];
            sp->title[ j - 1 ]->argument = j - 1;
            sp->forms[ j - 1 ]           = sp->forms[ j ];
        }

        sp->nforms--;
        sp->forms = fl_realloc( sp->forms, sp->nforms * sizeof *sp->forms );
        sp->title = fl_realloc( sp->title, sp->nforms * sizeof *sp->title );
    }

    if ( deleted )
    {
        fli_set_object_visibility( deleted, FL_INVISIBLE );

        if ( theform->form_callback == form_cb )
            theform->form_callback = NULL;

        if ( theform->visible == FL_VISIBLE )
            fl_hide_form( theform );

        /* Change active folder if need to */

        sp->last_active = -1;

        if ( i < sp->active_folder )
            sp->active_folder--;
        else if ( i == sp->active_folder )
        {
            sp->active_folder = -1;
            fl_set_folder_bynumber( ob, i );
        }

        fl_free_object( deleted );

        fl_redraw_form( ob->form );
    }
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_tabfolder_folder_bynumber( FL_OBJECT * ob,
                                  int         num )
{
    FLI_TABFOLDER_SPEC *sp = ob->spec;
    int i = num - 1;

    return ( i >= 0 && i < sp->nforms ) ? sp->forms[ i ] : NULL;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_tabfolder_folder_byname( FL_OBJECT  * ob,
                                const char * name )
{
    int i;
    FLI_TABFOLDER_SPEC *sp = ob->spec;

    for ( i = 0; i < sp->nforms; i++ )
        if ( strcmp( sp->title[ i ]->label, name ) == 0 )
            return fl_get_tabfolder_folder_bynumber( ob, i + 1 );

    return NULL;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_tabfolder_folder_byname_f( FL_OBJECT  * ob,
                                  const char * fmt,
                                  ...)
{
    FL_FORM *f;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    f = fl_get_tabfolder_folder_byname( ob, buf );
    fl_free( buf );
    return f;
}


/***************************************
 ***************************************/

void
fl_delete_folder( FL_OBJECT * ob,
                  FL_FORM   * form )
{
    int i, done;
    FLI_TABFOLDER_SPEC *sp = ob->spec;

    for ( done = i = 0; ! done && i < sp->nforms; i++ )
        if ( form == sp->forms[ i ] )
            done = i + 1;

    if ( done )
        fl_delete_folder_bynumber( ob, done );
}


/***************************************
 ***************************************/

void
fl_set_folder( FL_OBJECT * ob,
               FL_FORM   * form )
{
    FLI_TABFOLDER_SPEC *sp;
    int i,
        done;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_set_folder", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return;
    }

    sp = ob->spec;
    for ( done = i = 0; ! done && i < sp->nforms; i++ )
        if ( sp->forms[ i ] == form )
        {
            program_switch( sp->title[ i ], i );
            done = 1;
        }
}


/***************************************
 ***************************************/

void
fl_set_folder_byname( FL_OBJECT  * ob,
                      const char * name )
{
    FLI_TABFOLDER_SPEC *sp;
    int i,
        done;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_set_folder_byname", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return;
    }

    sp = ob->spec;
    for ( done = i = 0; ! done && i < sp->nforms; i++ )
        if ( strcmp( sp->title[ i ]->label, name ) == 0 )
        {
            program_switch( sp->title[ i ], i );
            done = 1;
        }
}


/***************************************
 ***************************************/

void
fl_set_folder_byname_f( FL_OBJECT  * ob,
                        const char * fmt,
                        ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_set_folder_byname( ob, buf );
    fl_free( buf );
}


/***************************************
 ***************************************/

void
fl_set_folder_bynumber( FL_OBJECT * ob,
                        int         num )
{
    FLI_TABFOLDER_SPEC *sp;
    int i = num - 1;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_set_folder_bynumber", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return;
    }

    sp = ob->spec;
    if ( i >= 0 && i < sp->nforms )
        program_switch( sp->title[ i ], i );
}


/***************************************
 * Keep tab but replace the folder content
 ***************************************/

void
fl_replace_folder_bynumber( FL_OBJECT * ob,
                            int         num,
                            FL_FORM   * form )
{
    FLI_TABFOLDER_SPEC *sp = ob->spec;
    int i = num - 1;

    if ( i >= 0 && i < sp->nforms && sp->forms[ i ] != form )
    {
        sp->forms[ i ] = form;

        if ( i == sp->active_folder )
        {
            sp->active_folder = -1;
            program_switch( sp->title[ i ], i );
        }
    }
}


/***************************************
 ***************************************/

int
fl_get_folder_number( FL_OBJECT * ob )
{
    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_get_folder_number", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return 0;
    }

    return ( ( FLI_TABFOLDER_SPEC * ) ob->spec )->last_active + 1;
}


/***************************************
 ***************************************/

int
fl_get_active_folder_number( FL_OBJECT * ob )
{
    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_get_active_folder_number", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return 0;
    }

    return ( ( FLI_TABFOLDER_SPEC * ) ob->spec )->active_folder + 1;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_folder( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_get_folder", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;
    return sp->last_active >= 0 ? sp->forms[ sp->last_active ] : NULL;
}


/***************************************
 ***************************************/

const char *
fl_get_folder_name( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_get_folder_name", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;
    return sp->last_active >= 0 ? sp->title[ sp->last_active ]->label : NULL;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_active_folder( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_get_active_folder", "%s is not tabfolder",
               ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;

    return ( sp->forms && sp->active_folder >= 0 ) ?
           sp->forms[ sp->active_folder ] : NULL;
}


/***************************************
 ***************************************/

const char *
fl_get_active_folder_name( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp;

    if ( ! IsFolderClass( ob ) )
    {
        M_err( "fl_get_active_folder_name", "%s is not tabfolder",
              ob ? ob->label : "null" );
        return NULL;
    }

    sp = ob->spec;
    return sp->active_folder >= 0 ?
           sp->title[ sp->active_folder ]->label : NULL;
}


/***************************************
 ***************************************/

void
fl_get_folder_area( FL_OBJECT * ob,
                    FL_Coord  * x,
                    FL_Coord  * y,
                    FL_Coord  * w,
                    FL_Coord  * h )
{
    FLI_TABFOLDER_SPEC *sp = ob->spec;

    compute_position( ob );
    *x = sp->canvas->x;
    *y = sp->canvas->y;
    *w = sp->canvas->w;
    *h = sp->canvas->h;
}


/***************************************
 ***************************************/

int
fl_get_tabfolder_offset( FL_OBJECT * obj )
{
    return ( ( FLI_TABFOLDER_SPEC * ) obj->spec )->offset;
}


/***************************************
 ***************************************/

int
fl_set_tabfolder_offset( FL_OBJECT * obj,
                         int         offset )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int old = sp->offset;

    if ( offset < 0 )
        offset = 0;
    else if ( offset + sp->num_visible + 1 > sp->nforms - 1 )
        offset = sp->nforms - sp->num_visible;

    if ( offset != sp->offset )
    {
        shift_tabs( obj, offset - sp->offset );
        fl_redraw_form( obj->form );
    }

    return old;
}


/***************************************
 * Compute the position and propagate the parent attributes
 ***************************************/

static void
compute_top_position( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp ;
    FL_OBJECT *tab;
    int i,
        max_h = 4;

    sp = ob->objclass == FL_TABFOLDER ? ob->spec : ob->u_vdata;

    sp->y = ob->y + 1;
    sp->x = sp->canvas->x - FL_abs( sp->canvas->bw );

    for ( i = 0; i < sp->offset; i++ )
        sp->title[ i ]->x = 2000;

    /* This gets the fl_get_folder_area() right (single line tab) - even if
       empty folder */

    if ( sp->nforms == 0 )
    {
        int junk;
        get_tabsize( ob, "AjbY", &junk, &max_h, 1 );
    }

    for ( i = sp->offset; i < sp->nforms; i++ )
    {
        tab = sp->title[ i ];
        get_tabsize( ob, tab->label, &tab->w, &tab->h, 1 );
        if ( tab->h > max_h )
            max_h = tab->h;
        tab->x = sp->x;
        tab->y = sp->y;
        sp->x += tab->w + ( ob->bw > 0 );
        if ( sp->x < sp->canvas->x + sp->canvas->w - 2 )
        {
            sp->num_visible = i;
            tab->boxtype &= ~ FLI_BROKEN_BOX;
            tab->align = FL_ALIGN_CENTER;
            tab->visible = 1;
        }
        else if ( ( tab->w -= sp->x - sp->canvas->x - sp->canvas->w ) > 0 )
        {
            tab->boxtype |= FLI_BROKEN_BOX;
            tab->align = fl_to_inside_lalign( FL_ALIGN_LEFT );
            tab->visible = 1;
        }
        else
        {
            tab->w = 20;
            tab->visible = 0;
        }
    }

    for ( i = 0; i < sp->nforms; i++ )
        sp->title[ i ]->h = max_h;

    /* This will be the canvas location */

    if ( ob->objclass == FL_TABFOLDER )
    {
        if ( ob->type != FL_BOTTOM_TABFOLDER )
            sp->canvas->y = sp->y + max_h - ( ob->bw < 0 );
    }
    else
    {
        if ( sp->parent->type != FL_BOTTOM_TABFOLDER )
            sp->canvas->y = sp->y + max_h - ( ob->bw < 0 );
    }

    sp->canvas->h = ob->h - max_h - FL_abs( ob->bw ) - 1;
    sp->max_h = max_h;
    fl_set_object_color( sp->canvas, ob->col1, ob->col2 );
}


/***************************************
 ***************************************/

static void
compute_bottom_position( FL_OBJECT * ob )
{
    FLI_TABFOLDER_SPEC *sp;
    FL_OBJECT *tab;
    int i,
        max_h = 4,
        absbw = FL_abs( ob->bw );

    sp = ob->objclass == FL_TABFOLDER ? ob->spec:ob->u_vdata;
    sp->x = ob->x;

    if ( sp->nforms == 0 )
    {
        int junk;
        get_tabsize( ob, "AjbY", &junk, &max_h, -1 );
    }

    for ( i = 0; i < sp->nforms; i++ )
    {
        tab = sp->title[ i ];
        get_tabsize( ob, tab->label, &tab->w, &tab->h, -1 );
        if ( tab->h > max_h )
            max_h = tab->h;
        tab->x = sp->x;
        sp->x += tab->w + ( ob->bw > 0 );
    }

    sp->canvas->h = ob->h - 2 * absbw - max_h - 1;
    sp->y = sp->canvas->y + sp->canvas->h + absbw - ( ob->bw < 0 );

    for ( i = 0; i < sp->nforms; i++ )
    {
        sp->title[ i ]->h = max_h;
        sp->title[ i ]->y = sp->y;
    }

    sp->max_h = max_h;
    fl_set_object_color( sp->canvas, ob->col1, ob->col2 );
}


/***************************************
 ***************************************/

static void
compute_position( FL_OBJECT * ob )
{
    if ( ob->type == FL_BOTTOM_TABFOLDER )
        compute_bottom_position( ob );
    else
        compute_top_position( ob );
}


/***************************************
 ***************************************/

int
fl_set_tabfolder_autofit( FL_OBJECT * ob,
                          int         y )
{
    FLI_TABFOLDER_SPEC *sp = ob->spec;
    int old = sp->auto_fit;

    sp->auto_fit = y;
    return old;
}


/***************************************
 ***************************************/

static void
shift_tabs( FL_OBJECT * ob,
            int         left )
{
    FLI_TABFOLDER_SPEC *sp = ob->u_vdata;
    int newp = sp->offset + left;

    if ( newp < 0 )
        newp = 0;

    if ( newp == sp->offset )
        return;

    sp->offset = newp;

    compute_position( ob );
}


/***************************************
 ***************************************/

void
fli_set_tab_color( FL_OBJECT * obj,
                     FL_COLOR    col1,
                     FL_COLOR    col2 )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int i;

    for ( i = 0; i < sp->nforms; i++ )
        fl_set_object_color( sp->title[ i ], col1, col2 );
}


/***************************************
 ***************************************/

void
fli_set_tab_lcolor( FL_OBJECT * obj,
                    FL_COLOR    lcol )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int i;

    for ( i = 0; i < sp->nforms; i++ )
        fl_set_object_lcolor( sp->title[ i ], lcol );
}


/***************************************
 ***************************************/

void
fli_set_tab_lsize( FL_OBJECT * obj,
                   int         lsize )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int i;

    for ( i = 0; i < sp->nforms; i++ )
        fl_set_object_lsize( sp->title[ i ], lsize );
}


/***************************************
 ***************************************/

void
fli_set_tab_lstyle( FL_OBJECT * obj,
                    int         lstyle )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int i;

    for ( i = 0; i < sp->nforms; i++ )
        fl_set_object_lstyle( sp->title[ i ], lstyle );
}


/***************************************
 ***************************************/

void
fli_set_tab_lalign( FL_OBJECT * obj,
                    int         align )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int i;

    for ( i = 0; i < sp->nforms; i++ )
        fl_set_object_lalign( sp->title[ i ], align );
}


/***************************************
 ***************************************/

void
fli_set_tab_bw( FL_OBJECT * obj,
                int         bw )
{
    FLI_TABFOLDER_SPEC *sp = obj->spec;
    int i;

    for ( i = 0; i < sp->nforms; i++ )
        fl_set_object_bw( sp->title[ i ], bw );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
