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
 * \file objects.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"


#define TRANSLATE_Y( obj, form )    ( form->h - obj->h - obj->y )

extern FL_FORM * fli_fast_free_object;     /* defined in forms.c */

extern FL_OBJECT * fli_handled_obj;        /* defined in  events.c */
extern FL_OBJECT * fli_handled_parent;     /* defined in  events.c */

static void redraw( FL_FORM *,
                    int );
static void lose_focus( FL_OBJECT * );
static void get_object_rect( const FL_OBJECT * obj,
                             XRectangle      * rect,
                             int               extra );
static XRectangle * get_label_rect( const FL_OBJECT  * obj,
                                    XRectangle       * rect );
static int objects_intersect( const FL_OBJECT *,
                              const FL_OBJECT * );
static void mark_object_for_redraw( FL_OBJECT * );
static int object_is_under( const FL_OBJECT * );
static void checked_hide_tooltip( FL_OBJECT *,
                                  XEvent    * );
static int prep_recalc( FL_FORM   * form,
                        FL_OBJECT * start_obj );
static void finish_recalc( FL_FORM   * form,
                           FL_OBJECT * start_obj );

static FL_OBJECT *refocus;

static void **tmp_vdata = NULL;
static FL_RECT *tmp_rects = NULL;

#define IS_BUTTON_CLASS( i )   (    i == FL_BUTTON           \
                                 || i == FL_ROUNDBUTTON      \
                                 || i == FL_ROUND3DBUTTON    \
                                 || i == FL_LIGHTBUTTON      \
                                 || i == FL_CHECKBUTTON      \
                                 || i == FL_BITMAPBUTTON     \
                                 || i == FL_PIXMAPBUTTON )


/* Macro for checking of a FL_FORM pointer points to a form that should
   be actually drawn to */

#define FORM_IS_UPDATABLE( form ) (    form                             \
                                    && ( form )->visible == FL_VISIBLE  \
                                    && ( form )->frozen == 0 )


/* Macro for checking if a label is to be considered to be "outside" of its
   object for redrawing purposes. When a label is outside of its object and
   we change the position or size of the object, the text, or style or
   font size of the label then other objects under the label also need
   to be redrawn. In priciple calling fl_is_outside_lalign() should do
   the job but there are some semi-transparent objects which we need to
   treat as if their labels are always "outside" even if they aren't
   marked that way. */

#define OL( o )   (    fl_is_outside_lalign( ( o )->align )   \
                    || ( o )->objclass == FL_ROUNDBUTTON      \
                    || ( o )->objclass == FL_ROUND3DBUTTON    \
                    || ( o )->objclass == FL_CHECKBUTTON )


#define IN_REDRAW         1
#define HIDE_WHILE_FROZEN 2


/***************************************
 * Returns the "background object" of a form or NULL if there isn't one
 * (this is either the first object of a form or, if that object has the
 * box type FL_NO_BOX, the next one).
 ***************************************/

static FL_OBJECT *
bg_object( FL_FORM * form )
{
    if ( ! form || ! form->first )
        return NULL;

    return form->first->boxtype == FL_NO_BOX ? form->first->next : form->first;
}


/***************************************
 * Creates an object - NOT MEANT FOR USE BY USERS OF THE LIBRARY!
 ***************************************/

FL_OBJECT *
fl_make_object( int            objclass,
                int            type,
                FL_Coord       x,
                FL_Coord       y,
                FL_Coord       w,
                FL_Coord       h,
                const char   * label,
                FL_HANDLEPTR   handle )
{
    FL_OBJECT *obj;
#ifdef FL_WIN32
    int def = -2;
#else
    int def = FL_BOUND_WIDTH;
#endif

    obj = fl_calloc( 1, sizeof *obj );

    obj->objclass  = objclass;
    obj->type      = type;
    obj->resize    = FL_RESIZE_ALL;
    obj->nwgravity = obj->segravity = FL_NoGravity;
    obj->boxtype   = FL_NO_BOX;
    obj->bw        = (    fli_cntl.borderWidth
                       && FL_abs( fli_cntl.borderWidth ) <= FL_MAX_BW ) ?
                     fli_cntl.borderWidth : def;

    obj->x         = x;
    obj->y         = y;
    obj->w         = w;
    obj->h         = h;

    obj->u_vdata = NULL;
    obj->u_cdata = NULL;

    switch ( fli_cntl.coordUnit )
    {
        case FL_COORD_PIXEL :
            break;

        case FL_COORD_MM :
            fli_scale_object( obj, fl_dpi / 25.4, fl_dpi / 25.4 );
            break;

        case FL_COORD_POINT :
            fli_scale_object( obj, fl_dpi / 72.0, fl_dpi / 72.0 );
            break;

        case FL_COORD_centiPOINT :
            fli_scale_object( obj, fl_dpi / 7200.0, fl_dpi / 7200.0 );
            break;

        case FL_COORD_centiMM :
            fli_scale_object( obj, fl_dpi / 2540.0, fl_dpi / 2540.0 );
            break;

        default:
            M_err( "fl_make_object", "Unknown unit: %d. Reset",
                   fli_cntl.coordUnit );
            fli_cntl.coordUnit = FL_COORD_PIXEL;
    }

    obj->wantkey  = FL_KEY_NORMAL;

    obj->flpixmap = NULL;
    obj->label    = fl_strdup( label ? label : "" );
    obj->handle   = handle;
    obj->align    = FL_ALIGN_CENTER;
    obj->lcol     = FL_BLACK;
    obj->col1     = FL_COL1;
    obj->col2     = FL_MCOL;

    if ( IS_BUTTON_CLASS( objclass ) && fli_cntl.buttonFontSize )
        obj->lsize = fli_cntl.buttonFontSize;
    else if ( objclass == FL_MENU && fli_cntl.menuFontSize )
        obj->lsize = fli_cntl.menuFontSize;
    else if (    ( objclass == FL_CHOICE || objclass == FL_SELECT )
              && fli_cntl.choiceFontSize )
        obj->lsize = fli_cntl.choiceFontSize;
    else if ( objclass == FL_INPUT && fli_cntl.inputFontSize )
        obj->lsize = fli_cntl.inputFontSize;
    else if ( objclass == FL_SLIDER && fli_cntl.sliderFontSize )
        obj->lsize = fli_cntl.sliderFontSize;
#if 0
    else if ( objclass == FL_BROWSER && fli_cntl.browserFontSize )
        obj->lsize = fli_cntl.browserFontSize;
#endif
    else if ( fli_cntl.labelFontSize )
        obj->lsize = fli_cntl.labelFontSize;
    else
        obj->lsize = FL_DEFAULT_SIZE;

    obj->lstyle             = FL_NORMAL_STYLE;
    obj->shortcut           = fl_calloc( 1, sizeof( long ) );
    *obj->shortcut          = 0;
    obj->active             = 1;
    obj->visible            = FL_VISIBLE;
    obj->object_callback    = NULL;
    obj->spec               = NULL;
    obj->next = obj->prev   = NULL;
    obj->form               = NULL;
    obj->dbl_background     = FL_COL1;
    obj->parent             = NULL;
    obj->child              = NULL;
    obj->nc                 = NULL;
    obj->group_id           = 0;
    obj->set_return         = NULL;
    obj->how_return         = FL_RETURN_ALWAYS;
    obj->returned           = 0;
    obj->is_under           = 0;

    return obj;
}


/***************************************
 * Adds an object to a form
 ***************************************/

void
fl_add_object( FL_FORM   * form,
               FL_OBJECT * obj )
{
    /* Checking for correct arguments. */

    if ( ! obj )
    {
        M_err( "fl_add_object", "NULL object" );
        return;
    }

    if ( ! form )
    {
        M_err( "fl_add_object", "NULL form for '%s'",
               fli_object_class_name( obj ) );
        return;
    }

    if ( obj->form )
    {
        M_err( "fl_add_object", "Object already belongs to a form" );
        return;
    }

    if ( obj->objclass == FL_BEGIN_GROUP || obj->objclass == FL_END_GROUP )
    {
        M_err( "fl_add_object", "Can't add an pseudo-object that marks the "
               "start or end of a group" );
        return;
    }

    obj->prev = obj->next = NULL;
    obj->form = form;

    if ( obj->automatic )
    {
        form->num_auto_objects++;
        fli_recount_auto_objects( );
    }

    if ( fli_inverted_y )
        obj->y = TRANSLATE_Y( obj, form );

    obj->fl1 = obj->x;
    obj->fr1 = form->w_hr - obj->fl1;
    obj->ft1 = obj->y;
    obj->fb1 = form->h_hr - obj->ft1;

    obj->fl2 = obj->x  + obj->w;
    obj->fr2 = form->w - obj->fl2;
    obj->ft2 = obj->y  + obj->h;
    obj->fb2 = form->h - obj->ft2;

    /* If adding to a group, set objects group ID, then find the end of the
       group or the end of the object list of this form */

    if ( fli_current_group )
    {
        FL_OBJECT *end = fli_current_group;

        obj->group_id = fli_current_group->group_id;

        while ( end && end->objclass != FL_END_GROUP )
            end = end->next;

        /* If 'end' exists must've opened the group with fl_addto_group */

        if ( end )
        {
            end->prev->next = obj;
            obj->prev = end->prev;
            obj->next = end;
            end->prev = obj;

            if ( obj->child )
            {
                FL_OBJECT * tmp;

                for ( tmp = obj->child; tmp; tmp = tmp->nc )
                    fl_add_object( form, tmp );
            }

            if (    fl_current_form != form
                 && FORM_IS_UPDATABLE( obj->form )
                 && ! obj->parent )
            {
                fli_recalc_intersections( form );
                fl_redraw_object( obj );
            }

            return;
        }
    }

    if ( ! form->first )
        form->first = form->last = obj;
    else
    {
        obj->prev = form->last;
        form->last->next = obj;
        form->last = obj;
    }

    if ( obj->input && obj->active && ! form->focusobj )
        fl_set_focus_object( form, obj );

    /* If the object has child objects also add them to the form */

    if ( obj->child )
        fli_add_composite( obj );

    if (    obj->form->first
         && obj->form->first != obj )
    {
        FL_COLOR bkcol = obj->form->first->col1;

        if ( obj->form->first->boxtype == FL_NO_BOX )
        {
            bkcol = obj->form->first->next->col1;

            if ( obj == obj->form->first->next )
                obj->col1 = obj->form->first->col1;
        }

        obj->dbl_background = bkcol;
    }

    /* It only make sense to recalculate intersections between objects
       and to redraw the form with the new object when we're not within
       a fl_bgn_form()/fl_end_form() pair and also only for objects that
       aren't child objects */

    if (    fl_current_form != form
         && FORM_IS_UPDATABLE( obj->form )
         && ! obj->parent )
    {
        fli_recalc_intersections( form );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Inserts object 'obj' in front of the object 'before'
 ***************************************/

void
fli_insert_object( FL_OBJECT * obj,
                   FL_OBJECT * before )
{
    FL_FORM * form;

    /* Checking for correct arguments */

    if ( ! obj || ! before )
    {
        M_err( "fli_insert_object", "NULL object" );
        return;
    }

    if ( ! before->form  )
    {
        M_err( "fli_insert_object", "Trying to insert object into NULL form" );
        return;
    }

    form      = before->form;
    obj->next = before;

    if ( before->type != FL_BEGIN_GROUP )
        obj->group_id = before->group_id;

    if ( before == form->first )
    {
        form->first = obj;
        obj->prev   = NULL;
    }
    else
    {
        obj->prev       = before->prev;
        obj->prev->next = obj;
    }

    obj->fl1 = obj->x;
    obj->fr1 = form->w_hr - obj->fl1;
    obj->ft1 = obj->y;
    obj->fb1 = form->h_hr - obj->ft1;

    obj->fl2 = obj->x  + obj->w;
    obj->fr2 = form->w - obj->fl2;
    obj->ft2 = obj->y  + obj->h;
    obj->fb2 = form->h - obj->ft2;

    before->prev = obj;
    obj->form    = form;

    if ( obj->automatic )
    {
        form->num_auto_objects++;
        fli_recount_auto_objects( );
    }

    if ( fli_inverted_y )
        obj->y = TRANSLATE_Y( obj, form );

    if ( obj->input && obj->active && ! form->focusobj )
        fl_set_focus_object( form, obj );

    /* If the object has child objects also insert them into the form */

    if ( obj->child )
        fli_insert_composite( obj, before );

    if (    fl_current_form != form
         && FORM_IS_UPDATABLE( form )
         && ! obj->parent )
    {
        fli_recalc_intersections( form );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Unlinks an object from its form
 ***************************************/

void
fl_delete_object( FL_OBJECT * obj )
{
    FL_FORM * form;

    if ( ! obj )
    {
        M_err( "fl_delete_object", "NULL object" );
        return;
    }

    if ( ! obj->form )
    {
        M_err( "fl_delete_object", "Delete '%s' from NULL form",
               ( obj->label && *obj->label ) ? obj->label : "object" );
        return;
    }

    checked_hide_tooltip( obj, NULL );

    /* If object is the pseudo-object starting a group delete the
       complete group */

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        FL_OBJECT *o;

        fl_freeze_form( obj->form );

        for ( o = obj->next; o; o = o->next )
        {
            /* Hack for fdesign to allow deletion of the FL_BEGIN_GROUP and
               FL_END_GROUP objects while keeping the objects in the group
               if their group ID was unset */

            if (    o->group_id != obj->group_id
                 || ( o->parent && o->parent->group_id != obj->group_id ) )
                continue;

            fl_delete_object( o );
            if ( o->objclass == FL_END_GROUP )
                break;
        }

        fl_unfreeze_form( obj->form );
    }

    /* Avoid deleting an object that represents the end of a group if
       the group isn't empty */

    if ( obj->objclass == FL_END_GROUP )
    {
        FL_OBJECT *o;

        for ( o = obj->form->first; o && o != obj; o = o->next )
        {
            /* Hack for fdesign to allow deletion of the FL_BEGIN_GROUP
               and FL_END_GROUP objects with the objects in the group
               (if there group ID was unset) */

            if (    o->group_id != obj->group_id
                 || ( o->parent && o->parent->group_id != obj->group_id ) )
                continue;

            if ( o->group_id == obj->group_id && o->objclass != FL_BEGIN_GROUP )
                break;
        }

        if ( o != obj )
        {
            M_err( "fl_delete_object", "Can't delete end of group object "
                   "while the group still has members" );
            return;
        }
    }

    /* If this object has childs also unlink them */

    if ( obj->child )
        fli_delete_composite( obj );

    form = obj->form;

    if ( obj->automatic )
    {
        form->num_auto_objects--;
        fli_recount_auto_objects( );
    }

    lose_focus( obj ); 

    if ( obj == fli_int.pushobj )
        fli_int.pushobj = NULL;
    if ( obj == fli_int.mouseobj )
        fli_int.mouseobj = NULL;

#ifdef DELAYED_ACTION
    fli_object_qflush_object( obj );
#endif

    /* Object also loses its group membership */

    if ( obj->objclass != FL_BEGIN_GROUP && obj->objclass != FL_END_GROUP )
        obj->group_id = 0;

    obj->form = NULL;

    if ( obj->prev )
        obj->prev->next = obj->next;
    else
        form->first = obj->next;

    if ( obj->next )
        obj->next->prev = obj->prev;
    else
        form->last = obj->prev;

    /* Redraw the form (except when the complete form is being deleted, in
       that case 'fli_fast_free_object' is set to the form being deleted) */

    if ( fli_fast_free_object != form && ! obj->parent )
    {
        fli_recalc_intersections( form );
        redraw( form, 1 );
    }
}


/***************************************
 * Frees the memory used by an object
 ***************************************/

void
fl_free_object( FL_OBJECT * obj )
{
    /* Check whether it's ok to free it */

    if ( ! obj )
    {
        M_err( "fl_free_object", "NULL object" );
        return;
    }

    /* If the object is the pseudo-object starting a group free the
       complete group */

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        FL_OBJECT *o,
                  *on;

        for ( o = obj->next; o && o->objclass != FL_END_GROUP; o = on )
        {
            on = o->next;

            /* Skip child objects, they get removed automatically when the
               parent gets deleted */

            while ( on->parent )
                on = on->next;

            fl_free_object( o );
        }

        if ( o )
            fl_free_object( o );
    }

    /* Avoid deleting an object that represents the end of a group if
       the group isn't empty */

    if ( obj->objclass == FL_END_GROUP )
    {
        FL_OBJECT *o;

        for ( o = obj->form->first; o && o != obj; o = o->next )
            if ( o->group_id == obj->group_id && o->objclass != FL_BEGIN_GROUP )
                break;

        if ( o != obj )
        {
            M_err( "fl_free_object", "Can't free end of group object "
                   "while the group still has members" );
            return;
        }
    }

    /* If the object hasn't yet been unlinked from its form do it know */

    if ( obj->form )
        fl_delete_object( obj );

    /* If this is a parent object free its children first */

    if ( obj->child )
        fli_free_composite( obj );

    /* If it's a child object remove it from the linked list of childs
       of the parent object */

    if ( obj->parent )
    {
        FL_OBJECT *o = obj->parent->child;

        if ( o == obj )
            obj->parent->child = obj->nc;
        else
        {
            while ( o->nc != obj )
                o = o->nc;
            o->nc = obj->nc;
        }
    }

    /* Make the object release all memory it may have allocated */

    fli_handle_object( obj, FL_FREEMEM, 0, 0, 0, NULL, 0 );

    /* Finally free all other memory we allocated for the object */

    fli_safe_free( obj->label );
    fli_safe_free( obj->tooltip );
    fli_safe_free( obj->shortcut );

    if ( obj->flpixmap )
    {
        fli_free_flpixmap( obj->flpixmap ) ;
        fli_safe_free( obj->flpixmap );
    }

    /* We might have arrived here due to a callback for the object we just
       deleted (or one of it's child objects). The following tests allow
       the routine that invoked the callback to check if that is the case
       and avoid further uses of the object/parent. */

    if ( obj == fli_handled_obj )
        fli_handled_obj = NULL;
    if ( obj == fli_handled_parent )
        fli_handled_parent = NULL;

    fl_free( obj );
}


/*-----------------------------------------------------------------------
   Setting/getting attributes.
-----------------------------------------------------------------------*/

/***************************************
 * Returns the object class of the object
 ***************************************/

int
fl_get_object_objclass( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_objclass", "NULL object" );
        return -1;
    }

    return obj->objclass;
}


/***************************************
 * Returns the type of the object
 ***************************************/

int
fl_get_object_type( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_type", "NULL object" );
        return -1;
    }

    return obj->type;
}


/***************************************
 * Sets the boxtype of the object
 ***************************************/

void
fl_set_object_boxtype( FL_OBJECT * obj,
                       int         boxtype )
{
    int need_show = 0;

    if ( ! obj )
    {
        M_err( "fl_set_object_boxtype", "NULL object" );
        return;
    }

    if ( obj->boxtype == boxtype )
        return;

    if ( obj->visible )
    {
        need_show = 1;
        fl_hide_object( obj );
    }

    obj->boxtype = boxtype;
    fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

    if ( need_show )
        fl_show_object( obj );
}


/***************************************
 * Returns the boxtype of the object
 ***************************************/

int
fl_get_object_boxtype( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_boxtype", "NULL object" );
        return -1;
    }

    return obj->boxtype;
}


/***************************************
 * Sets the resize property of an object
 ***************************************/

void
fl_set_object_resize( FL_OBJECT    * obj,
                      unsigned int   what )
{
    if ( ! obj )
    {
        M_err( "fl_set_object_resize", "NULL object" );
        return;
    }

    obj->resize = what & FL_RESIZE_ALL;

    /* Check if thr object has childs, if so also change all of them */

    if ( obj->child )
        fli_set_composite_resize( obj, obj->resize );

    /* Check if thr object is a group, if so also change all members */

    if ( obj->objclass == FL_BEGIN_GROUP )
        for ( obj = obj->next; obj && obj->objclass != FL_END_GROUP;
              obj = obj->next )
            fl_set_object_resize( obj, what );
}


/***************************************
 * Returns the resize setting of an object
 ***************************************/

void
fl_get_object_resize( FL_OBJECT    * obj,
                      unsigned int * resize )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_resize", "NULL object" );
        return;
    }

    if ( resize )
        *resize = obj->resize;
}


/***************************************
 * Sets the gravity properties of an object
 ***************************************/

void
fl_set_object_gravity( FL_OBJECT    * obj,
                       unsigned int   nw,
                       unsigned int   se )
{
    if ( ! obj )
    {
        M_err( "fl_set_object_gravity", "NULL object" );
        return;
    }

    obj->nwgravity = nw;
    obj->segravity = se;

    /* Check if the object has childs, if so also change all of them */

    if ( obj->child )
        fli_set_composite_gravity( obj, nw, se );

    /* Check if object is a group, if so change also all members */

    if ( obj->objclass == FL_BEGIN_GROUP )
        for ( ; obj && obj->objclass != FL_END_GROUP; obj = obj->next )
        {
            obj->nwgravity = nw;
            obj->segravity = se;
            fli_set_composite_gravity( obj, nw, se );
        }
}


/***************************************
 * Returns the gravity settings for an object
 ***************************************/
void
fl_get_object_gravity( FL_OBJECT    * obj,
                       unsigned int * nw,
                       unsigned int * se )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_gravity", "NULL object" );
        return;
    }

    if ( nw )
        *nw = obj->nwgravity;
    if ( se )
        *se = obj->segravity;
}


/***************************************
 * Sets the color of the object
 ***************************************/

void
fl_set_object_color( FL_OBJECT * obj,
                     FL_COLOR    col1,
                     FL_COLOR    col2 )
{
    FL_COLOR old_col1;

    if ( ! obj )
    {
        M_err( "fl_set_object_color", "NULL object" );
        return;
    }

    if ( col1 >= FL_MAX_COLORS || col2 >= FL_MAX_COLORS )
    {
        M_err( "fl_set_object_color", "Invalid color" );
        return;
    }

    if (    obj->col1 == col1
         && obj->col2 == col2
         && obj->objclass != FL_TABFOLDER )
        return;

    old_col1 = obj->col1;

    obj->col1 = col1;
    obj->col2 = col2;
    fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

    /* If this is the object for the background of the form all of its
       objects must be told about the new color. */

    if (    obj->col1 != old_col1
         && obj == bg_object( obj->form ) )
    {
        FL_OBJECT *o;

        for ( o = obj->next; o; o = o->next )
            o->dbl_background = col1;
    }

    if ( obj->objclass == FL_TABFOLDER )
        fli_set_tab_color( obj, col1, col2 );

    fl_redraw_object( obj );
}


/***************************************
 * Returns the colors of the object
 ***************************************/

void
fl_get_object_color( FL_OBJECT * obj,
                     FL_COLOR  * col1,
                     FL_COLOR  * col2 )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_color", "NULL object" );
        return;
    }

    if ( col1 )
        *col1 = obj->col1;
    if ( col2 )
        *col2 = obj->col2;
}


/***************************************
 * If called with a non-zero value for 'timeout' the object will
 * receive FL_DBLCLICK events if the mouse is clicked twice within
 * 'timeout' milliseconds, if called with 0 no FL_DBLCLICK events
 * are received.
 ***************************************/

void
fl_set_object_dblclick( FL_OBJECT     * obj,
                        unsigned long   timeout )
{
    if ( ! obj )
    {
        M_err( "fl_set_object_dblclick", "NULL object" );
        return;
    }

    obj->click_timeout = timeout;
}


/***************************************
 * Returns the double click timeout for the object
 ***************************************/

unsigned long
fl_get_object_dblclick( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_dblclick", "NULL object" );
        return ULONG_MAX;
    }

    return obj->click_timeout;
}


/***************************************
 ***************************************/

void
fl_set_object_dblbuffer( FL_OBJECT * obj,
                         int         yesno )
{
    FL_OBJECT *o;;

    if ( ! obj )
    {
        M_err( "fl_set_object_dblbuffer", "NULL object" );
        return;
    }

    /* Never bother with composite objects */

    if ( obj->child || obj->parent )
        return;

    if ( obj->use_pixmap == yesno )
        return;

    obj->use_pixmap = yesno ? 1 : 0;

    /* Figure out the background color to be used */

    if ( obj->form && ( o = bg_object( obj->form ) ) )
        obj->dbl_background = o->col1;
}


/* Test if an object is really visible */

#define ObjIsVisible( obj )  (    ( obj )->visible                        \
                               && ( obj )->form                           \
                               && ( obj )->form->visible == FL_VISIBLE )


/***************************************
 * Sets the label of an object
 ***************************************/

void
fl_set_object_label( FL_OBJECT  * obj,
                     const char * label )
{
    int need_show = 0;

    if ( ! obj )
    {
        M_err( "fl_set_object_label", "NULL object" );
        return;
    }

    if ( ! label )
        label = "";

    if ( ! strcmp( obj->label, label )  )
        return;

    if ( OL( obj ) && obj->visible )
    {
        need_show = 1; 
        fl_hide_object( obj );
    }

    obj->label = fl_realloc( obj->label, strlen( label ) + 1 );
    strcpy( obj->label, label );

    if ( need_show )
        fl_show_object( obj );
    else if ( obj->visible )
    {
        fli_recalc_intersections( obj->form );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Sets the label of an object using a format string and an appropriate
 * number of (unspecified) argiments
 ***************************************/

void
fl_set_object_label_f( FL_OBJECT  * obj,
                       const char * fmt,
                       ... )
{
    char * buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_set_object_label( obj, buf );
    fl_free( buf );
}


/***************************************
 * Returns the objects label string
 ***************************************/

const char *
fl_get_object_label( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_label", "NULL object" );
        return NULL;
    }

    return obj->label;
}


/***************************************
 * Sets the label color of an object
 ***************************************/

void
fl_set_object_lcol( FL_OBJECT * obj,
                    FL_COLOR    lcol )
{
    FL_FORM * form;

    if ( ! obj )
    {
        M_err( "fl_set_object_lcol", "NULL object" );
        return;
    }

    form = obj->form;

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        obj->lcol = lcol;

        if ( form )
            fl_freeze_form( form );

        for ( obj = obj->next; obj && obj->objclass != FL_END_GROUP;
              obj = obj->next )
            fl_set_object_lcol( obj, lcol );

        if ( form )
            fl_unfreeze_form( form );
    }
    else if ( obj->lcol != lcol )
    {
        obj->lcol = lcol;

        if ( obj->objclass == FL_TABFOLDER )
            fli_set_tab_lcolor( obj, lcol );

        fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Returns the label color of an object
 ***************************************/

FL_COLOR
fl_get_object_lcol( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_lcol", "NULL object" );
        return FL_NOCOLOR;
    }

    return obj->lcol;
}


/***************************************
 * Sets the label's text size of an object
 ***************************************/

void
fl_set_object_lsize( FL_OBJECT * obj,
                     int         lsize )
{
    FL_OBJECT *o;
    int need_show = 0;

    if ( ! obj )
    {
        M_err( "fl_set_object_lsize", "NULL object" );
        return;
    }

    if ( obj->objclass != FL_BEGIN_GROUP && obj->lsize == lsize )
        return;

    /* For objects that have their label on the outside (or that are
       transparent) we hide the object and, after setting the new label font
       size, re-show them in order to get everything beneath them redrawn */

    if ( OL( obj ) && obj->visible )
    {
        need_show = 1; 
        fl_hide_object( obj );
    }

    obj->lsize = lsize;
    fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

    if ( obj->objclass == FL_TABFOLDER )
        fli_set_tab_lsize( obj, lsize );

    if ( obj->objclass == FL_BEGIN_GROUP )
        for ( o = obj->next; o && o->objclass != FL_END_GROUP; o = o->next )
        {
            obj->lsize = lsize;
            fli_handle_object( o, FL_ATTRIB, 0, 0, 0, NULL, 0 );
        }

    if ( need_show )
        fl_show_object( obj );
    else if ( obj->visible )
    {
        fli_recalc_intersections( obj->form );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Returns the labels text size of an object
 ***************************************/

int
fl_get_object_lsize( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_lsize", "NULL object" );
        return -1;
    }

    return obj->lsize;
}


/***************************************
 * Sets the label style of an object
 ***************************************/

void
fl_set_object_lstyle( FL_OBJECT * obj,
                      int         lstyle )
{
    FL_OBJECT *o;
    int need_show = 0;

    if ( ! obj )
    {
        M_err( "fl_set_object_lstyle", "NULL object" );
        return;
    }

    if ( obj->objclass != FL_BEGIN_GROUP && obj->lstyle == lstyle )
        return;

    if ( OL( obj ) && obj->visible )
    {
        need_show = 1; 
        fl_hide_object( obj );
    }

    obj->lstyle = lstyle;
    fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

    if ( obj->objclass == FL_TABFOLDER )
        fli_set_tab_lstyle( obj, lstyle );

    if ( obj->objclass == FL_BEGIN_GROUP )
        for ( o = obj->next; o && o->objclass != FL_END_GROUP; o = o->next )
        {
            obj->lstyle = lstyle;
            fli_handle_object( o, FL_ATTRIB, 0, 0, 0, NULL, 0 );
        }

    if ( need_show )
        fl_show_object( obj );
    else if ( obj->visible )
    {
        fli_recalc_intersections( obj->form );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Returns the label style of an object
 ***************************************/

int
fl_get_object_lstyle( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_lstyle", "NULL object" );
        return -1;
    }

    return obj->lstyle;
}


/***************************************
 * Sets the label alignment of an object
 ***************************************/

void
fl_set_object_lalign( FL_OBJECT * obj,
                      int         align )
{
    int need_show = 0;

    if ( ! obj )
    {
        M_err( "fl_set_object_lalign", "NULL object" );
        return;
    }

    if ( fl_is_center_lalign( align ) )
        align = FL_ALIGN_CENTER;

    if ( ! fli_test_lalign( align, "fl_set_object_lalign" ) )
        return;

    if ( OL( obj ) && obj->visible )
    {
        need_show = 1; 
        fl_hide_object( obj );
    }

    obj->align = align;
    fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

    if ( obj->objclass == FL_TABFOLDER )
        fli_set_tab_lalign( obj, align );

    if ( need_show )
        fl_show_object( obj );
    else if ( obj->visible )
    {
        fli_recalc_intersections( obj->form );
        fl_redraw_object( obj );
    }
}


/***************************************
 * Returns the label alignment of an object
 ***************************************/

int
fl_get_object_lalign( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_lalign", "NULL object" );
        return -1;
    }

    return obj->align;
}


/***************************************
 * Makes an object active
 ***************************************/

static void
activate_object( FL_OBJECT * obj )
{
    if ( obj->active )
        return;

    obj->active = 1;

    if ( obj->input && obj->active && ! obj->form->focusobj )
        fl_set_focus_object( obj->form, obj );

    if ( obj->child )
        fli_activate_composite( obj );
}


/***************************************
 * Public function for making an object active
 ***************************************/

void
fl_activate_object( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_activate_object", "NULL object" );
        return;
    }

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        obj->active = 1;

        for ( obj = obj->next; obj && obj->objclass != FL_END_GROUP;
              obj = obj->next )
            activate_object( obj );
    }
    else
        activate_object( obj );
}


/***************************************
 * Deactivates an object
 ***************************************/

static void
deactivate_object( FL_OBJECT * obj )
{
    if ( ! obj->active )
        return;

    obj->active = 0;
    lose_focus( obj );

    if ( obj->child )
        fli_deactivate_composite( obj );
}


/***************************************
 * Public function for deactivating an object
 ***************************************/

void
fl_deactivate_object( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_deactive_object", "NULL object" );
        return;
    }

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        obj->active = 0;

        for ( obj = obj->next;
              obj && obj->objclass != FL_END_GROUP;
              obj = obj->next )
            deactivate_object( obj );
    }
    else
        deactivate_object( obj );
}


/***************************************
 * Returns if an object is in active state, i.e. reacting to events
 ***************************************/

int
fl_object_is_active( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_object_is_active", "NULL object" );
        return 0;
    }

    return obj->active;
}


/***************************************
 * Makes an object visible and sets the visible flag to 1
 ***************************************/

void
fli_show_object( FL_OBJECT * obj )
{
    if ( obj->visible )
        return;

    obj->visible = 1;

    if ( obj->child )
    {
        fli_show_composite( obj );
        fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );
    }

    if ( obj->input && obj->active && obj->form && ! obj->form->focusobj )
        fl_set_focus_object( obj->form, obj );
}


/***************************************
 * Public function for making an object visible
 ***************************************/

void
fl_show_object( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_show_object", "NULL object" );
        return;
    }

     if ( obj->objclass == FL_BEGIN_GROUP )
     {
         FL_OBJECT *o;

         for ( o = obj->next; o && o->objclass != FL_END_GROUP; o = o->next )
             fli_show_object( o );
     }
     else
         fli_show_object( obj );

     fli_recalc_intersections( obj->form );
     fl_redraw_object( obj );
}


/***************************************
 * Returns if an object is shown (given that the form it
 * belongs to is visible!)
 ***************************************/

int
fl_object_is_visible( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_object_is_visible", "NULL object" );
        return 0;
    }

    return obj->visible;
}


/***************************************
 * Sets an object up for being hidden and
 * adds the area it covers to a region
 ***************************************/

void
fli_hide_and_get_region( FL_OBJECT * obj,
                         Region    * reg )
{
    FL_RECT xrect;  

#ifdef DELAYED_ACTION
    /* Remove all entries for the object from the object queue */

    fli_object_qflush_object( obj );
#endif

    if ( ! FORM_IS_UPDATABLE( obj->form ) )
    {
        obj->visible = 0;

        /* If the form is just frozen remember this because when the form
           laten becomes unfrozen it needs a complete redraw (and not just
           a redraw of all modified objects) */

        if ( obj->form && obj->form->frozen )
            obj->form->in_redraw |= HIDE_WHILE_FROZEN;

        return;
    }

    /* The object can't be the object anymore that has the focus and it also
       can't be the pushed object or the object the mouse is on */

    lose_focus( obj );
    if ( obj == fli_int.pushobj )
        fli_int.pushobj = NULL;
    if ( obj == fli_int.mouseobj )
        fli_int.mouseobj = NULL;

    /* Get the area the object covers and add that to the region passed 
       to the function */

    if ( obj->objclass == FL_CANVAS || obj->objclass == FL_GLCANVAS )
        fli_hide_canvas( obj );

    get_object_rect( obj, &xrect, 0 );

    XUnionRectWithRegion( &xrect, *reg, *reg );

    /* Mark it as invisible (must be last, fli_hide_canvas() tests for
       visibility and doesn't do anything if already marked as invisible) */

    obj->visible = 0;
}


/***************************************
 * Makes an object (and all its children) invisible
 ***************************************/

void
fl_hide_object( FL_OBJECT * obj )
{
    FL_OBJECT *tmp;
    FL_RECT xrect;
    Region reg;

    if ( ! obj )
    {
        M_err( "fl_hide_object", "NULL object" );
        return;
    }

    if ( ! obj->visible )
    {
        M_warn( "fl_hide_object", "Object '%s' already is invisible",
                obj->label ? obj->label : "Object" );
        return;
    }

    reg = XCreateRegion( );

    /* If this is an object that marks the start of a group hide all
       objects that belong to the group */

    if ( obj->objclass == FL_BEGIN_GROUP )
        for ( tmp = obj->next; tmp && tmp->objclass != FL_END_GROUP;
              tmp = tmp->next )
        {
            if ( tmp->child )
            {
                fli_hide_composite( tmp, &reg );
                fli_handle_object( tmp, FL_ATTRIB, 0, 0, 0, NULL, 0 );
            }

            fli_hide_and_get_region( tmp, &reg );
        }
    else
    {
        if ( obj->child )
        {
            fli_hide_composite( obj, &reg );
            fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );
        }

        fli_hide_and_get_region( obj, &reg );
    }

    /* No redraw is needed if the object has no form or the form isn't shown
       or is frozen. */

    if ( ! FORM_IS_UPDATABLE( obj->form ) )
    {
        XDestroyRegion( reg );
        return;
    }

    /* Determine the rectangle that covers the area of the object */

    XClipBox( reg, &xrect );
    XDestroyRegion( reg );

    /* Redraw only the area covered by the object */

    fli_set_global_clipping( xrect.x, xrect.y, xrect.width, xrect.height );
    redraw( obj->form, 1 );
    fli_unset_global_clipping( );
}


/***************************************
 * Sets the list of shortcuts for the object. Shortcuts are specified
 * with a string with the following special sequences:
 * '^x'  stands for  Ctrl-x (for a-z case doesn't matter)
 * '#x'  stands for  Alt-x (case matters!)
 * '&n'  with n = 1,...,34 stands for function key n
 * '&A', '&B', '&C' '&D'  stand for up down, right and left cursor keys
 * '^[' stand for escape key
 * '^^  stand for '^'
 * '^#' stand for '#'
 * '^&' stand for '&'
 * Note: '&' followed by anything else than the above will be skipped,
 * e.g. '&E' or '&0'. If '&' is followed by a number larger than 34
 * only the first digit of the number is used.
 * Not escapable are Crtl-^, Crtl-# and Ctrl-&.
 ***************************************/

#include <ctype.h>

int
fli_convert_shortcut( const char * str,
                      long       * sc )
{
    int i = 0;
    long offset = 0;
    const char *c;

    for ( c = str; *c && i < MAX_SHORTCUTS; c++ )
    {
        switch ( *c )
        {
            case '^' :
                if ( offset & FL_CONTROL_MASK && c[ -1 ] == '^' )
                {
                    sc[ i++ ] = '^' + offset - FL_CONTROL_MASK;
                    offset = 0;
                }
                else
                {
                    if ( c[ 1 ] == '[' )
                    {
                        sc[ i++ ] = 0x1b;
                        c++;
                        offset = 0;
                    }
                    else
                        offset += FL_CONTROL_MASK;
                }
                break;

            case '#' :
                if ( offset & FL_CONTROL_MASK && c[ -1 ] == '^' )
                {
                    sc[ i++ ] = '#' + offset - FL_CONTROL_MASK;
                    offset = 0;
                }
                else
                    offset += FL_ALT_MASK;
                break;

            case '&' :
                if ( offset & FL_CONTROL_MASK && c[ -1 ] == '^' )
                {
                    sc[ i++ ] = '&' + offset - FL_CONTROL_MASK;
                    offset = 0;
                    break;
                }
                else if ( c[ 1 ] == 'A' )
                    sc[ i++ ] = XK_Up + offset;
                else if ( c[ 1 ] == 'B' )
                    sc[ i++ ] = XK_Down + offset;
                else if ( c[ 1 ] == 'C' )
                    sc[ i++ ] = XK_Right + offset;
                else if ( c[ 1 ] == 'D' )
                    sc[ i++ ] = XK_Left + offset;
                else if (    isdigit( ( unsigned char ) c[ 1 ] )
                          && c[ 1 ] > '0' )
                {
                    long j = c[ 1 ]  - '0';

                    if (    isdigit( ( unsigned char ) c[ 2 ] )
                         && 10 * j + c[ 2 ] - '0' <= 35 )
                    {
                         j = 10 * c[ 2 ] - '0';
                         c++;
                    }
                    sc[ i++ ] = offset + XK_F1 + j - 1;
                }
                offset = 0;
                c++;
                break;

            default :
                if ( offset & ( FL_CONTROL_MASK | FL_ALT_MASK ) )
                {
                    sc[ i ] = toupper( ( int ) *c );
                    if ( offset & FL_CONTROL_MASK )
                        sc[ i ] -= 'A' - 1;
                    sc[ i++ ] += offset & ~ FL_CONTROL_MASK;
                }
                else
                    sc[ i++ ] = *c + offset;
                offset = 0;
                break;
        }
    }

    sc[ i ] = 0;

    if ( *c )
    {
        M_err( "fli_convert_shortcut", "Too many shortcuts (>%d)",
               MAX_SHORTCUTS );
    }

    return i;
}


/***************************************
 ***************************************/

int
fli_get_underline_pos( const char * label,
                       const char * sc )
{
    int c;
    const char *p;

    /* Find the first non-special char in the shortcut string */

    for ( c = '\0', p = sc; ! c && *p; p++ )
    {
        if ( isalnum( ( unsigned char ) *p ) )
        {
            if ( p == sc )
                c = *p;
            else if (    * ( p - 1 ) != '&'
                      && ! isdigit( ( unsigned char ) * ( p - 1 ) ) )
                c = *p;
        }
    }

    if ( ! c )
        return -1;

    /* Find where the match occurs */

    if ( c == *sc )
        p = strchr( label, c );
    else if ( ! ( p = strchr( label, c ) ) )
        p = strchr( label, islower( ( unsigned char ) c ) ?
                    toupper( c ) : tolower( c ) );

    if ( ! p )
        return -1;

    return p - label + 1;
}


/***************************************
 ***************************************/

void
fl_set_object_shortcut( FL_OBJECT  * obj,
                        const char * sstr,
                        int          showit )
{
    int scsize,
        n;
    long sc[ MAX_SHORTCUTS + 1 ];      /* converted shortcuts - we need one
                                          more than max for trailing 0 */

    if ( ! obj )
    {
        M_err( "fl_set_object_shortcut", "NULL object" );
        return;
    }

    if ( ! sstr || ! *sstr )
    {
        *obj->shortcut = 0;
        return;
    }

    n = fli_convert_shortcut( sstr, sc );
    scsize = ( n + 1 ) * sizeof *obj->shortcut;
    obj->shortcut = fl_realloc( obj->shortcut, scsize );
    memcpy( obj->shortcut, sc, scsize );

    if (    ! showit
         || ! obj->label
         || ! *obj->label
         || *obj->label == '@' )
        return;

    /* Find out where to underline */

    if (    ( n = fli_get_underline_pos( obj->label, sstr ) ) > 0
         && ! strchr( obj->label, *fl_ul_magic_char ) )
    {
        size_t len = strlen( obj->label ) + 1;

        obj->label = fl_realloc( obj->label, len + 1 );
        memmove( obj->label + n + 1, obj->label + n, len - n );
        obj->label[ n ] = *fl_ul_magic_char;
    }
}


/***************************************
 * Set a shortcut with keysyms directly
 ***************************************/

void
fl_set_object_shortcutkey( FL_OBJECT    * obj,
                           unsigned int   keysym )
{
    size_t n;

    for ( n = 0; obj->shortcut[ n ]; n++ )
        /* empty */;

    /* Always have a terminator, thus n + 2 */

    obj->shortcut = fl_realloc( obj->shortcut,
                                ( n + 2 ) * sizeof *obj->shortcut );
    obj->shortcut[ n ] = keysym;
    obj->shortcut[ n + 1 ] = 0;
}


/***************************************
 * Sets the object in the form that gets keyboard input.
 ***************************************/

void
fl_set_focus_object( FL_FORM   * form,
                     FL_OBJECT * obj )
{
    if ( ! form )
    {
        M_err( "fl_set_focus_object", "NULL form" );
        return;
    }

    if ( obj == form->focusobj )
        return;

    if ( form->focusobj )
        fli_handle_object( form->focusobj, FL_UNFOCUS, 0, 0, 0, NULL, 0 );
    fli_handle_object( obj, FL_FOCUS, 0, 0, 0, NULL, 0 );
}


/***************************************
 * Returns the object that has the focus (take care, 'focusobj'
 * may be set to an input object that's a child of the object
 * we need to return)
 ***************************************/

FL_OBJECT *
fl_get_focus_object( FL_FORM * form )
{
    FL_OBJECT *fo = NULL;;

    if ( form && ( fo = form->focusobj ) )
        while ( fo->parent )
            fo = fo->parent;
    
    return fo;
}


/*-----------------------------------------------------------------------
   Searching in forms
-----------------------------------------------------------------------*/

/***************************************
 * Returns an object of type 'find' in a form, starting at 'obj'.
 * If the function does not return an object the event that
 * triggered the call will be eaten. This is how the deactived
 * and inactive objects reject events.
 * Modify with care!
 ***************************************/

FL_OBJECT *
fli_find_object( FL_OBJECT * obj,
                 int         find,
                 FL_Coord    mx,
                 FL_Coord    my )
{
    while ( obj )
    {
        if (    obj->objclass != FL_BEGIN_GROUP
             && obj->objclass != FL_END_GROUP
             && obj->visible
             && (     obj->active
                  || ( obj->posthandle && ! obj->active )
                  || ( obj->tooltip && *obj->tooltip && ! obj->active ) ) )
        {
            if ( find == FLI_FIND_INPUT && obj->input && obj->active )
                return obj;

            if ( find == FLI_FIND_AUTOMATIC && obj->automatic )
                return obj;

            if ( find == FLI_FIND_RETURN && obj->type == FL_RETURN_BUTTON )
                return obj;

            if (    find == FLI_FIND_MOUSE
                 && mx >= obj->x
                 && mx <= obj->x + obj->w
                 && my >= obj->y
                 && my <= obj->y + obj->h )
                return obj;

            if ( find == FLI_FIND_KEYSPECIAL && obj->wantkey & FL_KEY_SPECIAL )
                return obj;
        }

        obj = obj->next;
    }

    return NULL;
}


/***************************************
 * Same as above but going backwards through the linked list of objects.
 ***************************************/

FL_OBJECT *
fli_find_object_backwards( FL_OBJECT * obj,
                           int         find,
                           FL_Coord    mx,
                           FL_Coord    my )
{
    for ( ; obj; obj = obj->prev )
        if (    obj->objclass != FL_BEGIN_GROUP
             && obj->objclass != FL_END_GROUP
             && obj->visible
             && (     obj->active
                  || ( obj->posthandle && ! obj->active )
                  || ( obj->tooltip && *obj->tooltip && ! obj->active ) ) )
        {
            if ( find == FLI_FIND_INPUT && obj->input && obj->active )
                return obj;

            if ( find == FLI_FIND_AUTOMATIC && obj->automatic )
                return obj;

            if (    find == FLI_FIND_MOUSE
                 && mx >= obj->x
                 && mx <= obj->x + obj->w
                 && my >= obj->y
                 && my <= obj->y + obj->h )
                return obj;

            if ( find == FLI_FIND_KEYSPECIAL && obj->wantkey & FL_KEY_SPECIAL )
                return obj;
        }

    return NULL;
}


/***************************************
 * Returns the first object of type 'find' in 'form'
 ***************************************/

FL_OBJECT *
fli_find_first( FL_FORM  * form,
                int        find,
                FL_Coord   mx,
                FL_Coord   my )
{
    return fli_find_object( form->first, find, mx, my );
}


/***************************************
 * Returns the last object of the type find
 ***************************************/

FL_OBJECT *
fli_find_last( FL_FORM * form,
               int       find,
               FL_Coord  mx,
               FL_Coord  my )
{
    FL_OBJECT *last,
              *obj;

    last = obj = fli_find_first( form, find, mx, my );

    while ( obj )
    {
        last = obj;
        obj = fli_find_object( obj->next, find, mx, my );
    }

    return last;
}


/*-----------------------------------------------------------------------
   Drawing Routines.
-----------------------------------------------------------------------*/


/***************************************
 ***************************************/

static int
is_object_clipped( FL_OBJECT * obj )
{
    FL_RECT obj_rect,
            *xc;

    if ( ! fl_is_global_clipped( ) )
        return 0;

    get_object_rect( obj, &obj_rect, 1 );

    xc = fli_intersect_rects( &obj_rect, fli_get_global_clip_rect( ) );

    if ( ! xc )
        return 1;

    fl_free( xc );
    return 0;
}


/***************************************
 * Marks an object (and other objects them also needing a redraw)
 * for redraw
 ***************************************/

static void
mark_object_for_redraw( FL_OBJECT * obj )
{
    FL_OBJECT *o;

    if ( ! obj )
    {
        M_err( "mark_object_for_redraw", "Redrawing NULL object" );
        return;
    }

    if  (    obj->redraw
          || ! obj->form
          || ! obj->visible
          || ( obj->parent && ! obj->parent->visible )
          || obj->objclass == FL_BEGIN_GROUP
          || obj->objclass == FL_END_GROUP )
        return;

    obj->redraw = 1;

    /* Also mark all child objects for redraw */

    for ( o = obj->child; o; o = o->nc )
        mark_object_for_redraw( o );

    /* If an object is marked as being under another object we have to find
       the object(s) it is beneath and also mark them for a redraw. For the
       special case that the object to be redrawn is the first object of
       the form (i.e. the one for the background) we don't have to check
       if the other objects are on top of it, they all are. */

    if ( obj == bg_object( obj->form ) )
    {
        for ( o = obj->next; o; o = o->next )
        {
            if (    ! o->visible
                 || ( o->parent && ! o->parent->visible )
                 || o->objclass == FL_BEGIN_GROUP
                 || o->objclass == FL_END_GROUP )
                continue;

            obj->redraw = 1;
        }
    }
    else if ( obj->is_under )
    {
        /* If it hasn't been done yet pre-calculate the sizes of all
           objects possibly concerned */

        int need_finish = prep_recalc( obj->form, obj );
        int cnt = 0;

        for ( o = obj->next; o; o = o->next )
        {
            if (    o->redraw
                 || ! o->visible
                 || ( o->parent && ! o->parent->visible )
                 || o->objclass == FL_BEGIN_GROUP
                 || o->objclass == FL_END_GROUP )
                continue;

            if ( objects_intersect( obj, o ) )
            {
                mark_object_for_redraw( o );

                /* Since we know how many objects are on top of our object
                   we can stop if all of them have been marked for redraw. */

                if ( ++cnt >= obj->is_under )
                    break;
            }
        }

        if ( need_finish )
            finish_recalc( obj->form, obj );
    }
}


/***************************************
 * Function for (re)drawing an object
 ***************************************/

void
fl_redraw_object( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_redraw_object", "NULL object" );
        return;
    }

    if ( ! obj->form || ! obj->visible )
        return;

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        FL_OBJECT *o = obj->next;

        /* If it hasn't been done yet pre-calculate the sizes of all
            objects possibly concerned */

        int need_finish = prep_recalc( o->form, o );

        for ( ; o && o->objclass != FL_END_GROUP; o = o->next )
            mark_object_for_redraw( o );

        if ( need_finish )
            finish_recalc( obj->form, obj->next ); 
    }
    else
        mark_object_for_redraw( obj );

    redraw( obj->form, 0 );
}


/***************************************
 * Function to test if the areas of two objects (including their labels if
 * they're outside the object) intersect
 ***************************************/

static int
objects_intersect( const FL_OBJECT * obj1,
                   const FL_OBJECT * obj2 )
{
    if ( tmp_vdata )
    {
        FL_RECT *r1 = obj1->u_vdata,
                *r2 = obj2->u_vdata;

        return    r1->x + r1->width  > r2->x
               && r2->x + r2->width  > r1->x
               && r1->y + r1->height > r2->y
               && r2->y + r2->height > r1->y;

    }
    else
    {
        FL_RECT r1, r2;

        get_object_rect( obj1, &r1, 0 );
        get_object_rect( obj2, &r2, 0 );

        return    r1.x + r1.width  > r2.x
               && r2.x + r2.width  > r2.x
               && r1.y + r1.height > r2.y
               && r2.y + r2.height > r1.y;
    }
}


/***************************************
 * Redraws a form or only a subset of its objects - when called with the
 * 'draw_all' argument being set it redraws the complete form with all its
 * objects while, with 'draw_all' being unset (when getting call from e.g.
 * fl_redraw_object() or fl_unfreeze_form()), only draws those objects that
 * are marked for needing a redraw (and all objects as well that would be
 * obscured by that because they're "higher up").
 ***************************************/

static void
redraw( FL_FORM * form,
        int       draw_all )
{
    FL_OBJECT *obj;

    /* If the form is invisible or frozen we're already done */

    if ( ! FORM_IS_UPDATABLE( form ) || ( form->in_redraw & IN_REDRAW ) )
        return;

    form->in_redraw |= IN_REDRAW;

    /* Remember when we're asked to do a full redraw - we might leave without
       drawing at all since the form is invisible or frozen and then the next
       time the function is called, even for a partial redraw, we need to draw
       all its objects. */

    form->needs_full_redraw = form->needs_full_redraw || draw_all;

    /* Set the window (or drawable) to be drawn and, if necessary, set up
       a pixmap for the form */

    fli_set_form_window( form );
    fli_create_form_pixmap( form );

    for ( obj = bg_object( form ); obj; obj = obj->next )
    {
        int needs_redraw = obj->redraw;

        obj->redraw = 0;

        /* Only draw objects that are visible and, unless we're asked to draw
           all objects, are marked for a redraw and are within the current
           clipping area */

        if (    ! obj->visible
             || ! ( needs_redraw || form->needs_full_redraw )
             || obj->objclass == FL_BEGIN_GROUP
             || obj->objclass == FL_END_GROUP
             || is_object_clipped( obj ) )
            continue;

        /* Set up a pixmap for the object (does nothing if the form already
           has a pixmap we're drawing to) */

        fli_create_object_pixmap( obj );

        /* Don't allow free objects to draw outside of their boxes. */

        if ( obj->objclass == FL_FREE )
        {
            fl_set_clipping( obj->x, obj->y, obj->w, obj->h );
            fl_set_text_clipping( obj->x, obj->y, obj->w, obj->h );
        }

        fli_handle_object( obj, FL_DRAW, 0, 0, 0, NULL, 0 );

        if ( obj->objclass == FL_FREE )
        {
            fl_unset_clipping( );
            fl_unset_text_clipping( );
        }

        /* Copy the objects pixmap to the form window (does nothing if the
           form has a pixmap we're drawing to since then we've drawn to it) */

        fli_show_object_pixmap( obj );

        fli_handle_object( obj, FL_DRAWLABEL, 0, 0, 0, NULL, 0 );
    }

    /* Copy the forms pixmap to its window (if double buffering is on) */

    fli_show_form_pixmap( form );

    form->needs_full_redraw = 0;
    form->in_redraw &= ~ IN_REDRAW;
}


/***************************************
 * Exported function for drawing a form
 ***************************************/

void
fl_redraw_form( FL_FORM * form )
{
    fli_recalc_intersections( form );
    redraw( form, 1 );
}


/***************************************
 * Disables drawing of form
 ***************************************/

void
fl_freeze_form( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_freeze_form", "NULL form" );
        return;
    }

    form->frozen++;
}


/***************************************
 * Enables drawing of form
 ***************************************/

void
fl_unfreeze_form( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_unfreeze_form", "NULL form" );
        return;
    }

    if ( form->frozen == 0 )
    {
        M_err( "fl_unfreeze_form", "Unfreezing non-frozen form" );
        return;
    }

    /* If the form becomes unfrozen at last and is visible recalculate
       overlaps between the objects and then redraw all objects that have
       been marked for a redraw since it became frozen or, if some objects
       became hidden during that time, all objects. */

    if ( --form->frozen == 0 && form->visible == FL_VISIBLE )
    {
        fli_recalc_intersections( form );
        redraw( form, form->in_redraw & HIDE_WHILE_FROZEN );
        form->in_redraw &= ~ HIDE_WHILE_FROZEN;
    }
}


/*-----------------------------------------------------------------------
   Handling Routines.
-----------------------------------------------------------------------*/

/***************************************
 * Should only be used as a response to FL_UNFOCUS
 ***************************************/

void
fl_reset_focus_object( FL_OBJECT * obj )
{
    refocus = obj;
}

/*** handle tooltips ***/


/***************************************
 ***************************************/

static
FL_OBJECT * get_parent( FL_OBJECT * obj )
{
    if ( obj )
        while ( obj->parent && obj->parent != obj )
            obj = obj->parent;

    return obj;
}


/***************************************
 ***************************************/

static
void tooltip_handler( int    ID  FL_UNUSED_ARG,
                      void * data )
{
    FL_OBJECT * const obj = get_parent( data );

    if ( obj->tooltip && *obj->tooltip && obj->visible )
        fli_show_tooltip( obj->tooltip, obj->form->x + obj->x,
                          obj->form->y + obj->y + obj->h + 1 );
    obj->tipID = 0;
}


/***************************************
 ***************************************/

static
void checked_hide_tooltip( FL_OBJECT * obj,
                           XEvent    * xev )
{
    FL_OBJECT * const parent = get_parent( obj );
    char const * const tooltip = parent->tooltip;

    if ( ! tooltip || ! *tooltip )
        return;

    /* If obj is part of a composite widget, it may well be that we're
       leaving a child widget but are still within the parent.
       If that is the case, we don't want to hide the tooltip at all. */

    if (    parent != obj
         && xev
         && xev->xmotion.x >= parent->x
         && xev->xmotion.x <= parent->x + parent->w
         && xev->xmotion.y >= parent->y
         && xev->xmotion.y <= parent->y + parent->h )
        return;

    fli_hide_tooltip( );

    if ( parent->tipID )
    {
        fl_remove_timeout( parent->tipID );
        parent->tipID = 0;
    }
}


/***************************************
 ***************************************/

static
void unconditional_hide_tooltip( FL_OBJECT * obj )
{
    FL_OBJECT * const parent = get_parent( obj );

    fli_hide_tooltip( );
    if ( parent->tipID )
    {
        fl_remove_timeout( parent->tipID );
        parent->tipID = 0;
    }
}


/***************************************
 * Handles an event for an object
 ***************************************/

static int
handle_object( FL_OBJECT * obj,
               int         event,
               FL_Coord    mx,
               FL_Coord    my,
               int         key,
               XEvent    * xev,
               int         keep_ret )
{
    static unsigned long last_clicktime = 0;
    static int last_dblclick = 0,
               last_key = 0;
    static FL_Coord last_mx,
                    last_my;
    int cur_event;
    FL_OBJECT *p;

    if ( ! obj )
        return FL_RETURN_NONE;

#if FL_DEBUG >= ML_WARN
    if (    ! obj->form
         && event != FL_FREEMEM
         && event != FL_ATTRIB
         && event != FL_RESIZED )
    {
        M_err( "handle_object", "Bad object '%s', event = %s",
               obj->label ? obj->label : "",
               fli_event_name( event ) );
        return FL_RETURN_NONE;
    }
#endif

    if ( obj->objclass == FL_BEGIN_GROUP || obj->objclass == FL_END_GROUP )
        return FL_RETURN_NONE;

    if ( ! obj->handle )
        return FL_RETURN_NONE;

    /* Make sure return states of parents, grandparents etc. of current
       object are all set to FL_NO_RETURN */

    if ( ! keep_ret )
    {
        p = obj;
        while ( ( p = p->parent ) )
            p->returned = FL_RETURN_NONE;
    }

    switch ( event )
    {
        case FL_ENTER:
        {
            /* In the case of a composite object we assign the timer to the
               parent widget as that's the thing that's actually got the tip. */

            FL_OBJECT * const parent = get_parent( obj );

            if ( ! parent->tipID )
            {
                char const * const tooltip = parent->tooltip;

                if ( tooltip && *tooltip )
                    parent->tipID = fl_add_timeout( fli_context->tooltip_time,
                                                    tooltip_handler, parent );
            }

            obj->belowmouse = 1;
            break;
        }

        case FL_LEAVE:
            checked_hide_tooltip( obj, xev );
            obj->belowmouse = 0;
            break;

        case FL_PUSH:
            unconditional_hide_tooltip( obj );
            obj->pushed = 1;
            break;

        case FL_KEYPRESS:
            unconditional_hide_tooltip( obj );
            break;

        case FL_RELEASE:
            if ( ! obj->radio )
                obj->pushed = 0;

            /* Changed: before double and triple clicks weren't accepted for
               the middle mouse button (which didn't make too much sense IMHO),
               now they don't get flagged for the mouse wheel "buttons". JTT */

            if (    key == last_key
                 && ! ( key == FL_MBUTTON4 || key == FL_MBUTTON5 )
                 && ! (    FL_abs( last_mx - mx ) > 4
                        || FL_abs( last_my - my ) > 4 )
                 && xev
                 && xev->xbutton.time - last_clicktime < obj->click_timeout )
                event = last_dblclick ? FL_TRPLCLICK : FL_DBLCLICK;

            last_dblclick = event == FL_DBLCLICK;
            last_clicktime = xev ? xev->xbutton.time : 0;
            last_key = key;
            last_mx = mx;
            last_my = my;
            break;

        case FL_FOCUS:
            /* 'refocus' is set if on the last FL_UNFOCUS it was found
               that the text in the input field didn't validate. In that
               case the focus has to go back to that field and *not* to a
               different one */

            if ( refocus && refocus->form )
            {
                obj = refocus;
                refocus = NULL;
            }

            if ( obj->form )
            {
                obj->form->focusobj = obj;
                obj->focus = 1;
            }
            break;

        case FL_UNFOCUS:
            obj->form->focusobj = NULL;
            obj->focus = 0;
            break;

        case FL_DRAW:
            if ( obj->objclass == FL_FREE )
            {
                fl_set_clipping( obj->x, obj->y, obj->w, obj->h );
                fl_set_text_clipping( obj->x, obj->y, obj->w, obj->h );
            }
            break;
    }

    cur_event = event;
    if ( event == FL_DBLCLICK || event == FL_TRPLCLICK )
        event = FL_RELEASE;

 recover:

    /* Call a pre-handler if it exists and return if it tells us the event
       has been handled completely */

    if (    obj->prehandle
         && event != FL_FREEMEM
         && obj->prehandle( obj, event, mx, my, key, xev ) == FL_PREEMPT )
        return FL_RETURN_NONE;

    /* Now finally call the real object handler and filter the status it
       returns (to limit the value to what it expects) */

    if ( ! keep_ret )
    {
        obj->returned = obj->handle( obj, event, mx, my, key, xev );
        fli_filter_returns( obj );
    }
    else
        obj->handle( obj, event, mx, my, key, xev );

    /* Call post-handler if one exists */

    if ( obj->posthandle && event != FL_FREEMEM )
        obj->posthandle( obj, event, mx, my, key, xev );

    if ( cur_event == FL_DBLCLICK || cur_event == FL_TRPLCLICK )
    {
        event = cur_event;
        cur_event = 0;
        if ( ! keep_ret && obj->returned )
            fli_object_qenter( obj, cur_event );
        goto recover;
    }

    if ( obj->objclass == FL_FREE && event == FL_DRAW )
    {
        fl_unset_clipping( );
        fl_unset_text_clipping( );
    }

    return ( event == FL_DBLCLICK || event == FL_TRPLCLICK ) ?
           ( int ) FL_RETURN_NONE : obj->returned;
}


/***************************************
 * Handle and store object in object queue if handler returns non-zero
 ***************************************/

void
fli_handle_object( FL_OBJECT * obj,
                   int         event,
                   FL_Coord    mx,
                   FL_Coord    my,
                   int         key,
                   XEvent    * xev,
                   int         enter_it )
{
    if ( ! obj )
        return;

    /* If 'enter_it' is set the object is inserted into the object queue and
       it's 'returned' member is modified. If not, just the handler for
       the object is called, but it doesn't appear in the queue and the
       'returned' member remains unmodified. Also don't enter the object
       into the queue if it's form doesn't exist or the forms window isn't
       mapped. */

    if ( enter_it && obj->form && obj->form->window )
    {
        int res;

        if ( ( res = handle_object( obj, event, mx, my, key, xev, 0 ) ) )
            fli_object_qenter( obj, event );
    }
    else
        handle_object( obj, event, mx, my, key, xev, 1 );
}


/***************************************
 * Sets the callback routine for the object
 ***************************************/

FL_CALLBACKPTR
fl_set_object_callback( FL_OBJECT      * obj,
                        FL_CALLBACKPTR   callback,
                        long             argument )
{
    FL_CALLBACKPTR old;

    if ( ! obj )
    {
        M_err( "fl_set_object_callback", "NULL object" );
        return NULL;
    }

    old = obj->object_callback;
    obj->object_callback = callback;
    obj->argument = argument;

    /* In older versions scrollbars and browsers didn't return to the
       application on e.g. fl_do_forms() but still a callback associated
       with the object got called. To emulate the old behaviour we have
       to set the return policy to FL_RETURN_NEVER if the callback is
       removed and to (FL_RETURN_SELECTION|FL_RETURN_DESELECTION) or
       FL_RETURN_CHANGED when a callback is installed. */

#if defined USE_BWC_BS_HACK
    if ( obj->objclass == FL_BROWSER )
        fl_set_object_return( obj,
                              callback ?
                              ( FL_RETURN_SELECTION | FL_RETURN_DESELECTION ) :
                              FL_RETURN_NONE );
    else if ( obj->objclass == FL_SCROLLBAR )
        fl_set_object_return( obj,
                              callback ? FL_RETURN_CHANGED : FL_RETURN_NONE);
#endif

    return old;
}


/***************************************
 * Sets the borderwidth of an object
 ***************************************/

void
fl_set_object_bw( FL_OBJECT * obj,
                  int         bw )
{
    /* Clamp border width to a reasonable range */

    if ( FL_abs( bw ) > FL_MAX_BW )
        bw = bw > 0 ? FL_MAX_BW : - FL_MAX_BW;

    if ( bw == 0 )
        bw = -1;

    if ( ! obj )
    {
        M_err( "fl_set_object_bw", "NULL object" );
        return;
    }

    /* Check if this object is a group, if so, change all members */

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        FL_FORM * form = obj->form;

        obj->bw = bw;
        if ( form )
            fl_freeze_form( form );

        for ( obj = obj->next; obj && obj->objclass != FL_END_GROUP;
              obj = obj->next )
            if ( obj->bw != bw )
            {
                obj->bw = bw;
                fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );
                mark_object_for_redraw( obj );
            }

        if ( form )
            fl_unfreeze_form( form );
    }
    else if ( obj->bw != bw && obj->objclass != FL_TABFOLDER )
    {
        obj->bw = bw;
        fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

        if ( obj->objclass == FL_TABFOLDER )
            fli_set_tab_bw( obj, bw );

        fl_redraw_object( obj );
    }
}


/***************************************
 * Returns the borderwidth of an object
 ***************************************/

int
fl_get_object_bw( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_get_object_bw", "NULL object" );
        return -1;
    }

    return obj->bw;
}


/***************************************
 ***************************************/

Window
fl_get_real_object_window( FL_OBJECT * obj )
{
    FL_pixmap *objp = obj->flpixmap;
    FL_pixmap *formp = obj->form->flpixmap;

    if ( objp && objp->win ) 
        return objp->win;
    else if (    (    obj->objclass == FL_CANVAS
                   || obj->objclass == FL_GLCANVAS )
              && fl_get_canvas_id( obj ) )
        return fl_get_canvas_id( obj );
    else if ( formp && formp->win )
        return formp->win;

    return obj->form->window;
}


/***************************************
 * Takes two rectangles and returns a pointer to a new rectangle
 * (memory for it is allocated in the function and must be released
 * by the caller!) of the intersection of both - or a NULL pointer
 * if the two rectangles have no common area.
 ***************************************/

FL_RECT *
fli_intersect_rects( const FL_RECT * r1,
                     const FL_RECT * r2 )
{
    FL_RECT * p = fl_malloc( sizeof *p );
    int x = FL_min( r1->x + r1->width,  r2->x + r2->width  ),
        y = FL_min( r1->y + r1->height, r2->y + r2->height );

    p->x      = FL_max( r1->x, r2->x );
    p->y      = FL_max( r1->y, r2->y );
    p->width  = x - p->x;
    p->height = y - p->y;

    if ( p->width <= 0 || p->height <= 0 )
        fli_safe_free( p );

    return p;
}


/***************************************
 * Returns (via the first argument) the smallest rectangle covering
 * both the two argument rectangles
 ***************************************/

static void
fli_combine_rectangles( FL_RECT       * r1,
                        const FL_RECT * r2 )
{
    int xf = FL_max( r1->x + r1->width,  r2->x + r2->width  ),
        yf = FL_max( r1->y + r1->height, r2->y + r2->height );

    r1->x = FL_min( r1->x, r2->x );
    r1->y = FL_min( r1->y, r2->y );

    r1->width  = xf - r1->x;
    r1->height = yf - r1->y;
}


/***************************************
 * Scale an object. No gravity and resize settings for the object are
 * taken into account. The calculation takes care of rounding errors
 * and has the property that if two objects were "glued" together be-
 * fore scaling they will remain so. The function also doesn't re-
 * calculates intersection between objects, this has to be done by the
 * caller if necessary.
 ***************************************/

void
fli_scale_object( FL_OBJECT * obj,
                  double      xs,
                  double      ys )
{
    if ( xs == 1.0 && ys == 1.0 )
        return;

    if ( ! obj->form )
    {
        obj->x = FL_crnd( xs * obj->x );
        obj->y = FL_crnd( ys * obj->y );
        obj->w = FL_crnd( xs * obj->w );
        obj->h = FL_crnd( ys * obj->h );
    }
    else
    {
        double new_w = xs * ( obj->fl2 - obj->fl1 ),
               new_h = ys * ( obj->ft2 - obj->ft1 );

        obj->fl1 *= xs;
        obj->fr1  = obj->form->w_hr - obj->fl1;
        obj->ft1 *= ys;
        obj->fb1  = obj->form->h_hr - obj->ft1;

        obj->fl2  = obj->fl1 + new_w;
        obj->fr2  = obj->form->w_hr - obj->fl2;
        obj->ft2  = obj->ft1 + new_h;;
        obj->fb2  = obj->form->h_hr - obj->ft2;;

        obj->x    = FL_crnd( obj->fl1 );
        obj->y    = FL_crnd( obj->ft1 );
        obj->w    = FL_crnd( new_w );
        obj->h    = FL_crnd( new_h );

        fli_handle_object( obj, FL_RESIZED, 0, 0, 0, NULL, 0 );

        /* If there are child objects also inform them about the size change */

        if ( obj->child )
            fli_composite_has_been_resized( obj );
    }
}


/***************************************
 * Register a preemptive object handler
 ***************************************/

FL_HANDLEPTR
fl_set_object_prehandler( FL_OBJECT    * obj,
                          FL_HANDLEPTR   phandler )
{
    FL_HANDLEPTR oldh = obj->prehandle;

    obj->prehandle = phandler;
    return oldh;
}


/***************************************
 ***************************************/

FL_HANDLEPTR
fl_set_object_posthandler( FL_OBJECT    * obj,
                           FL_HANDLEPTR   post )
{
    FL_HANDLEPTR oldh = obj->posthandle;

    obj->posthandle = post;
    return oldh;
}


/***************************************
 ***************************************/

int
fl_get_object_return_state( FL_OBJECT *obj )
{
    return obj->returned;
}


/***************************************
 ***************************************/

void
fl_trigger_object( FL_OBJECT * obj )
{
    if (    obj
         && obj != FL_EVENT
         && obj->form
         && obj->visible
         && obj->active )
    {
        obj->returned = FL_RETURN_TRIGGERED;
        fli_object_qenter( obj, FL_TRIGGER );
    }
}


/***************************************
 ***************************************/

void
fl_draw_object_label( FL_OBJECT * obj )
{
    int align;

    if ( ! obj->label || ! *obj->label )
        return;

    align = fl_to_outside_lalign( obj->align );

    if ( fl_is_inside_lalign( obj->align ) )
        fl_draw_text( align, obj->x, obj->y, obj->w, obj->h,
                      obj->lcol, obj->lstyle, obj->lsize, obj->label );
    else
        fl_draw_text_beside( align, obj->x, obj->y, obj->w, obj->h,
                             obj->lcol, obj->lstyle, obj->lsize, obj->label );
}


/***************************************
 ***************************************/

void
fl_draw_object_label_outside( FL_OBJECT * obj )
{
    fl_draw_text_beside( fl_to_outside_lalign( obj->align ),
                         obj->x, obj->y, obj->w, obj->h,
                         obj->lcol, obj->lstyle, obj->lsize, obj->label );
}


/***************************************
 ***************************************/

void
fl_call_object_callback( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_call_object_callback", "NULL object" );
        return;
    }

    if ( obj->object_callback )
        obj->object_callback( obj, obj->argument );
}


/***************************************
 * Function to test if an object is (at least partially) hidden by any of
 * its successors in the forms list of objects (objects are always sorted in
 * a way that objects earlier in the list are drawn under those following
 * it). We don't need to look at objects that have a parent since for
 * them the tests for the parent objects will do. It returns the number
 * of objects that are "over" the object.
 ***************************************/

static int
object_is_under( const FL_OBJECT * obj )
{
    FL_OBJECT *o;
    int cnt = 0;

    /* The first object of a form is always below all others */

    if ( obj == bg_object( obj->form ) )
    {
        for ( o = obj->next; o; o = o->next )
            if (    obj->objclass != FL_BEGIN_GROUP 
                 && obj->objclass != FL_END_GROUP )
                cnt++;
        return cnt;
    }

    if (    obj->objclass == FL_BEGIN_GROUP 
         || obj->objclass == FL_END_GROUP )
        return 0;

    for ( o = obj->next; o; o = o->next )
    {
        if (    o->objclass == FL_BEGIN_GROUP 
             || o->objclass == FL_END_GROUP )
            continue;

        if ( objects_intersect( obj, o ) )
            cnt++;
    }

    return cnt;
}


/***************************************
 * Helper function for fli_recalc_intersections() and other functions -
 * without this is a O(N^2) operation with respect to the recalculations
 * of the N object bounding boxes. Here we use that the 'u_vdata' pointers
 * of the objects don't get used during fli_recalc_intersections() and
 * replace them all by pointers to pre-calculated bounding boxes, thus
 * reducing the number of recalculations to N (in objects_intersect() it
 * gets checked if 'tmp_vdata' is non-NULL and then uses the pre-calculated
 * bounding boxes).
 ***************************************/

static int
prep_recalc( FL_FORM   * form,
             FL_OBJECT * start_obj )
{
    FL_OBJECT *obj;
    int cnt = 0;
    int i = 0;

    if ( ! form || tmp_vdata )
        return 0;

    if ( ! start_obj )
        start_obj = bg_object( form );

    /* Count how many objects the form contains */

    for ( obj = start_obj; obj; obj = obj->next )
        cnt++;

    if ( cnt < 2 )
        return 0;

    /* Get memory for temporary storing the 'u_vdata' pointers of all objects
       and as many FL_RECT's */

    if ( ( tmp_vdata = fl_malloc( cnt * sizeof *tmp_vdata ) ) )
    {
        if ( ! ( tmp_rects = fl_malloc( cnt * sizeof *tmp_rects ) ) )
        {
            fli_safe_free( tmp_vdata );
            return 0;
        }
    }
    else
        return 0;

    /* Save the 'u_vdata' pointers and replace them by pointers to the
       bounding box rectangles */

    for ( obj = start_obj; obj; obj = obj->next )
    {
        tmp_vdata[ i ] = obj->u_vdata;
        obj->u_vdata = tmp_rects + i;
        get_object_rect( obj, tmp_rects + i++, 0 );
    }

    return 1;
}


/***************************************
 * Another helper function for fli_recalc_intersections() - to be called when
 * it's finished, restoring all objects 'u_vdata' pointers and getting rid
 * of allocated memory.
 ***************************************/

static void
finish_recalc( FL_FORM   * form,
               FL_OBJECT * start_obj )
{
    FL_OBJECT *obj;
    int i = 0;

    if ( ! tmp_vdata )
        return;

    for ( obj = start_obj ? start_obj : bg_object( form ); obj;
          obj = obj->next )
        obj->u_vdata = tmp_vdata[ i++ ];

    fli_safe_free( tmp_rects );
    fli_safe_free( tmp_vdata );
}
   

/***************************************
 * Rechecks for all objects of a form if they are
 * partially or fully hidden by another object
 ***************************************/

void
fli_recalc_intersections( FL_FORM * form )
{
    FL_OBJECT *obj;

    /* When we're still adding to a form (and thus 'fl_current_form' isn't
       NULL) there typically are a lot of calls that normally would require
       a recalculation of intersections. The same applies if the form is
       frozen. Delay this until the form gets closed (i.e. only recalculate
       the intersections during the final call of fl_end_form()) or when it
       isn't frozen anymore. */

    if ( fl_current_form || ! form || ( form && form->frozen ) )
        return;

    prep_recalc( form, NULL );
    for ( obj = bg_object( form ); obj && obj->next; obj = obj->next )
        obj->is_under = object_is_under( obj );
    finish_recalc( form, NULL );
}


/***************************************
 ***************************************/

void
fl_move_object( FL_OBJECT * obj,
                FL_Coord    dx,
                FL_Coord    dy )
{
     FL_Coord x,
              y;
     if ( fli_inverted_y )
         dy = - dy;

    if ( obj->objclass == FL_BEGIN_GROUP )
    {
        FL_FORM * form = obj->form;

        if ( form )
            fl_freeze_form( form );

        for ( obj = obj->next; obj && obj->objclass != FL_END_GROUP;
              obj = obj->next )
        {
            fl_get_object_position( obj, &x, &y );
            fl_set_object_position( obj, x + dx, y + dy );
        }
 
        if ( form )
            fl_unfreeze_form( form );
    }
    else
    {
        fl_get_object_position( obj, &x, &y );
        fl_set_object_position( obj, x + dx, y + dy );
    }
}


/***************************************
 * Returns the position of an object
 ***************************************/

void
fl_get_object_position( FL_OBJECT * obj,
                        FL_Coord  * x,
                        FL_Coord  * y )
{
    *x = obj->x;
    *y = fli_inverted_y ? TRANSLATE_Y( obj, obj->form ) : obj->y;
}


/***************************************
 * Sets the position of an object
 ***************************************/

void
fl_set_object_position( FL_OBJECT * obj,
                        FL_Coord    x,
                        FL_Coord    y )
{
    int need_show = 0;
    double diff;

    if ( fli_inverted_y )
        y = obj->form->h - obj->h - y;

    if ( obj->x == x && obj->y == y )
        return;

    /* If the object is displayed hide it to get its background redrawn */

    if ( obj->visible )
    {
        need_show = 1;
        fl_hide_object( obj );
    }

    if ( x != obj->x )
    {
        diff = x - obj->fl1;
        obj->fl1 += diff;
        obj->fl2 += diff;
        obj->fr1 -= diff;
        obj->fr2 -= diff;
        obj->x = x;
    }

    if ( y != obj->y )
    {
        diff = y - obj->ft1;
        obj->ft1 += diff;
        obj->ft2 += diff;
        obj->fb1 -= diff;
        obj->fb2 -= diff;
        obj->y = y;
    }

    fli_handle_object( obj, FL_MOVEORIGIN, 0, 0, 0, NULL, 0 );

    if ( need_show )
        fl_show_object( obj );
}


/***************************************
 * Returns the size of an object
 ***************************************/

void
fl_get_object_size( FL_OBJECT * obj,
                    FL_Coord  * w,
                    FL_Coord  * h )
{
    *w = obj->w;
    *h = obj->h;
}


/*****************************
 * Sets the size of an object
 *****************************/

void
fl_set_object_size( FL_OBJECT * obj,
                    FL_Coord    w,
                    FL_Coord    h )
{
    int need_show = 0;
    double diff;

    if ( obj->w == w && obj->h == h )
        return;

    if ( obj->visible )
    {
        need_show = 1;
        fl_hide_object( obj );
    }

    if ( w != obj->w )
    {
        diff = w - ( obj->fl2 - obj->fl1 );

        if ( HAS_FIXED_HORI_ULC_POS( obj ) )
        {
            obj->fl2 += diff;
            obj->fr2 -= diff;
        }
        if ( HAS_FIXED_HORI_LRC_POS( obj ) )
        {
            obj->fl1 -= diff;
            obj->fr1 += diff;
        }
        else    /* keep center of gravity */
        {
            diff *= 0.5;
            obj->fl1 -= diff;
            obj->fr1 += diff;
            obj->fl2 += diff;
            obj->fr2 -= diff;
        }

        obj->x = FL_crnd( obj->fl1 );
        obj->w = FL_crnd( obj->fl2 - obj->fl1 );
    }

    if ( h != obj->h )
    {
        diff = h - ( obj->ft2 - obj->ft1 );

        if ( HAS_FIXED_VERT_ULC_POS( obj ) )
        {
            obj->ft2 += diff;
            obj->fb2 -= diff;
        }
        else if ( HAS_FIXED_VERT_LRC_POS( obj ) )
        {
            obj->ft1 -= diff;
            obj->fb1 += diff;
        }
        else    /* keep center of gravity */
        {
            diff *= 0.5;
            obj->ft1 -= diff;
            obj->fb1 += diff;
            obj->ft2 += diff;
            obj->fb2 -= diff;
        }

        obj->y = FL_crnd( obj->ft1 );
        obj->h = FL_crnd( obj->ft2 - obj->ft1 );
    }

    fli_handle_object( obj, FL_RESIZED, 0, 0, 0, NULL, 0 );

    /* If there are child objects also inform them about the size change */

    if ( obj->child )
        fli_composite_has_been_resized( obj );

    if ( need_show )
        fl_show_object( obj );
}


/***************************************
 * Returns the position and size of an object
 ***************************************/

void
fl_get_object_geometry( FL_OBJECT * obj,
                        FL_Coord  * x,
                        FL_Coord  * y,
                        FL_Coord  * w,
                        FL_Coord  * h )
{
    fl_get_object_position( obj, x, y );
    fl_get_object_size( obj, w, h );
}


/***************************************
 * Sets the position and size of an object
 ***************************************/

void
fl_set_object_geometry( FL_OBJECT * obj,
                        FL_Coord    x,
                        FL_Coord    y,
                        FL_Coord    w,
                        FL_Coord    h )
{
    fl_set_object_size( obj, w, h );
    fl_set_object_position( obj, x, y );
}


/***************************************
 * Computes object geometry taking also the label into account
 ***************************************/

void
fl_get_object_bbox( FL_OBJECT * obj,
                    FL_Coord  * x,
                    FL_Coord  * y,
                    FL_Coord  * w,
                    FL_Coord  * h )
{
    XRectangle rect;

    get_object_rect( obj, &rect, 0 );

    *x = rect.x;
    if ( ! fli_inverted_y || ! obj->form )
        *y = rect.y;
    else
        *y = obj->form->h - rect.height - rect.y;
    *w = rect.width;
    *h = rect.height;
}


/***************************************
 ***************************************/

static XRectangle *
get_label_rect( const FL_OBJECT * obj,
                XRectangle      * rect )
{
    int sw,
        sh;
    int xx,
        yy,
        descent;

    if ( ! obj->label || ! *obj->label )
    {
        rect->x = rect->y = rect->width = rect->height = 0;
        return rect;
    }

    fl_get_string_dimension( obj->lstyle, obj->lsize, obj->label,
                             strlen( obj->label ), &sw, &sh );
    fl_get_char_height( obj->lstyle, obj->lsize, NULL, &descent );

    /* Some objects don't use the normal way of placing their label,
       for these use some approximation */

    if (    (    obj->objclass == FL_ROUNDBUTTON
              && fl_is_center_lalign( obj->align ) )
         || (    obj->objclass == FL_ROUND3DBUTTON
              && fl_is_center_lalign( obj->align ) )
         || (    obj->objclass == FL_CHECKBUTTON
              && fl_is_inside_lalign( obj->align ) ) )
    {
        rect->x      = obj->x;
        rect->y      = obj->y;
        rect->width  = FL_min( obj->w, obj->w ) + sw;
        rect->height = sh + descent;
    }
    else
    {
        fl_get_align_xy( obj->align, obj->x, obj->y, obj->w, obj->h,
                         sw, sh + descent, 3, 3, &xx, &yy );

        rect->x      = xx - 1;
        rect->y      = yy;
        rect->width  = sw + 1;
        rect->height = sh + descent;
    }

    return rect;
}


/***************************************
 * Returns the area covered by the object and its label via a FL_RECT
 ***************************************/

static void
get_object_rect( const FL_OBJECT * obj,
                 FL_RECT         * rect,
                 int               extra )
{
    if (    obj->objclass == FL_FRAME
         || obj->objclass == FL_LABELFRAME
         || obj->objclass == FL_CANVAS
         || obj->objclass == FL_GLCANVAS
         || (    obj->objclass >= FL_USER_CLASS_START
              && obj->objclass <= FL_USER_CLASS_END ) )
        extra += FL_abs( obj->bw );

    rect->x      = obj->x - extra;
    rect->y      = obj->y - extra;
    rect->width  = obj->w + 2 * extra + 1;
    rect->height = obj->h + 2 * extra + 1;

    /* Include the label into the box - but only for labels that are not
       within the object. If "inside" labels extend beyond the limits of the
       object things look ugly anyway and it doesn't seem to make too much
       sense to slow down the program for this case. */

    if ( obj->label && *obj->label && OL( obj ) )
    {
        XRectangle lr;
        fli_combine_rectangles( rect, get_label_rect( obj, &lr ) );
    }
}


/***************************************
 ***************************************/

void
fl_set_object_automatic( FL_OBJECT * obj,
                         int         flag )
{
    flag = flag ? 1 : 0;

    if ( obj->automatic == flag )
        return;

    obj->automatic = flag;

    if ( obj->form )
    {
        if ( flag )
            obj->form->num_auto_objects++;
        else
            obj->form->num_auto_objects--;
    }

    fli_recount_auto_objects( );
}


/***************************************
 ***************************************/

int
fl_object_is_automatic( FL_OBJECT * obj )
{
    if ( ! obj )
    {
        M_err( "fl_object_is_automatic", "NULL object" );
        return 0;
    }

    return obj->automatic;
}


/***************************************
 ***************************************/

static void
lose_focus( FL_OBJECT * obj )
{
    FL_FORM *form = obj->form;

    if ( ! form || ! obj->focus || obj != form->focusobj )
        return;

    if ( obj == form->focusobj )
        fli_handle_object( form->focusobj, FL_UNFOCUS, 0, 0, 0, NULL, 1 );

    obj->focus = 0;

    /* Try to find some input object to give it the focus */

    obj->input = 0;
    form->focusobj = fli_find_first( obj->form, FLI_FIND_INPUT, 0, 0 );
    obj->input = 1;

    if ( obj == refocus )
        refocus = form->focusobj ? form->focusobj : NULL;

    if ( form->focusobj )
        fli_handle_object( form->focusobj, FL_FOCUS, 0, 0, 0, NULL, 0 );
}


/***************************************
 * Part of the public interface, not used within the library.
 * Calls a user supplied function on all objects of a form but stops
 * in between of the function, when called on one of the objects,
 * returns 0. The function also gets called for objects that mark the
 * begin and end of a group!
 ***************************************/

void
fl_for_all_objects( FL_FORM * form,
                    int       ( * fp )( FL_OBJECT *, void * ),
                    void    * v )
{
    FL_OBJECT *obj;

    if ( ! form )
    {
        M_err( "fl_for_all_objects", "NULL form" );
        return;
    }

    if ( ! fp )
    {
        M_err( "fl_for_all_objects", "NULL callback function" );
        return;
    }

    for ( obj = bg_object( form ); obj && ! fp( obj, v ); obj = obj->next )
        /* empty */ ;
}


/***************************************
 ***************************************/

void
fl_set_object_helper( FL_OBJECT  * obj,
                      const char * tip )
{
    if ( ! obj )
    {
        M_err( "fl_set_object_helper", "NULL object" );
        return;
    }

    fli_safe_free( obj->tooltip );
    obj->tooltip = ( tip && *tip ) ? fl_strdup( tip ) : NULL;
}


/***************************************
 ***************************************/

void
fl_set_object_helper_f( FL_OBJECT  * obj,
                        const char * fmt,
                        ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_set_object_helper( obj, buf );
    fl_free( buf );
}


/***************************************
 * Function for setting the conditions under which an object gets
 * returned (or its callback invoked). If the object has to do
 * additional work on setting the condition (e.g. it has child
 * objects that also need to be set) it has to set up its own
 * function that then will be called in the end. This function should
 * only be called once an object has been fully created!
 ***************************************/

unsigned int
fl_set_object_return( FL_OBJECT    * obj,
                      unsigned int   when )
{
    int old_when;

    if ( ! obj )
        return FL_RETURN_ALWAYS;

    old_when = obj->how_return;

    /* FL_RETURN_END_CHANGED means FL_RETURN and FL_RETURN_CHANGED at the
       same moment, so it those two events can't be set at the same time */

    if ( when & FL_RETURN_END_CHANGED )
        when &= ~ ( FL_RETURN_END | FL_RETURN_CHANGED );

    if ( obj->set_return )
        obj->set_return( obj, when );
    else
        obj->how_return = when;

    return old_when;
}


/***************************************
 ***************************************/

unsigned int
fl_get_object_return( FL_OBJECT * obj )
{
    return obj->how_return;
}


/***************************************
 ***************************************/

void
fli_notify_object( FL_OBJECT * obj,
                   int         reason )
{
    if (    ! obj 
         || (    reason != FL_ATTRIB
              && reason != FL_RESIZED
              && reason != FL_MOVEORIGIN ) )
        return;

    fli_handle_object( obj, reason, 0, 0, 0, NULL, 0 );
}


/***************************************
 * Sets the visibility flag for an object and all its children
 * without inducing a redraw. Used e.g. in browser and multi-
 * line input object's code to switch scrollbars on and off.
 ***************************************/

void
fli_set_object_visibility( FL_OBJECT * obj,
                           int         vis )
{
    if ( obj )        /* let's be careful... */
    {
        obj->visible = vis;
        for ( obj = obj->child; obj; obj = obj->nc )
            fli_set_object_visibility( obj, vis );
    }
}


/***************************************
 * Mouse wheel (release) event conversion to a key press event.
 * Returns 1 if a conversion took place, otherwise 0.
 ***************************************/

int
fli_mouse_wheel_to_keypress( int  * ev,
                             int  * key,
                             void * xev )
{
    if ( ! (    *ev == FL_RELEASE
             && ( *key == FL_MBUTTON4 || *key == FL_MBUTTON5 ) ) )
        return 0;

    *ev = FL_KEYPRESS;

    if ( xev )
    {
        if ( shiftkey_down( ( ( XButtonEvent * ) xev )->state ) )
        {
            ( ( XKeyEvent * ) xev )->state = 0;
            *key = *key == FL_MBUTTON4 ? FLI_1LINE_UP : FLI_1LINE_DOWN;
        }
        else if ( controlkey_down( ( ( XButtonEvent * ) xev )->state ) )
        {
            ( ( XKeyEvent * ) xev )->state = 0;
            *key = *key == FL_MBUTTON4 ? XK_Prior : XK_Next;
        }
        else
        {
            ( ( XKeyEvent * ) xev )->state = 0;
            *key = *key == FL_MBUTTON4 ? FLI_HALFPAGE_UP : FLI_HALFPAGE_DOWN;
        }
    }

    return 1;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
