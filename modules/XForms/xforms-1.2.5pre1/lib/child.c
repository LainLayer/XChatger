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
 * \file child.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


/***************************************
 ***************************************/

void
fl_add_child( FL_OBJECT * parent,
              FL_OBJECT * child )
{
    FL_OBJECT *t;

    /* If the child is already linked to a form that is not the one of the
       parent unlink it from that form and then add it to the parents
       form (if the parent already belongs to one) */

    if ( child->form && child->form != parent->form )
        fl_delete_object( child );

    if ( ! child->form && parent->form )
        fl_add_object( parent->form, child );

    /* Now set up the parent-child relationship */

    child->parent = parent;

    /* Child gets same gravity and resize attributes as the parent */

    child->nwgravity = parent->nwgravity;
    child->segravity = parent->segravity;
    child->resize    = parent->resize;

    /* Append the new child to the linked list of objects that are
       children of the parent */

    if ( parent->child == NULL )
        parent->child = child;
    else
    {
        for ( t = parent->child; t->nc; t = t->nc )
            /* empty */ ;
        t->nc = child;
    }

    /* If the child itself has children set their gravity and resizing
       behaviour to that of the parent */

    if ( ! child->child )
    {
        parent = child;

        for ( child = child->child; child; child = child->nc )
        {
            fli_set_composite_gravity( child, parent->nwgravity,
                                       parent->segravity );
            fli_set_composite_resize( child, parent->resize );
        }
    }
}


/***************************************
 * Adds all children of an object to its form
 ***************************************/

void
fli_add_composite( FL_OBJECT * obj )
{
    FL_FORM *form = obj->form;
    FL_OBJECT *tmp;

    for ( tmp = obj->child; tmp; tmp = tmp->nc )
    {
        tmp->parent = obj;
        fl_add_object( form, tmp );
    }
}


/***************************************
 * Inserts all children of a object before the object 'before'
 ***************************************/

void
fli_insert_composite( FL_OBJECT * obj,
                      FL_OBJECT * before )
{
    FL_OBJECT *tmp;

    for ( tmp = obj->child; tmp; tmp = tmp->nc )
    {
        tmp->parent = obj;
        fli_insert_object( tmp, before );
    }
}


/***************************************
 * Unlinks all children of an object from its form
 ***************************************/

void
fli_delete_composite( FL_OBJECT * obj )
{
    for ( obj = obj->child; obj; obj = obj->nc )
        if ( obj->form )
            fl_delete_object( obj );
}


/***************************************
 * Irrevocably deletes all children of an object 
 ***************************************/

void
fli_free_composite( FL_OBJECT * obj )
{
    FL_OBJECT *next,
              *parent = obj;

    for ( obj = obj->child; obj; obj = next )
    {
        next = obj->nc;
        fl_free_object( obj ) ;
    }

    parent->child = NULL;
}


/***************************************
 ***************************************/

void
fli_show_composite( FL_OBJECT * obj )
{
    for ( obj = obj->child; obj; obj = obj->nc )
        fli_show_object( obj );
}


/***************************************
 ***************************************/

void
fli_hide_composite( FL_OBJECT * obj,
                    Region    * reg )
{
    for ( obj = obj->child; obj; obj = obj->nc )
    {
        if ( obj->child )
            fli_hide_composite( obj, reg );

        fli_hide_and_get_region( obj, reg );
    }
}


/***************************************
 ***************************************/

void
fli_activate_composite( FL_OBJECT * ob )
{
    for ( ob = ob->child; ob; ob = ob->nc )
    {
        if ( ob->child )
            fli_activate_composite( ob );
        ob->active = 1;
    }
}


/***************************************
 ***************************************/

void
fli_deactivate_composite( FL_OBJECT * ob )
{
    for ( ob = ob->child; ob; ob = ob->nc )
    {
        if ( ob->child )
            fli_deactivate_composite( ob );

        ob->active = 0;
    }
}


/***************************************
 ***************************************/

void
fli_set_composite_resize( FL_OBJECT *  obj,
                          unsigned int resize )
{
    for ( obj = obj->child; obj; obj = obj->nc )
    {
        if ( obj->child )
            fli_set_composite_resize( obj, resize );
        obj->resize = resize;
    }
}


/***************************************
 * Sets the gravity property for the children of an object
 * (and their children in turn)
 ***************************************/

void
fli_set_composite_gravity( FL_OBJECT *  obj,
                           unsigned int nw,
                           unsigned int se )
{
    for ( obj = obj->child; obj; obj = obj->nc )
    {
        if ( obj->child )
            fli_set_composite_gravity( obj, nw, se );

        obj->nwgravity = nw;
        obj->segravity = se;
    }
}


/***************************************
 ***************************************/

void
fli_composite_has_been_resized( FL_OBJECT * obj )
{
    for ( obj = obj->child; obj; obj = obj->nc )
    {
        if ( obj->child )
            fli_composite_has_been_resized( obj );
        fli_handle_object( obj, FL_RESIZED, 0, 0, 0, NULL, 0 );
    }
}


/***************************************
 * Inserts a composite object into a form after object 'after'
 ***************************************/

void
fli_insert_composite_after( FL_OBJECT * obj,
                            FL_OBJECT * after )
{
    FL_OBJECT *next,
              *tmp,
              *prev;
    FL_FORM *form;

    if ( ! obj || ! after )
    {
        M_err( "fli_insert_composite_after", "Bad argument" );
        return;
    }

    if ( ! ( form = after->form ) )
    {
        M_err( "fli_insert_composite_after", "Null form" );
        return;
    }

    obj->form = form;

    next            = after->next;
    after->next     = obj;
    obj->prev       = after;
    obj->next       = obj->child;
    obj->next->prev = obj;
    prev            = obj;

    for ( tmp = obj->child; tmp->nc; prev = tmp, tmp = tmp->nc )
    {
        tmp->parent = obj;
        tmp->form   = form;
        tmp->next   = tmp->nc;
        tmp->prev   = prev;
    }

    tmp->next = next;
    tmp->prev = prev;
    tmp->form = form;

    if ( form->last == after )
        form->last = tmp;
}


/***************************************
 ***************************************/

FL_OBJECT *
fl_get_object_component( FL_OBJECT * composite,
                         int         objclass,
                         int         type,
                         int         numb )
{
    FL_OBJECT *tmp;
    int n;

    for ( n = 0, tmp = composite->child; tmp; tmp = tmp->nc )
        if ( tmp->objclass == objclass && ( tmp->type == type || type < 0 ) )
        {
            if ( ++n >= numb )
                return tmp;
        }

    M_err( "fl_get_object_component", "Requested object not found" );

    return NULL;
}


/***************************************
 * copy the parent attributes. gravity stuff is taken care of by
 * fl_add_child()
 ***************************************/

void
fli_inherit_attributes( FL_OBJECT * parent,
                        FL_OBJECT * child )
{
    child->bw     = parent->bw;
    child->lcol   = parent->lcol;
    child->col1   = parent->col1;
    child->lsize  = parent->lsize;
    child->lstyle = parent->lstyle;

    if ( ! child->child )
        return;

    parent = child;

    for ( child = child->child; child; child = child->nc )
        fli_inherit_attributes( parent, child );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
