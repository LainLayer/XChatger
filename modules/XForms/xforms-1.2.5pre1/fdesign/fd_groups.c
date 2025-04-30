/*
 * This file is part of XForms.
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
 * \file fd_groups.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This file is part of the Form Designer.
 *
 * It maintains a list of groups in the form. Each group can be
 * assigned a name.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "fd_main.h"
#include "fd/ui_theforms.h"


/**** Data Structure maintaining groups in current form ****/

static FL_OBJECT **begobj = NULL;     /* Begin objects of the groups */


/**** Call-back routines ****/


/***************************************
 * Sets the current group in the form
 ***************************************/

void
group_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
          long        arg  FL_UNUSED_ARG )
{
    int n = fl_get_browser( fd_control->groupbrowser );

    cur_class = -1;

    fl_deselect_browser( fd_control->objectbrowser );
    reset_pallette( );
    cur_class = -1;

    if ( n > 0 )
    {
        /* In order to stay consistent with the rest of the interface
           (where adding to the selection requires the <Shift> button
           to be kept pressed down) we clear the selection of the
           <Shift> button isn't pressed */

        if ( ! ( fl_last_event( )->xmotion.state & ShiftMask ) )
            clear_selection( );
        addgroupto_selection( begobj[ n ] );
    }
    else if ( n < 0 )
        deletegroupfrom_selection( begobj[ -n ] );
    redraw_the_form( 0 );
}


/***************************************
 * Changes the name of the current group
 ***************************************/

void
changegroupname_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
                    long        arg  FL_UNUSED_ARG )
{
    char name[ MAX_VAR_LEN ];
    int i,
        numb = 0;
    const char *s;

    if ( cur_form == NULL )
        return;

    for ( i = 1; i <= fl_get_browser_maxline( fd_control->groupbrowser ); i++ )
        if ( fl_isselected_browser_line( fd_control->groupbrowser, i ) )
        {
            if ( numb != 0 )
            {
                fl_show_messages( "Cannot change name of multiple groups" );
                return;
            }
            numb = i;
        }

    if ( numb == 0 )
    {
        fl_show_messages( "No group is selected" );
        return;
    }

    get_object_name( begobj[ numb ], name, NULL, NULL );

 get_changed_group_name:

    if ( ! ( s = fl_show_input( "Group name (must be usable as "
                                "a C variable or empty):", name ) ) )
        return;

    if ( *s && ! is_valid_c_name( s ) )
    {
        fl_show_alert( "Error", "Invalid C identifier specified for group "
                       "name:", s, 0 );
        goto get_changed_group_name;
    }

    strcpy( name, s );
    set_object_name( begobj[ numb ], name, NULL, NULL );
    fillin_groups( );
    changed = FL_TRUE;
}


/***************************************
 * Fills in the current list of groups
 ***************************************/

void
fillin_groups( void )
{
    char name[ MAX_VAR_LEN ];
    FL_OBJECT *obj,
              *obj2;
    int i;

    if ( cur_form == NULL )
    {
        fl_clear_browser( fd_control->groupbrowser );
        return;
    }

    fl_freeze_form( fd_control->groupbrowser->form );
    fl_clear_browser( fd_control->groupbrowser );

    /* Check whether groups are empty. */

    obj = cur_form->first;
    while ( obj != NULL )
    {
        obj2 = obj;
        obj = obj->next;
        if (    obj2->objclass == FL_END_GROUP
             && obj2->prev != NULL
             && obj2->prev->objclass == FL_BEGIN_GROUP )
            fl_delete_object( obj2->prev );
    }

    /* Put the still existing groups in the list */

    for ( i = 0, obj = cur_form->first; obj; obj = obj->next )
        if ( obj->objclass == FL_BEGIN_GROUP )
            i++;

    if ( i > 0 )
    {
        begobj = fl_realloc( begobj, ( i + 1 ) * sizeof *begobj );

        for ( i = 1, obj = cur_form->first; obj; obj = obj->next )
            if ( obj->objclass == FL_BEGIN_GROUP )
            {
                begobj[ i ] = obj;
                get_object_name( obj, name, NULL, NULL );
                if ( ! *name )
                    strcpy( name, "<no name>" );
                fl_add_browser_line( fd_control->groupbrowser, name );
                if ( is_selected( obj ) )
                    fl_select_browser_line( fd_control->groupbrowser, i );
            }
            else if ( obj->objclass == FL_END_GROUP )
                i++;
        }

    fl_unfreeze_form( fd_control->groupbrowser->form );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
