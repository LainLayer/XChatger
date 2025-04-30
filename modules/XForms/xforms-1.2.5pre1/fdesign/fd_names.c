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
 * \file fd_names.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This file is part of the Form Designer.
 *
 * It contains the routines that keep track of the names and
 * callback routines associated to the different objects.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include "fd_main.h"

/****
 * Structure for storing names connected with an object
 ****/

typedef struct
{
    FL_OBJECT * obj;                        /* The object */
    char        name[    MAX_VAR_LEN ];     /* Its name (if any) */
    char        cbname[  MAX_VAR_LEN ];     /* Callback Routine */
    char        argname[ MAX_VAR_LEN ];     /* The argument */
} OBJ;

static OBJ * objects   = NULL;      /* The stored objects */
static int num_objects = 0;         /* Their number */


/***************************************
 * Deletes the list of object name structures
 ***************************************/

void
reset_object_list( void )
{
    fli_safe_free( objects );
    num_objects = 0;
}


/***************************************
 * Returns the index of the object in the list (or -1 if it's not found)
 ***************************************/

static int
get_object_numb( const FL_OBJECT * obj )
{
    int i;

    for ( i = 0; i < num_objects; i++ )
        if ( objects[ i ].obj == obj )
            return i;

    return -1;
}


/***************************************
 ***************************************/

static void
check_names( int on )
{
    /* Fill in argument if missing */

    if ( *objects[ on ].cbname && ! *objects[ on ].argname)
        strcpy( objects[ on ].argname, "0" );
}


/***************************************
 * Returns the names associated with an object
 ***************************************/

void
get_object_name( const FL_OBJECT * obj,
                 char            * name,
                 char            * cbname,
                 char            * argname)
{
    int on = get_object_numb( obj );

    if ( name )
        strcpy( name, on == -1 ? "" : objects[ on ].name );

    if ( cbname )
        strcpy( cbname, on == -1 ? "" : objects[ on ].cbname );

    if ( argname )
        strcpy( argname, on == -1 ? "" : objects[ on ].argname );
}


/***************************************
 * Sets the names belonging to an object
 ***************************************/

void
set_object_name( FL_OBJECT  * obj,
                 const char * name,
                 const char * cbname,
                 const char * argname )
{
    int on;

    if ( obj == NULL )
        return;

    if ( ( on = get_object_numb( obj ) ) == -1 )
    {
        if (    ( ! name    || ! *name    )
             && ( ! cbname  || ! *cbname  )
             && ( ! argname || ! *argname ) )
            return;

        objects = fl_realloc( objects, ++num_objects * sizeof *objects );
        on = num_objects - 1;

        objects[ on ].obj = obj;
        *objects[ on ].name = *objects[ on ].cbname
                            = *objects[ on ].argname = '\0';
    }

    if ( name )
        fli_sstrcpy( objects[ on ].name, name,
                     sizeof objects[ on ].name );

    if ( cbname)
        fli_sstrcpy( objects[ on ].cbname, cbname,
                     sizeof objects[ on ].cbname );

    if ( argname )
        fli_sstrcpy( objects[ on ].argname, argname,
                     sizeof objects[ on ].argname  );

    check_names( on );
}


/***************************************
 ***************************************/

const char *
get_object_c_name( FL_OBJECT * obj )
{
    int on = get_object_numb( obj );

    return on == -1 ? NULL : objects[ on ].name;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
