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
 * \file sp_freeobj.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting free object class specific attributes, in this
 * case, the handler name. We store this piece of into in
 * ob->c_vdata.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_freeobj.h"
#include "spec/freeobj_spec.h"

static char *get_free_handle( FL_OBJECT  * ob,
                              const char * name );

static char ori_handle_name[ 128 ];

static FD_freeobjattrib *fo_attrib;
static FL_OBJECT *curobj;


/***************************************
 ***************************************/

FL_FORM *
freeobj_create_spec_form( void )
{
    if ( ! fo_attrib )
        fo_attrib = create_form_freeobjattrib( );

    return fo_attrib->freeobjattrib;
}


/***************************************
 ***************************************/

void
freeobj_adjust_spec_form( FL_OBJECT * obj )
{
    curobj = obj;

    *ori_handle_name = '\0';
    if ( obj->c_vdata )
        strcpy( ori_handle_name, obj->c_vdata );
}


/***************************************
 ***************************************/

void
freeobj_fill_in_spec_form( FL_OBJECT * obj )
{
    fl_set_input( fo_attrib->hname, get_free_handle( obj, 0 ) );
}


/***************************************
 ***************************************/

void
freeobj_reread_spec_form( FL_OBJECT * obj  FL_UNUSED_ARG )
{
    if ( curobj )
        handler_name_change_cb( fo_attrib->hname, 0 );
}


/***************************************
 ***************************************/

void
freeobj_restore_spec( FL_OBJECT * obj )
{
    fli_safe_free( obj->c_vdata );
    obj->c_vdata = fl_strdup( ori_handle_name );
}


/***************************************
 ***************************************/

void
freeobj_emit_spec_fd_code( FILE      * fp,
                           FL_OBJECT * obj )
{
    if ( obj->c_vdata )
        fprintf( fp, "    handler: %s\n", ( char * ) obj->c_vdata );
}


/***************************************
 ***************************************/

int
noop_handle( FL_OBJECT * obj,
             int         e,
             FL_Coord    mx   FL_UNUSED_ARG,
             FL_Coord    my   FL_UNUSED_ARG,
             int         k    FL_UNUSED_ARG,
             void      * xev  FL_UNUSED_ARG )
{
    if ( e == FL_DRAW )
    {
        fl_draw_box( obj->boxtype, obj->x, obj->y, obj->w, obj->h,
                     obj->col1, obj->bw );
        return 0;
    }

    if ( obj->type == FL_INACTIVE_FREE )
        return 0;
    else if ( obj->type == FL_INPUT_FREE )
        return e == FL_KEYPRESS;

    return 1;
}


/***************************************
 ***************************************/

void
handler_name_change_cb( FL_OBJECT * obj,
                        long        data  FL_UNUSED_ARG )
{
    fli_safe_free( curobj->c_vdata );
    curobj->c_vdata = fl_strdup( fl_get_input( obj ) );
}


/* default free object handler name */

#define MAXFREEOBJ 16

/***************************************
 ***************************************/

static char *
get_free_handle( FL_OBJECT  * obj,
                 const char * name )
{
    static int n;
    static char buf[ 1024 ];
    static FL_OBJECT *freeobj[ MAXFREEOBJ ];

    if ( obj->c_vdata )
        strcpy( buf, obj->c_vdata );
    else if ( name && *name )
        sprintf( buf, "freeobj_%s_handle", name );
    else if ( *obj->label )
        sprintf( buf, "freeobj_%s_handle", obj->label );
    else
    {
        int i, k;

        for ( k = -1, i = 0; i < MAXFREEOBJ && k < 0; i++ )
            if ( freeobj[ i ] == obj )
                k = i;

        if ( k < 0 )
        {
            k = ++n;
            freeobj[ k ] = obj;
        }

        sprintf( buf, "freeobj%d_handle", k );
    }

    return buf;
}


#include "spec/freeobj_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
