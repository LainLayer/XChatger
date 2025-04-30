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
 * \file free.c
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


/***************************************
 ***************************************/

FL_OBJECT *
fl_create_free( int            type,
                FL_Coord       x,
                FL_Coord       y,
                FL_Coord       w,
                FL_Coord       h,
                const char   * label,
                FL_HANDLEPTR   handle )
{
    FL_OBJECT *obj;

    obj = fl_make_object( FL_FREE, type, x, y, w, h, label, handle );
    obj->boxtype = FL_FLAT_BOX;

    if ( type == FL_INACTIVE_FREE )
        obj->active = 0;
    else if ( type == FL_CONTINUOUS_FREE )
        obj->automatic = 1;
    else if ( type == FL_INPUT_FREE )
        obj->input = 1;
    else if ( type == FL_ALL_FREE )
    {
        obj->input = 1;
        obj->automatic = 1;
    }

    if ( type != FL_INACTIVE_FREE )
        obj->click_timeout = FL_CLICK_TIMEOUT;

    return obj;
}


/***************************************
 * Adds an object 
 ***************************************/

FL_OBJECT *
fl_add_free( int            type,
             FL_Coord       x,
             FL_Coord       y,
             FL_Coord       w,
             FL_Coord       h,
             const char   * label,
             FL_HANDLEPTR   handle)
{
    FL_OBJECT *ob;

    ob = fl_create_free( type, x, y, w, h, label, handle );
    fl_add_object( fl_current_form, ob );
    return ob;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
