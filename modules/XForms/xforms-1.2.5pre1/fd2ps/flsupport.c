/*
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file flsupport.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 *  Support routines to convert string/numeric values of
 *  object classes and types
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>
#include <ctype.h>
#include "fd2ps.h"

#define MAXTYPES 17

typedef struct {
    int          val;
    const char * name;
} VN_Pair;

#define VN_pair VN_Pair


/***************************************
 ***************************************/

static int
get_vn_val( VN_pair    * vn,
            const char * name )
{
    for ( ; vn->val >= 0; vn++ )
        if ( strcmp(name, vn->name) == 0 )
            return vn->val;
    return atoi( name );
}


/***************************************
 ***************************************/

static const char *
get_vn_name( VN_pair * vn,
             int       val )
{
    static char buf[ 128 ];

    for ( ; vn->val >= 0; vn++ )
        if ( vn->val == val )
            return vn->name;
    sprintf( buf, "%d", val );
    return buf;
}


typedef struct {
    VN_Pair classobj;
    VN_Pair objtype[ MAXTYPES ];
} AllObj;

#define VNP( a )   { a, #a }
#define VN( a )    { a, #a }

static AllObj allobj[ ] =
{
    /* begin button class */

    {
        VNP( FL_BUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( FL_MENU_BUTTON       ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_LIGHTBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_ROUNDBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_ROUND3DBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1)
        }
    },

    {
        VNP( FL_SCROLLBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1)
        }
    },

    {
        VNP( FL_BITMAPBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_PIXMAPBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_CHECKBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_LABELBUTTON ),
        {
            VNP( FL_NORMAL_BUTTON     ),
            VNP( FL_PUSH_BUTTON       ),
            VNP( FL_RADIO_BUTTON      ),
            VNP( FL_HIDDEN_BUTTON     ),
            VNP( FL_TOUCH_BUTTON      ),
            VNP( FL_INOUT_BUTTON      ),
            VNP( FL_RETURN_BUTTON     ),
            VNP( FL_HIDDEN_RET_BUTTON ),
            VNP( -1 )
        }
    },

    /* end of buttons of all kinds } */

    {
        VNP( FL_BITMAP ),
        {
            VNP( FL_NORMAL_BITMAP ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_PIXMAP ),
        {
            VNP( FL_NORMAL_PIXMAP ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_MENU ),
        {
            VNP( FL_PULLDOWN_MENU ),
            VNP( FL_TOUCH_MENU    ),
            VNP( FL_PUSH_MENU     ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_BOX ),
        {
            VNP( FL_NO_BOX            ),
            VNP( FL_UP_BOX            ),
            VNP( FL_DOWN_BOX          ),
            VNP( FL_FLAT_BOX          ),
            VNP( FL_BORDER_BOX        ),
            VNP( FL_SHADOW_BOX        ),
            VNP( FL_FRAME_BOX         ),
            VNP( FL_RFLAT_BOX         ),
            VNP( FL_EMBOSSED_BOX      ),
            VNP( FL_ROUNDED_BOX       ),
            VNP( FL_RSHADOW_BOX       ),
            VNP( FL_OVAL_BOX          ),
            VNP( FL_ROUNDED3D_UPBOX   ),
            VNP( FL_ROUNDED3D_DOWNBOX ),
            VNP( FL_OVAL3D_UPBOX      ),
            VNP( FL_OVAL3D_DOWNBOX    ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_TEXT ),
        {
            VNP( FL_NORMAL_TEXT ),
            VNP( -1 ),
        }
    },

    {
        VNP( FL_CHART ),
        {
            VNP( FL_BAR_CHART        ),
            VNP( FL_HORBAR_CHART     ),
            VNP( FL_LINE_CHART       ),
            VNP( FL_FILLED_CHART     ),
            VNP( FL_PIE_CHART        ),
            VNP( FL_SPECIALPIE_CHART ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_CHOICE ),
        {
            VNP( FL_NORMAL_CHOICE   ),
            VNP( FL_NORMAL_CHOICE2  ),
            VNP( FL_DROPLIST_CHOICE ),
            VNP( -1 ),
        }
    },

    {
        VNP( FL_COUNTER ),
        {
            VNP( FL_NORMAL_COUNTER ),
            VNP( FL_SIMPLE_COUNTER ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_SLIDER ),
        {
            VNP( FL_VERT_SLIDER          ),
            VNP( FL_HOR_SLIDER           ),
            VNP( FL_VERT_FILL_SLIDER     ),
            VNP( FL_HOR_FILL_SLIDER      ),
            VNP( FL_VERT_NICE_SLIDER     ),
            VNP( FL_HOR_NICE_SLIDER      ),
            VNP( FL_HOR_BROWSER_SLIDER   ),
            VNP( FL_VERT_BROWSER_SLIDER  ),
            VNP( FL_HOR_THIN_SLIDER      ),
            VNP( FL_VERT_THIN_SLIDER     ),
            VNP( FL_HOR_BROWSER_SLIDER2  ),
            VNP( FL_VERT_BROWSER_SLIDER2 ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_VALSLIDER ),
        {
            VNP( FL_VERT_SLIDER         ),
            VNP( FL_HOR_SLIDER          ),
            VNP( FL_VERT_FILL_SLIDER    ),
            VNP( FL_HOR_FILL_SLIDER     ),
            VNP( FL_VERT_NICE_SLIDER    ),
            VNP( FL_HOR_NICE_SLIDER     ),
            VNP( FL_HOR_BROWSER_SLIDER  ),
            VNP( FL_VERT_BROWSER_SLIDER ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_SCROLLBAR ),
        {
            VNP( FL_VERT_SCROLLBAR       ),
            VNP( FL_HOR_SCROLLBAR        ),
            VNP( FL_VERT_THIN_SCROLLBAR  ),
            VNP( FL_HOR_THIN_SCROLLBAR   ),
            VNP( FL_VERT_NICE_SCROLLBAR  ),
            VNP( FL_HOR_NICE_SCROLLBAR   ),
            VNP( FL_VERT_BASIC_SCROLLBAR ),
            VNP( FL_HOR_BASIC_SCROLLBAR  ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_THUMBWHEEL ),
        {
            VNP( FL_VERT_THUMBWHEEL ),
            VNP( FL_HOR_THUMBWHEEL  ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_INPUT ),
        {
            VNP( FL_NORMAL_INPUT    ),
            VNP( FL_FLOAT_INPUT     ),
            VNP( FL_INT_INPUT       ),
            VNP( FL_HIDDEN_INPUT    ),
            VNP( FL_MULTILINE_INPUT ),
            VNP( FL_SECRET_INPUT    ),
            VNP( -1 ),
        }
    },

    {
        VNP( FL_BROWSER ),
        {
            VNP( FL_NORMAL_BROWSER             ),
            VNP( FL_SELECT_BROWSER             ),
            VNP( FL_HOLD_BROWSER               ),
            VNP( FL_MULTI_BROWSER              ),
            VNP( FL_DESELECTABLE_HOLD_BROWSER  ),
            VNP( -1 ),
        }
    },

    {
        VNP( FL_TIMER ),
        {
            VNP( FL_NORMAL_TIMER ),
            VNP( FL_VALUE_TIMER  ),
            VNP( FL_HIDDEN_TIMER ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_DIAL ),
        {
            VNP( FL_NORMAL_DIAL ),
            VNP( FL_LINE_DIAL   ),
            VNP( FL_FILL_DIAL   ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_POSITIONER ),
        {
            VNP( FL_NORMAL_POSITIONER  ),
            VNP( FL_OVERLAY_POSITIONER ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_XYPLOT ),
        {
            VNP( FL_NORMAL_XYPLOT ),
            VNP( FL_SQUARE_XYPLOT ),
            VNP( FL_CIRCLE_XYPLOT ),
            VNP( FL_FILL_XYPLOT   ),
            VNP( FL_POINTS_XYPLOT ),
            VNP( FL_DASHED_XYPLOT ),
            VNP( FL_ACTIVE_XYPLOT ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_FRAME ),
        {
            VNP( FL_UP_FRAME       ),
            VNP( FL_DOWN_FRAME     ),
            VNP( FL_ENGRAVED_FRAME ),
            VNP( FL_EMBOSSED_FRAME ),
            VNP( FL_BORDER_FRAME   ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_LABELFRAME ),
        {
            VNP( FL_UP_FRAME       ),
            VNP( FL_DOWN_FRAME     ),
            VNP( FL_ENGRAVED_FRAME ),
            VNP( FL_EMBOSSED_FRAME ),
            VNP( FL_BORDER_FRAME   ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_CLOCK ),
        {
            VNP( FL_ANALOG_CLOCK  ),
            VNP( FL_DIGITAL_CLOCK ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_FREE ),
        {
            VNP( FL_NORMAL_FREE     ),
            VNP( FL_INACTIVE_FREE   ),
            VNP( FL_INPUT_FREE      ),
            VNP( FL_CONTINUOUS_FREE ),
            VNP( FL_ALL_FREE        ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_TIMER ),
        {
            VNP( FL_NORMAL_TIMER ),
            VNP( FL_VALUE_TIMER  ),
            VNP( FL_HIDDEN_TIMER ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_SPINNER ),
        {
            VNP( FL_INT_SPINNER ),
            VNP( FL_FLOAT_SPINNER  ),
            VNP( -1 )
        }
    },

    /* special: groups */

    {
        VNP( FL_BEGIN_GROUP ),
        {
            VNP(  0 ),
            VNP( -1 )
        }
    },

    {
        VNP( 10000 ),
        {
            VNP(  0 ),
            VNP( -1 )
        }
    },

    {
        VNP( FL_END_GROUP ),
        {
            VNP(  0 ),
            VNP( -1 )
        }
    },

    {
        VNP( 20000 ),
        {
            VNP(  0 ),
            VNP( -1 )
        }
    },

    /* sentinel */

    {
        VNP( -1 ),
        {
            VNP( -1 )
        }
    }
};


/***************************************
 ***************************************/

static AllObj *
find_valp( int val )
{
    AllObj *ob = allobj;

    for ( ; ob->classobj.val >= 0; ob++ )
        if ( ob->classobj.val == val )
            return ob;

    return NULL;
}


/***************************************
 ***************************************/

static AllObj *
find_namep( const char * name )
{
    AllObj *ob = allobj;

    for ( ; ob->classobj.val >= 0; ob++ )
        if (    strcmp( name, ob->classobj.name ) == 0
             || strcmp( name, ob->classobj.name + 3 ) == 0 )
            return ob;

    fprintf( stderr, "%s definition not found\n", name );
    return NULL;
}


/***************************************
 ***************************************/

int
find_class_val( const char * name )
{
    AllObj *ob = find_namep (name );

    return ob ? ob->classobj.val : atoi( name );
}


/***************************************
 ***************************************/

const char *
find_class_name( int val )
{
    AllObj *ob = find_valp( val );

    return ob ? ob->classobj.name : "??";
}


/***************************************
 ***************************************/

int
find_type_val( int          objclass,
               const char * name )
{
    AllObj *ob = find_valp( objclass );
    VN_Pair *vnp;

    if ( ! ob )
        return 0;

    for ( vnp = ob->objtype; vnp->val >= 0; vnp++ )
        if (    strcmp( name, vnp->name ) == 0
             || strcmp( name, vnp->name + 3 ) == 0 )
            return vnp->val;

    if ( ! isdigit( ( int ) *name ) )
        fprintf( stderr, "class %s type %s not found\n",
                 ob->classobj.name, name );
    return atoi( name );
}


static VN_Pair vn_unit[ ] =
{
    VN(FL_COORD_PIXEL),
    {FL_COORD_PIXEL, "pixel"},
    VN(FL_COORD_MM),
    {FL_COORD_MM, "mm"},
    VN(FL_COORD_POINT),
    {FL_COORD_POINT, "point"},
    VN(FL_COORD_centiPOINT),
    {FL_COORD_centiPOINT, "cp"},
    {FL_COORD_centiMM, "cmm"},
    {FL_COORD_centiPOINT, "cpoint"},
    VN(-1)
};


/***************************************
 ***************************************/

int
unit_val( const char * name )
{
    return get_vn_val( vn_unit, name );
}


/***************************************
 ***************************************/

const char *
unit_name( int u )
{
    return get_vn_name( vn_unit, u );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
