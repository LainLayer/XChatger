/*
 *  This file is part of XForms.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with XForms; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 59 Temple Place - Suite 330, Boston,
 *  MA 02111-1307, USA.
 */


/* This demo shows the use of all four types of nmenu's.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

extern FL_FORM *create_form( void );

FL_OBJECT *menu[ 4 ],
          *abox[ 4 ];
int set[ 4 ];

/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
   FL_FORM *form;
   int i;

   fl_initialize( &argc, argv, "FormDemo", 0, 0 );

   form = create_form( );

   for ( i = 0; i < 4; i++ )
   {
       fl_add_nmenu_items( menu[ i ],
                           "Red%SR%r%s%d|Green%SG%r%s%d|Yellow%SY%r%s%d|"
                           "Blue%SB%r%s%d|Purple%SP%r%s|Cyan%SC%r%s|"
                           "White%SW%r%s",
                           1, "Rr#R#r", 1, "Gg#G#g", 1, "Yy#Y#y", 1, "Bb#B#b",
                           1, "Pp#P#p", 1, "Cc#C#c", 1, "Ww#W#w" );

       fl_popup_entry_set_state( fl_get_nmenu_item_by_value( menu[ i ], i ),
                                 FL_POPUP_CHECKED );

       set[ i ] = i;
       fl_set_object_color( abox[ i ], FL_RED + set[ i ], FL_BLACK );
  }

   fl_show_form( form, FL_PLACE_CENTER, FL_TRANSIENT, "Nmenu" );

   fl_do_forms( );
   fl_hide_form( form );

   fl_finish( );

   return 0;
}


/***************************************
 * m is the menu index 0 - 3
 ***************************************/

static void
menu_cb( FL_OBJECT * obj,
         long        m )
{
    FL_POPUP_RETURN *r = fl_get_nmenu_item( obj );
    int i;

    if ( set[ m ] == r->val )
        return;

    for ( i = 0; i < 4; i++)
    {
        if ( i != m )
        {
            /* enable the old selected color for other menus*/

            fl_popup_entry_set_state( fl_get_nmenu_item_by_value( menu[ i ],
                                                                  set[ m ] ),
                                      0 );

            /* disable the currently selected color for other menus */

            fl_popup_entry_set_state( fl_get_nmenu_item_by_value( menu[ i ],
                                                                  r->val ),
                                      FL_POPUP_DISABLED );
        }
    }

    set[ m ] = r->val;
    fl_set_object_color( abox[ m ], FL_RED + r->val, FL_BLACK );
}


/***************************************
 ***************************************/

static void
done_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

FL_FORM *
create_form( void )
{
    FL_FORM *form;
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 444, 380 );

    obj = fl_add_box( FL_BORDER_BOX, 0, 0, 444, 380, "" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );

    obj = fl_add_box( FL_UP_BOX, 0, 0, 444, 29, "" );
    fl_set_object_color( obj, FL_COL1, FL_COL1 );

    menu[ 0 ] = obj = fl_add_nmenu( FL_NORMAL_NMENU, 2, 2, 110, 25, "Color 1" );
    fl_set_object_shortcut( obj, "1#1", 1 );
    fl_set_object_callback( obj, menu_cb, 0 );

    menu[ 1 ] = obj = fl_add_nmenu( FL_NORMAL_TOUCH_NMENU, 112, 2, 110, 25,
                                    "Color 2" );
    fl_set_object_shortcut( obj, "2#2", 1 );
    fl_set_object_callback( obj, menu_cb, 1 );

    menu[ 2 ] = obj = fl_add_nmenu( FL_BUTTON_NMENU, 222, 2, 110, 25,
                                    "Color 3" );
    fl_set_object_shortcut( obj, "3#3", 1 );
    fl_set_object_callback( obj, menu_cb, 2 );

    menu[ 3 ] = obj = fl_add_nmenu( FL_BUTTON_TOUCH_NMENU, 332, 2, 110, 25,
                                    "Color 4" );
    fl_set_object_shortcut( obj, "4#4", 1 );
    fl_set_object_callback( obj, menu_cb, 3 );

    abox[ 0 ] = obj = fl_add_box( FL_SHADOW_BOX,  20, 80, 70, 230, "" );
    abox[ 1 ] = obj = fl_add_box( FL_SHADOW_BOX, 130, 80, 70, 230, "" );
    abox[ 2 ] = obj = fl_add_box( FL_SHADOW_BOX, 240, 80, 70, 230, "" );
    abox[ 3 ] = obj = fl_add_box( FL_SHADOW_BOX, 350, 80, 70, 230, "" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 310, 330, 110, 30, "Quit" );
    fl_set_object_shortcut( obj, "Q#Q", 1 );
    fl_set_object_callback( obj, done_cb, 0 );

    fl_end_form( );

    return form;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
