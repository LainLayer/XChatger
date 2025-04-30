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


/* This demo shows the use of menu's.
 * The first two are PUSH_MENUs (pop-up).
 * The third one is PULLDOWN_MENU
 * and the last one is TOUCH_MENU
 *
 * a confusing demo, but a good testing program ..
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

extern FL_FORM *create_form(void);

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
   int i,
       j;

   fl_initialize( &argc, argv, "FormDemo", 0, 0 );

   form = create_form( );

   /* fl_setpup_color( FL_SLATEBLUE, FL_BLACK ); */

   for ( i = 0; i < 4; i++ )
   {
       fl_show_menu_symbol( menu[ i ], 1 );

       fl_set_menu( menu[ i ],
                    "Red%r1|Green%r1|Yellow%r1|Blue%r1|Purple%r1|"
                    "Cyran%r1|White%r1");

       fl_set_menu_item_shortcut( menu[ i ], 1, "Rr#R#r" );
       fl_set_menu_item_shortcut( menu[ i ], 2, "Gg#G#g" );
       fl_set_menu_item_shortcut( menu[ i ], 3, "Yy#Y#y" );
       fl_set_menu_item_shortcut( menu[ i ], 4, "Bb#B#b" );
       fl_set_menu_item_shortcut( menu[ i ], 5, "Pp#P#p" );
       fl_set_menu_item_shortcut( menu[ i ], 6, "Cc#C#c" );
       fl_set_menu_item_shortcut( menu[ i ], 7, "Ww#W#w" );

       /* Initially the last three entries are enabled */

       for ( j = 5; j <= 7; j++ )
           fl_set_menu_item_mode( menu[ i ], j, FL_PUP_RADIO );

       /* The first four are disabled except the item (i+1) */

       for ( j = 1; j <= 4; j++ )
           fl_set_menu_item_mode( menu[ i ], j, FL_PUP_GREY | FL_PUP_RADIO );

       set[ i ] = i + 1;
       fl_set_object_color( abox[ i ], FL_BLACK + set[ i ], FL_BLACK );
       fl_set_menu_item_mode( menu[ i ], set[ i ],
                              FL_PUP_CHECK | FL_PUP_RADIO );
  }

   fl_show_form( form, FL_PLACE_CENTER, FL_TRANSIENT, "Menu" );

   fl_do_forms( );
   fl_hide_form( form );

   return 0;
}


/***************************************
 * m is the menu index 0 - 3
 ***************************************/

static void
menu_cb( FL_OBJECT * obj,
         long        m )
{
    int i,
        item = fl_get_menu( obj );

    if ( item <= 0 || set[ m ] == item )
        return;

    for ( i = 0; i < 4; i++)
    {
        if ( i != m )
        {
            /* enable the old selected color for other menus*/

            fl_set_menu_item_mode( menu[ i ], set[ m ], FL_PUP_RADIO );

            /* disable the currently selected color for other menus */

            fl_set_menu_item_mode( menu[ i ], item,
                                   FL_PUP_GRAY | FL_PUP_RADIO );
        }
    }

    set[ m ] = item;
    fl_set_object_color( abox[ m ], FL_BLACK + item, FL_BLACK );
}


/***************************************
 ***************************************/

static void
done_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
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

    form = fl_bgn_form( FL_NO_BOX, 440, 380 );

    obj = fl_add_box( FL_BORDER_BOX, 0, 0, 440, 380, "" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );

    menu[ 0 ] = obj = fl_add_menu( FL_PUSH_MENU, 0, 0, 110, 30, "Color 1" );
    fl_set_menu_notitle( obj, 1 );
    fl_set_object_shortcut( obj, "1#1", 1 );
    fl_set_object_callback( obj, menu_cb, 0 );

    menu[ 1 ] = obj = fl_add_menu( FL_PUSH_MENU, 110, 0, 110, 30, "Color 2" );
    fl_set_object_shortcut( obj, "2#2", 1 );
    fl_set_object_callback( obj, menu_cb, 1 );

    menu[ 2 ] = obj = fl_add_menu( FL_PULLDOWN_MENU, 220, 0, 110, 30,
                                   "Color 3" );
    fl_set_object_shortcut( obj, "3#3", 1 );
    fl_set_object_callback( obj, menu_cb, 2 );

    menu[ 3 ] = obj = fl_add_menu( FL_TOUCH_MENU, 330, 0, 110, 30, "Color 4" );
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

    fl_scale_form( form, 0.9, 0.9 );
    fl_adjust_form_size( form );

    return form;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
