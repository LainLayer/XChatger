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


/*
 * This demo show the different boxtypes. Note that some
 * boxtypes are not appropriate for some objects
 *
 *  This file is part of xforms package.
 *  M. Overmars and T.C. Zhao  (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"


static int border = FL_TRANSIENT;

typedef struct {
    int    val;
    char * name;
} VN_struct;

#define VN( a ) { a, #a }

static VN_struct btypes[ ]=
{
   { FL_NO_BOX,            "No box"              },
   { FL_UP_BOX,            "Up box"              },
   { FL_DOWN_BOX,          "Down box"            },
   { FL_BORDER_BOX,        "Border box"          },
   { FL_SHADOW_BOX,        "Shadow box"          },
   { FL_FLAT_BOX,          "Flat box"            },
   { FL_FRAME_BOX,         "Frame box"           },
   { FL_EMBOSSED_BOX,      "Embossed box"        },
   { FL_ROUNDED_BOX,       "Rounded box"         },
   { FL_RFLAT_BOX,         "Rflat box"           },
   { FL_RSHADOW_BOX,       "Rshadow box"         },
   { FL_OVAL_BOX,          "Oval box"            },
   { FL_ROUNDED3D_UPBOX,   "Rounded 3D up box"   },
   { FL_ROUNDED3D_DOWNBOX, "Rounded 3D down box" },
   { FL_OVAL3D_UPBOX,      "Oval 3D up box"      },
   { FL_OVAL3D_DOWNBOX,    "Oval 3D down box"    },
   /* sentinel */
   { -1,                   NULL                }
};


#include "srs.xbm"


/*************** Callback **********************/

FL_FORM *form;
FL_OBJECT *tobj[ 18 ],
          *exitob,
          *btypeob;


/***************************************
 ***************************************/

static void
boxtype_cb( FL_OBJECT * ob,
            long        arg  FL_UNUSED_ARG )
{
    int req_bt = fl_get_select_item( ob )->val;
    static int lastbt = -1;

    if ( lastbt != req_bt )
    {
        size_t i;

        fl_freeze_form( form );
        for ( i = 0; i < sizeof tobj / sizeof *tobj; i++ )
            fl_set_object_boxtype( tobj[ i ], btypes[ req_bt ].val );
        fl_unfreeze_form ( form );
        lastbt = req_bt;
    }
}


/***************************************
 ***************************************/

static void
create_form( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 720, 520 );

    obj = fl_add_box( FL_UP_BOX, 0, 0, 720, 520, "" );
    fl_set_object_color( obj, FL_BLUE, FL_COL1 );

    obj = fl_add_box( FL_DOWN_BOX, 10, 90, 700, 420, "" );
    fl_set_object_color( obj, FL_COL1, FL_COL1 );

    obj = fl_add_box( FL_DOWN_BOX, 10, 10, 700, 70, "" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );

    tobj[ 0 ] = fl_add_box( FL_UP_BOX, 30, 110, 110, 110, "Box" );

    tobj[ 1 ] = fl_add_text( FL_NORMAL_TEXT, 30, 240, 110, 30, "Text" );

    tobj[ 2 ] = fl_add_bitmap( FL_NORMAL_BITMAP, 40, 280, 90, 80, "Bitmap" );
    fl_set_object_lcolor( tobj[ 2 ], FL_BLUE );

    tobj[ 3 ] = fl_add_chart(FL_BAR_CHART, 160, 110, 160, 110, "Chart");

    tobj[ 4 ] = fl_add_clock( FL_ANALOG_CLOCK, 40, 390, 90, 90, "Clock" );
    fl_set_object_dblbuffer( tobj[ 4 ], 1 );

    tobj[ 5 ] = fl_add_button( FL_NORMAL_BUTTON, 340, 110, 120, 30, "Button" );

    tobj[ 6 ] = fl_add_lightbutton( FL_PUSH_BUTTON, 340, 150, 120, 30,
                                    "Lightbutton" );

    tobj[ 7 ] = fl_add_roundbutton( FL_PUSH_BUTTON, 340, 190, 120, 30,
                                    "Roundbutton" );

    tobj[ 8 ] = fl_add_slider( FL_VERT_SLIDER, 160, 250, 40, 230, "Slider" );

    tobj[ 9 ] = fl_add_valslider( FL_VERT_SLIDER, 220, 250, 40, 230,
                                  "Valslider" );

    tobj[ 10 ] = fl_add_dial( FL_LINE_DIAL, 280, 250, 100, 100, "Dial" );

    tobj[ 11 ] = fl_add_positioner( FL_NORMAL_POSITIONER, 280, 380, 150, 100,
                                    "Positioner" );

    tobj[ 12 ] = fl_add_counter( FL_NORMAL_COUNTER, 480, 110, 210, 30,
                                 "Counter" );

    tobj[ 13 ] = fl_add_input( FL_NORMAL_INPUT, 520, 170, 170, 30, "Input" );

    tobj[ 14 ] = fl_add_menu( FL_PUSH_MENU, 400, 240, 100, 30, "Menu" );

    tobj[ 15 ] = fl_add_select( FL_NORMAL_SELECT, 580, 250, 110, 30, "Select" );

    tobj[ 16 ] = fl_add_timer( FL_VALUE_TIMER, 580, 210, 110, 30, "Timer" );
    fl_set_object_dblbuffer( tobj[ 16 ], 1 );

    tobj[ 17 ] = fl_add_browser( FL_NORMAL_BROWSER, 450, 300, 240, 180,
                                 "Browser" );

    exitob = fl_add_button( FL_NORMAL_BUTTON, 590, 30, 100, 30, "Exit" );

    btypeob = fl_add_select( FL_NORMAL_SELECT, 110, 30, 130, 30, "Boxtype" );
    fl_set_object_callback( btypeob, boxtype_cb, 0 );
    fl_popup_set_title( fl_get_select_popup( btypeob ), "Boxtype" );

    fl_end_form ( );
}


/*************** Main Routine ***********************/

static char * browserlines[ ] = {
    "@C1@c@l@bObjects Demo",
    "This demo shows you many of",
    "the objects that currently",
    "exist in the Forms Library.",
    "",
    "You can change the boxtype",
    "of the different objects",
    "using the buttons at the",
    "top of the form. Note that",
    "some combinations might not",
    "look too good. Also realize",
    "that for all object classes",
    "many different types are",
    "available with different",
    "behaviour.",
    NULL
};


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_COLOR c = FL_BLACK;
    char **p;
    VN_struct *vn;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    create_form( );

    fl_set_bitmap_data( tobj[ 2 ],
                        sorceress_width, sorceress_height, sorceress_bits );

    fl_add_chart_value( tobj[ 3 ],  15, "Item 1", c++ );
    fl_add_chart_value( tobj[ 3 ],   5, "Item 2", c++ );
    fl_add_chart_value( tobj[ 3 ], -10, "Item 3", c++ );
    fl_add_chart_value( tobj[ 3 ],  25, "Item 4", c++ );

    fl_set_menu( tobj[ 14 ], "Item 1|Item 2|Item 3|Item 4|item 5" );

    fl_add_select_items( tobj[ 15 ], "Item 1" );
    fl_add_select_items( tobj[ 15 ], "Item 2" );
    fl_add_select_items( tobj[ 15 ], "Item 3" );
    fl_add_select_items( tobj[ 15 ], "Item 4" );
    fl_add_select_items( tobj[ 15 ], "Item 5" );

    fl_set_timer( tobj[ 16 ], 1000.0 );

    for ( p = browserlines; *p; p++ )
        fl_add_browser_line( tobj[ 17 ], *p );

    for ( vn = btypes; vn->val >= 0; vn++ )
        fl_add_select_items( btypeob, vn->name );

    fl_set_select_item( btypeob, fl_get_select_item_by_value( btypeob, 1 ) );
    boxtype_cb( btypeob, 0 );

    fl_show_form ( form, FL_PLACE_MOUSE, border, "Box types" );

    while ( fl_do_forms ( ) != exitob )
        /* empty */;

    fl_finish( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
