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
 *
 * Author: Jens Thoms Toerring <jt@toerring.de>
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "include/forms.h"


typedef struct {
    FL_FORM *   grav;
    FL_OBJECT * box;
    FL_OBJECT * rx;
    FL_OBJECT * ry;
} FD_gravity_form;

typedef struct {
    FL_OBJECT *  box;
    FL_OBJECT *  rx;
    FL_OBJECT *  ry;
    unsigned int grav;
} FD_grav_data;

typedef struct {
    FL_FORM * help;
    int       is_shown;
} FD_help_form;


static FD_grav_data gd[ 9 ];
static unsigned int g[ ] = { FL_NorthWest, FL_North,     FL_NorthEast,
                             FL_West,      FL_NoGravity, FL_East,
                             FL_SouthWest, FL_South,     FL_SouthEast };
static int w = 500,
           h = 400;
static int bw = 200,
           bh = 200;


#define ULC_POS_LEFT_FIXED( obj )                \
    (    ( obj )->nwgravity == FL_NorthWest      \
      || ( obj )->nwgravity == FL_West           \
      || ( obj )->nwgravity == FL_SouthWest )

#define ULC_POS_RIGHT_FIXED( obj )               \
    (    ( obj )->nwgravity == FL_NorthEast      \
      || ( obj )->nwgravity == FL_East           \
      || ( obj )->nwgravity == FL_SouthEast )

#define LRC_POS_LEFT_FIXED( obj )                \
    (    ( obj )->segravity == FL_NorthWest      \
      || ( obj )->segravity == FL_West           \
      || ( obj )->segravity == FL_SouthWest )

#define LRC_POS_RIGHT_FIXED( obj )               \
    (    ( obj )->segravity == FL_NorthEast      \
      || ( obj )->segravity == FL_East           \
      || ( obj )->segravity == FL_SouthEast )

#define HAS_FIXED_HORI_ULC_POS( obj )                             \
    ( ULC_POS_LEFT_FIXED( obj ) || ULC_POS_RIGHT_FIXED( obj ) )

#define HAS_FIXED_HORI_LRC_POS( obj )                             \
    ( LRC_POS_LEFT_FIXED( obj ) || LRC_POS_RIGHT_FIXED( obj ) )

#define HAS_FIXED_WIDTH( obj )                                          \
    ( HAS_FIXED_HORI_ULC_POS( obj ) && HAS_FIXED_HORI_LRC_POS( obj ) ) 


#define ULC_POS_TOP_FIXED( obj )                 \
    (    ( obj )->nwgravity == FL_NorthWest      \
      || ( obj )->nwgravity == FL_North          \
      || ( obj )->nwgravity == FL_NorthEast )

#define ULC_POS_BOTTOM_FIXED( obj )              \
    (    ( obj )->nwgravity == FL_SouthWest      \
      || ( obj )->nwgravity == FL_South          \
      || ( obj )->nwgravity == FL_SouthEast )

#define LRC_POS_TOP_FIXED( obj )                 \
    (    ( obj )->segravity == FL_NorthWest      \
      || ( obj )->segravity == FL_North          \
      || ( obj )->segravity == FL_NorthEast )

#define LRC_POS_BOTTOM_FIXED( obj )              \
    (    ( obj )->segravity == FL_SouthWest      \
      || ( obj )->segravity == FL_South          \
      || ( obj )->segravity == FL_SouthEast )


#define HAS_FIXED_VERT_ULC_POS( obj )                             \
    ( ULC_POS_TOP_FIXED( obj ) || ULC_POS_BOTTOM_FIXED( obj ) )

#define HAS_FIXED_VERT_LRC_POS( obj )                             \
    ( LRC_POS_TOP_FIXED( obj ) || LRC_POS_BOTTOM_FIXED( obj ) )

#define HAS_FIXED_HEIGHT( obj )                                         \
    ( HAS_FIXED_VERT_ULC_POS( obj ) && HAS_FIXED_VERT_LRC_POS( obj ) ) 




/***************************************
 ***************************************/

static void
check_resize( FD_grav_data * g )
{
    fl_set_button( g->rx, g->box->resize & FL_RESIZE_X );
    fl_set_button( g->ry, g->box->resize & FL_RESIZE_Y );

    if ( HAS_FIXED_WIDTH( g->box ) )
        fl_set_object_lcolor( g->rx, FL_INACTIVE_COL );
    else
        fl_set_object_lcolor( g->rx, FL_BLACK );

    if ( HAS_FIXED_HEIGHT( g->box ) )
        fl_set_object_lcolor( g->ry, FL_INACTIVE_COL );
    else
        fl_set_object_lcolor( g->ry, FL_BLACK );
}


/***************************************
 ***************************************/

static void
nw_callback( FL_OBJECT * obj   FL_UNUSED_ARG,
             long              data )
{
    FD_grav_data * g = ( FD_grav_data * ) data;

    fl_set_object_gravity( g->box, g->grav, g->box->segravity );
    check_resize( g );
}


/***************************************
 ***************************************/

static void
se_callback( FL_OBJECT * obj   FL_UNUSED_ARG,
             long              data )
{
    FD_grav_data * g = ( FD_grav_data * ) data;

    fl_set_object_gravity( g->box, g->box->nwgravity, g->grav );
    check_resize( g );
}


/***************************************
 ***************************************/

static void
rx_callback( FL_OBJECT * obj   FL_UNUSED_ARG,
             long              data )
{
    FD_grav_data * g = ( FD_grav_data * ) data;
    unsigned int r = g->box->resize;

    if ( r & FL_RESIZE_X )
        r &= ~ FL_RESIZE_X;
    else
        r |= FL_RESIZE_X;

    fl_set_object_resize( g->box, r );
}
    

/***************************************
 ***************************************/

static void
ry_callback( FL_OBJECT * obj   FL_UNUSED_ARG,
             long              data )
{
    FD_grav_data * g = ( FD_grav_data * ) data;
    unsigned int r = g->box->resize;

    if ( r & FL_RESIZE_Y )
        r &= ~ FL_RESIZE_Y;
    else
        r |= FL_RESIZE_Y;

    fl_set_object_resize( g->box, r );
}
    

/***************************************
 ***************************************/

static void
reset_callback( FL_OBJECT * obj   FL_UNUSED_ARG,
                long        data )
{
    FD_grav_data * g = ( FD_grav_data * ) data;
    
    fl_set_form_size( g->box->form, w, h );
    fl_set_object_geometry( g->box, ( w - bw ) / 2, ( h - bh ) / 2, bw, bh );
}


/***************************************
 ***************************************/

static void
help_callback( FL_OBJECT * obj  FL_UNUSED_ARG,
                long       data )
{
    FD_help_form * h = ( FD_help_form * ) data;

    if ( ! h->is_shown )
    {
        fl_show_form( h->help, FL_PLACE_CENTER | FL_FREE_SIZE,
                      FL_FULLBORDER, "Gravity Demo Help" );
        h->is_shown = 1;
    }
}


/***************************************
 ***************************************/

static void
close_callback( FL_OBJECT * obj   FL_UNUSED_ARG,
                long        data )
{
    FD_help_form * h = ( FD_help_form * ) data;

    fl_hide_form( h->help );
    h->is_shown = 0;
}


/***************************************
 ***************************************/

static FD_gravity_form *
create_form_gravity( FD_help_form * help )
{
    FL_OBJECT * obj;
    FD_gravity_form * fdui = fl_malloc( sizeof *fdui );
    const char * label[ ] = { "NW", "N", "NE", "W", "-", "E", "SW", "S", "SE" };
    int i;
    int s = 25;
    int m = 5;

    fdui->grav = fl_bgn_form( FL_FLAT_BOX, 500, 400 );

    fl_set_form_background_color( fdui->grav, FL_DARKER_COL1 );

    fdui->box = obj = fl_add_box( FL_FRAME_BOX, ( w - bw ) / 2, ( h - bh ) / 2,
                                  bw, bh, "" );
    fl_set_object_color( obj, FL_GREEN, FL_GREEN );

    fl_bgn_group( );

    for ( i = 0; i < 9; i++ )
    {
        obj = fl_add_button( FL_RADIO_BUTTON,
                             s * ( i % 3 ) + m, s * ( i / 3 ) + m, s, s,
                             label[ i ] );
        fl_set_object_bw( obj, -1 );
        fl_set_object_resize( obj, FL_RESIZE_NONE );
        fl_set_object_gravity( obj, FL_NorthWest, FL_NorthWest );
        fl_set_object_callback( obj, nw_callback, ( long ) ( gd + i ) );
        fl_set_object_color( obj, FL_COL1, FL_MCOL );
        fl_set_button( obj, fdui->box->nwgravity == g[ i ] );
        fl_set_button_mouse_buttons( obj, 1 );
    }
    fl_end_group( );

    fl_bgn_group( );
    for ( i = 0; i < 9; i++ )
    {
        obj = fl_add_button( FL_RADIO_BUTTON,
                             s * ( i % 3 ) + w - 3 * s - m,
                             s * ( i / 3 ) + h - 3 * s - m, s, s,
                             label[ i ] );
        fl_set_object_bw( obj, -1 );
        fl_set_object_resize( obj, FL_RESIZE_NONE );
        fl_set_object_gravity( obj, FL_SouthEast, FL_SouthEast );
        fl_set_object_callback( obj, se_callback, ( long ) ( gd + i ) );
        fl_set_object_color( obj, FL_COL1, FL_MCOL );
        fl_set_button( obj, fdui->box->segravity == g[ i ] );
        fl_set_button_mouse_buttons( obj, 1 );
    }

    fl_end_group( );

    fdui->rx = obj = fl_add_button( FL_PUSH_BUTTON, m, h - s - m, 80, s,
                                    "X Resize" ); 
    fl_set_object_bw( obj, -1 );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_SouthWest, FL_SouthWest );
    fl_set_object_callback( obj, rx_callback, ( long ) gd );
    fl_set_object_color( obj, FL_COL1, FL_MCOL );
    fl_set_button( obj, fdui->box->resize & FL_RESIZE_X );
    fl_set_button_mouse_buttons( obj, 1 );

    fdui->ry = obj = fl_add_button( FL_PUSH_BUTTON, 2 * m + 80, h - s - m,
                                    80, s, "Y Resize" ); 
    fl_set_object_bw( obj, -1 );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_SouthWest, FL_SouthWest );
    fl_set_object_callback( obj, ry_callback, ( long ) gd );
    fl_set_object_color( obj, FL_COL1, FL_MCOL );
    fl_set_button( obj, fdui->box->resize & FL_RESIZE_Y );
    fl_set_button_mouse_buttons( obj, 1 );

    obj = fl_add_button( FL_NORMAL_BUTTON, w - 85, 5, 80, s, "Help" );
    fl_set_object_bw( obj, -1 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );
    fl_set_object_callback( obj, help_callback, ( long ) help );
    fl_set_button_mouse_buttons( obj, 1 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 200, h - s - m,
                         80, s, "Reset" );
    fl_set_object_bw( obj, -1 );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_South, FL_South );
    fl_set_object_callback( obj, reset_callback, ( long ) gd );
    fl_set_button_mouse_buttons( obj, 1 );

    obj = fl_add_button( FL_NORMAL_BUTTON, m + 280, h - s - m, 80, s, "Quit" );
    fl_set_object_bw( obj, -1 );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_South, FL_South );
    fl_set_button_mouse_buttons( obj, 1 );

    fl_end_form();

    return fdui;
}


/***************************************
 ***************************************/

static FD_help_form *
create_form_help( void )
{
    FL_OBJECT * obj;
    FD_help_form * fdui = fl_malloc( sizeof *fdui );  
    const char * text = "Gravity and resize settings demonstration\n"
                        "\n"
                        "The interaction between gravity and resize settings\n"
                        "can sometimes be difficult to understand  This pro-\n"
                        "gram allows you to test some of the effects.\n"
                        "\n"
                        "With the sets of buttons in the upper left hand and\n"
                        "lower right hand corner you can set the gravity for\n"
                        "the corresponding corners of the green rectangle.\n"
                        "\n"
                        "With the buttons labeled 'X Resize' and 'Y Resize'\n"
                        "you can set if the rectangle may be scaled in x-\n"
                        "and/or y-direction. Please note that for several\n"
                        "combinations of gravity settings the resizing\n"
                        "settings are not taken into account by XForms. In\n"
                        "these cases the corresponding buttons are grayed\n"
                        "out (but not deactivated).";

    fdui->help = fl_bgn_form( FL_FLAT_BOX, 345, 325 );

    fdui->is_shown = 0;

    obj = fl_add_browser( FL_NORMAL_BROWSER, 5, 5, 335, 285, "" );
    fl_set_object_bw( obj, -1 );
    fl_set_object_color( obj, FL_WHITE, FL_WHITE );
    fl_set_object_gravity( obj, FL_NorthWest, FL_SouthEast );
    fl_add_browser_line( obj, text );

    obj = fl_add_button( FL_NORMAL_BUTTON, 133, 295, 80, 25, "Close" );
    fl_set_object_bw( obj, -1 );
    fl_set_object_gravity( obj, FL_South, FL_South );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_callback( obj, close_callback, ( long ) fdui );
    fl_set_button_mouse_buttons( obj, 1 );

    fl_end_form();

    return fdui;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_gravity_form * grav;
    FD_help_form * help;
    int i;

    fl_initialize( &argc, argv, "Gravity Demo", 0, 0 );
    help = create_form_help( );
    grav = create_form_gravity( help );
    fl_set_app_mainform( grav->grav );

    for ( i = 0; i < 9; i++ )
    {
        gd[ i ].box = grav->box;
        gd[ i ].grav = g[ i ];
        gd[ i ].rx = grav->rx;
        gd[ i ].ry = grav->ry;
    }

    fl_show_form( grav->grav, FL_PLACE_CENTER | FL_FREE_SIZE,
                  FL_FULLBORDER, "Gravity Demo" );

    fl_do_forms( );

    fl_finish( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
