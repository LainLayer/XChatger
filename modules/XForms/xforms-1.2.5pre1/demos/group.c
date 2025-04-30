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
 * Demo showing the use of groups
 *
 * T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "porsche.xpm"
#include "nomail.xbm"
#include "bm1.xbm"

extern void show_group( FL_OBJECT *,
                        long );

/**** Forms and Objects ****/

#define NGROUP  4

typedef struct {
    FL_FORM   * objsform;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * bitbutton;
    FL_OBJECT * pixbutton;
    FL_OBJECT * bit;
    FL_OBJECT * pix;
    FL_OBJECT * chart;
    FL_OBJECT * quit;
    FL_OBJECT * menu;
    FL_OBJECT * choice;
    FL_OBJECT * browser;
    FL_OBJECT * xyplot;
    FL_OBJECT * button[ 5 ];
    FL_OBJECT * group[ 5 ];
} FD_objsform;


extern FD_objsform *create_form_objsform( void );

FD_objsform *fd_objsform;

/* callbacks for form objsform */

/***************************************
 ***************************************/

void
show_group( FL_OBJECT * ob    FL_UNUSED_ARG,
            long        data )
{
    int i;

    for ( i = 0; i <= NGROUP;i++)
        ( i == data ?
          fl_show_object : fl_hide_object )( fd_objsform->group[ i ] );
}


/***************************************
 ***************************************/

void
init_gui( FD_objsform *fd )
{
    float x[ ] = { 0, 1, 2, 3, 4, 5 };
    float y[ ] = { 5.5, 4, 4.5, 3.8, 4, 5};
    char *label[ ] = { "Mon", "Tue", "Wed", "Thur", "Fri", "Sat" };
    size_t i;

    fl_addto_menu( fd->menu, "One\tF1|Two\tF2|Three\tF3|Four\tF4" );
    fl_addto_choice( fd->choice, "Option1|Option2|Option3" );

    fl_set_pixmapbutton_data( fd->pixbutton, porsche );
    fl_set_pixmap_data( fd->pix, porsche );
    fl_set_bitmapbutton_data( fd->bitbutton, bm1_width, bm1_height, bm1_bits );
    fl_set_bitmap_data( fd->bit, nomail_width, nomail_height, nomail_bits );

    fl_set_browser_fontsize( fd->browser, FL_NORMAL_SIZE );
    fl_addto_browser( fd->browser, "browser line 1\nbrowser line 2" );
    fl_addto_browser( fd->browser, "browser line 3\nbrowser line 4" );
    fl_addto_browser( fd->browser, "browser line 5\nbrowser line 6" );
    fl_addto_browser( fd->browser, "browser line 7\nbrowser line 8" );
    fl_addto_browser( fd->browser, "browser line 9\nbrowser line 10" );
    fl_addto_browser( fd->browser, "browser line 11\nbrowser line 12" );
    fl_addto_browser( fd->browser, "browser line 13\nbrowser line 14" );
    fl_addto_browser( fd->browser, "browser line 15\nbrowser line 16" );
    fl_addto_browser( fd->browser, "browser line 17\nbrowser line 18" );

    for ( i = 0; i < sizeof y / sizeof *y; i++ )
        fl_add_chart_value( fd->chart, y[ i ], label[ i ], i + 1 );

    fl_set_xyplot_data( fd->xyplot, x, y, 6, "", "","" );
    fl_add_xyplot_overlay( fd->xyplot, 1, x, y, 6, FL_RED );
    fl_add_xyplot_text( fd->xyplot, 2.5, 5.2, "Weekly Summary",
                        FL_ALIGN_CENTER, FL_BLUE );
    fl_add_xyplot_text( fd->xyplot, 3, 3.85, "@-22->", FL_ALIGN_TOP, FL_RED );

    fl_set_xyplot_overlay_type( fd->xyplot, 1, FL_NORMAL_XYPLOT );
    fl_set_xyplot_alphaxtics( fd->xyplot, "Mon|Tue|Wed|Thu|Fri|Sat", 0 );
    fl_set_xyplot_ytics( fd->xyplot, -1, -1 );
    fl_set_xyplot_linewidth( fd->xyplot, 0, 3 );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_objsform = create_form_objsform( );
    init_gui( fd_objsform );

    /* fill-in form initialization code */

    fl_set_button( fd_objsform->button[ 0 ], 1 );
    show_group( 0, 0 );

    /* show the first form */

    fl_show_form( fd_objsform->objsform, FL_PLACE_CENTER,
                  FL_FULLBORDER, "objsform" );

    while ( fl_do_forms( ) != fd_objsform->quit )
        /* empty */ ;

    fl_finish( );
    return 0;
}


/* Form definition file generated with fdesign. */

#include <stdlib.h>

/***************************************
 ***************************************/

FD_objsform *
create_form_objsform( void )
{
    FL_OBJECT *obj;
    FD_objsform *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->objsform = fl_bgn_form( FL_NO_BOX, 456, 361 );

    fl_add_box( FL_FLAT_BOX, 0, 0, 456, 361, "" );

    fl_add_box( FL_UP_BOX, 0, 0, 455, 360, "" );

    fl_add_box( FL_UP_BOX, 0, 0, 456, 70, "" );

    fdui->button[ 0 ] = obj = fl_add_button( FL_RADIO_BUTTON, 15, 20, 75, 30,
                                             "Static" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE);
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );
    fl_set_object_callback( obj, show_group, 0 );

    fdui->button[ 1 ] = obj = fl_add_button( FL_RADIO_BUTTON, 90, 20, 75, 30,
                                             "Button" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );
    fl_set_object_callback( obj, show_group, 1 );

    fdui->button[ 2 ] = obj = fl_add_button( FL_RADIO_BUTTON, 165, 20, 70, 30,
                                             "Valuator" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );
    fl_set_object_callback( obj, show_group, 2 );

    fdui->button[ 3 ] = obj = fl_add_button( FL_RADIO_BUTTON, 235, 20, 70, 30,
                                             "Input" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );
    fl_set_object_callback( obj, show_group, 3 );

    fdui->button[ 4 ] = obj = fl_add_button( FL_RADIO_BUTTON, 305, 20, 70, 30,
                                             "Other" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );
    fl_set_object_callback( obj, show_group, 4 );

    fl_add_box( FL_UP_BOX, 0, 70, 456, 291, "" );

    fl_add_box( FL_DOWN_BOX, 9, 90, 435, 260, "" );

    fdui->group[ 2 ] = fl_bgn_group( );

    obj = fl_add_text( FL_NORMAL_TEXT, 260, 140, 80, 30, "Text" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_LEFT ) );

    fl_add_slider( FL_HOR_BROWSER_SLIDER, 60, 120, 170, 25, "" );

    obj = fl_add_slider( FL_HOR_FILL_SLIDER, 60, 160, 170, 30, "" );
    fl_set_slider_value( obj, 0.54 );

    obj = fl_add_slider( FL_VERT_SLIDER, 390, 110, 30, 170, "" );
    fl_set_slider_value( obj, 0.48 );

    fl_add_valslider( FL_VERT_SLIDER, 350, 110, 30, 170, "" );

    obj = fl_add_dial( FL_FILL_DIAL, 50, 220, 90, 70, "" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    fl_add_positioner( FL_NORMAL_POSITIONER, 150, 210,120, 100, "" );

    fl_add_counter( FL_NORMAL_COUNTER, 300, 300, 130, 30, "" );

    fl_end_group( );

    fdui->group[ 1 ] = fl_bgn_group( );

    fdui->bitbutton = fl_add_bitmapbutton( FL_NORMAL_BUTTON, 60, 250, 50, 40,
                                           "" );

    fdui->pixbutton = fl_add_pixmapbutton( FL_NORMAL_BUTTON, 85, 120, 80, 80,
                                           "" );

    fl_add_button( FL_NORMAL_BUTTON, 290, 270, 90, 35, "Button" );

    obj = fl_add_round3dbutton( FL_PUSH_BUTTON, 260, 95, 60, 40,
                                "Round3DButton" );
    fl_set_object_color( obj, FL_COL1, FL_MAGENTA );

    fl_add_roundbutton( FL_PUSH_BUTTON, 220, 140, 60, 40, "RoundButton" );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 190, 230, 50, 40, "CheckButton" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    fl_add_lightbutton( FL_PUSH_BUTTON, 290, 200, 100, 30, "LightButton" );

    obj = fl_add_button( FL_PUSH_BUTTON, 120, 290, 100, 35 ,"Button");
    fl_set_object_boxtype( obj, FL_ROUNDED3D_UPBOX );

    fl_end_group( );

    fdui->group[ 0 ] = fl_bgn_group( );

    obj = fl_add_box( FL_UP_BOX, 40, 120, 70, 70, "A Box" );
    fl_set_object_lsize( obj,FL_NORMAL_SIZE );
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );

    fdui->bit = fl_add_bitmap( FL_NORMAL_BITMAP, 30, 220, 80, 70, "bitmap" );

    fl_add_clock( FL_ANALOG_CLOCK, 330, 240, 90, 80, "" );

    obj = fl_add_frame( FL_ENGRAVED_FRAME, 130, 120, 80, 70, "A Frame" );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_lstyle( obj, FL_TIMESBOLD_STYLE );

    fdui->pix = fl_add_pixmap( FL_NORMAL_PIXMAP, 340, 110, 90, 70, "pixmap" );

    fdui->chart = fl_add_chart( FL_PIE_CHART, 160, 210, 130, 110, "chart" );

    obj = fl_add_text( FL_NORMAL_TEXT, 240, 130, 100, 30,
                       "Text stuff\nand more stuff" );
    fl_set_object_lalign( obj,FL_ALIGN_CENTER );

    fl_end_group( );

    fdui->group[ 3 ] = fl_bgn_group( );

    fl_add_input( FL_NORMAL_INPUT, 140, 120, 150, 30, "Input" );

    fl_add_input( FL_MULTILINE_INPUT, 60, 170, 320, 130, "" );

    fl_end_group( );

    fdui->quit = fl_add_button( FL_NORMAL_BUTTON, 385, 20, 60, 30, "Quit" );

    fdui->group[ 4 ] = fl_bgn_group( );

    fdui->menu = obj = fl_add_menu( FL_PULLDOWN_MENU, 190, 110, 40, 19,
                                    "Menu" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );

    fdui->choice = fl_add_choice( FL_NORMAL_CHOICE, 290, 110, 120, 30, "" );

    fdui->browser = fl_add_browser( FL_NORMAL_BROWSER, 30, 140, 140, 150, "" );

    fdui->xyplot = obj = fl_add_xyplot( FL_IMPULSE_XYPLOT, 190, 150, 240, 180,
                                        "" );
    fl_set_object_lsize( obj, FL_DEFAULT_SIZE );

    fl_end_group( );

    fl_end_form( );

    fdui->objsform->fdui = fdui;
    
    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
