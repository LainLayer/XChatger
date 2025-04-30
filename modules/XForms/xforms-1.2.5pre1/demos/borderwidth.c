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
 * demo showing the effect of different border widths
 *
 * This file is part of xforms packge
 * T.C. Zhao and M. Overmars  (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>


/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * bwform;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * done;
    FL_OBJECT * bw_select;
    FL_OBJECT * bwgroup;
    FL_OBJECT * pmobj;
} FD_bwform;

static FD_bwform * fd_bwform;

static FD_bwform * create_form_bwform( void );
static void done_callback( FL_OBJECT *, long );
static void bw_callback( FL_OBJECT *, long );


/* Callbacks for form bwform */

/***************************************
 ***************************************/

static void
done_callback( FL_OBJECT * ob    FL_UNUSED_ARG,
               long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    fl_free( fd_bwform );
    exit( 0 );
}


/***************************************
 ***************************************/

static void
bw_callback( FL_OBJECT * ob,
             long        data  FL_UNUSED_ARG )
{
    static int bws[ ] = { -5, -4, -3, -2, -1, 1, 2, 3, 4, 5 };
    FL_POPUP_RETURN *r =  fl_get_select_item( ob );
    int bw = bws[ r->val ];

    fl_set_object_bw( fd_bwform->bwgroup, bw );
    fl_set_object_bw( fd_bwform->done, bw );
    fl_popup_set_bw( ( FL_POPUP * ) r->popup, bw );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    int bw;
    char txt[ 9 ];

    /* Application default. Can be overriden by the command line options */

    fl_set_border_width( 1 );

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_bwform = create_form_bwform( );

    /* Form initialization code */

    fl_set_pixmapbutton_file( fd_bwform->pmobj, "crab.xpm" );

    fl_add_select_items( fd_bwform->bw_select,
                         "-5 Pixel|-4 Pixel|-3 Pixel|-2 Pixel|-1 Pixel|"
                         " 1 Pixel| 2 Pixel| 3 Pixel| 4 Pixel| 5 Pixel" );

    bw = fl_get_border_width( );
    if ( bw < -5 || bw == 0 || bw > 5 )
        fl_set_border_width( bw = -2 );

    sprintf( txt, "%2d Pixel", bw );
    fl_set_select_item( fd_bwform->bw_select,
                        fl_get_select_item_by_label( fd_bwform->bw_select,
                                                     txt ) );

    /* show the form */

    fl_show_form( fd_bwform->bwform, FL_PLACE_CENTER, FL_TRANSIENT, "bwform" );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}


/***************************************
 * Form definition file generated with fdesign.
 ***************************************/

static FD_bwform *
create_form_bwform( void )
{
    FL_OBJECT *obj;
    FD_bwform *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->bwform = fl_bgn_form( FL_NO_BOX, 380, 340 );

    fdui->bwgroup = fl_bgn_group();

    fl_add_box( FL_UP_BOX, 0, 0, 380, 340, "" );

    fl_add_frame( FL_EMBOSSED_FRAME, 220, 60, 135, 145, "" );

    fl_add_frame( FL_ENGRAVED_FRAME, 15, 60, 185, 145, "" );

    fl_add_slider( FL_HOR_SLIDER, 25, 70, 160, 20, "" );

    fl_add_valslider( FL_HOR_BROWSER_SLIDER, 25, 105, 160, 20, "" );

    obj = fl_add_scrollbar( FL_HOR_THIN_SCROLLBAR, 25, 140, 160, 20, "" );
    fl_set_scrollbar_size( obj, 0.2 );

    fl_add_counter( FL_NORMAL_COUNTER, 25, 175, 160, 20, "" );

    fdui->pmobj = fl_add_pixmapbutton( FL_NORMAL_BUTTON, 305, 145, 40, 35, "" );

    fl_add_positioner( FL_NORMAL_POSITIONER, 30, 225, 100, 80, "" );

    fl_add_button( FL_NORMAL_BUTTON, 230, 65, 100, 28, "Button" );

    fl_add_lightbutton( FL_PUSH_BUTTON, 230, 98, 100, 28, "LightButton" );

    fl_add_roundbutton( FL_PUSH_BUTTON, 230, 128, 80, 32, "Button" );

    obj = fl_add_round3dbutton( FL_PUSH_BUTTON, 230, 152, 80, 32, "Button" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    fl_add_checkbutton( FL_PUSH_BUTTON, 230, 175, 80, 32, "Button" );

    fl_add_input( FL_NORMAL_INPUT, 195, 240, 160, 28, "Input" );

    fdui->bw_select = obj = fl_add_select( FL_MENU_SELECT, 105, 20, 100, 28,
                                           "Border Width" );
    fl_set_object_callback( obj, bw_callback, 0 );

    fl_end_group( );

    fdui->done = obj = fl_add_button( FL_NORMAL_BUTTON, 270, 290, 75, 30,
                                      "Done" );
    fl_set_object_callback( obj, done_callback, 0 );

    fl_end_form( );

    fdui->bwform->fdui  = fdui;

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
