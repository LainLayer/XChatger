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


/* This demo shows the different types of sliders */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"


FL_FORM *form;
FL_OBJECT *exitobj;


/***************************************
 ***************************************/

void
create_form_form( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 780, 320 );

    obj = fl_add_box( FL_UP_BOX, 0, 0, 780, 320, "" );
    fl_set_object_color( obj, FL_PALEGREEN, FL_COL1 );

    obj = fl_add_box( FL_SHADOW_BOX, 20, 30, 360, 270, "SLIDER" );
    fl_set_object_color( obj, FL_SLATEBLUE, 47 );
    fl_set_object_lalign( obj, FL_ALIGN_TOP );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    obj = fl_add_box( FL_SHADOW_BOX, 390, 30, 370, 270, "VALSLIDER" );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_COL1 );
    fl_set_object_lalign( obj, FL_ALIGN_TOP );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    obj = fl_add_slider( FL_VERT_SLIDER, 30, 50, 40, 220, "vert" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );
    fl_set_slider_mouse_buttons( obj, 7 );

    obj = fl_add_slider( FL_VERT_FILL_SLIDER, 80, 50, 40, 220, "vert_fill" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    obj = fl_add_slider( FL_HOR_SLIDER, 180, 50, 195, 40, "hor" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    obj = fl_add_slider( FL_HOR_FILL_SLIDER, 180, 110, 190, 40, "hor_fill" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    obj = fl_add_valslider( FL_VERT_NICE_SLIDER, 610, 50, 30, 220,
                            "vert_nice" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_INDIANRED );

    obj = fl_add_valslider( FL_VERT_FILL_SLIDER, 660, 50, 40, 220,
                            "vert_fill" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    obj = fl_add_valslider( FL_HOR_SLIDER, 400, 50, 190, 40, "hor" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    obj = fl_add_valslider( FL_HOR_FILL_SLIDER, 400, 110, 190, 40, "hor_fill" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    fl_add_valslider( FL_HOR_BROWSER_SLIDER, 400, 220, 190, 25, "hor_browser" );

    exitobj = obj = fl_add_button( FL_NORMAL_BUTTON, 450, 260, 100, 30,
                                   "Exit" );
    fl_set_object_color( obj, FL_INDIANRED, FL_RED );

    obj = fl_add_slider( FL_VERT_NICE_SLIDER, 130, 50, 30, 220, "vert_nice" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_INDIANRED );

    obj = fl_add_slider( FL_HOR_NICE_SLIDER, 180, 170, 190, 30, "hor_nice" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_INDIANRED );

    fl_add_slider( FL_HOR_BROWSER_SLIDER, 180, 220, 190, 25, "hor_browser" );

    obj = fl_add_valslider( FL_HOR_NICE_SLIDER, 400, 170, 190, 30, "hor_nice" );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_color( obj, FL_SLATEBLUE, FL_INDIANRED );

    obj = fl_add_valslider( FL_VERT_SLIDER, 710, 50, 40, 220, "vert" );
    fl_set_object_color( obj, FL_INDIANRED, FL_PALEGREEN );

    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    create_form_form( );

    fl_show_form( form, FL_PLACE_CENTER | FL_FREE_SIZE, FL_FULLBORDER,
                  "All Sliders" );

    do
        obj = fl_do_forms( );
    while ( obj != exitobj );

    fl_hide_form( form );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
