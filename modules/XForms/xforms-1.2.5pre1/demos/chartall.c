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
 * Showing all different charts
 *
 *  This file is part of xforms package
 *  M. Overmars and T.C. Zhao   (1997)
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"


FL_FORM *form;

FL_OBJECT *barchart,
          *linechart,
          *filledchart,
          *piechart,
          *specialpiechart,
          *exitbut,
          *horbarchart,
          *spikechart;


void create_form_form( void );


/***************************************
 ***************************************/

void
fill_in( FL_OBJECT * ob )
{
   int c = FL_BLACK;

   fl_add_chart_value( ob, 15.0, "item 1", ++c );
   fl_add_chart_value( ob,  5.0, "item 2", ++c );
   fl_add_chart_value( ob,  0.0, "item 3", ++c );
   fl_add_chart_value( ob, -10., "item 4", ++c );
   fl_add_chart_value( ob, 25.0, "item 5", ++c );
   fl_add_chart_value( ob, 12.0, "item 6", ++c );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{

   fl_initialize( &argc, argv, "FormDemo", 0, 0 );

   create_form_form( );
   fill_in( barchart );
   fill_in( horbarchart );
   fill_in( linechart );
   fl_set_object_helper( linechart, "A LineChart" );
   fill_in( filledchart );
   fill_in( spikechart );
   fill_in( piechart );
   fill_in( specialpiechart );

   fl_show_form( form, FL_PLACE_CENTER, FL_TRANSIENT, "Charts" );

   fl_do_forms( );

   fl_finish( );
   return 0;
}


/***************************************
 ***************************************/

void
create_form_form( void )
{
    FL_OBJECT *obj;

    form = fl_bgn_form( FL_NO_BOX, 940, 360 );

    fl_add_box( FL_UP_BOX, 0, 0, 940, 360, "" );

    barchart = obj = fl_add_chart( FL_BAR_CHART, 20, 20, 210, 140,
                                   "BAR_CHART" );
    fl_set_object_boxtype( obj, FL_RSHADOW_BOX );

    linechart = obj = fl_add_chart( FL_LINE_CHART, 250, 20, 210, 140,
                                    "LINE_CHART" );
    fl_set_object_boxtype( obj, FL_RSHADOW_BOX );

    filledchart = obj = fl_add_chart( FL_FILLED_CHART, 250, 190, 210, 140,
                                      "FILLED_CHART" );
    fl_set_object_boxtype( obj ,FL_RSHADOW_BOX );

    piechart = obj = fl_add_chart( FL_PIE_CHART, 480, 190, 210, 140,
                                   "PIE_CHART" );
    fl_set_object_boxtype( obj, FL_RSHADOW_BOX );

    specialpiechart = obj = fl_add_chart( FL_SPECIALPIE_CHART,
                                          710, 20, 210, 140,
                                          "SPECIALPIE_CHART" );
    fl_set_object_boxtype( obj, FL_RSHADOW_BOX );

    horbarchart = obj = fl_add_chart( FL_HORBAR_CHART, 20, 190, 210, 140,
                                      "HORBAR_CHART" );
    fl_set_object_boxtype( obj, FL_RSHADOW_BOX );

    spikechart = obj = fl_add_chart( FL_SPIKE_CHART, 480, 20, 210, 140,
                                     "SPIKE_CHART" );
    fl_set_object_boxtype( obj, FL_RSHADOW_BOX );

    exitbut = fl_add_button( FL_NORMAL_BUTTON, 750, 260, 140, 30, "Exit" );

    fl_end_form( );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
