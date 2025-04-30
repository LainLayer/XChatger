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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>
#include "time.h"

/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * axypform;
    void      * vdata;
    long        ldata;
    FL_OBJECT * xyplot;
    FL_OBJECT * xmin;
    FL_OBJECT * xmax;
    FL_OBJECT * ymin;
    FL_OBJECT * ymax;
    FL_OBJECT * status;
} FD_axypform;

FD_axypform *create_form_axypform( void );

FD_axypform *xypui;

/* callbacks for form axypform */


/***************************************
 ***************************************/

void xyplot_cb( FL_OBJECT * ob,
                long        data  FL_UNUSED_ARG )
{
    float x, y;
    int i;
    char buf[ 64 ];

    fl_get_xyplot( ob, &x, &y, &i );
    if ( i < 0 )
       return;

    sprintf( buf, "X=%.3f  Y=%.3f", x, y );
    fl_set_object_label( xypui->status, buf );
}


/***************************************
 ***************************************/

void
alwaysreturn_cb( FL_OBJECT * ob,
                 long        data  FL_UNUSED_ARG )
{
    fl_set_object_return( xypui->xyplot,
                          fl_get_button( ob ) ?
                          FL_RETURN_CHANGED : FL_RETURN_END_CHANGED );
}


/***************************************
 ***************************************/

void
interpolate_cb( FL_OBJECT * ob,
                long        data  FL_UNUSED_ARG )
{
    fl_set_xyplot_interpolate( xypui->xyplot, 0, fl_get_button( ob ) ? 3 : 0,
                               0.2 );
}


/***************************************
 ***************************************/

void
inspect_cb( FL_OBJECT * ob,
            long        data  FL_UNUSED_ARG )
{
    fl_set_xyplot_inspect( xypui->xyplot, fl_get_button( ob ) );
}


/***************************************
 ***************************************/

void
notic_cb( FL_OBJECT * obj,
          long        data  FL_UNUSED_ARG )
{
    if ( fl_get_button( obj ) )
    {
        fl_set_xyplot_xtics( xypui->xyplot, -1, -1 );
        fl_set_xyplot_ytics( xypui->xyplot, -1, -1 );
    }
    else
    {
        fl_set_xyplot_xtics( xypui->xyplot, 0, 0 );
        fl_set_xyplot_ytics( xypui->xyplot, 0, 0 );
    }
}


/***************************************
 ***************************************/

void
bounds_cb( FL_OBJECT * ob  FL_UNUSED_ARG,
           long        data )
{
    char buf[ 50 ];

    if ( ! data )
    {
        float xmin = strtod( fl_get_input( xypui->xmin ), NULL );
        float xmax = strtod( fl_get_input( xypui->xmax ), NULL );

        fl_set_xyplot_xbounds( xypui->xyplot, xmin, xmax );

        fl_get_xyplot_xbounds( xypui->xyplot, &xmin, &xmax );
        sprintf( buf, "%g", xmin );
        fl_set_input( xypui->xmin, buf );
        sprintf( buf, "%g", xmax );
        fl_set_input( xypui->xmax, buf );
    }
    else
    {
        float ymin = strtod( fl_get_input( xypui->ymin ), NULL );
        float ymax = strtod( fl_get_input( xypui->ymax ), NULL );

        fl_set_xyplot_ybounds( xypui->xyplot, ymin, ymax );

        fl_get_xyplot_ybounds( xypui->xyplot, &ymin, &ymax );
        sprintf( buf, "%g", ymin );
        fl_set_input( xypui->ymin, buf );
        sprintf( buf, "%g", ymax );
        fl_set_input( xypui->ymax, buf );
    }
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    float x[ 11 ],
          y[ 11 ];
    int i;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    xypui = create_form_axypform( );

    /* Fill-in form initialization code */

    fl_set_xyplot_ybounds( xypui->xyplot, 0.0, 10.0 );

    for ( i  = 0; i <= 10; i++ )
        x[ i ] = y[ i ] = i;

    fl_add_xyplot_overlay( xypui->xyplot, 1, x, y, 11, FL_YELLOW );
    fl_set_xyplot_overlay_type( xypui->xyplot, 1, FL_LINEPOINTS_XYPLOT );
    fl_set_xyplot_interpolate( xypui->xyplot, 1, 2, 0.1 );

    srand( time( NULL ) );

    for ( i = 0; i <= 10; i++ )
        y[ i ] +=  ( double ) rand( ) / RAND_MAX - 0.5;

    fl_set_xyplot_data( xypui->xyplot, x, y, 11, "Active xyplot with overlay",
                        "x-axis", "y-axis" );
    fl_set_xyplot_linewidth( xypui->xyplot, 0, 2 );
    fl_set_xyplot_xgrid( xypui->xyplot, FL_GRID_MINOR );

    /* Show the first form */

    fl_show_form( xypui->axypform, FL_PLACE_MOUSE | FL_FREE_SIZE,
                  FL_FULLBORDER, "xyplotactive" );

    fl_do_forms( );

    return 0;
}


/***************************************
 ***************************************/

FD_axypform *
create_form_axypform( void )
{
    FL_OBJECT *obj;
    FD_axypform *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->axypform = fl_bgn_form( FL_NO_BOX, 431, 301 );

    fl_add_box( FL_UP_BOX, 0, 0, 431, 301, "" );

    fdui->xyplot = obj = fl_add_xyplot( FL_ACTIVE_XYPLOT, 20, 50, 285, 235,
                                        "" );

    fl_set_object_boxtype( obj, FL_DOWN_BOX );
    fl_set_object_color( obj, FL_BLACK, FL_GREEN );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_BOTTOM ) );
    fl_set_object_callback( obj, xyplot_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthWest, FL_SouthEast );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 40, 80, 25, "AlwaysReturn" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, alwaysreturn_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 65, 80, 25, "Interpolate" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, interpolate_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 90, 85, 25, "InspectOnly" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, inspect_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 120, 85, 25, "NoTics" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, notic_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );


    fdui->xmin = obj = fl_add_input( FL_FLOAT_INPUT, 315, 150, 50, 20,
                                     " x_min" );
    fl_set_input( obj, "0.0" );
    fl_set_object_lalign( obj, FL_ALIGN_RIGHT );
    fl_set_object_callback( obj, bounds_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    fdui->xmax = obj = fl_add_input( FL_FLOAT_INPUT, 315, 170, 50, 20,
                                     " x_max" );
    fl_set_input( obj, "10.0" );
    fl_set_object_lalign( obj, FL_ALIGN_RIGHT );
    fl_set_object_callback( obj, bounds_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    fdui->ymin = obj = fl_add_input( FL_FLOAT_INPUT, 315, 200, 50, 20,
                                     " y_min" );
    fl_set_input( obj, "0.0" );
    fl_set_object_lalign( obj, FL_ALIGN_RIGHT );
    fl_set_object_callback( obj, bounds_cb, 1 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    fdui->ymax = obj = fl_add_input( FL_FLOAT_INPUT, 315, 220, 50, 20,
                                     " y_max" );
    fl_set_input( obj, "10.0" );
    fl_set_object_lalign( obj, FL_ALIGN_RIGHT );
    fl_set_object_callback( obj, bounds_cb, 1 );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );

    fdui->status = obj = fl_add_box( FL_BORDER_BOX, 20, 15, 285, 25, "" );
    fl_set_object_boxtype( obj, FL_DOWN_BOX );
    fl_set_object_gravity( obj, FL_NorthWest, FL_NorthEast );
    fl_set_object_lalign( obj, FL_ALIGN_CENTER );

    obj = fl_add_button( FL_NORMAL_BUTTON, 325, 250, 90, 30, "Done" );
    fl_set_object_gravity( obj, FL_SouthEast, FL_SouthEast );

    fl_end_form( );

  return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
