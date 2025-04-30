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
#include <math.h>

/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * axypform;
    void      * vdata;
    long        ldata;
    FL_OBJECT * xyplot;
    FL_OBJECT * status;
} FD_axypform;


extern FD_axypform * create_form_axypform( void );

#define LOG

FD_axypform *xypui;


/* callbacks for form axypform */

/***************************************
 ***************************************/

void
xyplot_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
    float x,
          y;
    int i;
    char buf[ 64 ];

    fl_get_xyplot( ob, &x, &y, &i );
    fl_object_ps_dump( ob, "test.ps" );
    if ( i < 0 )
        return ;
    sprintf( buf, "X=%g  Y=%g", x, y );
    fl_set_object_label( xypui->status, buf );
}


/***************************************
 ***************************************/

void
alwaysreturn_cb( FL_OBJECT * ob,
                 long        data  FL_UNUSED_ARG )
{
    fl_set_xyplot_return( xypui->xyplot, fl_get_button( ob ) );
}


/***************************************
 ***************************************/

void
interpolate_cb( FL_OBJECT * ob,
                long        data  FL_UNUSED_ARG )
{
#ifdef LOG
    fl_set_xyplot_interpolate( xypui->xyplot, 0,
                               fl_get_button(ob) ? 2 : 0, 20000 );
#else
    fl_set_xyplot_interpolate( xypui->xyplot, 0,
                               fl_get_button( ob ) ? 2 : 0, 0.2 );
#endif
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
notic_cb( FL_OBJECT * ob,
          long      data  FL_UNUSED_ARG )
{
    int notic = fl_get_button( ob );

    if ( notic )
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

int
main( int    argc,
      char * argv[ ] )
{
    float x[ 25 ],
          y[ 25 ];
    int i;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    xypui = create_form_axypform( );
   
    fl_set_object_dblbuffer( xypui->status, 1 );
    for ( i  = 0; i <= 10; i++ )
#ifdef LOG
        x[ i ] = y[ i ] =  pow( 10, i - 12 );
#else
        x[ i ] = y[ i ] = i;
#endif
    fl_set_xyplot_data( xypui->xyplot, x, y, 11, "", "", "" );

#ifdef LOG
    fl_set_xyplot_xscale( xypui->xyplot, FL_LOG, 5 );
    fl_set_xyplot_yscale( xypui->xyplot, FL_LOG, 5 );
    fl_set_xyplot_xbounds( xypui->xyplot, 0.01, 10 );
    fl_set_xyplot_ytics( xypui->xyplot, 3, 5 );
    fl_set_xyplot_xgrid( xypui->xyplot, FL_GRID_MINOR );
/*   fl_set_xyplot_ygrid( xypui->xyplot, 2 ); */
#endif

    fl_show_form( xypui->axypform, FL_PLACE_MOUSE, FL_TRANSIENT, "axypform" );

    fl_do_forms( );
    fl_finish( );
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

    fdui->xyplot = obj = fl_add_xyplot( FL_ACTIVE_XYPLOT,
                                        20, 50, 285, 235, "" );
    fl_set_object_boxtype( obj, FL_DOWN_BOX );
    fl_set_object_color( obj, FL_BLACK, FL_GREEN );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_BOTTOM ) );
    fl_set_object_callback( obj, xyplot_cb, 0 );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 40, 80, 25, "AlwaysReturn" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, alwaysreturn_cb, 0 );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 65, 80, 25, "Interpolate" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, interpolate_cb, 0 );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 90, 85,  25, "InspectOnly" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, inspect_cb, 0 );

    fdui->status = obj = fl_add_text( FL_NORMAL_TEXT, 45, 15, 170, 25, "" );
    fl_set_object_boxtype( obj, FL_DOWN_BOX );

    fl_add_button( FL_NORMAL_BUTTON, 325, 250, 90, 30, "Done" );

    obj = fl_add_checkbutton( FL_PUSH_BUTTON, 315, 120, 85, 25, "NoTics" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, notic_cb, 0 );

    fl_end_form( );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
