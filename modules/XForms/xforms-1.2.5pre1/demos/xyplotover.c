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
 * Demo showing the use of xyplot overlay, plot key and
 * PostScript output.
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>
#include <math.h>

/**** Forms and Objects ****/

typedef struct
{
    FL_FORM *   fff;
    void *      vdata;
    long        ldata;
    FL_OBJECT * xyplot;
} FD_fff;

extern FD_fff * create_form_fff( void );
extern void init_xyplot( FD_fff * );


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_fff *fd_fff;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    fd_fff = create_form_fff( );

    /* Fill-in form initialization code */

    init_xyplot( fd_fff );

    /* Show the first form */

    fl_show_form( fd_fff->fff, FL_PLACE_MOUSE | FL_FREE_SIZE, FL_TRANSIENT,
                  "XYPlot Overlay" );

    fl_do_forms( );

    if ( fl_object_ps_dump( fd_fff->xyplot, "test.ps" ) >= 0 )
        fprintf( stderr, "PostScript output test.ps written\n" );

    return 0;
}


/***************************************
 ***************************************/

void
init_xyplot( FD_fff * fd_fff )
{
    int i;
    float xx[ 20 ],
          yy[ 20 ];

    for ( i = 0; i <= 10; i++ )
    {
        xx[ i ] = i;
        yy[ i ] = exp( - 0.125 * ( i - 5 ) * ( i - 5 ) );
    }

    fl_set_xyplot_data( fd_fff->xyplot, xx, yy, 8,
                        "Plot Title", "X-Axis", "Y|Axis");
    fl_set_xyplot_ybounds( fd_fff->xyplot, 0, 1.1 );
    fl_set_xyplot_xbounds( fd_fff->xyplot, 0, 10 );
    fl_add_xyplot_overlay( fd_fff->xyplot, 1, xx, yy, 11, FL_YELLOW );
    fl_set_xyplot_overlay_type( fd_fff->xyplot, 1, FL_LINEPOINTS_XYPLOT );
    fl_set_xyplot_interpolate( fd_fff->xyplot, 1, 2, 0.1 );

    fl_add_xyplot_text( fd_fff->xyplot, 0.5, 1.0, "Gaussian\nDistribution",
                        FL_ALIGN_RIGHT, FL_WHITE );

    fl_set_xyplot_key( fd_fff->xyplot, 0, "Original" );
    fl_set_xyplot_key( fd_fff->xyplot, 1, "Overlay" );
    fl_set_xyplot_key_position( fd_fff->xyplot, 9.8, 1.08,
                                FL_ALIGN_LEFT_BOTTOM );
}


/***************************************
 ***************************************/

FD_fff *
create_form_fff( void )
{
    FL_OBJECT *obj;
    FD_fff *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->fff = fl_bgn_form( FL_NO_BOX, 370, 310 );

    fl_add_box( FL_UP_BOX, 0, 0, 370, 310, "" );

    fdui->xyplot = obj = fl_add_xyplot( FL_IMPULSE_XYPLOT, 10, 20, 350, 260,
                                        "An XYPlot with overlay" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_BOTTOM ) );
    fl_set_object_lsize( obj, FL_NORMAL_SIZE );
    fl_set_object_boxtype( obj, FL_DOWN_BOX );
    fl_set_object_color( obj, FL_BLACK, FL_GREEN );

    obj = fl_add_button( FL_HIDDEN_BUTTON, 10, 10, 350, 290, "" );
    fl_set_button_shortcut( obj,"qQ", 0 );

    fl_end_form( );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
