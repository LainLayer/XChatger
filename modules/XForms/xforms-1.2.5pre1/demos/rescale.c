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


/* Demo for scaling forms. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include "include/forms.h"

typedef struct
{
    FL_FORM   * form;
    FL_OBJECT *smallerobj,
              *largerobj,
              *scaleobj,
    *cell00,
              *exitobj;
} FD_form;


/***************************************
 ***************************************/

FD_form *
create_form_form(void)
{
    FL_OBJECT *obj;
    FD_form *fdui = calloc( 1, sizeof *fdui );

    fdui->form = fl_bgn_form( FL_NO_BOX, 470, 370 );

    fl_add_box( FL_UP_BOX, 0, 0, 470, 370, "" );

    obj = fl_add_box( FL_SHADOW_BOX, 30, 30, 410, 70, "Scaling Forms" );
    fl_set_object_color( obj, 9, 47 );
    fl_set_object_lsize( obj, 16 );

    fdui->smallerobj = fl_add_button( FL_NORMAL_BUTTON, 30, 220, 130, 40,
                                      "Smaller" );

    fdui->largerobj = fl_add_button( FL_NORMAL_BUTTON, 310, 220, 130, 40,
                                     "Larger" );

    fdui->scaleobj = obj = fl_add_input( FL_FLOAT_INPUT, 170, 140, 270, 40,
                                         "Scale:" );

    fdui->exitobj = obj = fl_add_button( FL_NORMAL_BUTTON, 310, 300, 130, 40,
                                         "Exit" );

    fl_end_form( );

    return fdui;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    float sc = 1,
          oldsc;
    FL_OBJECT *obj;
    FD_form *ui;
    char str[ 32 ];

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    ui = create_form_form( );
    sprintf( str, "%.2f", sc );
    fl_set_input( ui->scaleobj, str );

    fl_show_form( ui->form, FL_PLACE_CENTER | FL_FREE_SIZE,
                  FL_FULLBORDER, "Scaling" );

    while ( 1 )
    {
        oldsc = sc;
        obj = fl_do_forms( );

        if ( obj == ui->exitobj )
            exit( 0 );

        if ( obj == ui->smallerobj )
            sc = sc * 0.8;

        if ( obj == ui->largerobj )
            sc = sc / 0.8;

        if ( obj == ui->scaleobj )
            sc = atof( fl_get_input( ui->scaleobj ) );

        if ( sc < 0.50 )
            sc = 0.50;

        if ( sc > 3 )
            sc = 3;

        if ( sc != oldsc )
        {
            fl_scale_form( ui->form, sc / oldsc, sc / oldsc );
            sprintf( str, "%.2f", sc );
            fl_set_input( ui->scaleobj, str );
        }
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
