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
 * Input return setting and raw callback. Terrible hack.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

extern void howreturn_callback( FL_OBJECT *, long );
extern void input_callback( FL_OBJECT *, long );

/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * inputform;
    void      * vdata;
    long        ldata;
    FL_OBJECT * input1;
    FL_OBJECT * howreturn;
    FL_OBJECT * status;
    FL_OBJECT * input2;
} FD_inputform;

extern FD_inputform *create_form_inputform( void );

/* end of minput.h */

FD_inputform *ui;


/***************************************
 ***************************************/

int
peek_event( FL_FORM * form  FL_UNUSED_ARG,
            void    * xev )
{
    if ( ( ( XEvent * )xev )->type == KeyPress )
    {
        fl_set_object_label( ui->status, "keyboard input" );
        fl_XFlush(  );           /* necessary to show the label? */
        fl_msleep( 50 );
    }

    return 0;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    ui = create_form_inputform( );
    fl_register_raw_callback( ui->inputform, KeyPressMask, peek_event );

    fl_show_form( ui->inputform, FL_PLACE_CENTER, FL_TRANSIENT, "Input" );

    fl_do_forms( );
    fl_finish( );

    return 0;
}


/***************************************
 ***************************************/

void
input_callback( FL_OBJECT * ob  FL_UNUSED_ARG,
                long        data )
{
     char buf[ 32 ];

     sprintf( buf, "Input%ld returned", data );
     fl_set_object_label( ui->status, buf );
     fl_XFlush( );
     fl_msleep( 50 );
}


/***************************************
 ***************************************/

void
howreturn_callback( FL_OBJECT * ob,
                    long        data  FL_UNUSED_ARG )
{
    fl_set_input_return( ui->input1, fl_get_button( ob ) );
    fl_set_input_return( ui->input2, fl_get_button( ob ) );
}


/***************************************
 ***************************************/

FD_inputform *
create_form_inputform( void )
{
    FL_OBJECT *obj;
    FD_inputform *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->inputform = fl_bgn_form( FL_NO_BOX, 475, 485 );

    fl_add_box( FL_UP_BOX, 0, 0, 475, 485, "" );

    fdui->input1 = obj = fl_add_input( FL_MULTILINE_INPUT, 15, 275, 350, 180,
                                       "" );
    fl_set_object_lalign( obj, FL_ALIGN_TOP );
    fl_set_object_callback( obj, input_callback, 1 );

    fdui->howreturn = obj = fl_add_checkbutton( FL_PUSH_BUTTON,
                                                375, 435, 80, 35,
                                                "always\nreturn" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );
    fl_set_object_callback( obj, howreturn_callback, 0 );

    fdui->status = obj = fl_add_text( FL_NORMAL_TEXT, 20, 15, 270, 30, "" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );

    fl_add_button( FL_NORMAL_BUTTON, 375, 15, 80, 35, "Done" );

    fdui->input2 = obj = fl_add_input( FL_MULTILINE_INPUT, 15, 60, 349, 185,
                                       "" );
    fl_set_object_lalign( obj, FL_ALIGN_TOP );
    fl_set_object_callback( obj, input_callback, 2 );

    fl_end_form( );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
