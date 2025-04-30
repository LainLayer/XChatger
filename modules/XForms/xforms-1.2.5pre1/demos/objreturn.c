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


/* demo showing the choices when to return object. Note this program,
 * strictly speaking, is illegal in the usage of user data parameter
 * in the callback function.
 *
 *  T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "include/forms.h"
#include <stdlib.h>


/**** Forms and Objects ****/

typedef struct
{
    FL_FORM   * form0;
    void      * vdata;
    long        ldata;
    FL_OBJECT * obj[ 4 ];
    FL_OBJECT * br;
    FL_OBJECT * when;
} FD_form0;


extern FD_form0 *create_form_form0( void );
static FD_form0 *fd_form0;


/* callbacks for form form0 */

/***************************************
 ***************************************/

const char *mess[ ] = { "slider returned",
                        "counter returned",
                        "input 1 returned",
                        "input 2 returned" };


void
return_cb( FL_OBJECT * ob  FL_UNUSED_ARG,
           long        data )
{
    fl_addto_browser( fd_form0->br, mess[ data ] );
}


/***************************************
 ***************************************/

void
set_when( int n )
{
    fl_set_object_return( fd_form0->obj[ 0 ], n );
    fl_set_object_return( fd_form0->obj[ 1 ], n );
    fl_set_object_return( fd_form0->obj[ 2 ], n );
    fl_set_object_return( fd_form0->obj[ 3 ], n );
}


/***************************************
 ***************************************/

void
when_cb( FL_OBJECT * ob,
         long        data  FL_UNUSED_ARG )
{
    set_when( fl_get_select_item( ob )->val );
}


/***************************************
 ***************************************/

void
resetlog_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
             long        data  FL_UNUSED_ARG )
{
    fl_clear_browser( fd_form0->br );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_set_border_width( -2 );

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_form0 = create_form_form0( );

    /* fill-in form initialization code */

    set_when( 0 );
    fl_set_object_dblbuffer( fd_form0->br, 1);
    fl_add_select_items( fd_form0->when,
                         "RETURN_NONE%x|RETURN_CHANGED%x|"
                         "RETURN_END%x|RETURN_END_CHANGED%x|RETURN_ALWAYS%x",
                         FL_RETURN_NONE, FL_RETURN_CHANGED, FL_RETURN_END,
                         FL_RETURN_END_CHANGED, FL_RETURN_ALWAYS );

    /* show the first form */

    fl_show_form( fd_form0->form0, FL_PLACE_CENTER, FL_FULLBORDER, "form0" );

    fl_do_forms( );

    return 0;
}


/***************************************
 ***************************************/

FD_form0 *
create_form_form0( void )
{
    FL_OBJECT *obj;
    FD_form0 *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->form0 = fl_bgn_form( FL_NO_BOX, 321, 276 );

    fl_add_box( FL_UP_BOX, 0, 0, 321, 276, "" );

    fdui->obj[ 0 ] = obj = fl_add_valslider( FL_HOR_SLIDER, 12, 55, 138, 22,
                                             "" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_BOTTOM ) );
    fl_set_object_callback( obj, return_cb, 0 );
    fl_set_slider_return( obj, FL_RETURN_CHANGED );

    fdui->obj[ 1 ] = obj = fl_add_counter( FL_NORMAL_COUNTER, 12, 85, 138, 22,
                                           "" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_BOTTOM ) );
    fl_set_object_callback( obj, return_cb, 1 );

    fdui->obj[ 2 ] = obj = fl_add_input( FL_NORMAL_INPUT, 12, 150, 138, 25,
                                         "" );
    fl_set_object_callback( obj, return_cb, 2 );

    fdui->br = obj = fl_add_browser( FL_NORMAL_BROWSER, 170, 55, 140, 160, "" );

    fdui->obj[ 3 ] = obj = fl_add_input( FL_INT_INPUT, 12, 187, 138, 25,
                                         "" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_LEFT ) );
    fl_set_object_callback( obj, return_cb, 3 );

    fdui->when = obj = fl_add_select( FL_NORMAL_SELECT, 40, 12, 240, 27, "" );
    fl_set_object_callback( obj, when_cb, 0 );

    fl_add_button( FL_NORMAL_BUTTON, 170, 239, 80, 25, "Done" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 70, 239, 80, 25, "ResetLog" );
    fl_set_object_callback( obj, resetlog_cb, 0 );

    fl_end_form( );

    return fdui;
}
/*---------------------------------------*/


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
