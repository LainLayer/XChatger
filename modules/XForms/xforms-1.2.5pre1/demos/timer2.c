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


/* A demo showing the use of timer objects.
 * note there is only one fl_do_form().
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "include/forms.h"

FL_FORM *form1, *form2;
FL_OBJECT *tim, *tim2;

#define TIME 5


/***************************************
 ***************************************/

void
timer1_expired( FL_OBJECT * ob,
                long        q )
{
    fl_deactivate_form( form1 );
    fl_set_timer( tim2, 10 );
    fl_show_form( form2, FL_PLACE_MOUSE, FL_TRANSIENT, "Q" );
}


/***************************************
 ***************************************/

void
nothing( FL_OBJECT * ob,
         long        q )
{
}


/***************************************
 ***************************************/

void
continue_cb( FL_OBJECT * ob,
             long        q )
{
    fl_hide_form( form2 );
    fl_activate_form( form1 );
    fl_set_timer( tim, TIME );
    fl_set_object_callback( tim, nothing, 0 );
}


/***************************************
 ***************************************/

void
done_cb( FL_OBJECT * ob,
         long        a )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void
makeforms( void )
{
    FL_OBJECT *obj;

    form1 = fl_bgn_form( FL_UP_BOX, 400, 400 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 140, 160, 120, 80, "Push Me" );
    fl_set_object_callback( obj, done_cb, 0 );

    tim = fl_add_timer( FL_VALUE_TIMER, 200, 40, 90, 50, "Time Left" );
    fl_set_object_callback( tim, timer1_expired, 0 );
    fl_set_object_lcolor( tim, FL_BLACK );

    fl_end_form( );

    form2 = fl_bgn_form( FL_UP_BOX, 320, 120 );

    fl_add_box( FL_NO_BOX, 160, 40, 0, 0, "You were too late" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 100, 70, 120, 30, "Try Again" );
    fl_set_object_callback( obj, continue_cb, 0 );

    tim2 = fl_add_timer( FL_HIDDEN_TIMER, 0, 0, 1, 2, "" );
    fl_set_object_callback( tim2, continue_cb, 0 );
    fl_end_form( );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    makeforms( );
    fl_show_form( form1, FL_PLACE_CENTER, FL_NOBORDER, "Timer" );
    fl_set_timer( tim, TIME );
    fl_do_forms( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
