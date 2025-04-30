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
 * timer routine tester
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

/**** Callback routines ****/

extern void expired( FL_OBJECT *,
                     long );
extern void suspend_resume( FL_OBJECT *,
                            long );
extern void reset( FL_OBJECT *,
                   long );
extern void timer_direction( FL_OBJECT *,
                             long );


/**** Forms and Objects ****/

typedef struct {
    FL_FORM   * timerform;
    void      * vdata;
    long        ldata;
    FL_OBJECT * timer;
    FL_OBJECT * down;
} FD_timerform;

extern FD_timerform * create_form_timerform( void );


#define T  20

FD_timerform *fd_timerform;


/***************************************
 * callbacks for form timer form
 ***************************************/

void
suspend_resume( FL_OBJECT * ob  FL_UNUSED_ARG,
                long        data )
{
   if ( data )
       fl_resume_timer( fd_timerform->timer );
   else
       fl_suspend_timer( fd_timerform->timer );
}


/***************************************
 ***************************************/

void
reset( FL_OBJECT * ob    FL_UNUSED_ARG,
       long        data  FL_UNUSED_ARG )
{
    fl_set_timer( fd_timerform->timer, T );
}


/***************************************
 ***************************************/

void
timer_direction( FL_OBJECT * ob  FL_UNUSED_ARG,
                 long        data )
{
    fl_set_timer_countup( fd_timerform->timer, data );
}


/***************************************
 ***************************************/

void
expired( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
   if ( fl_show_question( "Expired!\n\nQuit?", 0 ) == 1 )
   {
       fl_finish( );
       exit( 0 );
   }
   else
       fl_set_timer( fd_timerform->timer, T );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{

   fl_set_border_width( -2 );

   fl_initialize( &argc, argv, 0, 0, 0 );
   fd_timerform = create_form_timerform( );

   /* fill-in form initialization code */

   fl_set_timer( fd_timerform->timer, T );
   fl_set_button( fd_timerform->down, 1 );

   /* show the first form */

   fl_show_form( fd_timerform->timerform, FL_PLACE_CENTER,
                 FL_FULLBORDER, "timerform" );

   fl_do_forms( );

   return 0;
}


/***************************************
 * Form definition file generated with fdesign
 ***************************************/

FD_timerform *
create_form_timerform( void )
{
    FL_OBJECT *obj;
    FD_timerform *fdui = fl_calloc(1, sizeof *fdui );

    fdui->timerform = fl_bgn_form( FL_NO_BOX, 290, 210 );
    fl_add_box( FL_UP_BOX, 0, 0, 290, 210, "" );
    fl_add_frame( FL_UP_FRAME, 0, 0, 290, 94, "" );
    fl_add_frame( FL_UP_FRAME, 0, 100, 330, 190, "" );
    fl_add_button( FL_NORMAL_BUTTON, 100, 170, 80, 30, "Done" );

    fdui->timer = obj = fl_add_timer( FL_VALUE_TIMER, 20, 30, 180, 40,
                                      "Timer" );
    fl_set_object_boxtype( obj, FL_UP_BOX );
    fl_set_object_lsize( obj, FL_MEDIUM_SIZE );
    fl_set_object_lalign( obj, FL_ALIGN_TOP );
    fl_set_object_lstyle( obj, FL_TIMES_STYLE );
    fl_set_object_callback( obj, expired, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 20, 120, 80, 30, "Suspend" );
    fl_set_object_callback( obj, suspend_resume, 0);

    obj = fl_add_button( FL_NORMAL_BUTTON, 100, 120, 80, 30, "Resume" );
    fl_set_object_callback( obj, suspend_resume, 1 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 180, 120, 80, 30, "Reset" );
    fl_set_object_callback( obj, reset, 0 );

    obj = fdui->down = fl_add_checkbutton( FL_RADIO_BUTTON, 210, 20, 70, 30,
                                           "Down" );
    fl_set_object_shortcut( obj, "D#D", 1 );
    fl_set_object_callback( obj, timer_direction, 0 );

    obj = fl_add_checkbutton( FL_RADIO_BUTTON, 210, 50, 70, 30, "Up" );
    fl_set_object_shortcut( obj, "U#U", 1 );
    fl_set_object_callback( obj, timer_direction, 1 );

    fl_end_form( );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
