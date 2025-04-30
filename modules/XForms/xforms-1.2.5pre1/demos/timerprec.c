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
 * Test the accuracy of timer
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars  (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include "include/forms.h"


typedef struct {
    FL_FORM   * form0;
    void      * vdata;
    long        ldata;
    FL_OBJECT * timer;
    FL_OBJECT * restart;
    FL_OBJECT * report;
} FD_form0;

typedef struct {
    long sec,
         usec;
} Start_Time;

static FD_form0 * create_form_form0( void );


/***************************************
 ***************************************/

static void
exit_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 * Callback for timer expiry, 'data' is set to requested delay (in ms)
 ***************************************/

static void
timer_cb( FL_OBJECT * obj,
          long        data )
{
    double df;
    FD_form0 *fd = obj->form->fdui;
    Start_Time *start_time = fd->vdata;
    long end_sec,
         end_usec;

    fl_gettime( &end_sec, &end_usec );
    df = end_sec - start_time->sec + 1.0e-6 * ( end_usec - start_time->usec );
    fl_set_object_label_f( fd->report,
                           "Timeout: %.3f s, Actual: %.3f s, Delta: %d ms",
                           0.001 * data, df, FL_nint( 1000 * df - data ) );
}


/***************************************
 ***************************************/

static void
start_timer( FL_OBJECT * obj,
             long        data )
{
    FD_form0 *fd = obj->form->fdui;
    Start_Time *start_time = fd->vdata;
    static long delay = 3000;

    if ( data > 0 )
        delay = data;
    else
        delay += 200;

    fl_set_object_label_f( fd->report, "Timer accuracy testing %.3f sec ...",
                           0.001 * delay );
    fl_gettime( &start_time->sec, &start_time->usec );
    fl_set_object_callback( fd->timer, timer_cb, delay );
    fl_set_timer( fd->timer, 0.001 * delay );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_form0 *fd_form0;
    Start_Time start_time;

    fl_initialize( &argc, argv, 0, 0, 0 );

    fd_form0 = create_form_form0( );
    fd_form0->vdata = &start_time;

    start_timer( fd_form0->timer, 3000 );

    fl_show_form( fd_form0->form0, FL_PLACE_CENTER, FL_FULLBORDER,
                  "Timer object precision" );
    fl_do_forms( );
    return 0;
}


/***************************************
 ***************************************/

static FD_form0 *
create_form_form0( void )
{
    FL_OBJECT *obj;
    FD_form0 *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->form0 = fl_bgn_form( FL_NO_BOX, 350, 130 );

    fl_add_box( FL_UP_BOX, 0, 0, 350, 130, "" );

    fdui->timer = fl_add_timer( FL_HIDDEN_TIMER, 0, 0, 0, 0, "" );

    fdui->report = obj = fl_add_text( FL_NORMAL_TEXT, 20, 20, 310, 50,"" );
    fl_set_object_align( obj, FL_ALIGN_CENTER );
    fl_set_object_boxtype( obj, FL_DOWN_BOX );

    fdui->restart = obj = fl_add_button( FL_NORMAL_BUTTON, 140, 80, 90, 35,
                                         "Restart" );
    fl_set_object_callback( obj, start_timer, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 240, 80, 90, 35, "Done" );
    fl_set_object_callback( obj, exit_cb, 0 );

    fl_end_form( );

    fdui->form0->fdui = fdui;

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
