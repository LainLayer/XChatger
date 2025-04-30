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
 * Demo showing the use of preemptive and post-object handler,
 * and one possible way of implementing a "tool tip"
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars (1997)
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

typedef struct {
    FL_FORM   * form0;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * butt;
    FL_OBJECT * enter;
    FL_OBJECT * leave;
    FL_OBJECT * push;
    FL_OBJECT * release;
    FL_OBJECT * peek;
    FL_OBJECT * override;
    FL_OBJECT * event;
    FL_OBJECT * done;
} FD_form0;

extern FD_form0 *create_form_form0( void );

FD_form0 *fd_form0;


/***************************************
 * Which event to take over is better kept in a state varible
 * even though query of the status via fl_get_button is cheap
 ***************************************/

int
preemptive_handler( FL_OBJECT * ob   FL_UNUSED_ARG,
                    int         event,
                    FL_Coord    mx   FL_UNUSED_ARG,
                    FL_Coord    my   FL_UNUSED_ARG,
                    int         key  FL_UNUSED_ARG,
                    void *      xev  FL_UNUSED_ARG )
{
    int override = fl_get_button( fd_form0->override );
    char buf[ 128 ];
    char *what = override ? "preempted" : "detected";

    switch( event )
    {
        case FL_ENTER:
            if ( fl_get_button(fd_form0->enter ) )
            {
                sprintf( buf,"%s %s", "FL_ENTER", what );
                fl_set_object_label( fd_form0->event, buf );
                return override ? FL_PREEMPT : 0;
            }
            break;

        case FL_LEAVE:
            if ( fl_get_button( fd_form0->leave ) )
            {
                sprintf( buf,"%s %s", "FL_LEAVE", what);
                fl_set_object_label( fd_form0->event, buf );
                return override ? FL_PREEMPT : 0;
         }
         break;

        case FL_PUSH:
        case FL_MOTION: /* one of the quirks of the button class */
            if ( fl_get_button( fd_form0->push ) )
            {
                sprintf( buf,"%s %s", "FL_PUSH", what );
                fl_set_object_label( fd_form0->event, buf );
                return override ? FL_PREEMPT : 0;
            }
            break;

        case FL_RELEASE:
            if ( fl_get_button( fd_form0->release ) )
            {
                sprintf( buf,"%s %s", "FL_RELEASE", what );
                fl_set_object_label( fd_form0->event, buf );
                return override ? FL_PREEMPT : 0;
         }
         break;
    }

    return 0;
}


#define INTERVAL  800  /* wait this long before showing tip */
static int timeoutID;  /* we can also use ob->u_ldata to hold it */

/***************************************
 ***************************************/

static void
do_tips( int    id  FL_UNUSED_ARG,
         void * p )
{
    FL_OBJECT *ob = p;

    fl_show_oneliner( ob->u_vdata, ob->form->x + ob->x,
                      ob->form->y + ob->y + ob->h + 1 );
    timeoutID = fl_add_timeout( INTERVAL, do_tips, ob );
}


/***************************************
 * Use the post handler as a tipper
 ***************************************/

int
post_handler( FL_OBJECT * ob,
              int         event,
              FL_Coord    mx   FL_UNUSED_ARG,
              FL_Coord    my   FL_UNUSED_ARG,
              int         key  FL_UNUSED_ARG,
              void *      xev  FL_UNUSED_ARG )
{
    if ( ! ob->u_vdata )
        return 0;

    if ( event == FL_ENTER )
        timeoutID = fl_add_timeout( INTERVAL,do_tips, ob );
    else if ( event == FL_LEAVE || event == FL_PUSH )
    {
        fl_hide_oneliner( );
        if( timeoutID )
        {
            fl_remove_timeout( timeoutID );
            timeoutID = 0;
        }
     }

     return 0;
}


/***************************************
 ***************************************/

void
set_tip( FL_OBJECT * ob,
         char *      s )
{
    ob->u_vdata = s;
    fl_set_object_posthandler( ob, post_handler );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    fd_form0 = create_form_form0( );

    /* Fill-in form initialization code */

    fl_set_button( fd_form0->peek, 1 );
    fl_set_button( fd_form0->enter, 1 );
    fl_set_button( fd_form0->leave, 1 );
    fl_set_button( fd_form0->push, 1 );
    fl_set_button( fd_form0->release, 1 );

    fl_set_object_prehandler( fd_form0->butt, preemptive_handler );

    set_tip( fd_form0->done, "Want to quit ?\nPress me" );
    set_tip( fd_form0->peek, "Turn preempting off" );
    set_tip( fd_form0->override, "Turn preempting on" );

    /* Show the first form */

    fl_show_form( fd_form0->form0, FL_PLACE_CENTER, FL_TRANSIENT,
                  "Preemptive" );

    while ( fl_do_forms( ) != fd_form0->done )
        /* empty */ ;

    return 0;
}


/***************************************
 ***************************************/

FD_form0 *
create_form_form0( void )
{
    FL_OBJECT *obj;
    FD_form0 *fdui = fl_calloc(1, sizeof *fdui );

    fdui->form0 = fl_bgn_form(FL_NO_BOX, 320, 250);

    fl_add_box( FL_UP_BOX, 0, 0, 320, 250, "" );

    fl_add_frame( FL_ENGRAVED_FRAME, 200, 70, 95, 100, "" );

    fdui->butt = fl_add_button( FL_NORMAL_BUTTON, 20, 70, 170, 100,
                                "A Button" );

    fdui->enter = fl_add_checkbutton( FL_PUSH_BUTTON, 210, 70, 45, 30,
                                      "Enter" );

    fdui->leave = fl_add_checkbutton( FL_PUSH_BUTTON, 210, 95, 40, 30,
                                      "Leave" );

    fdui->push = fl_add_checkbutton( FL_PUSH_BUTTON, 210, 120, 50, 30, "Push" );

    fdui->release = fl_add_checkbutton( FL_PUSH_BUTTON, 210, 140, 60, 30,
                                        "Release" );

    obj = fl_add_text( FL_NORMAL_TEXT, 55, 15, 220, 30, "Pre-emptive Handler" );
    fl_set_object_lsize( obj, FL_MEDIUM_SIZE );
    fl_set_object_lalign( obj, FL_ALIGN_CENTER );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );

    fdui->peek = obj = fl_add_checkbutton( FL_RADIO_BUTTON, 150, 40, 35, 30,
                                           "Peek" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    fdui->override = obj = fl_add_checkbutton( FL_RADIO_BUTTON, 210, 40, 35, 30,
                                               "Override" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    fdui->event = fl_add_box( FL_FLAT_BOX, 40, 180, 245, 25, "" );

    fdui->done = fl_add_button( FL_NORMAL_BUTTON, 170, 210, 100, 30, "Done" );

    fl_end_form( );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
