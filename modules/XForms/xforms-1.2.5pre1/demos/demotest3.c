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


/**** Forms and Objects ****/

typedef struct {
        FL_FORM *S;
        void *vdata;
        char *cdata;
        long  ldata;
} FD_S;

FD_S *S;


/***************************************
 ***************************************/

void
timeoutCB( int    tid    FL_UNUSED_ARG,
           void * stuff  FL_UNUSED_ARG )
{
    fl_show_alert( "Standby", "This may abort", "with SEGV", 1 );
}


/***************************************
 ***************************************/

void
pressedCB( FL_OBJECT * obj   FL_UNUSED_ARG,
           long        data  FL_UNUSED_ARG )
{
    int tid = fl_add_timeout( 300L, timeoutCB, NULL );

    fprintf( stderr, "tid=%d\n", tid );
}


/***************************************
 ***************************************/

FD_S *
create_form_S( void )
{
    FL_OBJECT *obj;
    FD_S *fdui = fl_calloc( 1, sizeof *fdui );
    int old_unit = fl_get_coordunit( );

    fl_set_coordunit( FL_COORD_centiMM );

    fdui->S = fl_bgn_form( FL_NO_BOX, 10837, 8467 );

    fl_add_box( FL_UP_BOX, 0, 0, 10837, 8467, "" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 1693, 1693, 7451, 4403, "Press Me" );
    fl_set_object_callback( obj, pressedCB, 0 );

    fl_end_form( );

    fdui->S->fdui = fdui;
    fl_set_coordunit( old_unit );

    return fdui;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "S", 0, 0 );

    S = create_form_S( );

    fl_show_form( S->S, FL_PLACE_CENTER, FL_FULLBORDER, "Crash Test" );

    while ( 1 )
        fl_do_forms( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
