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
 * Cursor routines demo.
 *
 * This file is part of xforms package
 * T.C. Zhao and M. Overmars   (1997)
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "include/forms.h"
#include "bm1.xbm"
#include "bm2.xbm"


static int animated = 0;

typedef struct {
    FL_FORM * cursor;
    void    * vdata;
    char    * cdata;
    long      ldata;
} FD_cursor;

extern FD_cursor * create_form_cursor( void );


/* callbacks for form cursor */

/***************************************
 ***************************************/

void
setcursor_cb( FL_OBJECT * ob,
              long        data )
{
    fl_set_cursor( FL_ObjWin( ob ), data );
}


/***************************************
 ***************************************/

void
setbitmapcursor_cb( FL_OBJECT * ob,
                    long        data  FL_UNUSED_ARG )
{
    static int bitmapcur;

    if ( ! bitmapcur )
        bitmapcur = fl_create_bitmap_cursor( ( char * ) bm1_bits,
                                             ( char * ) bm2_bits,
                                             bm1_width, bm1_height,
                                             bm1_width / 2, bm1_height / 2 );
    fl_set_cursor( FL_ObjWin( ob ), bitmapcur );

}


/***************************************
 ***************************************/

void
setanimatedcursor_cb( FL_OBJECT * ob,
                      long        data  FL_UNUSED_ARG )
{
    fl_set_cursor( FL_ObjWin(ob), animated );
}


/***************************************
 ***************************************/

void done_cb( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
    fl_free( ob->form->fdui );
    fl_finish( );
    exit( 0 );
}



int curs[ ] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, -1 };


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_cursor *fd_cursor;

    fl_set_border_width( -2 );
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_cursor = create_form_cursor( );

    /* fill-in form initialization code */

    fl_set_cursor_color( XC_watch, FL_BLACK, FL_RED );

    animated = fl_create_animated_cursor( curs, 100 );

    fl_show_form( fd_cursor->cursor, FL_PLACE_CENTER, FL_FULLBORDER, "cursor" );

    fl_do_forms( );

    return 0;
}


/***************************************
 ***************************************/

FD_cursor *
create_form_cursor( void )
{
    FL_OBJECT *obj;
    FD_cursor *fdui = fl_calloc(1, sizeof *fdui );

    fdui->cursor = fl_bgn_form( FL_NO_BOX, 325, 175 );

    fl_add_box( FL_UP_BOX, 0 ,0, 325, 175, "" );
    fl_add_frame( FL_EMBOSSED_FRAME, 10, 10, 305, 120, "" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 20, 20, 50, 25, "Hand" );
    fl_set_object_callback( obj, setcursor_cb, XC_hand2 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 70, 20, 50, 25, "Watch" );
    fl_set_object_callback( obj, setcursor_cb, XC_watch );

    obj = fl_add_button( FL_NORMAL_BUTTON, 120, 20, 60, 25, "Invisible" );
    fl_set_object_callback( obj, setcursor_cb, FL_INVISIBLE_CURSOR );

    obj = fl_add_button( FL_NORMAL_BUTTON, 180, 20, 62, 25, "Animated" );
    fl_set_object_callback( obj, setanimatedcursor_cb, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 242, 20, 62, 25, "BitmapCur" );
    fl_set_object_callback( obj, setbitmapcursor_cb, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 90, 70, 140, 50, "DefaultCursor" );
    fl_set_button_shortcut( obj, "Dd#d", 1);
    fl_set_object_callback( obj, setcursor_cb, FL_DEFAULT_CURSOR );

    obj = fl_add_button( FL_NORMAL_BUTTON, 250, 140, 60, 25, "Done" );
    fl_set_object_callback( obj, done_cb, 0 );

    fl_end_form( );

    fl_adjust_form_size( fdui->cursor );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
