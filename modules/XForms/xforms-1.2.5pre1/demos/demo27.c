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


/**
 * \file demo27.c
 *
 * This demo shows the use of event callbacks and form callbacks.
 * purposesly mixed form callback, object callback and event callback
 * to show the flexibility of Forms Library's event handling (and
 * test if they actually work together).
 *
 *  This file is part of xforms package
 *  T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "include/forms.h"

Window  main_win;


/*------------ Color Part --------------------*/

FL_FORM *colorform;
FL_OBJECT *redsl,
          *greensl,
          *bluesl, *colorobj;

int r = 128,
    g = 128,
    b = 128;


/***************************************
 * color form callback routine
 ***************************************/

void
color_callback( FL_OBJECT * obj  FL_UNUSED_ARG,
                void      * d    FL_UNUSED_ARG )
{
    r = 255 * fl_get_slider_value( redsl   );
    g = 255 * fl_get_slider_value( greensl );
    b = 255 * fl_get_slider_value( bluesl  );

    fl_mapcolor( FL_FREE_COL1, r, g, b );
    fl_redraw_object( colorobj );
}


/***************************************
 ***************************************/

void
create_colorform( void )
{
    FL_OBJECT *obj;

    if ( colorform )
      return;

    colorform = fl_bgn_form( FL_NO_BOX, 315, 190 );

    fl_add_box( FL_UP_BOX, 0, 0, 315, 190, "" );

    bluesl = obj = fl_add_slider( FL_HOR_SLIDER, 20, 25, 220, 35, "" );
    fl_set_object_color( obj, FL_COL1, FL_BLUE );

    redsl = obj = fl_add_slider( FL_HOR_SLIDER, 20, 135, 220, 35, "" );
    fl_set_object_color( obj, FL_COL1, FL_RED );

    greensl = obj = fl_add_slider( FL_HOR_SLIDER, 20, 80, 220, 35, "" );
    fl_set_object_color( obj, FL_COL1, FL_GREEN );

    colorobj = obj = fl_add_box( FL_BORDER_BOX, 250, 25, 50, 145, "" );
    fl_set_object_color( obj, FL_FREE_COL1, FL_FREE_COL1 );

    fl_end_form( );
}


/***************************************
 * initializes the color part
 ***************************************/

void
init_colorpart( void )
{
    create_colorform( );
    fl_set_form_callback( colorform, color_callback, 0 );
    fl_set_form_position( colorform, 20, -300 - colorform->h );
    fl_show_form( colorform, FL_PLACE_GEOMETRY, FL_TRANSIENT, "Color" );
    fl_mapcolor( FL_FREE_COL1,r,g,b );
    fl_redraw_object( colorobj );
}


/*--------------- Control Part -------------------*/

FL_FORM * controlform;
FL_OBJECT * squareobj,
          * exitobj,
          * sizeobj;

int curobj = 1,
    cursize = 20;


/***************************************
 ***************************************/

void
select_object( FL_OBJECT * ob  FL_UNUSED_ARG,
               long        which )
{
    curobj = which;
}


void clearit( FL_OBJECT *, long );


/***************************************
 * control form callback routine
 ***************************************/

void
control_callback( FL_OBJECT * obj,
                  void      * d  FL_UNUSED_ARG )
{
   if ( obj == sizeobj )
       cursize = 40 * fl_get_slider_value( sizeobj );
   else if ( obj == exitobj )
   {
       fl_finish( );
       exit( 0 );
   }
}


/***************************************
 ***************************************/

void
create_controlform( void )
{
    FL_OBJECT *obj;

    controlform = fl_bgn_form( FL_UP_BOX, 260, 230 );

    fl_bgn_group( );

    squareobj = obj = fl_add_button( FL_RADIO_BUTTON, 20, 150, 60, 60,
                                     "@square" );
    fl_set_object_lcolor( obj, FL_YELLOW );
    fl_set_object_callback( obj, select_object, 1 );

    obj = fl_add_button( FL_RADIO_BUTTON, 20, 90, 60, 60, "@circle" );
    fl_set_object_lcolor( obj, FL_YELLOW );
    fl_set_object_callback( obj, select_object, 2 );

    obj = fl_add_button( FL_RADIO_BUTTON, 20, 30, 60, 60, "@8>" );
    fl_set_object_lcolor( obj, FL_YELLOW );
    fl_set_object_callback( obj, select_object, 3 );

    fl_end_group( );

    exitobj = fl_add_button( FL_NORMAL_BUTTON, 160, 30, 80, 30, "Exit" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 160, 180, 80, 30, "Clear" );
    fl_set_object_callback( obj, clearit, 0 );

    sizeobj = fl_add_slider( FL_VERT_SLIDER, 100, 30, 40, 180, "size" );
    fl_set_slider_bounds( sizeobj, 0.025, 1.0 );

    fl_end_form( );
}


/***************************************
 * initializes the control part
 ***************************************/

void
init_controlpart( void )
{
    create_controlform( );
    fl_set_form_callback( controlform, control_callback, 0 );
    fl_set_button( squareobj, 1 );
    fl_set_form_geometry( controlform, 20, -controlform->h - 40,
                          controlform->w, controlform->h );
    fl_show_form( controlform, FL_PLACE_SIZE, FL_TRANSIENT, "Control" );
}


/*--------------- Main part -------------------*/

typedef struct{
    int type,
        r,
        g,
        b,
        x,
        y,
        size;
} OBJ;

OBJ ob[ 10000 ];
int onumb = 0;


/***************************************
 ***************************************/

void
drawit( OBJ * obj )
{
    fl_winset( main_win );
    fl_mapcolor( FL_FREE_COL1, obj->r, obj->g, obj->b );

    if ( obj->type == 1 )
        fl_rectf( obj->x - obj->size, obj->y - obj->size,
                  2 * obj->size, 2 * obj->size, FL_FREE_COL1 );
    else if ( obj->type == 2 )
        fl_circf( obj->x, obj->y, obj->size, FL_FREE_COL1 );
    else if ( obj->type == 3 )
    {
        FL_POINT point[ 3 ];

        point[ 0 ].x = obj->x - obj->size;
        point[ 0 ].y = obj->y + obj->size;
        point[ 1 ].x = obj->x + obj->size;
        point[ 1 ].y = obj->y + obj->size;
        point[ 2 ].x = obj->x;
        point[ 2 ].y = obj->y - obj->size;
        fl_polyf( point, 3, FL_FREE_COL1 );
    }
}


/***************************************
 * draws a particular object
 ***************************************/

void
drawobject( void )
{
    FL_Coord x0,
             y0;
    unsigned int km;
    OBJ *cur_obj = ob + onumb;

    fl_get_win_mouse( main_win, &x0, &y0, &km );
    cur_obj->x = x0 ;
    cur_obj->y = y0 ;
    cur_obj->r = r;
    cur_obj->g = g;
    cur_obj->b = b;
    cur_obj->type = curobj;
    cur_obj->size = cursize;
    drawit( cur_obj );
    onumb++;
}


/***************************************
 ***************************************/

void
redrawit( void )
{
   int i;

   XClearWindow( fl_display, main_win );
   for ( i = 0; i < onumb; i++ )
       drawit( ob + i );
}



/***************************************
 ***************************************/

void
clearit( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
   onumb = 0;
   redrawit( );
}


/***************************************
 * Event callback routine
 ***************************************/

int main_callback( XEvent * xev,
                   void   * p    FL_UNUSED_ARG )
{
    fl_winset( main_win );

    if ( xev->type == Expose )
        redrawit( );
    else if ( xev->type == ButtonPress )
        drawobject( );
    return 0;
}


/***************************************
 ***************************************/

void
init_mainpart( void )
{
    fl_pref_wingeometry( 400, 300, 400, 400 );
    fl_pref_winsize( 400, 400 );
    fl_winbackground( 0, fl_get_flcolor( FL_COL1 ) );
    main_win = fl_winopen( "Drawing" );
    fl_set_event_callback( main_callback, 0 );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    init_colorpart( );
    init_controlpart( );
    init_mainpart( );
    color_callback( colorobj, 0 );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
