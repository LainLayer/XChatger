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
 * OpenGL/mesa canvas demo
 *
 * On most platforms, the mesa/OpenGL support is not compiled into
 * the shared library (It it in the static library). You can compile
 * ../FORMS/gl.c and put it in the shared library if you have mesa/OpenGL
 *
 * Also you might want to make a link libGL.a to libMesaGL.a
 *
 * T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <GL/gl.h>
#include <GL/glx.h>

#include "include/forms.h"
#include "gl/glcanvas.h"

typedef struct {
    FL_FORM   * form;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * canvas;
    FL_OBJECT * done;
    FL_OBJECT * menu;
    FL_OBJECT * butgrp;
} FD_form;

extern FD_form * create_form_form(void);

FD_form *ui;

static int prim = GL_POLYGON ;

#define v3f glVertex3f


/***************************************
 ***************************************/

static
void draw_cube( void )
{
    glColor3f( 1.0, 0.0, 0.0 );
    glBegin( prim );
    v3f( 1.0, 1.0, 1.0 );   v3f( 1.0, -1.0, 1.0 );
    v3f( 1.0, -1.0, -1.0 ); v3f( 1.0, 1.0, -1.0 );
    glEnd( );

    glBegin( prim );
    v3f( -1.0,  1.0,  1.0 );
    v3f( -1.0,  1.0, -1.0 );
    v3f( -1.0, -1.0, -1.0 );
    v3f( -1.0, -1.0,  1.0 );
    glEnd( );

    glColor3f( 0.0, 1.0, 0.0 );
    glBegin( prim );
    v3f(  1.0,  1.0,  1.0 );
    v3f(  1.0,  1.0, -1.0 );
    v3f( -1.0,  1.0, -1.0 );
    v3f( -1.0,  1.0,  1.0 );
    glEnd( );

    glBegin( prim );
    v3f(  1.0, -1.0,  1.0 );
    v3f( -1.0, -1.0,  1.0 );
    v3f( -1.0, -1.0, -1.0 );
    v3f(  1.0, -1.0, -1.0 );
    glEnd( );

    glColor3f( 0.0, 0.0, 1.0 );
    glBegin( prim );
    v3f(  1.0,  1.0,  1.0 );
    v3f( -1.0,  1.0,  1.0 );
    v3f( -1.0, -1.0,  1.0 );
    v3f(  1.0, -1.0,  1.0 );
    glEnd( );

    glBegin( prim );
    v3f(  1.0,  1.0, -1.0 );
    v3f(  1.0, -1.0, -1.0 );
    v3f( -1.0, -1.0, -1.0 );
    v3f( -1.0,  1.0, -1.0 );
    glEnd( );
}


/***************************************
 ***************************************/

int
idle_cb( XEvent * ev,
         void   * data  FL_UNUSED_ARG )
{
    static GLfloat xrot,
                   yrot,
                   zrot;

    if (    ! fl_form_is_visible( ui->form )
         || ! fl_object_is_visible( ui->canvas ) )
        return 0;

    fl_activate_glcanvas( ui->canvas );

    glClear( GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT );

    glPushMatrix( );

    glRotatef( xrot, 1.0, 0.0, 0.0 );
    glRotatef( yrot, 0.0, 1.0, 0.0 );
    glRotatef( zrot, 0.0, 0.0, 1.0 );
    glTranslatef( -1.0,1.2,-0.5 );

    draw_cube( );

    glPopMatrix( );

    glFinish( );

    if ( ev )
    {
        xrot += 10.0;
        yrot += 7.0;
        zrot -= 3.0;
    }

    glXSwapBuffers( fl_display, fl_get_canvas_id( ui->canvas ) );

    return 0;
}


/***************************************
 ***************************************/

int
canvas_expose( FL_OBJECT * ob   FL_UNUSED_ARG,
               Window      win  FL_UNUSED_ARG,
               int         w,
               int         h,
               XEvent *    xev  FL_UNUSED_ARG,
               void *      ud   FL_UNUSED_ARG )
{
    glViewport( 0, 0, ( GLint ) w, ( GLint ) h );
    glClearColor( 0.0, 0.0, 0.0, 0.0 );

    glMatrixMode( GL_PROJECTION );
    glLoadIdentity( );
    glFrustum( -1.0, 1.0, -1.0, 1.0, 1.0, 10.0 );
    glTranslatef( 0.0, 0.0, -5.0 );

    glMatrixMode( GL_MODELVIEW );
    glLoadIdentity( );
    glCullFace( GL_BACK );
    glEnable( GL_CULL_FACE );

    glShadeModel( GL_FLAT );

    /* refresh */

    idle_cb( 0, 0 );
    return 0;
}


/***************************************
 ***************************************/

int
buttonpress_cb( FL_OBJECT * ob   FL_UNUSED_ARG,
                Window      win  FL_UNUSED_ARG,
                int         w    FL_UNUSED_ARG,
                int         h    FL_UNUSED_ARG,
                XEvent *    xev  FL_UNUSED_ARG,
                void *      ud   FL_UNUSED_ARG )
{
   static int suspended = 0;

   suspended ^= 1;
   fl_set_idle_callback( suspended ? 0 : idle_cb, 0 );

   return 0;
}


/***************************************
 ***************************************/

void
switch_primitive( FL_OBJECT * ob    FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
    static int primitive[ ] = { GL_POLYGON, GL_LINE_LOOP };
    static int i ;

    prim = primitive[ ++i % 2 ];
}


/* switch single/dblbuffer */

static int sbuf[ ]= { GLX_RGBA,GLX_DEPTH_SIZE, 1,
                      GLX_RED_SIZE,            1,
                      GLX_GREEN_SIZE,          1,
                      GLX_BLUE_SIZE,           1,
                      None                        };

static int dbuf[ ]= { GLX_RGBA,
                      GLX_DEPTH_SIZE,
                      1,
                      GLX_RED_SIZE,
                      1,
                      GLX_GREEN_SIZE,
                      1,
                      GLX_BLUE_SIZE,
                      1,
                      /* GLX_DOUBLEBUFFER, */
                      None};


/***************************************
 ***************************************/

void
buffer_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
    static int is_double = 1;
    FD_form *fdui = ob->form->fdui;

    is_double = ! is_double;
    fl_set_object_label( ob,is_double ? "Single":"Double" );
    fl_set_glcanvas_attributes( fdui->canvas, is_double ? dbuf : sbuf );
}


/***************************************
 ***************************************/

void
menu_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
}


/***************************************
 ***************************************/

int main( int    argc,
          char * argv[ ] )
{
   fl_initialize( &argc, argv, "FormDemo", 0, 0 );
   ui = create_form_form( );

   /* fill-in form initialization code */

   fl_set_object_gravity( ui->butgrp, NorthEastGravity, NorthEastGravity );
   fl_addto_menu( ui->menu,"Item1|Item2|Item3|Item4" );

   fl_add_canvas_handler( ui->canvas, Expose, canvas_expose, 0 );
   fl_add_canvas_handler( ui->canvas, ButtonPress, buttonpress_cb, 0 );
   fl_set_idle_callback( idle_cb, 0 );

   /* geometry stuff */

//   fl_set_form_minsize( ui->form, 340, 280 );

   fl_show_form( ui->form, FL_PLACE_CENTER | FL_FREE_SIZE, FL_FULLBORDER,
                 "OpenGL Canvas");

   while ( fl_do_forms( ) != ui->done )
       /* empty */ ;

   fl_finish( );
   return 0;
}


/***************************************
 ***************************************/

static void
hide_it( FL_OBJECT * ob,
         long        data  FL_UNUSED_ARG )
{
    if ( fl_object_is_visible( ui->canvas ) )
    {
        fl_hide_object( ui->canvas );
        fl_set_object_label( ob,"Show" );
    }
    else
    {
       fl_show_object( ui->canvas );
       fl_set_object_label( ob, "Hide" );
    }
}


/***************************************
 ***************************************/

static void
reshow( FL_OBJECT * ob,
        long        data  FL_UNUSED_ARG )
{
    fl_hide_form( ob->form );
    fl_show_form( ui->form, FL_PLACE_CENTER | FL_FREE_SIZE, FL_FULLBORDER,
                  "OpenGL Canvas" );
}


/***************************************
 ***************************************/

FD_form *
create_form_form( void )
{
    FL_OBJECT *obj;
    FD_form *fdui = fl_calloc( 1, sizeof *fdui);

    fdui->form = fl_bgn_form( FL_NO_BOX, 340, 280 );

    fl_add_box( FL_UP_BOX, 0, 0, 340, 280, "" );

    fdui->canvas = obj = fl_add_glcanvas( FL_NORMAL_CANVAS, 20, 45, 225, 215,
                                          "" );
    fl_set_object_gravity( obj, FL_NorthWest, FL_SouthEast );

    fdui->done = obj = fl_add_button( FL_NORMAL_BUTTON, 255, 230, 70, 30,
                                      "Done");
    fl_set_button_shortcut( obj, "Dd#d", 1 );
    fl_set_object_gravity( obj, FL_SouthEast, FL_SouthEast );

    fdui->menu = obj = fl_add_menu( FL_PULLDOWN_MENU, 20, 15, 54, 20,
                                    "Canvas" );
    fl_set_object_shortcut( obj, "#CcC", 1 );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE );
    fl_set_object_gravity( obj, FL_NorthWest, FL_NorthWest );
    fl_set_object_callback( obj, menu_cb, 0 );

    fdui->butgrp = fl_bgn_group( );

    obj = fl_add_button( FL_NORMAL_BUTTON, 255, 45, 70, 30, "Poly/Line" );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );
    fl_set_object_callback( obj, switch_primitive, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 255, 75, 70, 30, "Hide" );
    fl_set_button_shortcut( obj, "#HhH", 1 );
    fl_set_object_callback( obj,hide_it, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 255, 105, 70, 30, "ReShow" );
    fl_set_button_shortcut( obj, "#RRr", 1 );
    fl_set_object_callback( obj, reshow, 0 );

    obj = fl_add_button( FL_NORMAL_BUTTON, 255, 135, 70, 30, "Single" );
    fl_set_object_callback( obj, buffer_cb, 0 );

    fl_end_group( );

    fl_end_form( );

    fdui->form->fdui = fdui;

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
