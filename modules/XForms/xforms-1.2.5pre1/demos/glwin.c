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
 * OpenGL rendering in its own window
 *
 *  T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <GL/glx.h>
#include <GL/gl.h>

#include "include/forms.h"
#include "gl/glcanvas.h"

extern Window fl_glwincreate( int *,
                              GLXContext *,
                              int, int );

/* Forms and Objects */

typedef struct {
    FL_FORM   * glcontrol;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * polybutt;
} FD_glcontrol;

extern FD_glcontrol *create_form_glcontrol( void );

extern int handle_expose( XEvent *,
                          void * );

int prim = GL_POLYGON;     /* GL primitive to draw */

Window glwin;


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_glcontrol *fd_glcontrol;
    GLXContext context;
    int config[ ] = { GLX_RGBA, GLX_DEPTH_SIZE, 16, GLX_DOUBLEBUFFER, None };

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_glcontrol = create_form_glcontrol( );

    if ( ! ( glwin = fl_glwincreate( config, &context, 250, 250 ) ) )
    {
        fprintf( stderr, "GLWin: Can't create OpenGL window\n" );
        exit( 0 );
    }

    fl_add_event_callback( glwin, Expose, handle_expose, 0 );

    fl_winshow( glwin );

    /* show the first form */

    fl_set_button( fd_glcontrol->polybutt, 1 );
    fl_show_form( fd_glcontrol->glcontrol, FL_PLACE_CENTER,
                  FL_FULLBORDER, "glcontrol" );

    fl_do_forms( );

    return 0;
}


/***************************************
 ***************************************/

static void
draw_cube( void )
{
    glColor3f( 1.0, 0.0, 0.0 );
    glBegin( prim );
    glVertex3f( 1.0, 1.0, 1.0 );
    glVertex3f( 1.0, -1.0, 1.0 );
    glVertex3f( 1.0, -1.0, -1.0 );
    glVertex3f( 1.0, 1.0, -1.0 );
    glEnd( );

    glBegin( prim );
    glVertex3f( -1.0, 1.0, 1.0 );
    glVertex3f( -1.0, 1.0, -1.0 );
    glVertex3f( -1.0, -1.0, -1.0 );
    glVertex3f( -1.0, -1.0, 1.0 );
    glEnd( );

    /* Y faces */

    glColor3f( 0.0, 1.0, 0.0 );
    glBegin( prim );
    glVertex3f(  1.0, 1.0,  1.0 );
    glVertex3f(  1.0, 1.0, -1.0 );
    glVertex3f( -1.0, 1.0, -1.0 );
    glVertex3f( -1.0, 1.0,  1.0 );
    glEnd( );

    glBegin( prim );
    glVertex3f(  1.0, -1.0,  1.0 );
    glVertex3f( -1.0, -1.0,  1.0 );
    glVertex3f( -1.0, -1.0, -1.0 );
    glVertex3f(  1.0, -1.0, -1.0 );
    glEnd( );

   /* Z faces */

    glColor3f( 0.0, 0.0, 1.0 );
    glBegin( prim );
    glVertex3f(  1.0,  1.0,  1.0 );
    glVertex3f( -1.0,  1.0,  1.0 );
    glVertex3f( -1.0, -1.0,  1.0 );
    glVertex3f(  1.0, -1.0,  1.0 );
    glEnd( );

    glBegin( prim );
    glVertex3f(  1.0, 1.0, -1.0 );
    glVertex3f(  1.0,-1.0, -1.0 );
    glVertex3f( -1.0,-1.0, -1.0 );
    glVertex3f( -1.0, 1.0, -1.0 );
    glEnd( );
}


/***************************************
 ***************************************/

int
animate( XEvent * ev,
         void   * data  FL_UNUSED_ARG )
{
    static GLfloat xrot,
                   yrot,
                   zrot;

    glClear( GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glPushMatrix( );
    glRotatef( xrot, 1.0, 0.0, 0.0 );
    glRotatef( yrot, 0.0, 1.0, 0.0 );
    glRotatef( zrot, 0.0, 0.0, 1.0 );
    glTranslatef( -1.0,1.2,-0.5 );
    draw_cube( );
    glPopMatrix( );
    glFinish( );

    if ( ev->type != Expose )
    {
        xrot += 10.0;
        yrot += 7.0;
        zrot -= 3.0;
    }

    glXSwapBuffers( fl_display, glwin );
    return 0;
}


/***************************************
 * Initialization and expose handler
 ***************************************/

int
handle_expose( XEvent * xev,
               void   * data  FL_UNUSED_ARG )
{
    FL_Coord w ,h ;

    fl_get_winsize( glwin, &w, &h );
    glViewport( 0,0, w, h );

    glClearColor( 0.0,0.0,0.0,0.0 );

    glMatrixMode( GL_PROJECTION );
    glLoadIdentity( );
    glFrustum( -1.0, 1.0, -1.0, 1.0, 1.0, 10.0 );
    glTranslatef( 0.0, 0.0, -5.0 );

    glMatrixMode( GL_MODELVIEW );
    glLoadIdentity( );
    glCullFace( GL_BACK );
    glEnable( GL_CULL_FACE );
    glShadeModel( GL_FLAT );
    animate( xev, 0 );
    return 0;
}


/* Form definition generated by fdesign */

/* callback functions */

/***************************************
 ***************************************/

void
change_primitive( FL_OBJECT * ob    FL_UNUSED_ARG,
                  long        data )
{
    prim = data;
}


/***************************************
 ***************************************/

void
animate_callback( FL_OBJECT * ob,
                  long        data  FL_UNUSED_ARG )
{
    fl_set_idle_callback( fl_get_button( ob ) ? animate:0, 0 );
}


/***************************************
 ***************************************/

FD_glcontrol *
create_form_glcontrol( void )
{
    FL_OBJECT *obj;
    FD_glcontrol *fdui = fl_calloc( 1, sizeof *fdui );

    fdui->glcontrol = fl_bgn_form( FL_NO_BOX, 241, 121 );

    fl_add_box( FL_UP_BOX, 0, 0, 241, 121, "" );

    fl_add_frame( FL_ENGRAVED_FRAME, 20, 26, 90, 70, "" );

    fdui->polybutt = obj = fl_add_checkbutton( FL_RADIO_BUTTON,
                                               30, 61, 70, 30, "Polygon" );
    fl_set_object_callback( obj, change_primitive, GL_POLYGON );

    obj = fl_add_checkbutton( FL_RADIO_BUTTON, 30, 31, 70, 30, "Line" );
    fl_set_object_callback( obj, change_primitive, GL_LINE_LOOP );

    obj = fl_add_button( FL_NORMAL_BUTTON, 150, 21, 80, 30, "Done" );
    fl_set_button_shortcut( obj, "Dd", 1 );

    obj = fl_add_roundbutton( FL_PUSH_BUTTON, 150, 71, 80, 30, "Animate" );
    fl_set_object_callback( obj, animate_callback, 0 );

    fl_end_form( );

    return fdui;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
