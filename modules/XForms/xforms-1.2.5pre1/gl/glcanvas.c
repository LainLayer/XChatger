/*
 *  This file is part of the XForms library package.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file glcanvas.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  A sample implementation of OpenGL/Mesa canvas class.
 *
 *  For typical objects, ob->spec is the place for the
 *  object specific info. For OpenGL canvas, however, the
 *  ob->spec is already used by the generic canvas. We use
 *  ob->c_vdata to hang the OpenGL specific stuff.
 *
 *  See ../DEMOS/gl.c for an example use of glcanvas.
 *  See ../DEMOS/glwin.c for an example use of fl_glwinopen
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <GL/glx.h>
#include <GL/gl.h>
#include "include/forms.h"
#include "glcanvas.h"
#include <stdlib.h>

#define MAXATTRIB  34

typedef struct
{
    XVisualInfo * xvinfo;
    GLXContext    context;
    int           direct;
    int           glconfig[ MAXATTRIB ];
} CSPEC;


/***************************************
 * Default GL canvas configuration. The user can modify this default
 * using fl_set_glcanvas_defaults(const int *config) or
 * fl_set_glcanvas_attributes(FL_OBJECT *, const int *config)
 ***************************************/

static int glconfig[ MAXATTRIB ] =
{
    GLX_RGBA,
    GLX_DEPTH_SIZE, 1,
    GLX_RED_SIZE,   1,
    GLX_GREEN_SIZE, 1,
    GLX_BLUE_SIZE,  1,
    GLX_DOUBLEBUFFER,
    None
};

#define GLPROP( ob )   ( ( CSPEC * ) ( ob )->c_vdata )
#define ISGLC( ob )    ( ( ob ) && ( ob )->objclass == FL_GLCANVAS )

static int glx_init( FL_OBJECT * );
static int glx_activate( FL_OBJECT * );
static int glx_cleanup( FL_OBJECT * );
static void copy_attributes( int *,
                             const int * );


/***************************************
 * Add a GL canvas to the form
 ***************************************/

FL_OBJECT *
fl_add_glcanvas( int          type,
                 FL_Coord     x,
                 FL_Coord     y,
                 FL_Coord     w,
                 FL_Coord     h,
                 const char * label )
{
    FL_OBJECT * ob = fl_create_glcanvas( type, x, y, w, h, label );

    fl_add_object( fl_current_form, ob );
    return ob;
}


/***************************************
 * Modify the global defaults
 ***************************************/

void
fl_set_glcanvas_defaults( const int * config )
{
    copy_attributes( glconfig, config );
}


/***************************************
 ***************************************/

void
fl_get_glcanvas_defaults( int * config )
{
    copy_attributes( config, glconfig );
}


/***************************************
 * Modify the default configuration of a particular canvas
 ***************************************/

void
fl_set_glcanvas_attributes( FL_OBJECT * ob,
                            const int * config )
{
    if ( ! ISGLC( ob ) )
        fprintf( stderr, "object %s is not glcanvas\n",
                 ob ? ob->label : "null" );

    copy_attributes( GLPROP( ob )->glconfig, config );

    if ( ob->visible )
    {
        fl_hide_object( ob );
        fl_show_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_get_glcanvas_attributes( FL_OBJECT * ob,
                            int       * attributes )
{
    copy_attributes( attributes, GLPROP( ob )->glconfig );
}


/***************************************
 ***************************************/

void
fl_set_glcanvas_direct( FL_OBJECT * ob,
                        int         direct )
{
    if ( direct != GLPROP( ob )->direct )
    {
        GLPROP( ob )->direct = direct ? GL_TRUE : GL_FALSE;
        if ( ob->visible )
        {
            fl_hide_object( ob );
            fl_show_object( ob );
        }
    }
}


/***************************************
 ***************************************/

GLXContext
fl_get_glcanvas_context( FL_OBJECT * ob )
{
    return GLPROP( ob )->context;
}


/***************************************
 ***************************************/

XVisualInfo *
fl_get_glcanvas_xvisualinfo( FL_OBJECT * ob )
{
    return GLPROP( ob )->xvinfo;
}


/***************************************
 ***************************************/

void
fl_activate_glcanvas( FL_OBJECT * ob )
{
    if ( FL_ObjWin( ob ) )
        glx_activate( ob );
}


/***************************************
 * Interface routines
 ***************************************/

FL_OBJECT *
fl_create_glcanvas( int          type,
                    FL_Coord     x,
                    FL_Coord     y,
                    FL_Coord     w,
                    FL_Coord     h,
                    const char * label )
{
    FL_OBJECT *ob = fl_create_canvas( type, x, y, w, h, label );

    ob->objclass = FL_GLCANVAS;
    fl_modify_canvas_prop( ob, glx_init, glx_activate, glx_cleanup );

    /* Initialize glcanvas specific stuff */

    ob->c_vdata = fl_calloc( 1, sizeof( CSPEC ) );
    memcpy( GLPROP( ob )->glconfig, glconfig, sizeof glconfig );
    GLPROP( ob )->direct = GL_TRUE;

    return ob;
}


/***************************************
 * Initialize the OpenGL stuff before window creation
 ***************************************/

static int
glx_init( FL_OBJECT * ob )
{
    XVisualInfo *vi;
    GLXContext context;

    /* Query for OpenGL capabilities */

    if ( ! glXQueryExtension( fl_display, 0, 0 ) )
    {
        fprintf( stderr, "GLCanvas: OpenGL not supported\n" );
        return -1;
    }

    /* Quit if we can't get a visual */

    if ( ! ( vi = glXChooseVisual( fl_display, fl_screen,
                                   GLPROP( ob )->glconfig ) ) )
    {
        fprintf( stderr, "GLCanvas: Can't get visual\n" );
        return -1;
    }

    /* Change canvas defaults */

    fl_set_canvas_visual( ob, vi->visual );
    fl_set_canvas_depth( ob, vi->depth );
    fl_set_canvas_colormap( ob, fl_create_colormap( vi, 1 ) );

    context = glXCreateContext( fl_display, vi, None, GLPROP( ob )->direct );

    if ( ! context )
    {
        fprintf( stderr, "Can't create GLX context!\n" );
        return -1;
    }

    /* Under some conditions the parent of the gl canvas might go away,
       leaving the old context and vi hanging. */

    glx_cleanup( ob );

    GLPROP( ob )->context = context;
    GLPROP( ob )->xvinfo = vi;

    return 0;
}


/***************************************
 * This routine is called after a valid window is created. It simply
 * binds the OpenGL context to the canvas window
 ***************************************/

static int
glx_activate( FL_OBJECT * ob )
{
    glXMakeCurrent( fl_display, FL_ObjWin( ob ), GLPROP( ob )->context );
    return 0;
}


/***************************************
 * Cleanup is called before destroying the window.  Might be called
 * more than once
 ***************************************/

static int
glx_cleanup( FL_OBJECT * ob )
{
    if ( GLPROP( ob )->context )
    {
        glXDestroyContext( fl_display, GLPROP( ob )->context );
        XFree( GLPROP( ob )->xvinfo );
        GLPROP( ob )->context = 0;
        GLPROP( ob )->xvinfo = 0;
    }

    return 0;
}


/***************************************
 ***************************************/

static void
copy_attributes( int *       dest,
                 const int * src )
{
    while ( *src != None )
        *dest++ = *src++;
    *dest = None;
}


/*************************************************************
 * Open a top-level OpenGL window.
 *
 * fl_winset won't work for switching OpenGL windows.
 * Use glXMakeCurrent
 ************************************************************/

Window
fl_glwincreate( int *        config,
                GLXContext * context,
                int          w,
                int          h )
{
    XVisualInfo *xvi;
    XSetWindowAttributes xswa;
    unsigned int mask;
    Window win;

    if ( ! glXQueryExtension( fl_display, 0, 0 ) )
        return None;

    if ( ! ( xvi = glXChooseVisual( fl_display, fl_screen,
                                    config ? config : glconfig ) ) )
        return None;

    *context = glXCreateContext( fl_display, xvi, None, GL_TRUE );

    xswa.colormap = fl_create_colormap( xvi, 1 );
    xswa.border_pixel = 0;
    mask = CWColormap | CWBorderPixel;

    xswa.event_mask = ExposureMask | StructureNotifyMask;
    mask |= CWEventMask;

    win = XCreateWindow( fl_display, RootWindow( fl_display, fl_screen ),
                         0, 0, w, h, 0,
                         xvi->depth, InputOutput,
                         xvi->visual, mask, &xswa );
    if ( win )
        glXMakeCurrent( fl_display, win, *context );

    return win;
}


/***************************************
 ***************************************/

Window
fl_glwinopen( int *        config,
              GLXContext * context,
              int          w,
              int          h )
{
    Window win;

    if ( ( win = fl_glwincreate( config, context, w, h ) ) )
        fl_winshow( win );

    return win;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
