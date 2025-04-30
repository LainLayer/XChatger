/*
 * This file is part of XForms.
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
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file fd_rubber.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This file is part of the Form Designer.
 *
 *  Someday, we'll have to re-write all of these so it fits with
 *  X event handling better.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"

extern void color( unsigned long );

extern GC fd_gc,
          fd_xorgc,
           fd_copygc;
extern Colormap fd_colormap;
extern Display *fd_display;

/****
  ROUNDING
*****/

static double xmin   = 0.0,
              ymin   = 0.0,
              width  = 1280.0,
              height = 1024.0;
static double stepsize = 10.0;   /* Step size (for alignment) */


/***************************************
 * Sets the step size
 ***************************************/

void
set_step_size( double size )
{
    stepsize = size < 1.0 ? 1.0 : size;
}


/***************************************
 * Returns the step size
 ***************************************/

double
get_step_size( void )
{
    return stepsize;
}


/***************************************
 * Sets the bounding box.
 ***************************************/

void
set_bounding_box( double x,
                  double y,
                  double w,
                  double h )
{
    xmin   = x;
    ymin   = y;
    width  = w;
    height = h;
}


/***************************************
 * Rounds the box size to the step size and inside the bounding box
 ***************************************/

static void
round_size( double * x,
            double * y,
            double * w,
            double * h )
{
    if ( *w > width )
        *w = width;

    if ( *h > height )
        *h = height;

    if ( stepsize > 0.0 )
    {
        int t = *w / stepsize + 0.5;

        if ( *w >= 0.0 )
            *w = stepsize * t;
        else
            *w = stepsize * ( t - 1 );
        t = *h / stepsize + 0.5;
        *h = stepsize * t;
        if ( *h >= 0.0 )
            *h = stepsize * t;
        else
            *h = stepsize * ( t - 1 );
    }

    if ( *x + *w > xmin + width )
        *w = xmin + width - *x;

    if ( *y + *h > ymin + height )
        *h = ymin + height - *y;

    if ( *x + *w < xmin )
        *w = xmin - *x;

    if ( *y + *h < ymin )
        *h = ymin - *y;

    if ( *w >= 0.0f && *w < stepsize )
        *w = stepsize;

    if ( *h >= 0.0 && *h < stepsize )
        *h = stepsize;

    if ( *w < 0.0 && *w > -stepsize )
        *w = -stepsize;

    if ( *h < 0.0 && *h > -stepsize )
        *h = -stepsize;
}


/***************************************
 * Rounds the position to the stepsize and inside the bounding box
 ***************************************/

static void
round_position( double * x,
                double * y,
                double * w,
                double * h )
{
    if ( *w > width )
        *w = width;

    if ( *h > height )
        *h = height;

    if ( stepsize > 0.0 )
    {
        int t = *x / stepsize + 0.5;

        *x = stepsize * t;
        t = *y / stepsize + 0.5;
        *y = stepsize * t;
    }

    if ( *x < xmin )
        *x = xmin;

    if ( *y < ymin )
        *y = ymin;

    if ( *x + *w > xmin + width )
        *x = xmin + width - *w;

    if ( *y + *h > ymin + height )
        *y = ymin + height - *h;
}


/****
  DRAWING
****/

/***************************************
 * Draws a box
 ***************************************/

static void
show_box( double x,
          double y,
          double w,
          double h )
{
    XSetFunction( fd_display, fd_gc, GXxor );
    color( fd_col ^ fd_black );
    rect( x, y, x + w - 1, y + h - 1 );
    XSetFunction( fd_display, fd_gc, GXcopy );
}

#define hide_box show_box

/****
  THE ACTUAL ROUTINES
****/


/***************************************
 * Whether we should stop
 ***************************************/

static int
ready( void )
{
    XEvent xev;

    if ( fl_check_forms( ) == FL_EVENT )
    {
        fl_XNextEvent( &xev );
        fli_xevent_name( "ready:", &xev );
        return (   xev.type == ButtonRelease
                || ( is_pasting && xev.type == KeyPress ) );
    }

    fl_msleep( 10 );

    return 0;
}


/***************************************
 * Returns the position of the mouse in world coordinates
 ***************************************/

void
get_mouse_pos( double * xx,
               double * yy )
{
    FL_Coord x,
             y;
    unsigned int kmask;

    fl_get_win_mouse( main_window, &x, &y, &kmask );
    *xx = x;
    *yy = y;
}


/***************************************
 * Drag a box around until the user releases a mouse button
 ***************************************/

void
move_box( double * x,
          double * y,
          double * w,
          double * h,
          int      offset )
{
    double oldx = *x, oldy = *y, oldw = *w, oldh = *h;
    double xoff, yoff;

    if ( offset )
    {
        get_mouse_pos( &xoff, &yoff );
        xoff -= *x;
        yoff -= *y;
    }
    else
    {
        xoff = *w / 2.0;
        yoff = *h / 2.0;
    }

    show_box( *x, *y, *w, *h );

    while ( ! ready( ) )
    {
        get_mouse_pos( x, y );
        *x -= xoff;
        *y -= yoff;
        round_position( x, y, w, h );
        if ( *x != oldx || *y != oldy )
        {
            hide_box( oldx, oldy, oldw, oldh );
            show_box( *x, *y, *w, *h );

            if ( fd_trackgeometry )
                show_geometry( *x, *y, *w, *h );
            oldx = *x;
            oldy = *y;
            oldw = *w;
            oldh = *h;
        }
    }

    hide_box( oldx, oldy, *w, *h );
}


/***************************************
 * Scales a box until the user releases a mouse button
 ***************************************/

void
scale_box( double * x,
           double * y,
           double * w,
           double * h )
{
    double oldw = 1.0,
           oldh = 1.0;

    round_position( x, y, w, h );

    while ( ! ready( ) )
    {
        get_mouse_pos( w, h );
        *w -= *x;
        *h -= *y;
        round_size( x, y, w, h );

        if ( *w != oldw || *h != oldh )
        {
            if ( fd_trackgeometry )
                show_geometry( *x, *y, *w, *h );
            hide_box( *x - 1, *y - 1, oldw, oldh );
            show_box( *x - 1, *y - 1, *w, *h );
            oldw = *w;
            oldh = *h;
        }
    }

    hide_box( *x - 1, *y - 1, oldw, oldh );

    if ( *w < 0.0 )
    {
        *x += *w;
        *w = - *w;
    }

    if ( *h < 0.0 )
    {
        *y += *h;
        *h = - *h;
    }
}


/***************************************
 ***************************************/

void
color( unsigned long n )
{
    static unsigned long oldcol;

    if ( fd_gc && oldcol != n )
    {
        XSetForeground( fd_display, fd_gc, n );
        oldcol = n;
    }
}


/***************************************
 ***************************************/

void
rectf( FL_Coord x1,
       FL_Coord y1,
       FL_Coord x2,
       FL_Coord y2 )
{
    int x = x1,
        y = y1,
        w = x2 - x1,
        h = y2 - y1;

    fli_canonicalize_rect( &x, &y, &w, &h );
    XFillRectangle( fd_display, main_window, fd_gc, x, y, w, h );
}


/***************************************
 ***************************************/

void
rect( FL_Coord x1,
      FL_Coord y1,
      FL_Coord x2,
      FL_Coord y2 )
{
    FL_Coord x = x1,
             y = y1,
             w = x2 - x1,
             h = y2 - y1;

    fli_canonicalize_rect( &x, &y, &w, &h );
    XDrawRectangle( fd_display, main_window, fd_gc, x, y, w, h );
}


/***************************************
 ***************************************/

void
fd_clear( int x,
          int y,
          int w,
          int h )
{
    static GC blk_gc;

    if ( main_window && w > 0 && h > 0 )
    {
        if ( ! blk_gc )
        {
            blk_gc = XCreateGC( fd_display, main_window, 0, 0 );
            XSetForeground( fd_display, blk_gc, fd_black );
        }

        XFillRectangle( fd_display, main_window, blk_gc, x, y, w, h );
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
