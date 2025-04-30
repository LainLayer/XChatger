/*
 *  This file is part of the XForms library package.
 *
 *  XForms is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1, or
 *  (at your option) any later version.
 *
 *  XForms is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/********************** crop here for forms.h **********************/

/**
 * \file canvas.h
 *
 * Header for FL_CANVAS
 *
 */

#ifndef FL_CANVAS_H_
#define FL_CANVAS_H_

typedef enum {
    FL_NORMAL_CANVAS,
    FL_SCROLLED_CANVAS
} FL_CANVAS_TYPE;

typedef int ( * FL_HANDLE_CANVAS )( FL_OBJECT *,
                                    Window,
                                    int,
                                    int,
                                    XEvent *,
                                    void * );

typedef int ( * FL_MODIFY_CANVAS_PROP )( FL_OBJECT * );

/******************** Default *********************/

#define FL_CANVAS_BOXTYPE   FL_DOWN_BOX     /* really the decoration frame */
#define FL_CANVAS_ALIGN     FL_ALIGN_TOP

/************ Interfaces    ************************/

FL_EXPORT FL_OBJECT * fl_create_generic_canvas( int          canvas_class,
                                                int          type,
                                                FL_Coord     x,
                                                FL_Coord     y,
                                                FL_Coord     w,
                                                FL_Coord     h,
                                                const char * label );

FL_EXPORT FL_OBJECT * fl_add_canvas( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_create_canvas( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

/* backward compatibility */

#define fl_set_canvas_decoration fl_set_object_boxtype

FL_EXPORT void fl_set_canvas_colormap( FL_OBJECT * ob,
                                       Colormap    colormap );

FL_EXPORT void fl_set_canvas_visual( FL_OBJECT * obj,
                                     Visual    * vi );

FL_EXPORT void fl_set_canvas_depth( FL_OBJECT * obj,
                                    int         depth );

FL_EXPORT void fl_set_canvas_attributes( FL_OBJECT            * ob,
                                         unsigned int           mask,
                                         XSetWindowAttributes * xswa );

FL_EXPORT FL_HANDLE_CANVAS fl_add_canvas_handler( FL_OBJECT        * ob,
                                                  int                ev,
                                                  FL_HANDLE_CANVAS   h,
                                                  void             * udata );

FL_EXPORT Window fl_get_canvas_id( FL_OBJECT * ob );

FL_EXPORT Colormap fl_get_canvas_colormap( FL_OBJECT * ob );

FL_EXPORT int fl_get_canvas_depth( FL_OBJECT * obj );

FL_EXPORT void fl_remove_canvas_handler( FL_OBJECT        * ob,
                                         int                ev,
                                         FL_HANDLE_CANVAS   h );

FL_EXPORT void fl_share_canvas_colormap( FL_OBJECT * ob,
                                         Colormap    colormap );

FL_EXPORT void fl_clear_canvas( FL_OBJECT * ob );

FL_EXPORT void fl_modify_canvas_prop( FL_OBJECT             * obj,
                                      FL_MODIFY_CANVAS_PROP   init,
                                      FL_MODIFY_CANVAS_PROP   activate,
                                      FL_MODIFY_CANVAS_PROP   cleanup );

FL_EXPORT void fl_canvas_yield_to_shortcut( FL_OBJECT * ob,
                                            int         yes );

/* This is an attempt to maintain some sort of backwards compatibility
 * with old code whilst also getting rid of the old, system-specific
 * hack. */

#ifdef AUTOINCLUDE_GLCANVAS_H
#include <glcanvas.h>
#endif

#endif /* ! defined FL_CANVAS_H */
