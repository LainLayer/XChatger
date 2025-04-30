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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file pcanvas.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1995-1997  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 */

#ifndef PCANVAS_H
#define PCANVAS_H


/* Canvas specific stuff */

typedef struct {
    const char            * winname;    /* name of the window                */
    Window                  parent;     /* real parent(needed for dblbuffer) */
    Window                  window;     /* Canvas window                     */
    Visual                * visual;     /* canvas visual                     */
    void                  * context;    /* context for glx/mesa              */

    FL_MODIFY_CANVAS_PROP   init;
    FL_MODIFY_CANVAS_PROP   activate;
    FL_MODIFY_CANVAS_PROP   cleanup;

    Colormap                colormap;   /* colormap for the canvas       */
    GC                      gc;
    unsigned int            mask,
                            user_mask;
    int                     depth;
    int                     dec_type;   /* if and how to decorate canvas */
    int                     x,          /* window size                   */
                            y,
                            w,
                            h;
    int                     yield_to_shortcut;  /* other object's shortcut
                                                 has priority */

    XSetWindowAttributes    xswa;
    XSetWindowAttributes    user_xswa;

    FL_OBJECT             * last_active;    /* last sp->activated object */

    /* this is not exactly right. sort of wasteful */

    FL_HANDLE_CANVAS         canvas_handler[ LASTEvent ];
    void *                   user_data[ LASTEvent ];
    int                      keep_colormap;

    Window                   swindow;       /* scrolled/subwindow           */
    int                      sx,
                             sy,
                             sw,
                             sh;            /* scrolled window size          */
} FLI_CANVAS_SPEC;


#endif /* PCANVAS_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
