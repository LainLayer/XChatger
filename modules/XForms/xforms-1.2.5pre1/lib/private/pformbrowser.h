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
 * \file pformbrowser.h
 */

#ifndef PFORMBROWSER_H
#define PFORMBROWSER_H

typedef struct {
    FL_OBJECT  * canvas;
    FL_OBJECT  * parent;
    int          nforms;
    FL_FORM   ** form;
    int          v_pref;
    int          h_pref;
    int          vw_def,
                 vw;
    int          hh_def,
                 hh;
    FL_OBJECT  * hsl;
    FL_OBJECT  * vsl;
    int          h_on,
                 v_on;
    double       old_vval,
                 old_hval;

    int          x,
                 y;
    int          left_edge;
    int          top_edge;
    int          top_form;

    int          max_height;
    int          max_width;

    int          processing_destroy;
    int          in_draw;
    int          scroll;            /* either pixel based or form based */
} FLI_FORMBROWSER_SPEC;

#define IsFormBrowserClass( ob )  \
    ( ( ob ) && ( ob )->objclass == FL_FORMBROWSER )

#if defined sun && ! defined __SVR4
#define memmove( a, b, c )   bcopy( b, a, c )
#endif

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
