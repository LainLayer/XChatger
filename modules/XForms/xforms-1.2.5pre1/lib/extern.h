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
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file extern.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-1998  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * All global variables used in forms.  Should not be used
 * by application programs.  There is no guarantee that these
 * variables exist in future version of XForms
 */

#ifndef FL_EXTERN_H_MAKING_FORMS_ONLY
#define FL_EXTERN_H_MAKING_FORMS_ONLY

extern Pixmap fli_gray_pattern[ ];
extern GC fli_bwgc[ ];
extern GC fli_whitegc;
extern XKeyboardControl fli_keybdcontrol;
extern unsigned long fli_keybdmask;

extern FL_OBJECT *fli_current_group;

#define FLI_INACTIVE_PATTERN fli_gray_pattern[ 1 ]

extern FL_IOPT fli_cntl;
extern int fli_inverted_y;

extern FLI_CONTEXT * fli_context;
extern FLI_TARGET * flx;
extern long fli_requested_vid;
extern int fli_no_connection;
extern char fli_curfnt[ 127 ];
extern FLI_WIN *fli_app_win;

extern void fli_draw_tbox( int,
                           FL_Coord,
                           FL_Coord,
                           FL_Coord,
                           FL_Coord,
                           FL_COLOR,
                           int );


#endif /* !def EXTERN.H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
