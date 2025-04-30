/*
 *
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
 * \file global.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-1998  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * All gloabl varialbes used in XForms. It is important to start all
 * variables with fl/FL or fli/FLI to avoid name space pollution.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "include/forms.h"
#include "flinternal.h"


Window fl_root,
       fl_vroot;

int fl_screen;

/* memory routines */

void * ( * fl_calloc  )( size_t, size_t ) = calloc;
void * ( * fl_malloc  )( size_t )         = malloc;
void * ( * fl_realloc )( void *, size_t ) = realloc;
void   ( * fl_free    )( void * )         = free;

FL_State fl_state[ 6 ];

int fl_vmode = -1;

int fl_scrh,
    fl_scrw;

char *fl_ul_magic_char = "\b";

XKeyboardControl fli_keybdcontrol;

unsigned long fli_keybdmask = ( 1L << 8 ) - 1;

double fl_dpi = 96.0;

int fli_inverted_y;

long fli_requested_vid;

FLI_INTERNAL fli_int = { NULL,      /* forms */
                         0,         /* formnumb */
                         0,         /* hidden_formnumb */
                         0,         /* auto)count */
                         0,         /* unmanaged_count */
                         0,         /* mousex */
                         0,         /* mousey */
                         0,         /* keymask */
                         UINT_MAX,  /* query_age */
                         NULL,      /* mouseform */
                         NULL,      /* keyform */
                         NULL,      /* pushobj */
                         NULL       /* mouseobj */
                       };   

FL_IOPT fli_cntl;

FLI_CONTEXT *fli_context;

char fli_curfnt[ 127 ];

FL_FORM *fl_current_form;

FL_OBJECT *fli_current_group;

int fli_no_connection = 0;        /* Set only when fdesign is run with
                                     the '-convert' option */
FLI_WIN *fli_app_win;

FL_OBJECT *FL_EVENT = ( FL_OBJECT * ) - 1L;   /* The special event object */


FLI_TARGET *flx;

/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
