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
 * \file pbrowser.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) T.C. Zhao and Mark Overmars
 *  All rights reserved.
 */

#ifndef PBROWSER_H_
#define PBROWSER_H_

#include "ptbox.h"
#include "pscrollbar.h"


typedef struct {
    FL_OBJECT                  * tb;            /* the textbox                */
    FL_OBJECT                  * hsl;           /* horizontal scrollbar       */
    FL_OBJECT                  * vsl;           /* vertical scrollbar         */
    FL_CALLBACKPTR               callback;
    long                         callback_data;
    double                       hsize,
                                 vsize;
    double                       hval,
                                 vval;
    double                       hinc1,
                                 hinc2;
    double                       vinc1,
                                 vinc2;
    int                          dead_area;
    int                          attrib;
    int                          v_on,          /* scrollbar on/off state     */
                                 h_on;
    int                          v_pref,        /* on/off prefererence        */
                                 h_pref;
    int                          vw,
                                 vw_def;
    int                          hh,
                                 hh_def;
    int                          user_set;
    FL_BROWSER_SCROLL_CALLBACK   hcb,
                                 vcb;
    void                       * hcb_data,
                               * vcb_data;
    double                     old_vp;
    double                     old_hp;                          
} FLI_BROWSER_SPEC;

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
