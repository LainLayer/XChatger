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
 * \file flps.h
 */

#ifndef FLPS_H
#define FLPS_H

/* postscript stuff */

enum {
   FLPS_AUTO,                  /* switch to landscale if does not fit */
   FLPS_LANDSCAPE,             /* landscape always                    */
   FLPS_PORTRAIT,              /* portrait always                     */
   FLPS_BESTFIT                /* even margins/best fit               */
};

enum {
  FLPS_BW = -1,
  FLPS_GRAYSCALE,
  FLPS_COLOR
};

typedef struct {
    int          ps_color;
    int          orientation;
    int          auto_fit;
    int          drawbox;
    int          eps;
    float        xdpi,
                 ydpi;
    float        paper_w,
                 paper_h;
    float        gamma;
    const char * tmpdir;
    int          printer_dpi;
    float        hm,
                 vm;
    float        xscale,
                 yscale;
    int          scale_text;
    int          first_page_only;
    int          clip;
} FLPS_CONTROL;

FL_EXPORT FLPS_CONTROL * flps_init( void );

FL_EXPORT int fl_object_ps_dump( FL_OBJECT  * ob,
                                 const char * fname );

#endif /* ! defined FLPS_H */
