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
 * \file bitmap.h
 *
 *   Object Class: Bitmap
 */

#ifndef FL_BITMAP_H
#define FL_BITMAP_H

#define    FL_NORMAL_BITMAP      0

/***** Defaults *****/

#define FL_BITMAP_BOXTYPE   FL_NO_BOX
#define FL_BITMAP_COL1      FL_COL1     /* background of bitmap */
#define FL_BITMAP_COL2      FL_COL1     /* not used currently   */
#define FL_BITMAP_LCOL      FL_LCOL     /* foreground of bitmap */
#define FL_BITMAP_ALIGN     FL_ALIGN_BOTTOM

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_bitmap( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_bitmap( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_set_bitmap_data( FL_OBJECT     * ob,
                                   int             w,
                                   int             h,
                                   unsigned char * data );

FL_EXPORT void fl_set_bitmap_file( FL_OBJECT  * ob,
                                   const char * fname );

FL_EXPORT Pixmap fl_read_bitmapfile( Window         win,
                                     const char   * file,
                                     unsigned int * w,
                                     unsigned int * h,
                                     int          * hotx,
                                     int          * hoty );

FL_EXPORT Pixmap fl_create_from_bitmapdata( Window       win,
											const char * data,
											int          width,
											int          height );

/* for compatibility */

#define fl_set_bitmap_datafile    fl_set_bitmap_file

/* PIXMAP stuff */

#define FL_NORMAL_PIXMAP   0

FL_EXPORT FL_OBJECT * fl_create_pixmap( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_pixmap( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_set_pixmap_data( FL_OBJECT   * ob,
                                   char       ** bits );

FL_EXPORT void fl_set_pixmap_file( FL_OBJECT  * ob,
                                   const char * fname );

FL_EXPORT void fl_set_pixmap_align( FL_OBJECT * ob,
                                    int         align,
                                    int         xmargin,
                                    int         ymargin );

FL_EXPORT void fl_set_pixmap_pixmap( FL_OBJECT * ob,
                                     Pixmap      id,
                                     Pixmap      mask );

FL_EXPORT void fl_set_pixmap_colorcloseness( int red,
                                             int green,
                                             int blue );

FL_EXPORT void fl_free_pixmap_pixmap( FL_OBJECT * ob );

FL_EXPORT void fl_free_pixmap_focus_pixmap( FL_OBJECT * obj );

FL_EXPORT Pixmap fl_get_pixmap_pixmap( FL_OBJECT * ob,
                                       Pixmap    * p,
                                       Pixmap    * m );

FL_EXPORT Pixmap fl_read_pixmapfile( Window         win,
                                     const char   * file,
                                     unsigned int * w,
                                     unsigned int * h,
                                     Pixmap       * shape_mask,
                                     int          * hotx,
                                     int          * hoty,
                                     FL_COLOR       tran );

FL_EXPORT Pixmap fl_create_from_pixmapdata( Window          win,
                                            char         ** data,
                                            unsigned int  * w,
                                            unsigned int  * h,
                                            Pixmap        * sm,
                                            int           * hotx,
                                            int           * hoty,
                                            FL_COLOR        tran );

FL_EXPORT void fl_free_pixmap( Pixmap id );


#endif /* ! defined FL_BITMAP_H */
