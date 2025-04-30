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
 * \file filesys.h
 *
 *  Convenience functions to read a directory
 */

#ifndef FL_FILESYS_H
#define FL_FILESYS_H

/*  File types */

enum {
    FT_FILE,
    FT_DIR,
    FT_LINK,
    FT_SOCK,
    FT_FIFO,
    FT_BLK,
    FT_CHR,
    FT_OTHER
};

typedef struct {
    char          * name;           /* entry name             */
    int             type;           /* FILE_TYPE              */
    long            dl_mtime;       /* file modification time */
    unsigned long   dl_size;        /* file size in bytes     */
} FL_Dirlist;

enum {
    FL_ALPHASORT = 1,       /* sort in alphabetic order           */
    FL_RALPHASORT,          /* sort in reverse alphabetic order   */
    FL_MTIMESORT,           /* sort according to modifcation time */
    FL_RMTIMESORT,          /* sort in reverse modificaiton time  */
    FL_SIZESORT,            /* sort in increasing size order      */
    FL_RSIZESORT,           /* sort in decreasing size order      */
    FL_CASEALPHASORT,       /* sort case insensitive              */
    FL_RCASEALPHASORT       /* sort case insensitive              */
};

typedef int ( * FL_DIRLIST_FILTER )( const char *, int );

/* read dir with pattern filtering. All dirs read might be cached.
 * Must not change dirlist in anyway. */

FL_EXPORT const FL_Dirlist * fl_get_dirlist( const char * dir,
                                             const char * pattern,
                                             int        * n,
                                             int          rescan );

FL_EXPORT FL_DIRLIST_FILTER fl_set_dirlist_filter( FL_DIRLIST_FILTER filter );

FL_EXPORT int fl_set_dirlist_sort( int method );

FL_EXPORT int fl_set_dirlist_filterdir( int yes );

FL_EXPORT void fl_free_dirlist( const FL_Dirlist * dl );

#endif /* ! defined FL_FILESYS_H */
