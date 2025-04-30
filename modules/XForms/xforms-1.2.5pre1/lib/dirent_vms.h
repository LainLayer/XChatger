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


/*
**  Header file for VMS readdir() routines.
**  Written by Rich Salz, <rsalz@bbn.com> in August, 1990.
**  This code has no copyright.
**
**  Feb'95 --   eliminate reliance on <descrip.h>; safeguard multiple
**      inclusion; fully prototype the routines provided.   [pr]
*/

#ifndef DIRENT_H
#define DIRENT_H

/* Data structure returned by READDIR(). */
struct dirent {
    char    d_name[100];        /* File name        */
    int     vms_verscount;      /* Number of versions   */
    short   vms_versions[64];   /* Version numbers  */
};

/* Handle returned by opendir(), used by the other routines.  You
 * are not supposed to care what's inside this structure. */
typedef struct _dirdesc {
    unsigned long   context;
    int         count;
    int         vms_wantversions;
    char        *pattern;
    struct dirent   entry;
                /* pattern string descriptor */
    struct { unsigned short len, mbz; char *adr; } pat;
} DIR;


#define rewinddir(dirp)     seekdir((dirp), 0L)


extern DIR      *opendir(const char *);
extern struct dirent    *readdir(DIR *);
extern long     telldir(DIR *);
extern void     seekdir(DIR *,long);
extern void     closedir(DIR *);
extern int      vmsreaddirversions(DIR *,int);

#endif  /* DIRENT_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
