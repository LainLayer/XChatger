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
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/*
   **  VMS readdir() routines.
   **  Written by Rich $alz, <rsalz@bbn.com> in August, 1990.
   **  This code has no copyright.
   **
   **  Feb'95 -- reliance on <descrip.h> eliminated, here and in dirent.h;
   **            support for Unix-style directory specifications implemented;
   **            vmsreaddirversions() modified to return prior flag setting;
   **            use ANSI headers <stdlib.h> and <string.h> plus VMS headers
   **            <lib$routines.h> and <fscndef.h>; minor lint cleanup.   [pr]
   **
   **  Known problems:
   **           garbage directory specifications aren't always diagnosed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <lib$routines.h>
#include <fscndef.h>        /* $FILESCAN arguments */
#include <rmsdef.h>


 /* Protect against TEST being defined by some other module */

#undef TEST

/* Uncomment the next line to get a test routine. */
/* #define TEST */

 /* Number of elements in vms_versions array */
#define VERSIZE(e)  (sizeof e->vms_versions / sizeof e->vms_versions[0])

 /* Simplified string descriptor */
struct dsc
{
    unsigned short len, mbz;
    char *adr;
};

 /* Parts of file specification used to specify a directory. */
#define FSCN_DIR (FSCN$M_NODE | FSCN$M_DEVICE | FSCN$M_ROOT | FSCN$M_DIRECTORY)

extern unsigned long sys$filescan();

 /* Filename syntax conversion routine */
#ifdef __DECC           /* (really depends on run-time library, not
                   compiler) */
#define cvt__to_vms decc$to_vms
#else
#define cvt__to_vms shell$to_vms
#endif
extern int cvt__to_vms(char *, int (*)(char *, int), int, int);
static int cvt_action(char *, int);

 /* Callback routine uses non re-entrant communication w/ caller. */
static char nambuf[255 + 1];

/*
   **  XXX$to_vms callback routine.  Note: old versions of shell$to_vms
   **  didn't document the second argument, which indicates whether a
   **  directory of foo/bar was converted into "[.foo]bar.dir" rather
   **  than "[.foo.bar]" (such conversion is requested by passing non-zero
   **  as XXX$to_vms's 4th argument; also undocumented in old versions).
 */
static int
cvt_action(char *name, int dir_flag___unused)
{
    nambuf[sizeof nambuf - 1] = '\0';
    (void) strncpy(nambuf, name, sizeof nambuf - 1);
    /* An even value tells xxx$to_vms that conversion should stop; that point
       is moot here since wildcard processing is disabled. */
    return 0;
}

/*
   **  Open a directory, return a handle for later use.
 */

DIR *
opendir( name )
     const char *name;
{
    DIR *dd;
    struct dsc name_dsc;
    int len, retry = 0;
    unsigned long flags;

    /* Validate the directory name argument.  ("[...]" is allowed!) */
    if (!name || !*name || strchr(name, '*') != 0
    || strchr(name, '%') != 0 || strchr(name, '?') != 0)
    {
    /* Name is required; wildcards are not allowed. */
    errno = ENOTDIR;
    return NULL;
    }
    nambuf[sizeof nambuf - 1] = '\0';   /* (strncpy doesn't guarantee it) */
    name_dsc.adr = strncpy(nambuf, name, sizeof nambuf - 1);
    name_dsc.mbz = 0;
    do
    {
    name_dsc.len = len = strlen(nambuf);
    /* Check which components of file specification seem to be present. */
    flags = ~0;     /* (init so that we can ignore return status)
                 */
    (void) sys$filescan(&name_dsc, (void *) 0, &flags);
    if ((flags & ~FSCN_DIR) != 0 || strchr(nambuf, '/') != 0)
    {
        /* Didn't supply nice directory name; check for Unix-style one. */
        /* (stupid shell$to_vms doesn't like trailing slash) */
        if (len > 1 && nambuf[len - 1] == '/')
        nambuf[len - 1] = '\0';

        if (++retry > 1 || cvt__to_vms(nambuf, cvt_action, 0, 0) != 1)
        {
        errno = ENOTDIR;
        return NULL;
        }           /* else:        cvt_action() has updated
                   `nambuf'; `retry' is now 1 */
    }
    else
        retry = 0;      /* have something, possibly after retrying
                   once */
    }
    while (retry);

    /* Get memory for the handle, and the pattern. */
    if ((dd = fl_malloc( sizeof *dd ) ) == NULL )
    {
        errno = ENOMEM;
        return NULL;
    }
    dd->pattern = fl_malloc( strlen( nambuf ) + sizeof "*.*" );
    if (dd->pattern == NULL)
    {
        fl_free( dd );
        errno = ENOMEM;
        return NULL;
    }

    /* Fill in the fields. */
    strcat(strcpy(dd->pattern, nambuf), "*.*");
    dd->context = 0;
    dd->count = 0;
    dd->vms_wantversions = 0;
    dd->pat.adr = dd->pattern;
    dd->pat.len = strlen(dd->pattern);
    dd->pat.mbz = 0;
    memset(&dd->entry, 0, sizeof dd->entry);

    return dd;
}


/*
   **  Set the flag to indicate we want versions or not.  Return old setting.
 */
int
vmsreaddirversions(dd, flag)
     DIR *dd;
     int flag;
{
    int old_flag = dd->vms_wantversions;

    dd->vms_wantversions = flag;
    return old_flag;
}


/*
   **  Free up an opened directory.
 */

void
closedir( dd )
     DIR *dd;
{
    if (dd)
    {
    (void) lib$find_file_end(&dd->context);
    fl_free(dd->pattern);
    fl_free((void *) dd);
    }
}


/*
   **  Collect all the version numbers for the current file.
 */

static void
collectversions( dd )
     DIR *dd;
{
    struct dsc pat;
    struct dsc res;
    struct dirent *e;
    char *p;
    char buff[sizeof dd->entry.d_name];
    int i;
    char *text;
    long context;

    /* Convenient shorthand. */
    e = &dd->entry;

    /* Add the name plus version wildcard, replacing the "*.*" put on before */
    i = strlen(dd->pattern);
    /* assert( i > 3 ); */
    i = FL_max( i, 4 );
    text = fl_malloc( (i - 3) + strlen(e->d_name) + sizeof ";*");
    if (text == NULL)
        return;
    strcpy(text, dd->pattern);
    strcat(strcpy(&text[i - 3], e->d_name), ";*");

    /* Set up the pattern and result descriptors. */
    pat.adr = text;
    pat.len = strlen(text);
    res.adr = buff;
    res.len = sizeof buff - 1;
    pat.mbz = res.mbz = 0;

    /* Read files, collecting versions. */
    for (context = 0; e->vms_verscount < VERSIZE(e); e->vms_verscount++)
    {
        if (lib$find_file(&pat, &res, &context) == RMS$_NMF || context == 0)
            break;
        buff[sizeof buff - 1] = '\0';
        if (p = strchr(buff, ';'))
            e->vms_versions[e->vms_verscount] = atoi(p + 1);
        else
            e->vms_versions[e->vms_verscount] = -1;
    }
    if (e->vms_verscount < VERSIZE(e))
        e->vms_versions[e->vms_verscount] = -1;

    (void) lib$find_file_end(&context);
    fl_free(text);
}


/*
   **  Read the next entry from the directory.
 */
struct dirent *
readdir(dd)
     DIR *dd;
{
    struct dsc res;
    char *p, *q;
    int i;

    /* Set up result descriptor, and get next file. */
    res.adr = nambuf;
    res.len = sizeof nambuf - 1;
    res.mbz = 0;
    dd->count++;
    /* (ought to check for generic success/failure, not a specific value) */
    if (lib$find_file(&dd->pat, &res, &dd->context) == RMS$_NMF
    || dd->context == 0L)
    /* None left... */
    return NULL;

    /* Strip trailing blanks. */
    nambuf[sizeof nambuf - 1] = '\0';
    for (p = &nambuf[sizeof nambuf - 1]; p > nambuf && *--p == ' ';)
    *p = '\0';

    /* Skip any directory component and just copy the name. */
    p = nambuf;
    while ((q = strchr(p, ']')) != 0 || (q = strchr(p, '>')) != 0)
    p = q + 1;
    (void) strncpy(dd->entry.d_name, p, sizeof dd->entry.d_name - 1);
    dd->entry.d_name[sizeof dd->entry.d_name - 1] = '\0';

    /* Clobber the version. */
    if ((p = strchr(dd->entry.d_name, ';')) != 0)
    *p = '\0';

    dd->entry.vms_verscount = 0;
    dd->entry.vms_versions[0] = 0;
    if (dd->vms_wantversions)
    collectversions(dd);
    return &dd->entry;
}


/*
   **  Return something that can be used in a seekdir later.
 */
long
telldir(dd)
     DIR *dd;
{
    return dd->count;
}


/*
   **  Return to a spot where we used to be.  Brute force.
 */
void
seekdir(dd, count)
     DIR *dd;
     long count;
{
    int vms_wantversions;

    /* If we haven't done anything yet... */
    if (dd->count == 0)
    return;

    /* Remember some state, and clear it. */
    vms_wantversions = dd->vms_wantversions;
    dd->vms_wantversions = 0;
    (void) lib$find_file_end(&dd->context);
    dd->context = 0;

    /* The increment is in readdir(). */
    for (dd->count = 0; dd->count < count;)
    (void) readdir(dd);

    dd->vms_wantversions = vms_wantversions;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
