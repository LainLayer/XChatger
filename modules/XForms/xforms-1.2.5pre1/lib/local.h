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
 * \file local.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-1998  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Some machine specific stuff.
 */

#ifndef FL_LOCAL_H
#define FL_LOCAL_H

#ifndef _WIN32
#include <unistd.h>
#endif

#ifndef HAVE_STRCASECMP
extern int strcasecmp( const char *,
                       const char * );
#endif

#if defined Lynx
#define NEED_GETCWD
#endif

#if defined __VMS
#define NEED_GETCWD

#if __VMS_VER < 70000000
struct timezone
{
    int tz_minuteswest;     /* minutes west of Greenwich */
    int tz_dsttime;         /* type of dst correction */
};

extern int gettimeofday( struct timeval  * tv,
                         struct timezone * tz );
#endif /* ___VMS_VER  */

#endif /* __VMS */


/********* End of Configurable stuff ***********/

#ifndef FL_PATH_MAX
#ifdef PATH_MAX
#define FL_PATH_MAX   PATH_MAX
#else
#define FL_PATH_MAX   1024
#endif
#endif /* FL_PATH_MAX */

#ifndef FL_FLEN
#define FL_FLEN           256
#endif

/* There are two ways to handle motion events, one is to constantly
 * query the server for mouse position, and the other is to use
 * motion events. The first way obviously is slow and expensive
 * if runs across network. The latter however suffers with stepping
 * events.
 */

/*#define NO_MSG_INFO */

#endif /* ifndef local.h } */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
