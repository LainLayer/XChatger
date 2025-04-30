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
 * \file dmalloc.h
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-1998  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Very simple debug version of malloc family. It works by replacing the
 * standard malloc and its cousins with  my own routines that track, among
 * other things, where mallocs are called and how many bytes they get. All
 * these relies on the the work of true malloc. A true debug version of
 * malloc should replace malloc with calls to sbrk. Anyway, All I want out of
 * this hack is to make sure there are no memory leaks.
 */

#ifndef TC_DMALLOC_H_
#define TC_DMALLOC_H_

#include <stdlib.h>

#ifdef TC_MEMDBG

extern void *tc_dbg_malloc( size_t,
                            const char *,
                            int );
extern void *tc_dbg_calloc( size_t,
                            size_t,
                            const char *,
                            int );
extern void *tc_dbg_realloc( void *,
                             size_t,
                             const char *,
                             int );
extern void *tc_dbg_getmat( int,
                            int,
                            size_t,
                            const char *,
                            int );
extern char *tc_dbg_strdup( const char *,
                            const char *,
                            int );
extern void tc_dbg_free( void *,
                         const char *,
                         int );
extern void tc_true_free( void * );
extern void tc_set_mem_warn( int );
extern void tc_mem_stat( int );

#ifndef TC_MEMDBG_OWNER     /* actual replacememnt */
#define fl_malloc( a )        tc_dbg_malloc( a, __FILE__, __LINE__ )
#define fl_calloc( a, b )     tc_dbg_calloc( a, b, __FILE__, __LINE__ )
#define fl_realloc( a, b )    tc_dbg_realloc( a, b, __FILE__, __LINE__ )
#define fl_free( a )          tc_dbg_free( a, __FILE__, __LINE__ )
#define fl_strdup( a )        tc_dbg_strdup( a, __FILE__, __LINE__ )
#endif /* TC_MEMDBG_OWNER */

#else /* if not debug, tfree becomes free */

#ifndef fl_free
#define fl_malloc( a )        malloc( a )
#define fl_calloc( a, b )     calloc( a, b )
#define fl_realloc( a, b )    realloc( a, b )
#define fl_free( a )          free( a )
#endif

#define tc_true_free( p )     free( p )
#define tc_mem_stat( a )
#define tc_set_mem_warn( p )

#endif /* TC_MEMDBG */

#endif /* _MY_MALLOC_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
