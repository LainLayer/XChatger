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


#ifndef FLVASPRINTF_H
#define FLVASPRINTF_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include "flsnprintf.h"

#if defined ( HAVE_VASPRINTF ) && ! defined ( HAVE_DECL_VASPRINTF )
int
vasprintf( char       ** strp,
           const char  * fmt,
           va_list       ap );
#endif

/* Macro for allocating a buffer and filling it with a string
 * constructed from a format string and an unspecified number
 * of arguments. It expects a char pointer first (which will
 * be set to the address of the memory allocated for the resulting
 * string) and a (const) char pointer with a printf-like format
 * string (if the pointer to the format string is NULL memory is
 * obtained for the empty string). Of course, the function from
 * which the macro is invoked from must be a variadic function,
 * called with the appropriate number of types of arguments for
 * the format string.
 *
 * On success the first argument will be set to a buffer long
 * enough and containing the intended string. If there wasn't
 * enough memory available an attempted is make to at least
 * allocate memory for the empty string. If even this fails
 * the first macro argument is set to NULL.
 *
 * Of course it's the responsibility of whatever invoked
 * this macro to release the memory allocated here at the
 * appropriate time.
 *
 * The best function to use here would be vasprintf(), which
 * exactly does what we need. Older systems may not have it -
 * in this case 'HAVE_VASPRINTF isn't defined. Unfortunately,
 * we can't use the implementation from the flsnprintf.c file
 * since it doesn't get compiled in the way this file is made
 * up (and for good reasonsm the way the necessary va_copy()
 * function gets defined is broken in more than one way). But
 * we can use fli_vsnprintf() from that file, though with some
 * difficulties.
 *
 * For such systems we need a way to not "use up" the va_list
 * by initializing it and then passing it to some function
 * (that's actually the rationale for using a macro here
 * instead of a function!), so we must do the memory allo-
 * cation here (if necessary repeatedly) and only call
 * fli_vsnprintf().
 *
 * So the whole existence of this macro is due to backward
 * compatibility with old (pre C99) compilers that may have
 * a uncommon way of defining a va_list. Messy, isnt' it?
 *
 * BTW, all locally used variables have names starting with 'l1I_'
 * since this is a prefix no sane person would ever use - we try to
 * avoid compiler warnings about local variables shadowing already
 * defined ones.
 */

#if defined ( HAVE_VASPRINTF )

#define EXPAND_FORMAT_STRING( buf, fmt )                                    \
do {                                                                        \
    if ( ! fmt || ! *fmt )                                                  \
        buf = NULL;                                                         \
    else if ( ! strchr( fmt, '%' ) )                                        \
    {                                                                       \
        if ( ( buf = fl_malloc( strlen( fmt ) + 1 ) ) )                     \
            strcpy( buf, fmt );                                             \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        va_list l1I_ap;                                                     \
                                                                            \
        va_start( l1I_ap, fmt );                                            \
        if ( ! vasprintf( &buf, fmt, l1I_ap ) )                             \
            buf = NULL;                                                     \
        va_end( l1I_ap );                                                   \
    }                                                                       \
                                                                            \
    if ( ! buf && ( buf = fl_malloc( 1 ) ) )                                \
            *buf = '\0';                                                    \
} while ( 0 )

#else

#define EXPAND_FORMAT_STRING( buf, fmt )                                    \
do {                                                                        \
    if ( ! fmt || ! *fmt )                                                  \
        buf = NULL;                                                         \
    else if ( ! strchr( fmt, '%' ) )                                        \
    {                                                                       \
        if ( ( buf = fl_malloc( strlen( fmt ) + 1 ) ) )                     \
            strcpy( buf, fmt );                                             \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        int l1I_min_needed = strlen( fmt ) + 1;                             \
        int l1I_len = l1I_min_needed;                                       \
        char *l1I_p;                                                        \
                                                                            \
        for ( l1I_p = strchr( fmt, '%' ); l1I_p;                            \
              l1I_p = strchr( ++l1I_p, '%' ) )                              \
            l1I_len += 16;                                                  \
                                                                            \
        if ( ( buf = fl_malloc( l1I_len ) ) )                               \
        {                                                                   \
            while ( 1 )                                                     \
            {                                                               \
                va_list l1I_ap;                                             \
                int l1I_written;                                            \
                                                                            \
                va_start( l1I_ap, fmt );                                    \
                l1I_written = fli_vsnprintf( buf, l1I_len, fmt, l1I_ap );   \
                va_end( l1I_ap );                                           \
                                                                            \
                /* Take care: older libc versions returned a negative       \
                   value if the buffer wasn't large enough space while      \
                   newer ones follow C99 and return the length of the       \
                   string needed (without the trailing '\0') */             \
                                                                            \
                if ( l1I_written > -1 && l1I_len > l1I_written )            \
                {                                                           \
                    if ( l1I_len != l1I_written + 1 )                       \
                    {                                                       \
                        l1I_p = buf;                                        \
                        if ( ! ( buf = fl_realloc( l1I_p,                   \
                                                   l1I_written + 1 ) ) )    \
                            buf = l1I_p;                                    \
                    }                                                       \
                    break;                                                  \
                }                                                           \
                                                                            \
                l1I_len = l1I_written < 0 ?                                 \
                          ( 2 * l1I_len ) : ( l1I_written + 16 );           \
                l1I_p = buf;                                                \
                if ( ! ( buf = fl_realloc( l1I_p, l1I_len ) ) )             \
                {                                                           \
                    fl_free( l1I_p );                                       \
                    break;                                                  \
                }                                                           \
            }                                                               \
        }                                                                   \
    }                                                                       \
                                                                            \
    if ( ! buf && ( buf = fl_malloc( 1 ) ) )                                \
            *buf = '\0';                                                    \
} while ( 0 )

#endif


#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
