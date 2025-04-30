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
 * \file flsnprintf.h
 */

#ifndef FL_SNPRINTF_H
#define FL_SNPRINTF_H

#include <stdio.h>

#ifdef HAVE_SNPRINTF

#ifndef HAVE_DECL_SNPRINTF
int snprintf( char *,
              size_t,
              const char *,
              ...);
#endif

#ifndef HAVE_DECL_VSNPRINTF
int vsnprintf( char *,
               size_t,
               const char *,
               va_list);
#endif

#define fli_snprintf  snprintf
#define fli_vsnprintf vsnprintf

#else

int fli_portable_snprintf( char *,
                           size_t,
                           const char *,
                                     ... );

int fli_portable_vsnprintf( char *,
                            size_t,
                            const char *,
                            va_list );

#define fli_snprintf  fli_portable_snprintf
#define fli_vsnprintf fli_portable_vsnprintf

#endif /* HAVE_SNPRINTF */

#endif /* NOT FL_SNPRINTF_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
