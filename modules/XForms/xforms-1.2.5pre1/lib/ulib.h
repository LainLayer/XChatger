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
 * \file ulib.h
 *
 * Macros and Prototypes for the utilities routines
 */

#ifndef TC_ULIB_H
#define TC_ULIB_H

#include <stdio.h>      /* for FILE */
#include <errno.h>


#ifndef FL_EXPORT
#  if ! defined FL_WIN32 || ! defined SHARED_LIB
#      define FL_EXPORT
#  else
#      ifdef MAKING_FORMS
#          define FL_EXPORT __declspec( dllexport ) extern
#     else
#          define FL_EXPORT __declspec( dllimport ) extern
#     endif                           /* MAKING_FORMS */
#  endif                          /* FL_WIN32 */
#endif     /* !def FL_EXPORT */


/***************** Portable IO operations *******************{**/

int fli_readint( FILE * );
int fli_readpint( FILE * );
int fli_readhexint( FILE * );
int fli_fget4MSBF( FILE * );
int fli_fput4MSBF( int,
                         FILE * );
int fli_fget2LSBF( FILE * );
int fli_fput2LSBF( int,
                   FILE * );
int fli_fget2MSBF( FILE * );
int fli_fput2MSBF( int,
                   FILE * );
int fli_fget4LSBF( FILE *);
int fli_fput4LSBF( int,
                   FILE * );


/********** End of  Portable IO *******************}**/

char * fli_de_space( char * );
char * fli_space_de( char * );
char * fli_de_space_de( char * );
char * fli_nuke_all_non_alnum( char * );


/*********************************************************************
 * Basic error handling routines
 ********************************************************************/

/* Message levels (verbosity). Error generating routine should
 * have a (positive) control parameter specifying how loud
 * to bark (i.e., amount of messages generated) */

# define ML_ERR     -1
# define ML_WARN     0
# define ML_INFO1    1
# define ML_INFO2    2
# define ML_DEBUG    3
# define ML_TRACE    4

FL_ERROR_FUNC fli_error_setup( int,
                               const char *,
                               int );

extern FL_ERROR_FUNC efp_;
extern FL_ERROR_FUNC user_error_function_;


/* Define the actual names that will be used */

# define M_err   \
    ( efp_ = fli_error_setup( ML_ERR,   __FILE__, __LINE__ ) ), efp_

# define M_warn   \
    ( efp_ = fli_error_setup( ML_WARN,  __FILE__, __LINE__ ) ), efp_

# define M_info   \
    ( efp_ = fli_error_setup( ML_INFO1, __FILE__, __LINE__ ) ), efp_

# define M_info2  \
    ( efp_ = fli_error_setup( ML_INFO2, __FILE__, __LINE__ ) ), efp_

# define M_debug  \
    ( efp_ = fli_error_setup( ML_DEBUG, __FILE__, __LINE__ ) ), efp_

# define M_trace  \
    ( efp_ = fli_error_setup( ML_TRACE, __FILE__, __LINE__ ) ), efp_


/****** Misc. control routines **********/

void fli_set_msg_threshold( int );

const char *fli_get_syserror_msg( void );


#endif /* TC_ULIB_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
