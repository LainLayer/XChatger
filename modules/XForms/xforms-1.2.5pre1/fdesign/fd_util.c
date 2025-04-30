/*
 * This file is part of XForms.
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


/**
 * \file fd_util.c
 *
 * Eliminate the emission of duplicate info. This is necessary as
 * some #include define data (pixmap for example).
 *
 * We should eventually move the functionality of already_emited in
 * fd_printC.c into this function so callback is also checked. This
 * probably means we need make struct CodeInfo more efficient.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "fd_main.h"

static char ** dup_info_cache = NULL;
static size_t n_dup_info = 0;


/***************************************
 ***************************************/

unsigned int
check_resize( unsigned int what,
              int          nw,
              int          se )
{
    if (    what & FL_RESIZE_X
         && (    nw == FL_NorthWest
              || nw == FL_West
              || nw == FL_SouthWest )
         && (    se == FL_NorthWest
              || se == FL_West
              || se == FL_SouthWest ) )
        what &= ~ FL_RESIZE_X;
    else if (    ! ( what & FL_RESIZE_X )
              && (    nw == FL_NorthWest
                   || nw == FL_West
                   || nw == FL_SouthWest )
              && (    se == FL_NorthEast
                   || se == FL_East
                   || se == FL_SouthEast ) )
        what |= ~ FL_RESIZE_X;

    if (    what & FL_RESIZE_Y
         && (    nw == FL_NorthWest
              || nw == FL_North
              || nw == FL_NorthEast )
         && (    se == FL_NorthWest
              || se == FL_North
              || se == FL_NorthEast ) )
        what &= ~ FL_RESIZE_Y;
    else if (    ! ( what & FL_RESIZE_Y )
              && (    nw == FL_NorthWest
                   || nw == FL_North
                   || nw == FL_NorthEast )
              && (    se == FL_SouthWest
                   || se == FL_South
                   || se == FL_SouthEast ) )
        what |= ~ FL_RESIZE_Y;

    return what;
}


/***************************************
 ***************************************/

void
reset_dupinfo_cache( void )
{
    size_t i;

    for ( i = 0; i < n_dup_info; i++ )
        fl_free( dup_info_cache[ i ] );

    fli_safe_free( dup_info_cache );
    n_dup_info = 0;
}


/***************************************
 ***************************************/

int
is_duplicate_info( const char * s )
{
    size_t i;

    for ( i = 0; i < n_dup_info; i++ )
        if ( ! strcmp( s, dup_info_cache[ i ] ) )
            return 1;

    if ( ! (    ( dup_info_cache =
                         fl_realloc( dup_info_cache,
                                     ++n_dup_info * sizeof dup_info_cache ) )
             && ( dup_info_cache[ n_dup_info - 1 ] = fl_strdup( s ) ) ) )
    {
        fprintf( stderr, "Running oit of memory\n" );
        exit( 1 );
    }

    return 0;
}


/***************************************
 * Returns a newly allocated string with the aboslute path
 * for the input path
 ***************************************/

char *
rel2abs( const char * rel_path )
{
    char * abs_path = NULL;
    char *res;

    if ( *rel_path == '/' )
        abs_path = fl_strdup( rel_path );
    else
    {
        long path_max = pathconf( ".", _PC_PATH_MAX );
        size_t size;

        if ( path_max == -1 )
            size = 1024;
        else
            size = path_max;

        while ( 1 )
        {
            abs_path = fl_realloc( abs_path, size + strlen( rel_path ) + 2 );
            if ( ! getcwd( abs_path, size ) )
                size += 1024;
            else
                break;
        }

        strcat( strcat( abs_path, "/" ), rel_path );
    }

    while ( ( res = strstr( abs_path, "/./" ) ) )
        memmove( res, res + 2, strlen( res ) - 1 );

    while ( ( res = strstr( abs_path, "/../" ) ) )
    {
		if ( res != abs_path )
		{
			char * dest = res - 1;

			while ( *dest != '/' )
				dest--;

			memmove( dest, res + 3, strlen( res ) - 2 );
		}
		else
			memmove( abs_path, abs_path + 3, strlen( abs_path ) - 2 );
    }

    return fl_realloc( abs_path, strlen( abs_path ) + 1 );
}


/***************************************
 * Returns if a string can be used as a valid C identifier
 ***************************************/

int
is_valid_c_name( const char * str )
{
    const char * sp;

    if ( fdopt.lax )
        return 1;

    if (    ! isascii( ( unsigned char ) *str )
         || ! ( isalpha( ( unsigned char ) *str ) || *str == '_' ) )
        return 0;

    for ( sp = str + 1; *sp; sp++ )
        if (    ! isascii( ( unsigned char ) *sp )
             || ! ( isalnum( ( unsigned char ) *sp ) || *sp == '_' ) )
            return 0;

    return 1;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
