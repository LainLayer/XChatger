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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "fd_main.h"
#include "fd_iconinfo.h"


/***************************************
 ***************************************/

static int
is_blank( char c )
{
    return c == ' ' || c == '\t';
}


/***************************************
 ***************************************/

IconInfo *
get_iconinfo( FL_OBJECT * obj )
{
	IconInfo *info = obj->c_vdata;

    if (    obj->objclass != FL_PIXMAPBUTTON
         && obj->objclass != FL_BITMAPBUTTON
         && obj->objclass != FL_PIXMAP
         && obj->objclass != FL_BITMAP )
		return NULL;

	if ( ! info )
	{
		info = obj->c_vdata = fl_malloc( sizeof *info );

        info->use_data        = 0;
		info->show_focus      = 1;
		info->dx              = 0;
        info->dy              = 0;
		info->align           = FL_ALIGN_CENTER;
		info->fullpath        = 1;
		*info->filename       = '\0';
		*info->focus_filename = '\0';
		*info->data           = '\0';
		*info->focus_data     = '\0';
		*info->width          = '\0';
		*info->height         = '\0';
	}

	return info;
}


/***************************************
 ***************************************/

void
copy_iconinfo( FL_OBJECT * target,
			   FL_OBJECT * src )
{
	IconInfo *si = get_iconinfo( src ),
		     *ti;

	fli_safe_free( target->c_vdata );

	if ( ! si )
		return;

	ti = get_iconinfo( target );
	*ti = *si;
}
		

/***************************************
 ***************************************/

void
free_iconinfo( FL_OBJECT * obj )
{
	fli_safe_free( obj->c_vdata );
}


/***************************************
 * Function tries to read a line (of arbirary length) from a file
 * On failure (either due to read error or missing memory) NULL is
 * returned, otherwise a pointer to an allocated buffer that must
 * be freed by the caller.
 ***************************************/

#define STRING_TRY_LENGTH 128

static char *
read_line( FILE * fp )
{
    char *line = NULL;
    char *old_line = NULL;
    size_t len = STRING_TRY_LENGTH;
    size_t old_len = 0;

    while ( 1 )
    {
        if ( ( line = fl_realloc( line, len ) ) == NULL )
        {
            fli_safe_free( old_line );
            return NULL;
        }

        if ( ! fgets( line + old_len, len - old_len, fp ) )
        {
            if ( ferror( fp ) )
            {
                fl_free( line );
                return NULL;
            }

            if ( old_len == 0 )
            {
                fl_free( line );
                return NULL;
            }

            break;
        }

        if ( strchr( line + old_len, '\n' ) )
            break;

        old_line = line;
        old_len = len - 1;
        len *= 2;
    }

    old_line = line;
    if ( ( line = fl_realloc( line, strlen( line ) + 1 ) ) == NULL )
        return old_line;
    return line;
}


/***************************************
 ***************************************/

static const char *
check_for_define( const char * line )
{
    while ( *line && is_blank( *line ) )
        line++;

    if ( ! *line || *line != '#' )
        return NULL;

    while ( *++line && is_blank( *line ) )
        /* empty */ ;

    if ( ! *line )
        return NULL;

    if ( strncmp( line, "define", 6 ) )
        return NULL;

    line += 6;

    while ( *line && is_blank( *line ) )
        line++;

    if ( ! ( isupper( *line ) || islower( *line ) || *line == '_' ) )
        return NULL;

    return line;
}


/***************************************
 ***************************************/

static char *
check_for_end( const char * line,
               const char * what )
{
    static char name[ MAX_VAR_LEN ];
    const char *start;
    size_t len;

    if ( ( ! ( start = check_for_define( line ) ) ) )
        return NULL;

    line = start;

    while ( *line
            && (    isupper( *line )
                 || islower( *line )
                 || isdigit( *line )
                 || *line == '_' ) )
        line++;

    if ( ! is_blank( *line ) )
        return NULL;

    len = line - start;
    if ( len > MAX_VAR_LEN - 1 || len <= strlen( what ) )
        return NULL;

    strncpy( name, start, len );
    name[ len ] = '\0';

    if ( strcmp( name + len - strlen( what ), what ) )
        return NULL;

    return name;
}          


/***************************************
 ***************************************/

static char *
check_for_data( const char * line,
                const char * what )
{
    static char name[ MAX_VAR_LEN ];
    const char *start;
    size_t len;

    /* Skip leading blanks */

    while ( *line && is_blank( *line ) )
        line++;

    /* First word must be 'static', followed by a blank */

    if ( ! *line || strncmp( line, "static", 6 ) )
        return NULL;

    line += 6;

    if ( ! *line || ! is_blank( *line ) )
        return NULL;

    while ( *++line && is_blank( *line ) )
        /* empty */ ;

    /* Skip optional 'const', followed by a blank */

    if ( ! strncmp( line, "const", 5 ) )
    {
        line += 5;

        if ( ! *line || ! is_blank( *line ) )
            return NULL;

        while ( *++line && is_blank( *line ) )
            /* empty */ ;
    }

    /* Skip optional 'unsigned', followed by a blank */

    if ( ! strncmp( line, "unsigned", 8 ) )
    {
        line += 8;

        if ( ! *line || ! is_blank( *line ) )
            return NULL;

        while ( *++line && is_blank( *line ) )
            /* empty */ ;
    }

    /* Now 'char', followed by at least one blank must follow */

    if ( ! *line || strncmp( line, "char", 4 ) )
        return NULL;

    line += 4;

    if ( ! *line || ! ( is_blank( *line ) || *line == '*' ) )
        return NULL;

    while ( *++line && is_blank( *line ) )
        /* empty */ ;

    /* Skip optional 'const', followed by a blank */

    if ( ! strncmp( line, "const", 5 ) )
    {
        line += 5;

        while ( *line && is_blank( *line ) )
            line++;
    }

    /* When reading an xpm file a '*' must come next */

    if ( ! strcmp( what, "_pixels" ) )
    {
        if ( ! *line || *line != '*' )
            return NULL;

        while ( ++line && is_blank( *line ) )
            /* empty */ ;
    }    

    /* Now we should have arrived at the variable name */

    start = line;

    while (    *line
            && (    isupper( *line )
                 || islower( *line )
                 || isdigit( *line )
                 || *line == '_' ) )
        line++;

    /* Check that the variable name is ok */

    len = line - start;
    if ( len > MAX_VAR_LEN - 1 || ( ! strcmp( what, "_bits" ) && len < 6 ) )
        return NULL;

    strncpy( name, start, len );
    name[ len ] = '\0';

    /* A blank or a '[' must immediately followe the variable name */

    if ( ! *line || ! ( is_blank( *line ) || *line == '[' ) )
        return NULL;

    /* Make sure that the next non-blank char is a '[' */

    while ( *line && is_blank( *line ) )
        line++;

    return *line == '[' ? name : NULL;
}


/***************************************
 * Tries to guess the names of the variables used for width, height
 * and data in a xbm file from the file name.
 ***************************************/

void
get_xbm_stuff( IconInfo * info,
               FILE     * fp )
{
    char *line;
    char *res;
    int found = 0;

    *info->width = *info->height = *info->data = '\0';

    while ( found < 3 && ( line = read_line( fp ) ) )
    {
        if ( ( res = check_for_end( line, "_width" ) ) )
        {
            strcpy( info->width, res );
            found++;
        }
        else if ( ( res = check_for_end( line, "_height" ) ) )
        {
            strcpy( info->height, res );
            found++;
        }
        else if ( ( res = check_for_data( line, "_bits" ) ) )
        {
            strcpy( info->data, res );
            found++;
        }

        fl_free( line );
    }

    if ( found < 3 )
    {
        fprintf( stderr, "Failed to parse xbm file\n" );
        *info->width = *info->height = *info->data = '\0';
    }
}


/***************************************
 * Read in an (already opened) xpm file and return via 'in'
 * the name of the variable for the data.
 ***************************************/

void
get_xpm_stuff( char * in,
               FILE * fp )
{
    char *line;
    char *res;

    *in = '\0';

    while ( ( line = read_line( fp ) ) )
    {
        if ( ( res = check_for_data( line, "_pixels" ) ) )
        {
            strcpy( in, res );
            fl_free( line );
            return;
        }

        fl_free( line );
    }
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
