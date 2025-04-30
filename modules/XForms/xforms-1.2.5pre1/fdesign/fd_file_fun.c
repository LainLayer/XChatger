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

#include "fd_main.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <float.h>
#include <ctype.h>
#include <stdarg.h>


static struct
{
    FILE   * fp;
    char   * fname;
    size_t   line_no;
    char   * line;
    char   * pos;
    int      merge;
} ff = { NULL, NULL, 0, NULL, NULL, 0 };



/***************************************
 * Returns a pointer to the first position in a string
 * that's not a white-space character
 ***************************************/

static char *
ff_skip_spaces( const char * cp )
{
    while ( *cp && isspace( ( unsigned char ) *cp ) )
        cp++;

    return ( char * ) cp;
}


/***************************************
 ***************************************/

char *
ff_get_filename_copy( void )
{
    if ( ! ff.fname || ! ff.fp )
        return NULL;

    return fl_strdup( ff.fname );
}


/***************************************
 ***************************************/

static int
ff_is_comment( void )
{
    ff.pos = ff_skip_spaces( ff.pos );

    return    ! *ff.pos
           || *ff.pos == ';'
           || *ff.pos == '#'
           || *ff.pos == '-'
           || *ff.pos == '=';
}


/***************************************
 ***************************************/

void
ff_close( void )
{
    if ( ff.fp )
    {
        fclose( ff.fp );
        ff.fp = NULL;
    }

    fli_safe_free( ff.fname );
    fli_safe_free( ff.line );

    ff.pos = NULL;
    ff.line_no = 0;
    ff.merge = 0;
}


/***************************************
 ***************************************/

int 
ff_err( const char * message )
{
    if ( message )
    {
        if ( ! fdopt.conv_only )
            fl_show_alert_f( 0, "Error:\f%s\n%s:%lu.%lu",
                             message, ff.fname, ( unsigned long ) ff.line_no,
                             ff.line ?
                             ( unsigned long ) ( ff.pos - ff.line ) : 0 );
        else
            M_err( "Error", "%s at %s:%lu.%lu",
               message, ff.fname, ( unsigned long ) ff.line_no,
                   ff.line ? ( unsigned long ) ( ff.pos - ff.line ) : 0 );
    }

    ff_close( );
    return FF_READ_FAILURE;
}


/***************************************
 ***************************************/

static int
ff_get_line( void )
{
    if ( ff.fp )
        do
        {
            fli_safe_free( ff.line );

            if ( ! ( ff.line = fli_read_line( ff.fp ) ) )
            {
                if ( feof( ff.fp ) )
                {
                    ff.line_no++;
                    return 0;
                }
                return ff_err( "Error while reading from file" );
            }

            ff.line_no++;
            ff.pos = ff.line;
        } while ( ff_is_comment( ) );

    return 0;
}


/***************************************
 ***************************************/

int
ff_get_fd_file( const char  * str,
                int           merge )
{
    ff_close( );

    ff.merge = merge;

    fl_use_fselector( LOAD_FSELECTOR );

    /* Get the filename if necessary */

    if ( ! str || ! *str )
    {
        str = fl_show_fselector( merge ? "Filename to merge forms from" :
                                 "Filename to load forms from",
                                 "", "*.fd", "" );

        if ( ! str || ! *str )
            return -1;
    }

    /* Append ".fd" if required. */

    ff.fname = append_fd_suffix( str );

    /* Open the file for reading */

    if ( ! ( ff.fp = fopen( ff.fname, "r" ) ) )
    {
        if ( ! fdopt.conv_only )
            fl_show_alert( "Can't open file for reading", ff.fname, "", 0 );
        else
            M_err( "ff_get_fd_file", "Can't open '%s' for reading", ff.fname );
        ff_close( );
        return -1;
    }

    if ( ff_get_line( ) < 0 )
    {
        if ( ! fdopt.conv_only )
            fl_show_alert( "Nothing to be read from", ff.fname, "", 0 );
        else
            M_err( "ff_get_fd_file", "Nothing to be read from '%s'",
                   ff.fname );
        ff_close( );
        return -1;
    }

    return 0;
}


/***************************************
 * Checks if an input text matches text read from the file
 * - with multiple white-spaces treated as a single space
 ***************************************/

static const char *
ff_match_text( const char *txt )
{
    char *src = ff.pos;

    txt = ff_skip_spaces( txt );

    while ( *src && *txt )
    {
        if (    *src != *txt
             && ! (    isspace( ( unsigned char ) *src )
                    && isspace( ( unsigned char ) *txt ) ) )
            return NULL;

        if ( isspace( ( unsigned char ) *src ) )
        {
            src = ff_skip_spaces( src );
            txt = ff_skip_spaces( txt );
        }
        else
        {
            src++;
            txt++;
        }
    }

    txt = ff_skip_spaces( txt );
    if ( *txt )
        return NULL;

    ff.pos = src;

    return txt;
}


/***************************************
 ***************************************/

static int
ff_match_long( long * p )
{
    long val;
    char *ep;

    val = strtol( ff.pos, &ep, 10 );

    if ( ep == ff.pos )
        return -1;

    if ( *ep != '\0' && ! isspace( ( unsigned char ) *ep ) )
        return -1;

    if ( ( val == LONG_MAX || val == LONG_MIN ) && errno == ERANGE )
        return -1;
        
    ff.pos = ep;

    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_ulong( unsigned long * p )
{
    unsigned long val;
    char *ep;

    if ( *ff.pos == '-' )
        return -1;

    val = strtoul( ff.pos, &ep, 10 );

    if (    ep == ff.pos
         || ( *ep != '\0' && ! isspace( ( unsigned char ) *ep ) )
         || ( val == ULONG_MAX && errno == ERANGE ) )
        return -1;

    ff.pos = ep;

    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_int( int * p )
{
    long val;
    char *old_pos = ff.pos;

    if ( ff_match_long( &val ) < 0 )
        return -1;

    if ( ( val > INT_MAX || val < INT_MIN ) )
    {
        ff.pos = old_pos;
        return -1;
    }
        
    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_uint( unsigned int * p )
{
    unsigned long val;
    char *old_pos = ff.pos;

    if ( ff_match_ulong( &val ) < 0 )
        return -1;

    if ( val > UINT_MAX )
    {
        ff.pos = old_pos;
        return -1;
    }

    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_double( double * p )
{
    double val;
    char *ep;

    val = strtod( ff.pos, &ep );

    if (    ep == ff.pos
         || ( *ep != '\0' && ! isspace( ( unsigned char ) *ep ) )
         || ( ( val == HUGE_VAL || val == - HUGE_VAL ) && errno == ERANGE ) )
        return -1;
        
    ff.pos = ep;

    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_float( float * p )
{
    double val;
    char *old_pos = ff.pos;

    if ( ff_match_double( &val ) < 0 || val < - FLT_MAX || val > FLT_MAX)
    {
        ff.pos = old_pos;
        return -1;
    }

    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_coord( FL_Coord * p,
                int        need_positive )
{
    int val;
    char *old_pos = ff.pos;

    if ( ff_match_int( &val ) < 0 || ( need_positive && val < 0 ) )
    {
        ff.pos = old_pos;
        return -1;
    }

    *p = val;
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_string( char ** p )
{
    /* Backtrack to start of line or last ':' */

    while ( ff.pos > ff.line && isspace( ( unsigned char ) *--ff.pos ) )
        /* empty */ ;

    /* If we're at a ':' skip the next space if if exists */

    if (    ff.pos > ff.line
         && *ff.pos == ':'
         && isspace( ( unsigned char ) *++ff.pos ) )
        ff.pos++;

    *p = ff.pos + strlen( ff.pos ) - 1;
    if ( **p == '\n' )
        **p = '\0';

    *p = fl_strdup( ff.pos );

    while ( *ff.pos )
        ff.pos++;

    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_trimmed_string( char ** p )
{
    char *ep = ff.pos + strlen( ff.pos ) - 1,
         *fp = ep + 1;
    char old_c;

    if ( ! *ff.pos )
    {
        *p = fl_strdup( ff.pos );
        return 0;
    }

    *p = NULL;

    while ( ep > ff.pos && isspace( ( unsigned char ) *ep ) )
        ep--;

    old_c = *ep;
    *++ep = '\0';

    *p = fl_strdup( ff.pos );
    *ep = old_c;
    ff.pos = fp;

    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_spaceless_string( char ** p )
{
    char *ep = ff.pos;

    while ( *ep && ! isspace( ( unsigned char ) *ep ) )
        ep++;

    if ( ep == ff.pos )
        *p = fl_strdup( "" );
    else if ( ( *p = fl_malloc( ep - ff.pos + 2 ) ) )
    {
        fli_sstrcpy( *p, ff.pos, ep - ff.pos + 1 );
        ff.pos = ep;
    }

    return p ? 0 : -1;
}


/***************************************
 ***************************************/

static int
ff_match_var( char ** p )
{
    char *ep = ff.pos;
    char old_c;

    if ( ! *ep )
    {
        *p = fl_strdup( ff.pos );
        return -1;
    }

    *p = NULL;

    if (    ! isascii( ( unsigned char ) *ep )
         || ! ( isalpha( ( unsigned char ) *ep ) || *ep == '_' ) )
    {
        *p = fl_strdup( "" );
        return -1;
    }

    while (    *++ep 
            && isascii( ( unsigned char ) *ep )
            && ( isalnum( ( unsigned char ) *ep ) || *ep == '_' ) )
        /* empty */ ;

    if ( *ep && ! isspace( ( unsigned char ) *ep ) )
    {
        *p = fl_strdup( "" );
        return -1;
    }

    /* Currently variable, function etc. names can't be longer... */

    if ( ep - ff.pos >= MAX_VAR_LEN )
    {
        *p = fl_strdup( "" );
        return -1;
    }

    old_c = *ep;
    *ep = '\0';

    *p = fl_strdup( ff.pos );

    *ep = old_c;
    ff.pos = ep + 1;

    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_objclass( int * p )
{
    char *class_name;
    int class;
    char * old_pos = ff.pos;
    

    if ( ff_match_spaceless_string( &class_name ) < 0 )
        return -1;

    if ( ! *class_name || ( class = class_val( class_name ) ) == -1 )
    {
        ff.pos = old_pos;
        fl_free( class_name );
        return -1;
    }

    *p = class;
    fl_free( class_name );
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_boxtype( int * p )
{
    char *boxtype_name;
    char *old_pos = ff.pos;
    int boxtype;

    if ( ff_match_spaceless_string( &boxtype_name ) < 0 )
        return -1;

    if ( ! *boxtype_name || ( boxtype = boxtype_val( boxtype_name ) ) == -1 )
    {
        ff.pos = old_pos;
        fl_free( boxtype_name );
        return -1;
    }

    *p = boxtype;
    fl_free( boxtype_name );
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_color( FL_COLOR * p )
{
    char *color_name;
    char *old_pos = ff.pos;
    FL_COLOR color;

    if ( ff_match_spaceless_string( &color_name ) < 0 )
        return -1;

    if (    ! *color_name
         || (    ( color = fli_query_namedcolor( color_name ) ) > FL_MAX_COLORS
              && color != FL_NoColor ) )
    {
        ff.pos = old_pos;
        fl_free( color_name );
        return -1;
    }

    *p = color;
    if ( *p == 0x8fffffff )
        *p = FL_NoColor;

    fl_free( color_name );
    return 0;
}


/***************************************
 * align may consist of two values, separated by a '|' or '+'
 ***************************************/

static int
ff_match_align( int * p )
{
    char *align_name;
    char *old_pos = ff.pos;
    char *sp = strchr( ff.pos, '|' );
    int align;

    if ( ! sp )
        sp = strchr( ff.pos, '+' );

    if (    ! sp
         || ( sp > ff.pos
              && ! isspace( ( unsigned char ) sp[ -1 ] )
              && ! isspace( ( unsigned char ) sp[ 1 ] ) ) )
    {
        if ( ff_match_spaceless_string( &align_name ) < 0 )
            return -1;
    }
    else
    {
        char *a1,
             *a2,
             o = *sp;

        *sp = '\0';
        if ( ff_match_spaceless_string( &a1 ) < 0 || ! *a1 )
        {
            fl_free( a1 );
            ff.pos = old_pos;
            *sp = o;
            return -1;
        }

        *sp = o;
        ff.pos = sp + 1;
        ff.pos = ff_skip_spaces( ff.pos );

        if ( ff_match_spaceless_string( &a2 ) < 0 || ! *a2 )
        {
            fl_free( a1 );
            fl_free( a2 );
            ff.pos = old_pos;
            return -1;
        }

        align_name = fl_malloc( strlen( a1 ) + strlen( a2 ) + 2 );
        if ( align_name )
            sprintf( align_name, "%s|%s", a1, a2 );

        fl_free( a1 );
        fl_free( a2 );
    }

    if (    ! align_name
         || ! *align_name
         || ( align = align_val( align_name ) ) == -1 )
    {
        ff.pos = old_pos;
        fl_free( align_name );
        return -1;
    }

    *p =  align;
    fl_free( align_name );
    return 0;
}


/***************************************
 * lstyle may consist of two values, separated by '|' or '+'
 ***************************************/

static int
ff_match_lstyle( int * p )
{
    char *lstyle_name = NULL;
    int lstyle;
    char *old_pos = ff.pos;
    char *sp = strchr( ff.pos, '|' );

    if ( ! sp )
        sp = strchr( ff.pos, '+' );

    if (    ! sp
         || ( sp > ff.pos
              && ! isspace( ( unsigned char ) sp[ -1 ] )
              && ! isspace( ( unsigned char ) sp[ 1 ] ) ) )
    {
        if ( ff_match_spaceless_string( &lstyle_name ) < 0 )
            return -1;
    }
    else
    {
        char *l1,
             *l2,
             *old_pos = ff.pos,
             o = *sp;

        *sp = '\0';
        if ( ff_match_spaceless_string( &l1 ) < 0 )
        {
            fl_free( l1 );
            *sp = o;
            return -1;
        }

        *sp = o;
        ff.pos = sp + 1;
        ff.pos = ff_skip_spaces( ff.pos );

        if ( ff_match_spaceless_string( &l2 ) < 0 || ! *l2 )
        {
            ff.pos = old_pos;
            fl_free( l1 );
            fl_free( l2 );
            return -1;
        }

        lstyle_name = fl_malloc( strlen( l1 ) + strlen( l2 ) + 2 );
        if ( lstyle_name )
            sprintf( lstyle_name, "%s|%s", l1, l2 );

        fl_free( l1 );
        fl_free( l2 );
    }

    if (    ! lstyle_name
         || ! *lstyle_name
         || ( lstyle = style_val( lstyle_name ) ) == -1 )
    {
        ff.pos = old_pos;
        fl_free( lstyle_name );
        return -1;
    }

    *p = lstyle;
    fl_free( lstyle_name );
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_lsize( int * p )
{
    char *lsize_name;
    char *old_pos = ff.pos;
    int lsize;

    if ( ff_match_spaceless_string( &lsize_name ) < 0 )
        return -1;

    if ( ! *lsize_name || ( lsize = lsize_val( lsize_name ) ) == -1 )
    {
        fl_free( lsize_name );
        ff.pos = old_pos;
        return -1;
    }

    *p = lsize;
    fl_free( lsize_name );
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_resize( int * p )
{
    char *resize_name;
    char *old_pos = ff.pos;
    int resize;

    if ( ff_match_spaceless_string( &resize_name ) < 0 )
        return -1;

    if ( ! *resize_name || ( resize = resize_val( resize_name ) ) == -1 )
    {
        fl_free( resize_name );
        ff.pos = old_pos;
        return -1;
    }

    *p = resize;
    fl_free( resize_name );
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_gravity( int * p )
{
    char *gravity_name;
    char *old_pos = ff.pos;
    int gravity;

    if ( ff_match_spaceless_string( &gravity_name ) < 0 )
        return -1;

    if ( ! *gravity_name || ( gravity = gravity_val( gravity_name ) ) == -1 )
    {
        ff.pos = old_pos;
        fl_free( gravity_name );
        return -1;
    }

    *p = gravity;
    fl_free( gravity_name );
    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_unit( int * p )
{
    char *unit_name;
    char *old_pos = ff.pos;
    int unit;

    if ( ff_match_spaceless_string( &unit_name ) < 0 )
        return -1;

    if ( ! *unit_name || ( unit = unit_val( unit_name ) ) == -1 )
    {
        ff.pos = old_pos;
        fl_free( unit_name );
        return -1;
    }

    *p = unit;
    fl_free( unit_name );
    return 0;
}

/***************************************
 ***************************************/

static int
ff_match_key( char ** p )
{
    char *ep = ff.pos;
    char *np;
    char old_c;

    *p = NULL;

    while ( *ep && *ep != ':' )
        ep++;

    if ( ! *ep )
        return -1;

    np = ep-- + 1;

    while ( ep > ff.pos && isspace( ( int ) *ep ) )
        ep--;

    if ( ep == ff.pos )
        return -1;

    old_c = *++ep;
    *ep = '\0';

    *p = fl_strdup( ff.pos );

    *ep = old_c;
    ff.pos = np;

    return 0;
}


/***************************************
 ***************************************/

static int
ff_match_type( char ** p )
{
    return ff_match_var( p );
}


/***************************************
 * Function for reading data from .fd files in a fscanf()-like way.
 *
 * The format string may contain the following:
 *  a) text which must match the text in the string at that position
 *  b) %l   match long  (requires long *)
 *  b) %d   match int (requires int *)
 *  c) %u   match unsigned int (requires int *)
 *  d) %D   match FL_Coord (requires FL_Coord *)
 *  e) %U   match FL_Coord with positive value (requires FL_Coord *)
 *  f) %s   match string (trimmed of spaces at start and end) (requires char **)
 *  g) %S   match string (with all spaces) (requires char **)
 *  h) %h   match string, stopping at the first space (requires char **)
 *  i) %f   match single-precision floating point value (requires float *)
 *  j) %D   match double floating point value (requires double *)
 *  k) %o   match object class (requires int *)
 *  l) %t   match type (requires char **)
 *  m) %b   match boxtype (requires int *)
 *  n) %c   match color (requires FL_COLOR *)
 *  o) %a   match align (requires int *)
 *  p) %p   match lstyle (requires int *)
 *  q) %q   match lsize (requires int *)
 *  r) %r   match resize (requires int *)
 *  s) %g   match gravity (requires int *)
 *  t) %x   match unit (requires int *)
 *  u) %v   match C variable  (requires char **)
 *  v) %k   match a key (word(s) with a final colon) (requires char **)
 *
 * In case a string gets returned a copy must be made before the next
 * call of this function.
 * The function returns the number of items matched or a negative
 * value on failure (in that case an error message is output).
 ***************************************/

int
ff_read( const char * format,
         ... )
{
    va_list ap;
    char *fmt;
    const char *fp;
    int cnt = 0;
    char last = '\0';

    if ( ! ff.line )
        return -1;

    format = ff_skip_spaces( format );

    if ( ! format || ! *format )
    {
        M_err( "ff_read", "Invalid argument(s)" );
        return FF_READ_FAILURE;
    }

    fp = fmt = fl_strdup( format );

    va_start( ap, format );

    while ( *fp )
    {
        if ( *fp != '%' )
        {
            if ( ! ( fp = ff_match_text( fp ) ) )
            {
                va_end( ap );
                return FF_READ_FAILURE;
            }

            last = '\0';
        }
        else
        {
            int r;

            switch ( *++fp )
            {
                case 'l' :                    /* long int */
                    r = ff_match_long( va_arg( ap, long * ) );
                    break;

                case 'd' :                    /* int */
                    r = ff_match_int( va_arg( ap, int * ) );
                    break;

                case 'u' :                    /* unsigned int */
                    r = ff_match_uint( va_arg( ap, unsigned int * ) );
                    break;

                case 'D' :                    /* FL_Coord ('U' for positive) */
                case 'U' :
                    r = ff_match_coord( va_arg( ap, FL_Coord * ), *fp == 'U' );
                    break;

                case 's' :                    /* trimmed string */
                    r = ff_match_trimmed_string( va_arg( ap, char ** ) );
                    break;

                case 'S' :                    /* string (with spaces) */
                    r = ff_match_string( va_arg( ap, char ** ) );
                    break;

                case 'h' :               /* string (without embedded spaces) */
                    r = ff_match_spaceless_string( va_arg( ap, char ** ) );
                    break;

                case 'f' :                    /* float */
                    r = ff_match_float( va_arg( ap, float * ) );
                    break;

                case 'F' :                    /* double */
                    r = ff_match_double( va_arg( ap, double * ) );
                    break;

                case 'o' :                    /* object class */
                    r = ff_match_objclass( va_arg( ap, int * ) );
                    break;

                case 't' :                    /* object type */
                    r = ff_match_type( va_arg( ap, char ** ) );
                    break;

                case 'b' :                    /* box type */
                    r = ff_match_boxtype( va_arg( ap, int * ) );
                    break;

                case 'c' :                    /* color */
                    r = ff_match_color( va_arg( ap, FL_COLOR * ) );
                    break;

                case 'a' :                    /* alignment value */
                    r = ff_match_align( va_arg( ap, int * ) );
                    break;

                case 'p' :                    /* lstyle value */
                    r = ff_match_lstyle( va_arg( ap, int * ) );
                    break;

                case 'q' :                    /* lsize value */
                    r = ff_match_lsize( va_arg( ap, int * ) );
                    break;

                case 'r' :                    /* resize value */
                    r = ff_match_resize( va_arg( ap, int * ) );
                    break;

                case 'g' :                    /* gravity value */
                    r = ff_match_gravity( va_arg( ap, int * ) );
                    break;

                case 'x' :                    /* unit value */
                    r = ff_match_unit( va_arg( ap, int * ) );
                    break;

                case 'v' :                    /* C variable name */
                    r = ff_match_var( va_arg( ap, char ** ) );
                    break;

                case 'k' :                    /* key with trailing colon */
                    r = ff_match_key( va_arg( ap, char ** ) );
                    break;

                default :                     /* error, wrong format */
                    va_end( ap );
                    fl_free( fmt );
                    M_err( "ff_read", "Invalid argument(s)" );
                    return FF_READ_FAILURE;
            }

            last = *fp;

            if ( r < 0 )
                break;

            cnt++;
            fp++;
        }

        ff.pos = ff_skip_spaces( ff.pos );
        fp = ff_skip_spaces( fp );
    }

    va_end( ap );
    fl_free( fmt );

    /* If we're at the end of the line read in the next - except when the
       last request was for a key, in that case the next one will be for
       a value and it's allowed that no value exists even when there's a
       key... */

    if ( last != 'k' && ! *ff.pos )
        ff_get_line( );

    return cnt;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
