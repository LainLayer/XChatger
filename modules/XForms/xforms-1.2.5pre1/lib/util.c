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


/**
 * \file util.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * X independent utilities
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>


/***************************************
 * Returns if two objects are the same - not of any use normally,
 * but seems to help with the Python port (so don't use it for
 * anything else, it might be gone if it should not needed for
 * the Python port anymore) 
 ***************************************/

int
fl_is_same_object( FL_OBJECT * obj1,
                   FL_OBJECT * obj2 )
{
    return obj1 == obj2;
}


/***************************************
 * Sets the form window
 ***************************************/

void
fli_set_form_window( FL_FORM * form )
{
    if ( form && form->window != None )
        flx->win = form->window;
}


/***************************************
 * Function is kept only for backward compatibility
 ***************************************/

void
fl_show_errors( int y   FL_UNUSED_ARG )
{
}


/***************************************
 * Convenience replacement for XFlush()
 ***************************************/

void
fl_XFlush( void )
{
    XFlush( fl_display );
}


/***************************************
 * For debugging
 ***************************************/

#define VN( v )  { v, #v }

static FLI_VN_PAIR flevent[ ] =
{
    VN( FL_ENTER     ),
    VN( FL_LEAVE     ),
    VN( FL_PUSH      ),
    VN( FL_RELEASE   ),
    VN( FL_STEP      ),
    VN( FL_SHORTCUT  ),
    VN( FL_UPDATE    ),
    VN( FL_MOTION    ),
    VN( FL_KEYPRESS  ),
    VN( FL_DRAW      ),
    VN( FL_FOCUS     ),
    VN( FL_UNFOCUS   ),
    VN( FL_FREEMEM   ),
    VN( FL_DRAWLABEL ),
    VN( FL_DBLCLICK  ),
    VN( FL_OTHER     ),
    VN( FL_ATTRIB    ),
    { -1, NULL }
};


/***************************************
 ***************************************/

const char *
fli_event_name( int ev )
{
    return fli_get_vn_name( flevent, ev );
}


static FLI_VN_PAIR flclass[ ] =
{
    VN( FL_BUTTON        ),
    VN( FL_LIGHTBUTTON   ),
    VN( FL_ROUNDBUTTON   ),
    VN( FL_ROUND3DBUTTON ),
    VN( FL_CHECKBUTTON   ),
    VN( FL_BITMAPBUTTON  ),
    VN( FL_PIXMAPBUTTON  ),
    VN( FL_BITMAP        ),
    VN( FL_PIXMAP        ),
    VN( FL_BOX           ),
    VN( FL_TEXT          ),
    VN( FL_MENU          ),
    VN( FL_CHART         ),
    VN( FL_CHOICE        ),
    VN( FL_COUNTER       ),
    VN( FL_SLIDER        ),
    VN( FL_VALSLIDER     ),
    VN( FL_INPUT         ),
    VN( FL_BROWSER       ),
    VN( FL_DIAL          ),
    VN( FL_TIMER         ),
    VN( FL_CLOCK         ),
    VN( FL_POSITIONER    ),
    VN( FL_FREE          ),
    VN( FL_XYPLOT        ),
    VN( FL_FRAME         ),
    VN( FL_LABELFRAME    ),
    VN( FL_CANVAS        ),
    VN( FL_GLCANVAS      ),
    VN( FL_TABFOLDER     ),
    VN( FL_SCROLLBAR     ),
    VN( FL_SCROLLBUTTON  ),
    VN( FL_MENUBAR       ),
    VN( FL_IMAGECANVAS   ),
    VN( FL_TEXTBOX       ),
    VN( FL_SPINNER       ),
    { -1, NULL }
};


/***************************************
 ***************************************/

const char *
fli_object_class_name( FL_OBJECT * ob )
{
    if ( ! ob )
        return "null";
    else if ( ob == FL_EVENT )
        return "FL_EVENT";

    return fli_get_vn_name( flclass, ob->objclass );
}


/***************************************
 * Function tries to read a line (of arbirary length) from a file
 * On failure (either due to read error or missing memory) NULL is
 * returned, otherwise a pointer to an allocated buffer that must
 * be freed by the caller.
 ***************************************/

#define STRING_TRY_LENGTH 128

char *
fli_read_line( FILE *fp )
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
            M_err( "fli_read_line", "Running out of memory\n" );
            return NULL;
        }

        if ( ! fgets( line + old_len, len - old_len, fp ) )
        {
            if ( ferror( fp ) )
            {
                M_err( "fli_read_line", "Failed to read from file" );
                fl_free( line );
                return NULL;
            }

            if ( old_len == 0 )
            {
                fl_free( line );
                return NULL;
            }

            M_warn( "fli_read_line", "Missing newline at end of line" );
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


/*******************************************
 * Secure string copy: a maximum of (n-1) bytes will be copied, the 
 * destination string is always ends in a '\0'.
 * Returns: dest or NULL if src or dest are NULL or n is 0
 *******************************************/

char *
fli_sstrcpy( char       * dest,
             const char * src,
             size_t       n )
{
    size_t l = src ? strlen( src ) : 0;

    if ( ! src || ! dest || n == 0 )
        return NULL;

    if ( l < n )
        memcpy( dest, src, l + 1 );
    else
    {
        memcpy( dest, src, n - 1 );
        dest[ n - 1 ] = '\0';
    }

    return dest;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
