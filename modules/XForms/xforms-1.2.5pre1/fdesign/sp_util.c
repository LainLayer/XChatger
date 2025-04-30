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


/***************************************
 * Returns a string suitable to be passed to fl_set_menu() which then
 * initializes the menu for selection of the return type of an object.
 * In the calling code some of the entries typically must be disabled,
 * which can be done with a call of fl_set_menu_item_mode() with the
 * menu object as the first, the menu item number as the second and
 * 'FL_PUP_BOX | FL_PUP_GRAY' as the third argument.
 ***************************************/

void
setup_how_return_menu( FL_OBJECT * obj )
{
    fl_set_menu( obj,
                 "Never%b|"                   /* menu item 1 */
                 "End & Changed%b|"           /* menu item 2 */
                 "Whenever Changed%b|"        /* menu item 3 */
                 "At End%b|"                  /* menu item 4 */
                 "On Selection%b|"            /* menu item 5 */
                 "On Deselection%b|"          /* menu item 6 */
                 "Always%b" );                /* menu item 7 */
}


/***************************************
 * Sets the check boxes of the menu entries of a menu as set up with
 * the string returned by set_up_how_return_menu() (see above) according
 * to the return settings of an object.
 ***************************************/

void
reset_how_return_menu( FL_OBJECT    * menu,
                       unsigned int how_return )
{
    int i;
    unsigned int modes[ 8 ];

    for ( i = 1; i <= 7; i++ )
    {
        modes[ i ] = fl_get_menu_item_mode( menu, i ) & FL_PUP_GRAY;
        fl_set_menu_item_mode( menu, i, modes[ i ] | FL_PUP_BOX );
    }

    if ( how_return == FL_RETURN_NONE )
        fl_set_menu_item_mode( menu, 1,
                               modes[ 1 ] | FL_PUP_BOX | FL_PUP_CHECK );
    else if ( how_return == FL_RETURN_ALWAYS )
        fl_set_menu_item_mode( menu, 7,
                               modes[ 7 ] | FL_PUP_BOX | FL_PUP_CHECK );
    else
    {
        if ( how_return & FL_RETURN_END_CHANGED )
            fl_set_menu_item_mode( menu, 2,
                                   modes[ 2 ] | FL_PUP_BOX | FL_PUP_CHECK );
        if ( how_return & FL_RETURN_CHANGED )
            fl_set_menu_item_mode( menu, 3,
                                   modes[ 3 ] | FL_PUP_BOX | FL_PUP_CHECK );
        if ( how_return & FL_RETURN_END )
            fl_set_menu_item_mode( menu, 4,
                                   modes[ 4 ] | FL_PUP_BOX | FL_PUP_CHECK );
        if ( how_return & FL_RETURN_SELECTION )
            fl_set_menu_item_mode( menu, 5,
                                   modes[ 5 ] | FL_PUP_BOX | FL_PUP_CHECK );
        if ( how_return & FL_RETURN_DESELECTION )
            fl_set_menu_item_mode( menu, 6,
                                   modes[ 6 ] | FL_PUP_BOX | FL_PUP_CHECK );
    }
}


/***************************************
 ***************************************/

void
handle_how_return_changes( FL_OBJECT * menu,
                           FL_OBJECT * target )
{
    unsigned int hr = FL_RETURN_NONE;

    if (    fl_get_menu_item_mode( menu, 1 ) & FL_PUP_CHECK
         && target->how_return != FL_RETURN_NONE )
        /* empty */ ;
    else if (    fl_get_menu_item_mode( menu, 7 ) & FL_PUP_CHECK
              && target->how_return != FL_RETURN_ALWAYS )
        hr = FL_RETURN_ALWAYS;
    else
    {
        if (    fl_get_menu_item_mode( menu, 2 ) & FL_PUP_CHECK
             && ! ( target->how_return & FL_RETURN_END_CHANGED ) )
            hr = FL_RETURN_END_CHANGED;
        else
        {
            if ( fl_get_menu_item_mode( menu, 3 ) & FL_PUP_CHECK )
                hr |= FL_RETURN_CHANGED;

            if ( fl_get_menu_item_mode( menu, 4 ) & FL_PUP_CHECK )
                hr |= FL_RETURN_END;
        }

        if ( fl_get_menu_item_mode( menu, 5 ) & FL_PUP_CHECK )
            hr |= FL_RETURN_SELECTION;

        if ( fl_get_menu_item_mode( menu, 6 ) & FL_PUP_CHECK )
            hr |= FL_RETURN_DESELECTION;
    }

    fl_set_object_return( target, hr );
    reset_how_return_menu( menu, fl_get_object_return( target ) );
}


/***************************************
 ***************************************/

#define VN( v )  { v, #v }

static FLI_VN_PAIR howreturn[ ] =
{
    VN( FL_RETURN_NONE        ),
    VN( FL_RETURN_END_CHANGED ),
    VN( FL_RETURN_CHANGED     ),
    VN( FL_RETURN_END         ),
    VN( FL_RETURN_SELECTION   ),
    VN( FL_RETURN_DESELECTION ),
    VN( FL_RETURN_ALWAYS      ),
    { -1, NULL }
};


/***************************************
 ***************************************/

int
get_how_return_val( const char * s )
{
    char *tmp = fl_strdup( s ),
         *p = strtok( tmp, "|" ),
         *st;
    int val = 0;

    while ( p )
    {
        while ( *p && isspace( ( unsigned char ) *p ) )
            p++;
        st = p;
        while ( *p && ! isspace( ( unsigned char ) *p ) )
            p++;
        *p = '\0';

        if ( ! strcmp( st, "FL_RETURN_NONE" ) )
        {
            val = FL_RETURN_NONE;
            break;
        }
        else if ( ! strcmp( st, "FL_RETURN_ALWAYS" ) )
        {
            val = FL_RETURN_ALWAYS;
            break;
        }
        else if ( ! strcmp( st, "FL_RETURN_END_CHANGED" ) )
        {
            val |= FL_RETURN_END_CHANGED;
            val &= ~ ( FL_RETURN_CHANGED | FL_RETURN_END );
        }
        else if ( ! strcmp( st, "FL_RETURN_CHANGED" ) )
        {
            val |= FL_RETURN_CHANGED;
            val &= ~ FL_RETURN_END_CHANGED;
        }
        else if ( ! strcmp( st, "FL_RETURN_END" ) )
        {
            val |= FL_RETURN_END;
            val &= ~ FL_RETURN_END_CHANGED;
        }
        else if ( ! strcmp( st, "FL_RETURN_SELECTION" ) )
            val |= FL_RETURN_SELECTION;
        else if ( ! strcmp( st, "FL_RETURN_DESELECTION" ) )
            val |= FL_RETURN_DESELECTION;

        val |= fli_get_vn_value( howreturn, st );
        p = strtok( NULL, "|" );
    }

    fli_safe_free( tmp );

    return val;
}


/***************************************
 * Returns a string suitable for output in a C file (with 'withspaces'
 * set to 1) or a .fd file (with 'withspaces' set to 0) of the return
 * setting of an object as passed as the first argument.
 ***************************************/

const char *
get_how_return_name( unsigned int how_return,
                     int          with_spaces )
{
    static char buf[ 256 ];
    FLI_VN_PAIR *hr = howreturn;

    if ( how_return == FL_RETURN_ALWAYS )
        return "FL_RETURN_ALWAYS";

    if ( how_return == FL_RETURN_NONE )
        return "FL_RETURN_NONE";

    *buf = '\0';

    while ( ( ++hr )->val != ( int ) FL_RETURN_ALWAYS )
    {
        if ( how_return & hr->val )
            strcat( strcat( buf, with_spaces ? " | " : "|" ), hr->name );
    }

    return buf + ( with_spaces ? 3 : 1 );
}


/***************************************
 ***************************************/

const char *
file_tail( const char * full )
{
    char *p;

    if ( ( p = strrchr( full, '/' ) ) )
        return p + 1;

    return full;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
