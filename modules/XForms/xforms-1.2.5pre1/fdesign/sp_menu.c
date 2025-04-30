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
 * \file sp_menu.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Setting menu class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_menu.h"
#include "private/pmenu.h"
#include "spec/menu_spec.h"

static FD_menuattrib *menu_attrib;
static FL_OBJECT *curobj;

static const char * int_out( FL_OBJECT * ob,
                             double      val,
                             int         prec );
static char * get_pupentry_name( FL_OBJECT * obj );


/***************************************
 ***************************************/

FL_FORM *
menu_create_spec_form( void )
{
    if ( menu_attrib )
        return menu_attrib->menuattrib;

    menu_attrib = create_form_menuattrib( );
    fl_addto_choice( menu_attrib->mode, get_pupmode_string( ) );
    fl_addto_choice( menu_attrib->scope, "local|global" );
    fl_set_choice_item_shortcut( menu_attrib->mode, 1, "Nn#N" );
    fl_set_choice_item_shortcut( menu_attrib->mode, 1, "Gg#G" );
    fl_set_choice_item_shortcut( menu_attrib->mode, 1, "Bb#B" );
    fl_set_choice_item_shortcut( menu_attrib->mode, 1, "Cc#C" );
    fl_set_choice_item_shortcut( menu_attrib->mode, 1, "Rr#R" );
    fl_set_browser_dblclick_callback( menu_attrib->content_br,
                                          change_menu_item_cb, 0 );

    return menu_attrib->menuattrib;
}


/***************************************
 ***************************************/

void
menu_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_MENU_SPEC *sp = obj->spec;
    SuperSPEC *ssp = get_superspec( obj );
    int i;
    int mval = sp->numitems + 1;

    curobj = obj;

    fl_freeze_form( menu_attrib->content_br->form );

    fl_set_button( menu_attrib->new_menuapi, ssp->new_menuapi );
    fl_clear_browser( menu_attrib->content_br );

    for ( i = 1; i <= sp->numitems; i++ )
    {
        fl_add_browser_line( menu_attrib->content_br, sp->items[ i ] );
        if ( sp->mval[ i ] >= mval )
            mval = sp->mval[ i ] + 1;
    }

    fl_set_choice( menu_attrib->scope, ssp->global_scope + 1 );

    if ( ssp->new_menuapi )
        fl_hide_object( menu_attrib->id );
    else
        fl_show_object( menu_attrib->id );

    fl_set_counter_filter( menu_attrib->id, int_out );
    fl_set_counter_value( menu_attrib->id, sp->numitems + 1 );

    fl_unfreeze_form( menu_attrib->content_br->form );
}


/***************************************
 ***************************************/

void
menu_emit_spec_fd_code( FILE      * fp,
                        FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_menu( obj->type, 0, 0, 0, 0, "" );
    FLI_MENU_SPEC *sp    = obj->spec,
                  *defsp = defobj->spec;
    SuperSPEC *ssp    = get_superspec( obj ),
              *defssp = get_superspec( defobj );
    int i;

    if ( ssp->new_menuapi != defssp->new_menuapi )
        fprintf( fp, "    struct: %d\n", ssp->new_menuapi );

    if ( ssp->global_scope != defssp->global_scope )
        fprintf( fp, "    global: %d\n", ssp->global_scope );

    for ( i = 1; i <= sp->numitems; i++ )
    {
        if ( sp->items[ i ] )
            fprintf( fp, "    content: %s\n", sp->items[ i ] );
        fprintf( fp, "    id: %d\n", sp->mval[ i ] );

        if ( sp->mode[ i ] != defsp->mode[ i ] )
            fprintf( fp, "    mode: %s\n", get_pupmode_name(sp->mode[ i ] ) );

        if ( sp->shortcut[ i ] && *sp->shortcut[ i ] )
            fprintf( fp, "    shortcut: %s\n", sp->shortcut[ i ] );

        if ( ssp->callback && ssp->callback[ i ] ) 
            fprintf( fp, "    callback: %s\n", ssp->callback[ i ] );
    }

    free_superspec( defobj );
    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
menu_emit_spec_c_code( FILE      * fp,
                       FL_OBJECT * obj )
{
    FL_OBJECT *defobj;
    FLI_MENU_SPEC *sp = obj->spec,
                  *defsp;
    SuperSPEC *ssp;

    if ( sp->numitems == 0 )
        return;

    /* Create a default object */

    defobj = fl_create_menu( obj->type, 0, 0, 0, 0, "" );
    defsp = defobj->spec;

    ssp = get_superspec( obj );

    if ( ssp->new_menuapi )
        fprintf( fp, "    fl_set_menu_entries( obj, %s );\n", ssp->misc_char );
    else
    {
        int i;

        for ( i = 1; i <= sp->numitems; i++ )
        {
            fprintf( fp, "    fl_addto_menu( obj, \"%s\" );\n",
                     sp->items[ i ] );

            if ( sp->mode[ i ] != defsp->mode[ i ] )
                fprintf(fp, "    fl_set_menu_item_mode( obj, %d, %s );\n",
                        i, get_pupmode_name( sp->mode[ i ] ) );

            if ( sp->shortcut[ i ] && *sp->shortcut[ i ] )
                fprintf( fp,
                         "    fl_set_menu_item_shortcut( obj, %d, \"%s\" );\n",
                         i, sp->shortcut[ i ] );

            if ( ssp->callback[ i ] && *ssp->callback[ i ] )
                fprintf( fp, "    fl_set_menu_item_callback( obj, %d, %s );\n",
                         i, ssp->callback[ i ] );

            if ( sp->mval[ i ] != i )
                fprintf( fp, "    fl_set_menu_item_id( obj, %d, %d );\n",
                         i, sp->mval[ i ] );
        }
    }

    fl_free_object( defobj );
}


/***************************************
 * emit things that are needed before code emission (file scope)
 ***************************************/

void
menu_emit_spec_header( FILE      * fp,
                       FL_OBJECT * obj )
{
    FLI_MENU_SPEC *sp = obj->spec;
    SuperSPEC *ssp = get_superspec( obj );
    int i;

    if ( ! ssp->new_menuapi || sp->numitems <= 0 )
        return;

    get_pupentry_name( obj );

    fprintf( fp, "\n%sFL_PUP_ENTRY %s[ ] = {\n",
             ssp->global_scope ? "" : "static ", ssp->misc_char );
    fprintf( fp, "    /*  itemtext callback  shortcut   mode */\n" );

    for ( i = 1; i <= sp->numitems; i++ )
        fprintf( fp, "    { \"%s\", %s, \"%s\", %s, { 0, 0 } },\n",
                 sp->items[ i ],
                 ( ssp->callback[ i ] && *ssp->callback[ i ] ) ?
                 ( char * ) ssp->callback[ i ] : "NULL",
                 sp->shortcut[ i ] ? sp->shortcut[ i ] : "",
                 get_pupmode_name( sp->mode[ i ] ) );

    /* sentinel */

    fprintf( fp, "    { NULL, 0, NULL, 0, { 0, 0 } }\n};\n\n");
}


/***************************************
 * emit header info that is global in nature
 ***************************************/

void
menu_emit_spec_global_header( FILE      * fp,
                              FL_OBJECT * obj )
{
    FLI_MENU_SPEC *sp = obj->spec;
    SuperSPEC *ssp = get_superspec( obj );

    if ( ! ssp->new_menuapi || sp->numitems <= 0 || ! ssp->global_scope )
        return;

    get_pupentry_name( obj );

    fprintf( fp, "extern FL_PUP_ENTRY %s[ ];\n", ssp->misc_char );
}


/***************************************
 * Emit menu item callback prototypes or function definitions
 ***************************************/

void
menu_emit_item_callback_headers( FILE      * fn,
                                 FL_OBJECT * obj,
                                 int         code )
{
    FLI_MENU_SPEC *sp = obj->spec;
    SuperSPEC *ssp = get_superspec( obj );
    int i;

    if ( ssp->new_menuapi || sp->numitems <= 0 )
        return;

    for ( i = 1; i <= sp->numitems; i++ )
    {
        if ( ! ssp->callback[ i ] )
            continue;

        if ( ! code )
            fprintf( fn, "int %s( int );\n", ssp->callback[ i ] );
        else
        {
            fprintf( fn, "/***************************************\n"
                     " ***************************************/\n\n" );
            fprintf( fn, "int %s( int menu_item_ID )\n{\n",
                     ssp->callback[ i ] );
            fprintf( fn, "    /* fill-in code for menu item callback */\n\n"
                     "    return menu_item_ID;\n}\n\n\n" );
        }
    }
}


/***************************************
 ***************************************/

static const char *
int_out( FL_OBJECT * ob    FL_UNUSED_ARG,
         double      val,
         int         prec  FL_UNUSED_ARG )
{
    static char buf[ 20 ];

    sprintf( buf, "%d", FL_nint( val ) );
    return buf;
}


/***************************************
 * create a name for the [menu|choice]_entry API and hang it off
 * sp->misc_char
 ***************************************/

static char *
get_pupentry_name( FL_OBJECT * obj )
{
    static int n = 0;
    char pupname[ 128 ],
         *p;
    char objname[ 128 ],
         cbname[ 128 ],
         argname[ 128 ];
    FLI_MENU_SPEC *sp = obj->spec;
    SuperSPEC *ssp = get_superspec( obj );
    int i;

    if ( ! ssp->new_menuapi || sp->numitems <= 0 )
        return "";

    if ( ssp->misc_char && *ssp->misc_char )
        return ssp->misc_char;

    get_object_name( obj, objname, cbname, argname );

    if ( *objname )
        sprintf( pupname, "fdmenu_%s_%d", objname, n );
    else if ( *obj->label )
        sprintf( pupname, "fdmenu_%s_%d", obj->label, n );
    else
        sprintf( pupname, "fdmenu_%d", n );

    n++;

    /* Get rid of illegal chars */

    for ( i = 0, p = pupname; *p; p++ )
        if ( isalnum( ( unsigned char ) *p ) || *p == '_' )
            pupname[ i++ ] = *p;

    pupname[ i++ ] = '\0';
    fli_safe_free ( ssp->misc_char );
    ssp->misc_char = fl_strdup( pupname );

    return ssp->misc_char;
}


/*
 * attributes callbacks
 */

/***************************************
 * callbacks and freeobj handles for form choiceattrib
 ***************************************/

void
add_menu_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
        FLI_MENU_SPEC *sp = curobj->spec;
        int i,
            k;

    const char *s = fl_get_input( menu_attrib->input );
    const char *sc = fl_get_input( menu_attrib->shortcut );
    const char *mode = fl_get_choice_text( menu_attrib->mode );
    const char *item_cb = fl_get_input( menu_attrib->item_cb );
    int mval = fl_get_counter_value( menu_attrib->id );

    if ( ! s || ! *s )
        return;

    fl_addto_browser( menu_attrib->content_br, s );

    i = fl_addto_menu( curobj, s );

    k = sp->mval[ i ];
    fl_set_menu_item_shortcut( curobj, k, sc );

    fl_set_menu_item_mode( curobj, k, get_pupmode_value( mode ) );

    fli_safe_free( sp->cb[ i ] );

    if ( item_cb && *item_cb )
        fl_set_menu_item_callback( curobj, k,
                                   ( FL_PUP_CB ) fl_strdup( item_cb ) );
    if ( k != mval )
        fl_set_menu_item_id( curobj, i, mval );

    if ( fl_get_button( menu_attrib->auto_clear ) )
        clear_menu_field_cb( menu_attrib->auto_clear, 0 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
replace_menu_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                      long        data  FL_UNUSED_ARG )
{
    FLI_MENU_SPEC *sp = curobj->spec;
    int i = fl_get_browser( menu_attrib->content_br );
    const char *s = fl_get_input( menu_attrib->input );
    const char *sc = fl_get_input( menu_attrib->shortcut );
    const char *mode = fl_get_choice_text( menu_attrib->mode );
    const char *item_cb = fl_get_input( menu_attrib->item_cb );
    int mval = fl_get_counter_value( menu_attrib->id );
    int k;

    if ( ! *s || i <= 0 )
        return;

    fl_replace_browser_line( menu_attrib->content_br, i, s );

    k = sp->mval[ i ];

    fl_replace_menu_item( curobj, k, s );

    fl_set_menu_item_shortcut( menu_attrib->vdata, k, sc );

    fl_set_menu_item_mode( curobj, k, get_pupmode_value( mode ) );

    fli_safe_free( sp->cb[ i ] );

    if ( item_cb && *item_cb )
        fl_set_menu_item_callback( curobj, k,
                                   ( FL_PUP_CB ) fl_strdup( item_cb ) );
    if ( k != mval )
        fl_set_menu_item_id( curobj, i, mval );

    if ( fl_get_button( menu_attrib->auto_clear ) )
        clear_menu_field_cb( menu_attrib->auto_clear, 0 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
delete_menu_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                     long        data  FL_UNUSED_ARG )
{
        FLI_MENU_SPEC *sp = curobj->spec;
    int i = fl_get_browser( menu_attrib->content_br );

    if ( i <= 0 )
        return;

    fl_delete_browser_line( menu_attrib->content_br, i );
    fli_safe_free( sp->cb[ i ] );
    fl_delete_menu_item( curobj, sp->mval[ i ] );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
change_menu_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                     long        data  FL_UNUSED_ARG )
{
    int i = fl_get_browser( menu_attrib->content_br );
    FLI_MENU_SPEC *sp = curobj->spec;

    if ( i <= 0 )
        return;

    fl_set_input( menu_attrib->input,
                  fl_get_browser_line( menu_attrib->content_br, i ) );

    if ( sp->shortcut[ i ] )
        fl_set_input( menu_attrib->shortcut, sp->shortcut[ i ] );

    fl_set_choice_text( menu_attrib->mode,
                        get_pupmode_name( sp->mode[ i ] ) + 3 );

    if ( sp->cb[ i ] )
        fl_set_input( menu_attrib->item_cb, ( char * ) sp->cb[ i ] );
    else
        fl_set_input( menu_attrib->item_cb, "" );

    fl_set_counter_value( menu_attrib->id, sp->mval[ i ] );
}


/***************************************
 ***************************************/

void
clear_menu_field_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                     long        data  FL_UNUSED_ARG )
{
    int i;
    FLI_MENU_SPEC *sp = curobj->spec;
    int mval = sp->numitems + 1;

    fl_set_input( menu_attrib->input, "" );
    fl_set_input( menu_attrib->shortcut, "" );
    fl_set_choice( menu_attrib->mode, 1 );
    fl_set_input( menu_attrib->item_cb, "" );

    for ( i = 1; i <= sp->numitems; i++ )
        if ( sp->mval[ i ] >= mval )
            mval = sp->mval[ i ] + 1;

    fl_set_counter_value( menu_attrib->id, mval );
}


/***************************************
 ***************************************/

void
new_menuapi_cb( FL_OBJECT * obj,
                long        data  FL_UNUSED_ARG )
{
    SuperSPEC * ssp = curobj->u_vdata;

    ssp->new_menuapi = fl_get_button( obj );

    if ( ssp->new_menuapi )
        fl_hide_object( menu_attrib->id );
    else
        fl_show_object( menu_attrib->id );
}


/***************************************
 ***************************************/

void
menuentry_scope_cb( FL_OBJECT * obj,
                    long        data  FL_UNUSED_ARG )
{
    ( ( SuperSPEC * ) curobj->u_vdata )->global_scope =
                                          ( fl_get_choice( obj ) - 1 ) > 0;
}


#include "spec/menu_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
