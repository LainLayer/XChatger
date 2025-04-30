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
 * \file sp_choice.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting choice class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_choice.h"
#include "private/pchoice.h"
#include "spec/choice_spec.h"

static FD_choiceattrib *choice_attrib;
static FL_OBJECT * curobj;

/***************************************
 ***************************************/

FL_FORM *
choice_create_spec_form( void )
{
    if ( choice_attrib )
        return choice_attrib->choiceattrib;

    choice_attrib = create_form_choiceattrib( );

    fl_addto_choice( choice_attrib->mode, get_pupmode_string( ) );
    fl_addto_choice( choice_attrib->scope, "local|global" );
    fl_set_choice_item_mode( choice_attrib->mode, 3, FL_PUP_GRAY );
    fl_set_choice_item_mode( choice_attrib->mode, 4, FL_PUP_GRAY );
    fl_set_choice_item_mode( choice_attrib->mode, 5, FL_PUP_GRAY );

    fl_addto_choice( choice_attrib->align,
                     align_name( FL_ALIGN_CENTER, 0 ) );
    fl_addto_choice( choice_attrib->align, align_name( FL_ALIGN_TOP, 0 ) );
    fl_addto_choice( choice_attrib->align,
                     align_name( FL_ALIGN_BOTTOM, 0 ) );
    fl_addto_choice( choice_attrib->align, align_name( FL_ALIGN_LEFT, 0 ) );
    fl_addto_choice( choice_attrib->align, align_name( FL_ALIGN_RIGHT, 0 ) );

    fl_set_browser_dblclick_callback( choice_attrib->content_br,
                                      change_choice_item_cb, 0 );

    return choice_attrib->choiceattrib;
}


/***************************************
 ***************************************/

void
choice_fill_in_spec_form( FL_OBJECT  * obj )
{
    FLI_CHOICE_SPEC *sp = obj->spec;
    SuperSPEC *ssp = get_superspec( obj );
    int i;

    curobj = obj;

    fl_freeze_form( choice_attrib->content_br->form );

    fl_set_button( choice_attrib->new_menuapi, ssp->new_menuapi );
    fl_set_counter_value( choice_attrib->val, sp->val );
    fl_set_choice_text( choice_attrib->align, align_name( sp->align, 0 ) );
    fl_set_choice( choice_attrib->scope, ssp->global_scope + 1 );
    fl_clear_browser( choice_attrib->content_br );

    for ( i = 1; i <= sp->numitems; i++ )
        fl_add_browser_line( choice_attrib->content_br, sp->items[ i ] );

    fl_set_counter_bounds( choice_attrib->val, 1,
                           sp->numitems >= 1 ? sp->numitems : 1 );

    fl_unfreeze_form( choice_attrib->content_br->form );
}


/***************************************
 ***************************************/

void
choice_emit_spec_fd_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_choice( obj->type, 0, 0, 0, 0, "" );
    FLI_CHOICE_SPEC *sp    = obj->spec,
                    *defsp = defobj->spec;
    SuperSPEC *ssp    = get_superspec( obj ),
              *defssp = get_superspec( defobj );
    int i;


    /* Create a default object */

    if ( sp->align != defsp->align )
        fprintf( fp, "    align: %s\n", align_name( sp->align, 0 ) );
    if ( ssp->new_menuapi != defssp->new_menuapi )
        fprintf( fp, "    struct: %d\n", ssp->new_menuapi );

    for ( i = 1; i <= sp->numitems; i++ )
    {
        fprintf( fp, "    content: %s\n", sp->items[ i ] );
        if ( sp->mode[ i ] != defsp->mode[ i ] )
            fprintf( fp, "    mode: %s\n", get_pupmode_name( sp->mode[ i ] ) );
        if ( sp->shortcut[ i ] && *sp->shortcut[ i ] )
            fprintf( fp, "    shortcut: %s\n", sp->shortcut[ i ] );
    }

    if ( sp->val != defsp->val )
        fprintf( fp, "    value: %d\n", sp->val );

    free_superspec( defobj );
    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
choice_emit_spec_c_code( FILE     * fp,
                         FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_choice( obj->type, 0, 0, 0, 0, "" );
    FLI_CHOICE_SPEC *sp    = obj->spec,
                    *defsp = defobj->spec;
    SuperSPEC *ssp = get_superspec( obj );


    if ( sp->align != defsp->align )
        fprintf( fp, "    fl_set_choice_align( obj, %s );\n",
                 align_name( sp->align, 1 ) );

    if ( sp->numitems >= 1 )
    {
        if ( ssp->new_menuapi )
            fprintf( fp, "    fl_set_choice_entries( obj, %s );\n",
                     ssp->misc_char );
        else
        {
            int i;

            for ( i = 1; i <= sp->numitems; i++ )
            {
                fprintf( fp, "    fl_addto_choice( obj, \"%s\" );\n",
                         sp->items[ i ] );
                if ( sp->mode[ i ] != defsp->mode[ i ] )
                    fprintf( fp, "    fl_set_choice_item_mode( obj, %d, "
                             "%s );\n", i, get_pupmode_name( sp->mode[ i ] ) );
                if ( sp->shortcut[ i ] && *sp->shortcut[ i ] )
                    fprintf( fp, "    fl_set_choice_item_shortcut( obj, %d, "
                             "\"%s\" );\n", i, sp->shortcut[ i ] );
            }
        }

        if ( sp->val != defsp->val )
            fprintf( fp, "    fl_set_choice( obj, %d );\n", sp->val );
    }

    fl_free_object( defobj );
}


/***************************************
 * Callbacks and freeobj handles for form choiceattrib
 ***************************************/

void
add_choice_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                    long        data  FL_UNUSED_ARG )
{
    const char *s = fl_get_input( choice_attrib->input );
    const char *sc = fl_get_input( choice_attrib->shortcut );
    const char *mode = fl_get_choice_text( choice_attrib->mode );
    int i;

    if ( ! s || ! *s )
        return;

    fl_addto_browser( choice_attrib->content_br, s );
    i = fl_addto_choice( curobj, s );
    fl_set_choice_item_shortcut( curobj, i, sc );
    fl_set_choice_item_mode( curobj, i, get_pupmode_value( mode ) );

    if ( fl_get_button( choice_attrib->auto_clear ) )
        clear_choice_field_cb( choice_attrib->auto_clear, 0 );

    redraw_the_form( 0 );

    fl_set_counter_bounds( choice_attrib->val, 1,
                           fl_get_choice_maxitems( curobj ) );
}


/***************************************
 ***************************************/

void
replace_choice_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                        long        data  FL_UNUSED_ARG )
{
    int i = fl_get_browser( choice_attrib->content_br );
    const char *s = fl_get_input( choice_attrib->input );
    const char *sc = fl_get_input( choice_attrib->shortcut );
    const char *mode = fl_get_choice_text( choice_attrib->mode );

    if ( ! *s || i <= 0 )
        return;

    fl_replace_browser_line( choice_attrib->content_br, i, s );
    fl_replace_choice( curobj, i, s );
    fl_set_choice_item_shortcut( curobj, i, sc );
    fl_set_choice_item_mode( curobj, i, get_pupmode_value( mode ) );

    if ( fl_get_button( choice_attrib->auto_clear ) )
        clear_choice_field_cb( choice_attrib->auto_clear, 0 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
delete_choice_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                       long        data  FL_UNUSED_ARG )
{
    int i = fl_get_browser( choice_attrib->content_br );

    if ( i <= 0 )
        return;

    fl_delete_browser_line( choice_attrib->content_br, i );
    fl_delete_choice( curobj, i );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
change_choice_item_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                       long        data  FL_UNUSED_ARG )
{
    int i = fl_get_browser( choice_attrib->content_br );
    FLI_CHOICE_SPEC *sp = curobj->spec;

    if ( i <= 0 )
        return;

    fl_set_input( choice_attrib->input,
                  fl_get_browser_line( choice_attrib->content_br, i ) );
    if ( sp->shortcut[ i ] )
        fl_set_input( choice_attrib->shortcut, sp->shortcut[ i ] );
    fl_set_choice_text( choice_attrib->mode,
                        get_pupmode_name( sp->mode[ i ] ) + 3 );
}


/***************************************
 ***************************************/

void
clear_choice_field_cb( FL_OBJECT * obj   FL_UNUSED_ARG,
                       long        data  FL_UNUSED_ARG )
{
    fl_set_input( choice_attrib->input, "" );
    fl_set_input( choice_attrib->shortcut, "" );
    fl_set_choice( choice_attrib->mode, 1 );
}


/***************************************
 ***************************************/

void
choice_align_cb( FL_OBJECT * obj,
                 long        data  FL_UNUSED_ARG )
{
    fl_set_choice_align( curobj, align_val( fl_get_choice_text( obj ) ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
choice_val_cb( FL_OBJECT * obj,
               long        data  FL_UNUSED_ARG )
{
    fl_set_choice( curobj, FL_nint( fl_get_counter_value( obj ) ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
use_struct_cb( FL_OBJECT * obj,
               long        data  FL_UNUSED_ARG )
{
    ( ( SuperSPEC * ) curobj->u_vdata )->new_menuapi = fl_get_button( obj );
}


/***************************************
 ***************************************/

void
choiceentry_scope_cb( FL_OBJECT * obj,
                      long        data  FL_UNUSED_ARG )
{
    ( ( SuperSPEC * ) curobj->u_vdata )->global_scope =
                                             ( fl_get_choice( obj ) - 1 ) > 0;
}


#include "spec/choice_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
