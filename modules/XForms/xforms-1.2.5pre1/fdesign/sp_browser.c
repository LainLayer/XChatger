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
 * \file sp_browser.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *.
 * Settting browser class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"
#include "sp_browser.h"
#include "private/pbrowser.h"
#include "spec/browser_spec.h"

static FD_browserattrib *br_attrib;
static FL_OBJECT * curobj;


/***************************************
 ***************************************/

FL_FORM *
browser_create_spec_form( void )
{
    if ( br_attrib )
        return br_attrib->browserattrib;

    br_attrib = create_form_browserattrib( );

    fl_addto_choice( br_attrib->hscb_pref, get_scrollbar_pref_string( ) );
    fl_addto_choice( br_attrib->vscb_pref, get_scrollbar_pref_string( ) );
    setup_how_return_menu( br_attrib->returnsetting );

    return br_attrib->browserattrib;
}


/***************************************
 ***************************************/

void
browser_fill_in_spec_form( FL_OBJECT * obj )
{
    FLI_BROWSER_SPEC *sp = obj->spec;
    int i;
    int nlines = fl_get_browser_maxline( obj );

    curobj = obj;

    fl_set_choice( br_attrib->hscb_pref, sp->h_pref + 1 );
    fl_set_choice( br_attrib->vscb_pref, sp->v_pref + 1 );

    fl_freeze_form( br_attrib->content_br->form );

    fl_clear_browser( br_attrib->content_br );

    for ( i = 1; i <= nlines; i++ )
        fl_add_browser_line( br_attrib->content_br,
                             fl_get_browser_line( obj, i ) );

    fl_unfreeze_form( br_attrib->content_br->form );

    reset_how_return_menu( br_attrib->returnsetting, obj->how_return );
}


/***************************************
 ***************************************/

void
browser_emit_spec_fd_code( FILE      * fp,
                           FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_browser( obj->type, 0, 0, 0, 0, "" );
    FLI_BROWSER_SPEC *sp    = obj->spec,
                     *defsp = defobj->spec;
    int i;
    int nlines = fl_get_browser_maxline( obj );

    if ( sp->h_pref != defsp->h_pref )
        fprintf( fp, "h_pref: %s\n",
                 get_scrollbar_pref_name( sp->h_pref ) );

    if ( sp->v_pref != defsp->v_pref )
        fprintf( fp, "v_pref: %s\n",
                 get_scrollbar_pref_name( sp->v_pref ) );

    for ( i = 1; i <= nlines; i++ )
        fprintf( fp, "content: %s\n", fl_get_browser_line( obj, i ) );
}


/***************************************
 ***************************************/

void
browser_emit_spec_c_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = fl_create_browser( obj->type, 0, 0, 0, 0, "" );
    FLI_BROWSER_SPEC *sp    = obj->spec,
                     *defsp = defobj->spec;
    int i;
    int nlines = fl_get_browser_maxline( obj );

    if ( sp->h_pref != defsp->h_pref )
        fprintf( fp, "    fl_set_browser_hscrollbar( obj, %s );\n",
                 get_scrollbar_pref_name( sp->h_pref ) );

    if ( sp->v_pref != defsp->v_pref )
        fprintf( fp, "    fl_set_browser_vscrollbar( obj, %s );\n",
                 get_scrollbar_pref_name( sp->v_pref ) );

    for ( i = 1; i <= nlines; i++ )
        fprintf( fp, "    fl_add_browser_line( obj, \"%s\" );\n",
                 fl_get_browser_line( obj, i ) );
}


/***************************************
 * Callbacks and freeobj handles for form browserattrib
 ***************************************/

void
add_item_cb( FL_OBJECT * obj,
             long        data  FL_UNUSED_ARG )
{
    FD_browserattrib *ui = obj->form->fdui;
    const char *s = fl_get_input( ui->input );

    if ( ! s )
        s = "";

    fl_addto_browser( ui->content_br, s );
    fl_addto_browser( curobj, s );

    if ( fl_get_button( ui->auto_clear ) )
        fl_set_input( ui->input, "" );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
replace_item_cb( FL_OBJECT * obj,
                 long        data  FL_UNUSED_ARG )
{
    FD_browserattrib *ui = obj->form->fdui;
    int i = fl_get_browser( ui->content_br );
    const char *s = fl_get_input( ui->input );

    if ( i > 0 )
    {
        if ( ! s )
            s = "";

        fl_replace_browser_line( ui->content_br, i, s );
        fl_replace_browser_line( curobj, i, s );

        if ( fl_get_button( ui->auto_clear ) )
            fl_set_input( ui->input, "" );
    }

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
insert_cb( FL_OBJECT * obj,
           long        data  FL_UNUSED_ARG )
{
    FD_browserattrib *ui = obj->form->fdui;
    int i = fl_get_browser( ui->content_br );
    const char *s = fl_get_input( ui->input );

    if ( i > 0 )
    {
        if ( ! s )
            s = "";

        fl_insert_browser_line( ui->content_br, i, s );
        fl_insert_browser_line( curobj, i, s );

        if ( fl_get_button( ui->auto_clear ) )
            fl_set_input( ui->input, "" );
    }

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
delete_item_cb( FL_OBJECT * obj,
                long        data  FL_UNUSED_ARG )
{
    FD_browserattrib *ui = obj->form->fdui;
    int i = fl_get_browser( ui->content_br );

    if ( i <= 0 )
        return;

    fl_delete_browser_line( ui->content_br, i );
    fl_delete_browser_line( curobj, i );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
hscb_pref_cb( FL_OBJECT * obj,
              long        data  FL_UNUSED_ARG )
{
    fl_set_browser_hscrollbar( curobj, fl_get_choice( obj ) - 1 );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
vscb_pref_cb( FL_OBJECT * obj,
              long        data  FL_UNUSED_ARG )
{
    fl_set_browser_vscrollbar( curobj, fl_get_choice( obj ) - 1 );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
br_returnsetting_change( FL_OBJECT * obj,
                         long        data  FL_UNUSED_ARG )
{
    handle_how_return_changes( obj, curobj );
}


/***************************************
 ***************************************/

void
clear_field_cb( FL_OBJECT * ob,
                long        data  FL_UNUSED_ARG )
{
    FD_browserattrib *ui = ob->form->fdui;

    fl_set_input( ui->input, "" );
}


#include "spec/browser_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
