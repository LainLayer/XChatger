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
 * \file sp_button.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Settting button class specific attributes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "fd_main.h"
#include "fd_spec.h"
#include "fd_iconinfo.h"
#include "spec/button_spec.h"

static FD_buttonattrib *bt_attrib = NULL;
static FL_OBJECT * curobj = NULL;

static FL_OBJECT * create_default_button( FL_OBJECT * ob );
static void get_data_name( FL_OBJECT *,
                           IconInfo * );


#define IsIconButton( obj )                     \
    (    ( obj )->objclass == FL_BITMAPBUTTON   \
      || ( obj )->objclass == FL_PIXMAPBUTTON )


/***************************************
 ***************************************/

FL_FORM *
button_create_spec_form( void )
{
    if ( bt_attrib )
        return bt_attrib->buttonattrib;

    bt_attrib = create_form_buttonattrib( );

    fl_addto_choice( bt_attrib->pixalign,
                     align_name( FL_ALIGN_CENTER, 0 ) );
    fl_addto_choice( bt_attrib->pixalign,
                     align_name( FL_ALIGN_TOP, 0 ) );
    fl_addto_choice( bt_attrib->pixalign,
                     align_name( FL_ALIGN_BOTTOM, 0 ) );
    fl_addto_choice( bt_attrib->pixalign,
                     align_name( FL_ALIGN_LEFT, 0 ) );
    fl_addto_choice( bt_attrib->pixalign,
                     align_name( FL_ALIGN_RIGHT, 0 ) );

    fl_set_input_return( bt_attrib->filename, FL_RETURN_END );
    fl_set_input_return( bt_attrib->focus_filename, FL_RETURN_END );

    return bt_attrib->buttonattrib;
}


/***************************************
 ***************************************/

void
button_adjust_spec_form( FL_OBJECT * obj )
{
    curobj = obj;

    if ( obj->type == FL_PUSH_BUTTON || obj->type == FL_RADIO_BUTTON )
        fl_show_object( bt_attrib->initialval );
    else
        fl_hide_object( bt_attrib->initialval );

    if ( IsIconButton( obj ) )
    {
        fl_show_object( bt_attrib->filename );
        fl_show_object( bt_attrib->browse );
        fl_show_object( bt_attrib->use_data );
        fl_show_object( bt_attrib->fullpath );

        if ( obj->objclass == FL_PIXMAPBUTTON )
        {
            fl_show_object( bt_attrib->pixalign );
            fl_show_object( bt_attrib->showfocus );
            fl_show_object( bt_attrib->focus_filename );
            fl_show_object( bt_attrib->browse2 );
        }
    }
    else
    {
        fl_hide_object( bt_attrib->filename );
        fl_hide_object( bt_attrib->focus_filename );
        fl_hide_object( bt_attrib->browse );
        fl_hide_object( bt_attrib->browse2 );
        fl_hide_object( bt_attrib->use_data );
        fl_hide_object( bt_attrib->fullpath );
    }

    if ( obj->objclass != FL_PIXMAPBUTTON )
    {
        fl_hide_object( bt_attrib->pixalign );
        fl_hide_object( bt_attrib->showfocus );
        fl_hide_object( bt_attrib->focus_filename );
        fl_hide_object( bt_attrib->browse2 );
    }
}


/***************************************
 ***************************************/

void
button_fill_in_spec_form( FL_OBJECT * obj )
{
    FL_BUTTON_SPEC *sp = obj->spec;
    IconInfo *info = get_iconinfo( obj );

    fl_set_button( bt_attrib->react_left,   sp->react_to[ 0 ] );
    fl_set_button( bt_attrib->react_middle, sp->react_to[ 1 ] );
    fl_set_button( bt_attrib->react_right,  sp->react_to[ 2 ] );
    fl_set_button( bt_attrib->react_up,     sp->react_to[ 3 ] );
    fl_set_button( bt_attrib->react_down,   sp->react_to[ 4 ] );
    fl_set_button( bt_attrib->initialval,   sp->val );

    if ( info )
    {
        fl_set_button( bt_attrib->use_data, info->use_data );
        fl_set_button( bt_attrib->fullpath, info->fullpath );

        fl_set_button( bt_attrib->showfocus, info->show_focus );
        fl_set_choice_text( bt_attrib->pixalign, align_name( info->align, 0 ) );

        fl_set_input( bt_attrib->filename, info->filename );
        fl_set_input( bt_attrib->focus_filename, info->focus_filename );
    }
}


/***************************************
 ***************************************/

void
button_reread_spec_form( FL_OBJECT * obj )
{
    if ( ! IsIconButton( obj ) || ! curobj )
        return;

    iconbutton_filename_change( bt_attrib->filename, 0 );

    if ( obj->objclass == FL_PIXMAPBUTTON )
        focusiconbutton_filename_change( bt_attrib->focus_filename, 0 );

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
button_restore_spec( FL_OBJECT * obj )
{
    IconInfo *info;

    if ( ! IsIconButton( obj ) )
        return;

    info = get_iconinfo( obj );

    if ( *info->filename )
    {
        if ( obj->objclass == FL_PIXMAPBUTTON )
            fl_set_pixmapbutton_file( obj, info->filename );
        else
            fl_set_bitmapbutton_file( obj, info->filename );
    }
    else
    {
        /* Show the default broken image link image */

        if ( obj->objclass == FL_PIXMAPBUTTON )
            set_testing_pixmap( obj );
        else
            set_testing_bitmap( obj );
    }

    if ( obj->objclass == FL_PIXMAPBUTTON )
    {
        if ( *info->focus_filename )
            fl_set_pixmapbutton_focus_file( obj, info->focus_filename );

        fl_set_pixmap_align( obj, fl_to_inside_lalign( info->align ),
                             info->dx, info->dy );
    }
}


/***************************************
 ***************************************/

void
button_emit_spec_fd_code( FILE      * fp,
                          FL_OBJECT * obj )
{
    FL_OBJECT *defobj = defobj = create_default_button( obj );
    FL_BUTTON_SPEC *sp    = obj->spec,
                   *defsp = defobj->spec;
    IconInfo *info,
             *definfo;

    if ( memcmp( sp->react_to, defsp->react_to, sizeof sp->react_to ) )
    {
        unsigned int rt =   ( sp->react_to[ 0 ] &  1 )
                          | ( sp->react_to[ 1 ] &  2 )
                          | ( sp->react_to[ 2 ] &  4 )
                          | ( sp->react_to[ 3 ] &  8 )
                          | ( sp->react_to[ 4 ] & 16 );

        fprintf( fp, "    mbuttons: %u\n", rt );
    }

    if ( sp->val != defsp->val )
        fprintf( fp, "    value: %d\n", sp->val );

    if ( ! IsIconButton( obj ) )
    {
        fl_free_object( defobj );
        return;
    }

    info = get_iconinfo( obj );
    spec_to_superspec( defobj );
    definfo = get_iconinfo( defobj );

    get_data_name( obj, info );

    if ( *info->filename )
    {
        fprintf( fp, "    file: %s\n", info->filename );
        if ( *info->focus_filename )
            fprintf( fp, "    focus_file: %s\n", info->focus_filename );
        fprintf( fp, "    fullpath: %d\n", info->fullpath );
    }

    if (    obj->objclass == FL_PIXMAPBUTTON
         && info->align != definfo->align )
        fprintf( fp, "    align: %s\n",
                 align_name( info->align | FL_ALIGN_INSIDE, 0 ) );

    if ( info->show_focus != definfo->show_focus )
        fprintf( fp, "    focus: %d\n", info->show_focus );

    if ( *info->data && *info->filename )
    {
        fprintf( fp, "    data: %s\n", info->data );
        if ( *info->focus_data )
            fprintf( fp, "    focus_data: %s\n", info->focus_data );
    }

    if ( *info->width )
        fprintf( fp, "    width: %s\n", info->width );
    if ( *info->height )
        fprintf( fp, "    height: %s\n", info->height );

    free_iconinfo( defobj );
    free_superspec( defobj );
    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
button_emit_spec_c_code( FILE      * fp,
                         FL_OBJECT * obj )
{
    FL_OBJECT *defobj = defobj = create_default_button( obj );
    FL_BUTTON_SPEC *sp    = obj->spec,
                   *defsp = defobj->spec;
    IconInfo *info,
             *definfo;

    if ( sp->val != defsp->val )
        fprintf( fp, "    fl_set_button( obj, %d );\n", sp->val );

    if ( memcmp( sp->react_to, defsp->react_to, sizeof sp->react_to ) )
    {
        unsigned int rt =   ( sp->react_to[ 0 ] &  1 )
                          | ( sp->react_to[ 1 ] &  2 )
                          | ( sp->react_to[ 2 ] &  4 )
                          | ( sp->react_to[ 3 ] &  8 )
                          | ( sp->react_to[ 4 ] & 16 );

        fprintf( fp, "    fl_set_button_mouse_buttons( obj, %u );\n", rt );
    }

    if ( ! IsIconButton( obj ) )
    {
        fl_free_object( defobj );
        return;
    }

    info = get_iconinfo( obj );
    spec_to_superspec( defobj );
    definfo = get_iconinfo( defobj );

    if (    obj->objclass == FL_PIXMAPBUTTON
         && info->align != definfo->align )
        fprintf( fp, "    fl_set_pixmapbutton_align( obj, %s, %d, %d );\n",
                 align_name( info->align | FL_ALIGN_INSIDE, 1 ),
                 info->dx, info->dy );

    if ( *info->filename && ! info->use_data )
    {
        fprintf( fp, "    fl_set_%sbutton_file( obj, \"%s\" );\n",
                 obj->objclass == FL_PIXMAPBUTTON ? "pixmap" : "bitmap",
                 info->filename );

        if ( obj->objclass == FL_PIXMAPBUTTON && *info->focus_filename )
            fprintf( fp, "    fl_set_pixmapbutton_focus_file( obj, \"%s\" );\n",
                     info->focus_filename );
    }

    if ( *info->data && info->use_data && *info->filename )
    {
        if ( obj->objclass == FL_PIXMAPBUTTON )
        {
            fprintf( fp, "    fl_set_pixmapbutton_data( obj, %s );\n",
                     info->data );

            if ( *info->focus_filename )
                fprintf( fp, "    fl_set_pixmapbutton_focus_data( obj, %s );\n",
                         info->focus_data );
        }
        else
            fprintf( fp, "    fl_set_bitmapbutton_data( obj, %s, %s, "
                     "( unsigned char * ) %s );\n",
                     info->width, info->height, info->data );
    }

    if (    obj->objclass == FL_PIXMAPBUTTON
         && info->show_focus != definfo->show_focus )
        fprintf( fp, "    fl_set_pixmapbutton_focus_outline( obj, %d );\n",
                 info->show_focus );

    free_iconinfo( defobj );
    free_superspec( defobj );
    fl_free_object( defobj );
}


/***************************************
 ***************************************/

void
button_emit_spec_header( FILE      * fp,
                         FL_OBJECT * obj )
{
    IconInfo *info;

    if ( ! IsIconButton( obj ) )
        return;

    info = get_iconinfo( obj );

    if ( info->use_data && *info->data && *info->filename )
    {
        const char *fn = info->fullpath ? info->filename
                                        : file_tail( info->filename );

        if ( ! is_duplicate_info( fn ) )
            fprintf( fp, "#include \"%s\"\n", fn );

        if ( obj->objclass == FL_PIXMAPBUTTON && *info->focus_filename )
        {
            fn = info->fullpath ? info->focus_filename
                                : file_tail( info->focus_filename );

            if ( ! is_duplicate_info( fn ) )
                fprintf( fp, "#include \"%s\"\n", fn );
        }
    }
}


/***************************************
 ***************************************/

void
usedata_change( FL_OBJECT * obj,
                long        data  FL_UNUSED_ARG )
{
    get_iconinfo( curobj )->use_data = fl_get_button( obj );
}


/***************************************
 ***************************************/

void
fullpath_cb( FL_OBJECT * ob,
             long        data  FL_UNUSED_ARG )
{
    get_iconinfo( curobj )->fullpath = fl_get_button( ob );
}


/***************************************
 ***************************************/

void
react_to_button( FL_OBJECT * obj,
                 long        data )
{
    unsigned int mb;

    fl_get_button_mouse_buttons( curobj, &mb );

    if ( fl_get_button( obj ) )
        mb |= 1 << data;
    else
        mb &= ~ ( 1 << data );

    fl_set_button_mouse_buttons( curobj, mb );
}


/***************************************
 ***************************************/

void
initialval_change( FL_OBJECT * obj,
                   long        data  FL_UNUSED_ARG )
{
    fl_set_button( curobj, fl_get_button( obj ) );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
showfocus_change( FL_OBJECT * obj,
                  long        data  FL_UNUSED_ARG )
{
    IconInfo *info = get_iconinfo( curobj );

    info->show_focus = fl_get_button( obj );
    fl_set_pixmapbutton_focus_outline( curobj, info->show_focus );
}


/***************************************
 ***************************************/

void
iconbutton_filename_change( FL_OBJECT * ob,
                            long        data  FL_UNUSED_ARG )
{
    IconInfo *info = get_iconinfo( curobj );

    strcpy( info->filename, fl_get_input( ob ) );

    if ( *info->filename )
    {
        ( curobj->objclass == FL_PIXMAPBUTTON ?
          fl_set_pixmapbutton_file : fl_set_bitmapbutton_file )
            ( curobj, info->filename );
    }
    else
    {
        if ( curobj->objclass == FL_PIXMAPBUTTON )
        {
            fl_free_pixmap_pixmap( curobj );
            set_testing_pixmap( curobj );
        }
        else
            set_testing_bitmap( curobj );
    }

    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
focusiconbutton_filename_change( FL_OBJECT * obj,
                                 long        data  FL_UNUSED_ARG )
{
    IconInfo *info = get_iconinfo( curobj );

    strcpy( info->focus_filename, fl_get_input( obj ) );

    if ( *info->focus_filename )
        fl_set_pixmapbutton_focus_file( curobj, info->focus_filename );
}


/***************************************
 ***************************************/

void
pixalign_change( FL_OBJECT * obj,
                 long        data  FL_UNUSED_ARG )
{
    IconInfo *info = get_iconinfo( curobj );
    const char *s = fl_get_choice_text( obj );

    if ( ! s )
        return;

    info->align = align_val( s );

    /* Don't allow outside align */

    fl_set_pixmap_align( curobj, fl_to_inside_lalign( info->align ),
                         info->dx, info->dy );
    redraw_the_form( 0 );
}


/***************************************
 ***************************************/

void
lookfor_pixmapfile_cb( FL_OBJECT * ob   FL_UNUSED_ARG,
                       long        data )
{
    const char *fn;
    const char * def = data
                       ? ( ( FL_BUTTON_STRUCT * ) curobj->spec )->focus_filename
                       : ( ( FL_BUTTON_STRUCT * ) curobj->spec )->filename;
    char buf[ 2048 ];
    char *cwd;

    fl_use_fselector( XPM_FSELECTOR );
    fl_set_fselector_placement( FL_PLACE_MOUSE );

    if ( curobj->objclass == FL_PIXMAPBUTTON )
        fn = fl_show_fselector( "XPM file", "", "*.xpm", def );
    else
        fn = fl_show_fselector( "XBM file", "", "*.xbm", def );

    if ( ! fn )
        return;

    cwd = fli_getcwd( buf, sizeof buf - 2 );
    if ( cwd && strstr( fn, cwd ) )
        fn += strlen( cwd ) + 1;

    ob = data ? bt_attrib->focus_filename : bt_attrib->filename;

    fl_set_input( ob, fn );
    fl_call_object_callback( ob );
}


/***************************************
 ***************************************/

static FL_OBJECT *
create_default_button( FL_OBJECT * ob )
{
    FL_OBJECT *defobj = NULL;

    /* Create a default object */

    if ( ob->objclass == FL_BUTTON )
        defobj = fl_create_button( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_BITMAPBUTTON )
        defobj = fl_create_bitmapbutton( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_PIXMAPBUTTON )
        defobj = fl_create_pixmapbutton( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_ROUNDBUTTON )
        defobj = fl_create_roundbutton( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_LABELBUTTON )
        defobj = fl_create_labelbutton( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_LIGHTBUTTON )
        defobj = fl_create_lightbutton( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_CHECKBUTTON )
        defobj = fl_create_checkbutton( ob->type, 0, 0, 0, 0, "" );
    else if ( ob->objclass == FL_ROUND3DBUTTON )
        defobj = fl_create_round3dbutton( ob->type, 0, 0, 0, 0, "" );
    else
        fprintf( stderr, "Unknown Button Class: %d\n", ob->objclass );

    return defobj;
}


/***************************************
 ***************************************/

static void
get_data_name( FL_OBJECT * obj,
               IconInfo  * info )
{
    FILE *fp;

    if ( ! info->use_data )
        return;

    if ( *info->filename )
    {
        if ( ( fp = fopen( info->filename, "r" ) ) )
        {
            if ( obj->objclass == FL_PIXMAPBUTTON )
                get_xpm_stuff( info->data, fp );
            else
                get_xbm_stuff( info, fp );

            fclose( fp );
        }

        if ( ! fp || ! *info->data )
        {
            fprintf( stderr, "Can't open or read '%s'\n", info->filename );
            *info->filename = '\0';
        }

    }

    if ( obj->objclass != FL_PIXMAPBUTTON || ! *info->focus_filename )
        return;

    if ( ( fp = fopen( info->focus_filename, "r" ) ) )
    {
        get_xpm_stuff( info->focus_data, fp );
        fclose( fp );
    }

    if ( ! fp || ! *info->focus_data )
    {
        fprintf( stderr, "Can't open or read focusfile '%s'\n",
                 info->focus_filename );
        *info->focus_filename = '\0';
    }
}


#include "spec/button_spec.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
