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
 * \file fd_forms.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This file is part of the Forms Designer.
 *
 * It contains the routines that maintain the collection of
 * forms on which the program is working. It contains the callback
 * routines to add forms, change their name, remove them ,etc.
 * It also contains the routine to draw them and the  basic routines
 * for loading and saving forms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "fd_main.h"

static FRM *forms = NULL;   /* The list of forms */
static int fnumb = 0;       /* number of forms */

FL_FORM *cur_form = NULL;   /* The current form */


/***************************************
 * Returns the number of the form
 ***************************************/

static int
get_form_numb( FL_FORM * form )
{
    int i;

    for ( i = 0; i < fnumb; i++ )
        if ( forms[ i ].form == form )
            return i;
    return -1;
}


/***************************************
 ***************************************/

const char *
get_form_name( FL_FORM * form )
{
    int i;

    for ( i = 0; i < fnumb; i++ )
        if ( forms[ i ].form == form )
            return *forms[ i ].fname ? forms[ i ].fname : NULL;

    return NULL;
}


/***************************************
 * Sets the current form to 'numb' or to NULL when 'numb' is -1
 ***************************************/

static void
set_form( int numb )
{
    if ( numb == -1 )
    {
        cur_form = NULL;
        fl_deselect_browser( fd_control->formbrowser );
    }
    else
    {
        cur_form = forms[ numb ].form;
        set_bounding_box( 0, 0, cur_form->w, cur_form->h );
        fl_select_browser_line( fd_control->formbrowser, numb + 1 );
        fl_winstepsize( main_window, 1, 1 );
        fl_winresize( main_window, cur_form->w, cur_form->h );
        if ( fl_display )
            XSync( fl_display, 0 );
    }

    fl_deselect_browser( fd_control->objectbrowser );
    reset_pallette( );
    cur_class = -1;

    clear_selection( );
    fillin_groups( );
    redraw_the_form( 1 );
}


/***************************************
 * Change the current forms background. Called when the main window is resized
 ***************************************/

void
reshape_form_background( FL_Coord neww,
                         FL_Coord newh )
{
    if ( cur_form && cur_form->first )
    {
        cur_form->w_hr = cur_form->w =
        cur_form->first->next->w = cur_form->first->next->fr1 =
        cur_form->first->next->fl2 = neww;
        cur_form->h_hr = cur_form->h =
        cur_form->first->next->h = cur_form->first->next->fb1 =
        cur_form->first->next->ft2 = newh;
         
        set_bounding_box( 0, 0, neww, newh );
    }
}


/****
  CALLBACK ROUTINES
****/

/***************************************
 * Callback routine that is called when the user selects another form
 * to work on.
 ***************************************/

void
form_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
         long        arg  FL_UNUSED_ARG )
{
    set_form( fl_get_browser( fd_control->formbrowser ) - 1 );
}


/***************************************
 * Callback routine called when the user adds a form.
 ***************************************/

void
addform_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
            long        arg  FL_UNUSED_ARG )
{
    double w = 0,
           h = 0;
    FL_Coord xx,
             yy;
    static int form_seq;
    const char *s;
    const char *sp;
    FRM *new_forms;
    int cc = cur_class;
    static int busy = 0;

    if ( busy )
        return;
    else
        busy = 1;

    new_forms = fl_realloc( forms, ( fnumb + 1 ) * sizeof *forms );

    if ( ! new_forms )
    {
        fl_show_alert( "Too many forms", "Running out of memory for forms",
                       NULL, 0 );
        busy = 0;
        return;
    }
    else
        forms = new_forms;

    /* Make old form invisible */

    set_form( -1 );

    /* Get boundary */

    fl_get_win_size( main_window, &xx, &yy );
    set_bounding_box( 0, 0, xx, yy );

    w = xx;
    h = yy;

 get_new_form_name:

    if (    ! ( s = fl_show_input( "Enter form name (must be usable as "
                                   "a C variable):", "" ) )
         || ! *s )
    {
        busy = 0;
        return;
    }

    if (    ! isascii( ( unsigned char ) *s )
         || ! ( isalpha( ( unsigned char ) *s ) || *s == '_' ) )
    {
        fl_show_alert( "Error", "Invalid C identifier for form name:", s, 0 );
        goto get_new_form_name;
    }

    for ( sp = s + 1; *sp; sp++ )
        if (    ! isascii( ( unsigned char ) *sp )
             || ! ( isalnum( ( unsigned char ) *sp ) || *sp == '_' ) )
        {
            fl_show_alert( "Error", "Invalid C identifier for form name:",
                           s, 0 );
            goto get_new_form_name;
        }

    /* Create the form */

    cur_form = forms[ fnumb ].form = fl_bgn_form( FL_NO_BOX, w, h );
    fl_end_form( );

    add_an_object( FL_BOX, FL_FLAT_BOX, 0, 0, w, h );
    fl_set_form_dblbuffer( cur_form, 1 );

    /* Get form name and add it */

    strcpy( forms[ fnumb ].fname, s );

    if ( ! forms[ fnumb ].fname[ 0 ] )
        sprintf( forms[ fnumb ].fname, "form%d", form_seq++ );
    fl_add_browser_line( fd_control->formbrowser, forms[ fnumb ].fname );

    /* Finish off */

    set_form( fnumb++ );
    changed = FL_TRUE;

    if ( cc >= 0 )
        select_object_by_class( cc );

    busy = 0;
}


/***************************************
 * Callback routine invoked when the user wants to change the name
 * of the current form
 ***************************************/

void
changename_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
               long        arg  FL_UNUSED_ARG )
{
    int fn = get_form_numb( cur_form );
    const char *s, *cn;
    int i;
    FL_OBJECT *o;

    if ( cur_form == NULL || fn == -1 )
        return;

 get_changed_form_name:

    if (    ! ( s = fl_show_input( "Enter form name (must be usable as "
                                   "a C variable):", forms[ fn ].fname ) )
         || ! *s )
        return;

    if ( ! is_valid_c_name( s ) )
    {
        fl_show_alert( "Error", "Invalid C identifier for form name:", s, 0 );
        goto get_changed_form_name;
    }

    for ( i = 0; i < fnumb; i++ )
    {
        if ( i == fn )
            continue;

        if ( ! strcmp( forms[ i ].fname, s ) )
        {
            fl_show_alert( "Error", "New name is already in use for another "
                           "form", NULL, 0 );
            goto get_changed_form_name;
        }
    }

    for ( o = forms[ fn ].form->first; o; o = o->next )
        if ( ( cn = get_object_c_name( o ) ) && ! strcmp( s, cn ) )
        {
            fl_show_alert( "Error", "New name is already used for one of the ",
                           "forms objects", 0 );
            goto get_changed_form_name;
        }

    fli_sstrcpy( forms[ fn ].fname, s, MAX_VAR_LEN );

    fl_replace_browser_line( fd_control->formbrowser, fn + 1,
                             forms[ fn ].fname );
    changed = FL_TRUE;
}


/***************************************
 * Callback routine invoked when the user wants to change the forms size
 ***************************************/

void
changesize_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
               long        arg  FL_UNUSED_ARG )
{
    FL_OBJECT *retobj;
    int fn = get_form_numb( cur_form );

    if ( cur_form == NULL || fn == -1 )
        return;

    /* While this form is shown no other should be operational (the user
       still can resize the forms window, that will automatically set the
       width and height spinners) */

    fl_deactivate_all_forms( );

    /* Set up the width and height spinner objects to show the sizes of
       the current form */

    fl_set_spinner_value( fd_resize->width,  cur_form->w );
    fl_set_spinner_value( fd_resize->height, cur_form->h );

    fl_show_form( fd_resize->resize, FL_PLACE_HOTSPOT, FL_TRANSIENT,
                  "Form size" );

    fl_update_display( 0 );
    fl_winfocus( fd_resize->resize->window );

    /* Loop until user clicks the "Dismiss" button */

    while ( ( retobj = fl_do_only_forms( ) ) != fd_resize->quit )
    {
        int w;
        int h;

        if ( retobj != fd_resize->set_size )
            continue;

        /* User has clicked on the "Set new size" button */

        w = FL_nint( fl_get_spinner_value( fd_resize->width  ) );
        h = FL_nint( fl_get_spinner_value( fd_resize->height ) );
        fl_set_spinner_value( fd_resize->width, w  );
        fl_set_spinner_value( fd_resize->height, h );

        if ( w == cur_form->w && h == cur_form->h )
            continue;

        XResizeWindow( flx->display, main_window, w, h );

        if ( cur_form && ( cur_form->w > w || cur_form->h > h ) )
        {
            reshape_form_background( w, h );
            redraw_the_form( 1 );
        }

        changed = FL_TRUE;
    }

    fl_hide_form( fd_resize->resize );
    fl_activate_all_forms( );
}


/***************************************
 * Callback routine for deleting a form
 ***************************************/

void
deleteform_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
               long        arg  FL_UNUSED_ARG )
{
    int i,
        fn = get_form_numb( cur_form );

    if ( cur_form == NULL || fn == -1 )
        return;

    if ( ! fl_show_question( "Delete current form?", 1 ) )
        return;

    fl_delete_browser_line( fd_control->formbrowser, fn + 1 );

    for ( i = fn; i < fnumb - 1; i++ )
        forms[ i ] = forms[ i + 1 ];

    fnumb--;
    set_form( -1 );
    changed = FL_TRUE;
}


/****
  DRAWING FORMS
****/

/***************************************
 * Redraws the form in main window. 'back' indicates whether the background
 * should be redrawn (when not double-buffering). This avoids flashing.
 ***************************************/

void
redraw_the_form( int back )
{
    if ( main_window == 0 )
        return;

    fl_winset( main_window );

    /* It's possible to have a NULL cur_form, e.g. when adding */

    if ( back && ! cur_form )
        fd_clear( 0, 0, winw + 1, winh + 1 );

    if ( cur_form != NULL )
    {
        cur_form->window = main_window;
        cur_form->visible = 1;
        fl_set_form_dblbuffer( cur_form, 1 );
        fl_redraw_form( cur_form );
        cur_form->window = 0;
        cur_form->visible = 0;
        draw_selbox( );
    }
}


/****
  LOADING AND SAVING
****/

int fd_magic;

/***************************************
 ***************************************/

char *
append_fd_suffix( const char * fn )
{
    size_t l = strlen( fn );
    char *fname = fl_malloc( l + 4 );

    strcpy( fname, fn );
    if ( l < 3 || strcmp( fname + l - 3, ".fd" ) )
        strcat( fname, ".fd" );
    return fname;
}


/***************************************
 * Reads in the very first part of a .fd file
 ***************************************/

static int
load_fd_header( void )
{
    char *p;
    int nforms = -1;

    /* Line with "magic" number must come first, followed by some
       boilerplate text */

    if (    ff_read( "%k", &p ) <= 0
         || strcmp( p, "Magic" )
         || ff_read( "%d", &fd_magic ) <= 0
         || (    fd_magic != MAGIC2 && fd_magic != MAGIC3
              && fd_magic != MAGIC4 && fd_magic != MAGIC5
              && fd_magic != MAGIC6 ) )
        return ff_err( "Wrong type of file" );

    if ( fd_magic < MAGIC6 )
    {
        char *tmp = ff_get_filename_copy( );

        if ( ! fdopt.conv_only )
            fl_show_alert_f( 0, "Warning:\fFile %s\nwas created with an older "
                             "fdesign version,\nthe new output file may not be "
                             "compatible.", tmp );
        else
            M_warn( "", "Warning: File %s was created with an older fdesign "
                    "version, the new output file may not be compatible",
                    tmp );

        fli_safe_free( tmp );
    }

    if (    ff_read( "Internal Form Definition File" ) < 0
         || ff_read( "(do not change)" ) < 0 )
        return ff_err( "Invalid format of file" );

    /* Now follows a set of keyword/value pairs. The key "Name" marks
       the end of the header and the start of the first form definition */

    while ( 1 )
    {
        if ( ff_read( "%k", &p ) <= 0 )
            return ff_err( "Invalid format of file" );

        if ( ! strcmp( p, "Number of forms" ) )
        {
            if ( ff_read( "%d", &nforms ) <= 0 )
                return ff_err( "Expected number of forms" );

            if ( nforms <= 0 )
                return ff_err( "Invalid number of forms" );
        }
        else if ( ! strcmp( p, "Unit of measure" ) )
        {
            if ( ff_read( "%x", &fdopt.unit ) < 0 )
                return ff_err( "Expected valid unit of measure" );

            fli_cntl.coordUnit = fdopt.unit;        /* make_obj uses this */
        }
        else if ( ! strcmp( p, "SnapGrid" ) || ! strcmp( p, "Snap" ) )
        {
            int snap_size;

            if ( ff_read( "%d", &snap_size ) < 0 )
                return ff_err( "Expected snap size" );

            if ( snap_size < 0 )
                return ff_err( "Invalid snap size" );

            set_snap_size( snap_size, 1 );
        }
        else if ( ! strcmp( p, "Border Width" ) )
        {
            int bw;

            if ( ff_read( "%d", &bw ) < 0 )
                return ff_err( "Expected border width" );
            
            if ( bw != FL_BOUND_WIDTH )
                fl_set_border_width( fd_bwidth = bw );
        }
        else if ( ! strcmp( p, "Name" ) )
        {
            if ( nforms < 0 )
                return ff_err( "Number of forms is missing" );

            return nforms;
        }
        else
            return ff_err( "Invalid format of file" );
    }

    return ff_err( "Invalid format of file" );
}


/***************************************
 * Loads or merges a file with form definitions
 ***************************************/

int
load_forms( int          merge,
            const char * str )
{
    int i,
        saved_unit = fdopt.unit,
        r,
        nforms;
    FRM *new_forms;
    char *fname;

    /* Try to open the .fd file */

    if ( ff_get_fd_file( str, merge ) < 0 )
        return -1;

    if ( ! merge )
    {
        fnumb = 0;
        fl_clear_browser( fd_control->formbrowser );
    }

    /* Try to read the header of the file (must indicate that there's at
       least one form */

    if ( ( nforms = load_fd_header( ) ) <= 0 )
        return -1;

    if ( ! ( new_forms = fl_realloc( forms,
                                     ( fnumb + nforms ) * sizeof *forms ) ) )
        return ff_err( "Can't load file, running out of memory" );

    forms = new_forms;

    fname = ff_get_filename_copy( );

    /* Now read in all forms - we have already read in the "Name:" key that
       starts a new form */

    r = FF_AT_START_OF_FORM;

    for ( i = 0; i < nforms && r == FF_AT_START_OF_FORM; i++ )
    {
        char *p;

        /* First thing to read is the name of the form (which must not be an
           empty string) */

        if ( ff_read( "%v", &p ) < 1 )
        {
            fl_free( fname );
            return ff_err( "Failed to read expected form name" );
        }

        if ( ! p || ! *p )
        {
            fli_safe_free( p );
            return ff_err( "Expected name of the form" );
        }

        fli_sstrcpy( forms[ fnumb ].fname, p, sizeof forms[ fnumb ].fname );
        fli_safe_free( p );

        /* Having gotten the name read all the remaining information. We then
           should either end up at the start of a new form or at the end of
           the file */

        if (    ( r = read_form( ) ) == FF_AT_START_OF_FORM
             || r == FF_AT_END_OF_FILE )
        {
            forms[ fnumb ].form = cur_form;
            fl_add_browser_line( fd_control->formbrowser,
                                 forms[ fnumb ].fname );
            fnumb++;
        }
    }

    /* Check if we're really at the end of the file and as many forms have
       been found as we were led to expect */

    if ( r == FF_AT_START_OF_FORM )
    {
        fl_free( fname );
        return ff_err( "More forms found than expected" );
    }
    else if ( r != FF_READ_FAILURE && i < nforms )
    {
        ff_err( "Less forms found than expected" );
        fl_free( fname );
        return -1;
    }

    /* Everything's dandy and we're done with the file */

    ff_close( );

    set_form( fnumb > 0 ? 0 : -1 );

    fli_safe_free( loadedfile );

    if ( ! merge )
    {
        loadedfile = rel2abs( fname );
        changed = FL_FALSE;
    }
    else
        changed = FL_TRUE;

    fl_free( fname );

    /* Reset active coordinate system to pixel */

    fli_cntl.coordUnit = FL_COORD_PIXEL;

    /* Force output to use the same unit as used in the input when converting
       directly. The reason is that we don't know the screen DPI. */

    if ( ! fdopt.conv_only )
        fdopt.unit = saved_unit;

    fd_magic = 0;
    return 0;
}


/***************************************
 * Saves the form definitions, returns whether saved
 ***************************************/

int
save_forms( const char *str )
{
    int i,
        snap;
    FILE *fp;
    char fname[ 1024 ],
         filename[ 1024 ];
    Conv *conv;

    fl_use_fselector( SAVE_FSELECTOR );

    /* Get the filename if necessary */

    if ( ! str || ! * str )
    {
        char *dir = NULL;

        if ( loadedfile && strchr( loadedfile, '/' ) )
        {
            dir = fl_strdup( loadedfile );
            *strrchr( dir, '/' ) = '\0';
        }
        else
            dir = fl_strdup( "" );

        str = fl_show_fselector( "Filename to save forms to", dir, "*.fd", "" );

        fl_free( dir );
    }

    if ( ! str )
        return 0;       /* cancel */

    if ( ! *str )
    {
        fl_show_alert( "Warning", "No forms were saved.", "", 0 );
        return 0;
    }

    /* Remove .fd if required */

    strcpy( filename, str );
    i = strlen( filename ) - 1;
    if ( ! strcmp( filename + i - 2, ".fd" ) )
        filename[ i - 2 ] = '\0';

    strcpy( fname, filename );

    /* In simple convert mode (i.e. not migrate) there's no need to (re)save
       the .fd file */

    if ( fdopt.conv_only == 1 )
        goto emit_code;

    /* Make the .fd file */

    strcat( fname, ".fd" );
    make_backup( fname );

    if ( ( fp = fopen( fname, "w" ) ) == 0 )
    {
        fl_show_alert_f( 1, "Error\fCannot open file\n%s\nfor writing",
                         fname );
        return 0;
    }

    snap = get_step_size( ) + 0.1;
    fprintf( fp, "Magic: %d\n\n"
                 "Internal Form Definition File\n"
                 "    (do not change)\n\n"
                 "Number of forms: %d\n"
                 "Unit of measure: %s\n",
             MAGIC6, fnumb, unit_name( fdopt.unit ) );

    if ( fd_bwidth != FL_BOUND_WIDTH && fd_bwidth )
        fprintf( fp, "Border Width: %d\n", fd_bwidth );

    if ( snap != 10 )
        fprintf( fp, "SnapGrid: %d\n", snap );

    for ( i = 0; i < fnumb; i++ )
        write_form( fp, forms[ i ].form, forms[ i ].fname );

    fprintf( fp, "\n==============================\n%s\n", main_name );
    fclose( fp );

 emit_code:

    /* If no code is desired, return */

    if ( ! fdopt.emit_code )
        return 1;

    conv = convertor + fdopt.language;

    /* Some converter works on the c code */

    if ( conv->need_c_code )
        convertor[ FD_C ].convert( filename, forms, fnumb );

    if ( conv->convert )
        return conv->convert( filename, forms, fnumb );
    else if ( conv->extern_convertor )
    {
        char cmdbuf[ 1024 ];
        char optbuf[ 512 ];
        int status;

        *optbuf = '\0';

        if ( fdopt.emit_main )
            strcat( optbuf, "-main " );
        if ( fdopt.emit_cb )
            strcat( optbuf, "-callback " );
        if ( fdopt.altformat )
            strcat( optbuf, "-altformat " );
        if ( fdopt.compensate )
            strcat( optbuf, "-compensate " );
        if ( fdopt.output_dir ) {
            strcat( optbuf, "-dir " );
            strcat( optbuf, fdopt.output_dir );
        }

        sprintf( cmdbuf, "%s %s%s", conv->extern_convertor, optbuf, filename );
        M_warn( "Convert", "Executing %s", cmdbuf );

        if ( fdopt.conv_only )
        {
            if ( ( status = system( cmdbuf ) ) )
                M_err( "Output", "Error executing %s\n", cmdbuf );
        }
        else
        {
            fl_clear_command_log( );
            if ( ( status = fl_exe_command( cmdbuf, 1 ) ) )
            {
                fl_addto_command_log( "\nerror executing " );
                fl_addto_command_log( cmdbuf );
                fl_show_command_log( FL_FULLBORDER );
            }
        }

        return status == 0;
    }
    else
    {
        fprintf( stderr, "Convertor %s for %s not found\n",
                 conv->extern_convertor, conv->lang_name );
        return 0;
    }

    return 1;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
