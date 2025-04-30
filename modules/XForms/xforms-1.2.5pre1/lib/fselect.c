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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file fselect.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Comprehensive interactive file selector. The actual directory reading
 *  code is isolated in listdir.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"
#include "private/flsnprintf.h"
#include <string.h>


/******************** Limits ***************************/

#define FL_FLEN   256
#define MAXFL     ( FL_PATH_MAX + FL_FLEN )

static int dirmarker    = 'D';  /* directory marker     */
static int bdevmarker   = 'b';  /* special file marker  */
static int cdevmarker   = 'c';  /* special file marker  */
static int fifomarker   = 'p';  /* pipe marker          */
static int sockmarker   = 's';  /* socket marker        */
static int filemarker   = ' ';  /* normal file marker   */
static int listdirfirst = 1;    /* list directory first */

extern int fli_sort_method;     /* form listdir.c */


/******* GUI parameters ********/

/*  Misc. buttons configurable from application program */

#define MAX_APPBUTT  3

typedef struct
{
    /* Due to FD_FSELECTOR, the order of these objects are important. maybe
       put them in a union ? */

    FL_FORM   * fselect;
    void      * vdata;
    char      * cdata;
    long        ldata;
    FL_OBJECT * browser,
              * input,
              * prompt,
              * resbutt;
    FL_OBJECT * patbutt,
              * dirbutt,
              * cancel,
              * ready;
    FL_OBJECT * dirlabel,
              * patlabel;
    FL_OBJECT * appbutt[ MAX_APPBUTT ];
    FL_OBJECT * appbuttgrp;
    FL_FSCB     fselect_cb;
    void      * callback_data;
    char        applabel[ MAX_APPBUTT ][ 32 ];
    void        ( * appcb[ MAX_APPBUTT ] )( void * );
    void      * appdata[ MAX_APPBUTT ];
    FL_COLOR    fg;
    FL_COLOR    brcol;
    FL_COLOR    brselcol;
    int         rescan;                 /* if update dir cache  */
    int         disabled_cache;
    int         border,
                place;
    char        retname[ MAXFL ];       /* complete filename */
    char        dname[ MAXFL ];         /* current path */
    char        filename[ FL_FLEN ];    /* bare filename */
    char        pattern[ FL_FLEN ];     /* patterns    */
    int         last_len;
    int         last_line;
} FD_fselect;

static FD_fselect * create_form_fselect( void );

static FD_fselect *fd_fselector[ FL_MAX_FSELECTOR ] = { NULL },
                  *fs;


/***************************************
 ***************************************/

static void
allocate_fselector( int a )
{
    if ( ! fd_fselector[ a ] )
    {
        fs = fd_fselector[ a ] = fl_calloc( 1, sizeof *fs );
        fs->fg       = FL_COL1;
        fs->brcol    = FL_COL1;
        fs->brselcol = FL_TOP_BCOL;
        fs->border   = FL_TRANSIENT;
        fs->place    = FL_PLACE_FREE_CENTER;
        strcpy( fs->dname, "." );
        strcpy( fs->pattern, "*" );

        create_form_fselect( );

        fl_set_form_title( fs->fselect, "FileSelector" );
        fl_set_object_resize( fs->appbuttgrp, FL_RESIZE_NONE );
        fl_set_object_gravity( fs->appbuttgrp, EastGravity, EastGravity );
    }

    fs = fd_fselector[ a ];
}


/***************************************
 ***************************************/

void
fli_free_fselectors( void )
{
    int i;

    for ( i = 0; i < FL_MAX_FSELECTOR; i++ )
        fli_safe_free( fd_fselector[ i ] );
}


/***************************************
 ***************************************/

int
fl_use_fselector( int n )
{
    if ( n < 0 || n >= FL_MAX_FSELECTOR )
        return -1;
    allocate_fselector( n );
    return n;
}


/***************************************
 ***************************************/

void
fl_add_fselector_appbutton( const char * label,
                            void         ( * cb )( void * ),
                            void       * data )
{
    int ok, i;

    if ( ! label || ! *label || ! cb )
        return;

    if ( ! fs )
        allocate_fselector( 0 );

    for ( ok = i = 0; ! ok && i < MAX_APPBUTT; i++ )
        if ( ! fs->appcb[ i ] || ! fs->applabel[ i ][ 0 ] )
        {
            ok = i + 1;
            fs->appcb[ i ] = cb;
            fs->appdata[ i ] = data;
            fli_sstrcpy( fs->applabel[ i ], label, 32 );
        }

    if ( ! ok )
        M_err( "fl_add_fselector_appbutton", "Only %d allowd. %s ignored",
               MAX_APPBUTT, label );
}


/***************************************
 ***************************************/

void
fl_remove_fselector_appbutton( const char * label )
{
    int i;

    if ( ! label || ! *label )
        return;

    for ( i = 0; i < MAX_APPBUTT; i++ )
        if ( strcmp( label, fs->applabel[ i ] ) == 0 )
        {
            fs->appcb[ i ] = NULL;
            *fs->applabel[ i ] = '\0';
            fl_hide_object( fs->appbutt[ i ] );
        }
}


/***************************************
 * Just a fake to get the prototypes right
 ***************************************/

static void
appbutton_cb( FL_OBJECT * ob  FL_UNUSED_ARG,
              long        arg )
{
    if ( fs->appcb[ arg ] )
        ( fs->appcb[ arg ] )( fs->appdata[ arg ] );
}


/***************************************
 ***************************************/

void
fl_disable_fselector_cache( int yes )
{
    if ( ! fs )
        allocate_fselector( 0 );

    fs->disabled_cache = yes;
}


static int fill_entries( FL_OBJECT *,
                         const char *,
                         int );

static const char * contract_dirname( const char *,
                                      int );


/***************************************
 ***************************************/

static char *
append_slash( char * d )
{
    int n = strlen( d );

    if ( d[ n - 1 ] != '/' )
    {
        d[ n++ ] = '/';
        d[ n ] = '\0';
    }
    return d;
}


/***************************************
 * Combine directory and file name to form a complete name
 ***************************************/

static char *
cmplt_name( void )
{
    const char *f = fl_get_input( fs->input );

    if ( f && *f )
    {
        fli_sstrcpy( fs->filename, f, FL_FLEN );

        if ( *f != '/' )
            append_slash( strcpy( fs->retname, fs->dname ) );
        else
            *fs->retname = '\0';
        return strcat( fs->retname, f );
    }
    else
    {
        *fs->filename = '\0';
        return fs->filename;
    }
}


/***************************************
 ***************************************/

static char *
fli_del_tail_slash( char * d )
{
    int i = strlen( d ) - 1;

#ifndef FL_WIN32
    if ( d[ i ] == '/' )
#else
    if ( d[ i ] == '/' || d[ i ] == '\\' )
#endif
        d[ i ] = '\0';
    return d;
}


/***************************************
 * Callback for selection of a file name. On double click on a directory
 * we change to that directory while for a double click on a normal file
 * the return button gets triggered
 ***************************************/

static void
select_cb( FL_OBJECT * obj,
           long        isdblclick )
{
    char seltext[ FL_PATH_MAX ];
    int thisline;
    FD_fselect *lfs = obj->form->fdui;
    int is_dir;

    if ( ( thisline = fl_get_browser( obj ) ) <= 0 )
        return;

    fli_sstrcpy( seltext, fl_get_browser_line( obj, thisline ),
                 sizeof seltext );
    is_dir = seltext[ 0 ] == dirmarker && seltext[ 1 ] == ' ';
    lfs->last_len = strlen( seltext + 2 );
    lfs->last_line = thisline;
    memmove( seltext, seltext + 2, lfs->last_len + 1 );

    if ( is_dir )  /* directory */
    {
        if ( isdblclick )
        {
            strcat( append_slash( lfs->dname ), seltext );
            fli_fix_dirname( lfs->dname );
            if ( fill_entries( lfs->browser, NULL, 0 ) < 0 )
                fli_del_tail_slash( lfs->dname );
            *seltext = '\0';
        }

        fl_set_input( lfs->input, seltext );
    }
    else                                                     /* normal file */
    {
        fl_set_input( lfs->input, seltext );
        strcpy( lfs->filename, seltext );

        if ( isdblclick )
        {
            if ( lfs->fselect_cb || lfs->fselect->attached )
            {
                const char *fn = cmplt_name( );

                if ( lfs->fselect_cb )
                    lfs->fselect_cb( fn, lfs->callback_data );

                if ( fli_is_valid_dir( fn ) )
                    fl_set_directory( fn );
            }
            else
                fl_trigger_object( lfs->ready );
        }
    }
}


/***************************************
 ***************************************/

int
fl_set_directory( const char * p )
{
    char tmpdir[ FL_PATH_MAX + 2 ];

    if ( ! fs )
        allocate_fselector( 0 );

    if ( p == NULL )
    {
        M_err( "fl_set_directory", "invalid NULL argument" );
        return 1;
    }

    fli_sstrcpy( tmpdir, p, sizeof tmpdir );
    fli_de_space_de( tmpdir );
    if ( strcmp( tmpdir, fs->dname ) == 0 )
        return 0;

    fli_fix_dirname( tmpdir );
    if ( ! fli_is_valid_dir( tmpdir ) )
    {
        M_err( "fl_set_directory", "invalid directory: %s", tmpdir );
        return 1;
    }

    strcpy( fs->dname, tmpdir );
    if ( fill_entries( fs->browser, NULL, 1 ) < 0 )
        fli_del_tail_slash( fs->dname );
    else
        fl_set_object_label( fs->dirbutt, contract_dirname( fs->dname, 38 ) );

    return 0;
}


/***************************************
 ***************************************/

static void
directory_cb( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
    const char *p;
    FD_fselect *savefs = fs;

    fs = ob->form->fdui;
    if ( ! ( p = fl_show_input( "Enter New Directory:", fs->dname ) ) )
        return;

    fl_set_directory( p );
    fs = savefs;
}


/***************************************
 ***************************************/

void
fl_set_pattern( const char * s )
{
    if ( ! fs )
        allocate_fselector( 0 );

    if ( s && strcmp( fs->pattern, s ) )
    {
        fli_sstrcpy( fs->pattern, s, sizeof fs->pattern );
        fl_set_object_label( fs->patbutt, fs->pattern );
        fill_entries( fs->browser, fs->filename, 1 );
    }
}


/***************************************
 ***************************************/

static void
pattern_cb( FL_OBJECT * ob,
            long        q  FL_UNUSED_ARG )
{
    const char *s = fl_show_input( "New Pattern", fs->pattern );
    FD_fselect *savefs = fs;

    fs = ob->form->fdui;
    if ( s )
        fl_set_pattern( s );
    fs = savefs;
}


/***************************************
 * Show all files in directory dname that match selection pattern.
 * Note: fn indicates if we should highlight the current selection.
 ***************************************/

static int
fill_entries( FL_OBJECT  * br,
              const char * fn,
              int          show )
{
    const FL_Dirlist *dirlist,
                     *dl;
    int n, i;
    FD_fselect *lfs = br->form->fdui;
    int dcount = 1;
    int lcount = 1;
    int sel_line = 0;

    if ( br->form->visible )
    {
        fl_set_cursor( br->form->window, XC_watch );
        fl_update_display( 0 );
    }

    if ( ! ( dirlist = fl_get_dirlist( lfs->dname, lfs->pattern, &n,
                                       lfs->rescan || lfs->disabled_cache ) ) )
    {
        char * tmpbuf,
             *p;

        if ( asprintf( &tmpbuf, "Can't read %s", lfs->dname ) != -1 )
        {
            fl_show_alert( "ReadDir", tmpbuf, fli_get_syserror_msg( ), 0 );
            fl_free( tmpbuf );
        }
        M_err( "fill_entries", "Can't read %s", lfs->dname );

        /* Backup */

        if ( ( p = strrchr( lfs->dname, '/' ) ) )
            *p = '\0';
        if ( br->form->window )
            fl_reset_cursor( br->form->window );
        return -1;
    }

    fl_freeze_form( lfs->fselect );
    fl_set_object_label( lfs->dirbutt, contract_dirname( lfs->dname, 38 ) );
    fl_clear_browser( br );

    for ( i = 0, dl = dirlist; i < n; i++, dl++ )
    {
        int cur_line;
        char marker;
        char *p;
        char * tt = fl_malloc( strlen( dl->name ) + 3 );

        switch ( dl->type )
        {
            case FT_DIR :
                marker = dirmarker;
                break;

            case FT_FIFO :
                marker = fifomarker;
                break;

            case FT_SOCK :
                marker = sockmarker;
                break;

            case FT_BLK :
                marker = bdevmarker;
                break;

            default :
                marker = filemarker;
        }

        sprintf( tt, "%c %s", marker, dl->name );

        if ( dl->type == FT_DIR && listdirfirst )
        {
            cur_line = dcount;
            if ( sel_line > 0 && sel_line >= dcount )
                sel_line++;
            fl_insert_browser_line( br, dcount++, tt );
        }
        else
        {
            cur_line = lcount;
            fl_add_browser_line( br, tt );
        }

        fl_free( tt );

        lcount++;

        if (    sel_line <= 0
             && fn
             && (    ! strcmp( dl->name, fn )
                  || (    ( p = strrchr( fn, '/' ) )
                       && ! strcmp( dl->name, p + 1 ) ) ) )
        {
            sel_line = cur_line;
            fl_select_browser_line( br, cur_line );
        }
    }

    if ( show && sel_line > 0 )
    {
        int total = fl_get_browser_screenlines( br );

        if ( sel_line <= total / 2 )
            fl_set_browser_topline( br,  1 );
        else if ( sel_line > lcount - total - 1 )
            fl_set_browser_topline( br, lcount - total - 1 );
        else
            fl_set_browser_topline( br, sel_line - total / 2 );
    }

    fl_unfreeze_form( lfs->fselect );
    if ( br->form->window )
        fl_reset_cursor( br->form->window );

    lfs->last_line = 0;
    lfs->last_len = 0;

    return 0;
}


/***************************************
 * Handles changes of the input object the user can enter a file name
 * in. Tries to find a name in the browser that matches the input and
 * select it if it exists.
 ***************************************/

static void
input_cb( FL_OBJECT * obj,
          long        arg  FL_UNUSED_ARG )
{
    FD_fselect *lfs = obj->form->fdui;
    const char *ip = fl_get_input( obj );
    int len;
    int num_lines;
    int i;
    int dir;        /* 1: forward, 0: backward */

    if ( ! *ip )
    {
        lfs->last_line = 0;
        lfs->last_len = 0;
        return;
    }

    len = strlen( ip );
    num_lines = fl_get_browser_maxline( lfs->browser );


    /* If the entries aren't sorted in alphabetical order we can't use
       any tricks to shorten the search, we have to run over all entries
       and pick the first one that matches */

    if (    fli_sort_method != FL_ALPHASORT
         && fli_sort_method != FL_RALPHASORT )
    {
        lfs->last_line = 0;

        for ( i = 1; i <= num_lines; i++ )
        {
            const char *line = fl_get_browser_line( lfs->browser, i );

            if ( line[ 1 ] == '\0' )
                continue;

            if ( ! strncmp( line + 2, ip, len ) )
            {
                fl_select_browser_line( lfs->browser, i );
                fl_show_browser_line( lfs->browser, i );
                return;
            }
        }

        return;
    }

    /* Otherwise we start at the entry found last time and search forward
       from there if the string in the input field got longer (or we haven't
       a stored match) and search backwards if it got shorter */

    dir = len > lfs->last_len || lfs->last_line == 0;
    lfs->last_len = len;

    /* First check if the last matched entry still matches */

    if (    lfs->last_line > 0
         && dir
         && ! strncmp( fl_get_browser_line( lfs->browser, lfs->last_line ) + 2,
                       ip, len ) )
        return;

    if ( dir ) 
        for ( i = lfs->last_line + 1; i <= num_lines; i++ )
        {
            const char *line = fl_get_browser_line( lfs->browser, i );
            int cmp;

            if ( line[ 1 ] == '\0' )
                continue;

            if ( ! ( cmp = strncmp( line + 2, ip, len ) ) )
            {
                fl_select_browser_line( lfs->browser, i );
                fl_show_browser_line( lfs->browser, i );
                lfs->last_line = i;
                return;
            }

	        if (    (    ( fli_sort_method == FL_ALPHASORT  && cmp > 0 )
	                  || ( fli_sort_method == FL_RALPHASORT && cmp < 0 ) )
	             && (    ( listdirfirst && *line != dirmarker )
	                  || ! listdirfirst ) )
	            return;
	    }
    else
    {
        int found = 0;

        for ( i = lfs->last_line - 1; i > 0; i-- )
        {
            const char *line = fl_get_browser_line( lfs->browser, i );
            int cmp;

            if ( line[ 1 ] == '\0' )
                continue;

            if ( ! ( cmp = strncmp( line + 2, ip, len ) ) )
                found = i;

	        if (    (    ( fli_sort_method == FL_ALPHASORT  && cmp < 0 )
	                  || ( fli_sort_method == FL_RALPHASORT && cmp > 0 ) )
	             && (    ( listdirfirst && *line == dirmarker )
	                  || ! listdirfirst ) )
                break;
        }

        if ( found )
        {
            fl_select_browser_line( lfs->browser, found );
            fl_show_browser_line( lfs->browser, found );
            lfs->last_line = found;
        }
    }
}


/***************************************
 ***************************************/

void
fl_set_fselector_callback( FL_FSCB   fscb,
                           void    * data )
{
    if ( ! fs )
        allocate_fselector( 0 );

    fs->fselect_cb    = fscb;
    fs->callback_data = data;

    /* Force creation if it does not already exists */

    fl_get_fselector_form( );

    if ( fscb )
    {
        fl_set_object_label( fs->cancel, "Close" );
        fl_set_button_shortcut( fs->cancel, "#C#c^[", 1 );
        fl_set_object_label( fs->ready, "Select" );
    }
    else
    {
        fl_set_object_label( fs->cancel, "Cancel" );
        fl_set_button_shortcut( fs->cancel, "#C#c^[", 1 );
        fl_set_object_label( fs->ready, "Ready" );
    }
}


/***************************************
 ***************************************/

void
fl_set_fselector_placement( int place )
{
    if ( ! fs )
        allocate_fselector( 0 );

    fs->place = place;
}


/***************************************
 ***************************************/

void
fl_set_fselector_border( int b )
{
    if ( ! fs )
        allocate_fselector( 0 );

    fs->border = b;
}


/***************************************
 ***************************************/

void
fl_invalidate_fselector_cache( void )
{
    if ( ! fs )
        allocate_fselector( 0 );

    fs->rescan = 1;
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_fselector_form( void )
{
    if ( ! fs )
        allocate_fselector( 0 );

    return fs->fselect;
}


/***************************************
 ***************************************/

FD_FSELECTOR *
fl_get_fselector_fdstruct( void )
{
    if ( ! fs )
        allocate_fselector( 0 );

    return ( FD_FSELECTOR * ) fs;
}


/***************************************
 ***************************************/

void
fl_hide_fselector( void )
{
    FD_FSELECTOR *fd = fl_get_fselector_fdstruct( );

    if ( fd->fselect && fd->fselect->visible )
        fl_trigger_object( fd->cancel );
}


/***************************************
 ***************************************/

static void
pre_attach( FL_FORM * form )
{
    FD_fselect *savefs = fs;

    fs = form->fdui;
    if ( ! form->attach_data )
        form->attach_data = "FileName";
    fl_show_fselector( form->attach_data, 0, 0, 0 );
    fs = savefs;
}


/***************************************
 ***************************************/

const char *
fl_show_fselector( const char * message,
                   const char * dir,
                   const char * pat,
                   const char * fname )
{
    FL_OBJECT *obj;
    int i;

    fl_get_fselector_form( );

    /* Update directory only if requested dir is valid. This way, passing
       NULL for dir has the effect of keeping us where we were the last time */

    if ( fli_is_valid_dir( dir ) )
        strcpy( fs->dname, dir );

    fli_fix_dirname( fs->dname );

    *fs->filename = '\0';

    if ( pat && *pat )
        fli_sstrcpy( fs->pattern, pat, sizeof fs->pattern );

    if ( fname && *fname )
    {
        if ( strchr( fname, '/' ) )
            fli_sstrcpy( fs->filename, strrchr( fname, '/' ) + 1,
                         sizeof fs->filename );
        else
            fli_sstrcpy( fs->filename, fname, sizeof fs->filename );
    }

    for ( i = 0; i < MAX_APPBUTT; i++ )
    {
        if ( fs->appcb[ i ] && fs->applabel[ i ][ 0 ] )
        {
            fl_set_object_label( fs->appbutt[ i ], fs->applabel[ i ] );
            fl_set_object_callback( fs->appbutt[ i ], appbutton_cb, i );
            fl_show_object( fs->appbutt[ i ] );
        }
        else
            fl_hide_object( fs->appbutt[ i ] );
    }

    /* Check cache settings */

    fl_fit_object_label( fs->resbutt, 1, 1 );

    /* If selection call back exists, cancel has no meaning as whenever a file
       is selected a callback is executed and there is no backing out */

    if ( ! ( fs->fselect_cb || fs->fselect->attached ) )
    {
        fl_deactivate_all_forms( );
        fs->fselect->sort_of_modal = 1;
    }

    fl_set_object_label( fs->prompt, message );
    fl_set_input( fs->input, fs->filename );
    fl_set_object_label( fs->patbutt, fs->pattern );
    fl_set_object_label( fs->dirbutt, contract_dirname( fs->dname, 38 ) );

    /* Fill the browser */

    fill_entries( fs->browser, fs->filename, 1 );

    if ( fs->cancel->lsize != FL_DEFAULT_SIZE )
        fl_fit_object_label( fs->cancel, 16, 1 );

    /* If attached to another form, don't show the form. The parent will
       handle it */

    if ( fs->fselect->attached )
        return "";

    if ( ! fs->fselect->visible )
    {
        fl_set_form_minsize( fs->fselect, fs->fselect->w, fs->fselect->w );
        fl_show_form( fs->fselect, fs->place, fs->border,
                      fs->fselect->label );
    }
    else
        fl_redraw_form( fs->fselect );

    do
    {
        const char *tmp = NULL;

        obj = fl_do_only_forms( );

        if ( obj == fs->ready && ( tmp = fl_get_input( fs->input ) ) && *tmp )
        {
            if ( *tmp != '/' && *tmp != '~' )
            {
                strncat( append_slash( fs->dname ), tmp, sizeof fs->dname - 1 );
                fs->dname[ sizeof fs->dname - 1 ] = '\0';
            }
            else
                fli_sstrcpy( fs->dname, tmp, sizeof fs->dname );

            fli_fix_dirname( fs->dname );

            if ( fs->fselect_cb )
                fs->fselect_cb( fs->dname, fs->callback_data );

            if ( fli_is_valid_dir( fs->dname ) )
            {
                fill_entries( fs->browser, 0, 1 );
                fl_set_input( fs->input, "" );
                fl_set_focus_object( fs->input->form, fs->input );
                obj = NULL;
            }
            else
            {
                char *p;

                while ( ( p = strrchr( fs->dname, '/' ) ) )
                {
                    *p = '\0';
                    if ( fli_is_valid_dir( fs->dname ) )
                        break;
                }
            }
        }
    } while (    obj != fs->cancel
              && (    obj != fs->ready
                   || fs->fselect_cb
                   || fs->fselect->attached ) );

    fl_hide_form( fs->fselect );

    if ( ! ( fs->fselect_cb || fs->fselect->attached ) )
    {
        fl_activate_all_forms( );
        fs->fselect->sort_of_modal = 0;
    }

    /* Do we really want to remove the fselect_cb ? Previous version did, so
       keep the way it was */

    fl_set_fselector_callback( NULL, NULL );
    fs->place = FL_PLACE_FREE_CENTER;
    return ( obj == fs->cancel || fs->fselect_cb ) ? NULL : cmplt_name( );
}


/***************************************
 ***************************************/

const char *
fl_get_directory( void )
{
    if ( ! fs )
        allocate_fselector( 0 );

    return fs->dname;
}


/***************************************
 ***************************************/

const char *
fl_get_pattern( void )
{
    if ( ! fs )
        allocate_fselector( 0 );

    return fs->pattern;
}


/***************************************
 ***************************************/

const char *
fl_get_filename( void )
{
    if ( ! fs )
        allocate_fselector( 0 );

    return fs->filename;
}


/***************************************
 ***************************************/

static void
rescan_cb( FL_OBJECT * ob,
           long        arg  FL_UNUSED_ARG )
{
    FD_fselect *lfs = ob->form->fdui;

    lfs->rescan = 1;
    fill_entries( lfs->browser, lfs->filename, 1 );
    lfs->rescan = 0;
}


/***************************************
 ***************************************/

void
fl_refresh_fselector( void )
{
    rescan_cb( fs->resbutt, 0 );
}


/******************************************************************
 * Contract dirname from /usr/people/xxx to ~/ to save some length.
 * Also replace the middle part of a path with X if the path is longer
 * than limit. Useful when indicator is of limited length
 ******************************************************************/

static void
pat_replace( char         str[ ],
             const char * pat,
             const char * rep )
{
    char *t, *d;

    if ( ! ( t = strstr( str, pat ) ) )
        return;

    d = fl_strdup( t + strlen( pat ) );
    *t = '\0';
    strcat( str, rep );
    strcat( str, d );
    fl_free( d );
}


/***************************************
 ***************************************/

static const char *
contract_dirname( const char * dir,
                  int          limit )
{
    static char buf[ FL_PATH_MAX ];
    const char *home = getenv( "HOME" );
    char *p,
         *q;
    FL_OBJECT *ob = fs->dirbutt;
    int l,
        len;

    if ( fl_get_string_width( ob->lstyle, ob->lsize,
                              dir, strlen( dir ) ) < ob->w - 4 )
        return dir;

    strcpy( buf, dir );

    if ( home )
        pat_replace( buf, home, "~" );

    if ( fl_get_string_width( ob->lstyle, ob->lsize, buf,
                              strlen( buf ) ) < ob->w - 4 )
        return buf;

    /* Try to replace middle components with ... */

    if ( ( l = strlen( buf ) ) > limit )
    {
        int k = limit / 3 - 3;

        if ( ( p = strchr( buf + k, '/' ) ) )
        {
            q = buf + l - k;
            while ( *q != '/' && q > buf )
                q--;

            if ( q > p + 3 )
            {
                *++p = '.';
                *++p = '.';
                *++p = '.';
                *++p = '\0';
                memmove( p, q, strlen( q ) + 1 );
            }
        }
    }

    /* Reolacement may have been impossible or the string may still be too
       long, in this case truncate and put three dots at the end and */

    if ( strlen( buf ) > ( size_t ) limit )
    {
        p = buf + limit - 3;
        *p++ = '.';
        *p++ = '.';
        *p++ = '.';
        *p = '\0';
    }

    len = strlen( buf );
    while (    len > 3
            && fl_get_string_width( ob->lstyle, ob->lsize,
                                    buf, len ) > ob->w - 4 )
    {
        buf[ len - 4 ] = '.';
        buf[ len - 3 ] = '.';
        buf[ len - 2 ] = '.';
        buf[ len - 1 ] = '\0';
        len--;
    }

    return buf;
}


/***************************************
 ***************************************/

static FD_fselect *
create_form_fselect( void )
{
    FL_OBJECT *obj;
    int oldy = fli_inverted_y;
    int oldunit = fl_get_coordunit( );

    fli_inverted_y = 0;
    fl_set_coordunit( FL_COORD_PIXEL );

    fs->fselect = fl_bgn_form( FL_FLAT_BOX, 305, 330 );

    fs->dirlabel = obj = fl_add_text( FL_NORMAL_TEXT, 12, 15, 64, 24,
                                      "D\010irectory" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_lalign( obj, FL_ALIGN_CENTER );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_NorthWest, FL_NorthWest );

    fs->dirbutt = obj = fl_add_button( FL_NORMAL_BUTTON, 76, 15, 217, 24, "" );
    fl_set_button_shortcut( obj, "#D#d", 1 );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_LEFT ) );
    fl_set_object_resize( obj, FL_RESIZE_X );
    fl_set_object_gravity( obj, FL_NorthWest, FL_NorthEast );
    fl_set_object_callback( obj, directory_cb, 0 );

    fs->patlabel = obj = fl_add_text( FL_NORMAL_TEXT, 12, 41, 64, 24,
                                      "P\010attern" );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_lalign( obj, FL_ALIGN_CENTER );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_NorthWest, FL_NorthWest );

    fs->patbutt = obj = fl_add_button( FL_NORMAL_BUTTON, 76, 41, 217, 24, "" );
    fl_set_button_shortcut( obj, "#P#p", 1 );
    fl_set_object_boxtype( obj, FL_FRAME_BOX );
    fl_set_object_resize(  obj, FL_RESIZE_X );
    fl_set_object_gravity( obj, FL_NorthWest, FL_NorthEast );
    fl_set_object_callback( obj, pattern_cb, 0 );

    fs->resbutt = obj = fl_add_button( FL_NORMAL_BUTTON, 210, 80, 83, 28,
                                       "Rescan" );
    fl_set_button_shortcut( obj, "#R#r", 1 );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_NorthEast, FL_NorthEast );
    fl_set_object_callback( obj, rescan_cb, 0 );

    fs->cancel = obj = fl_add_button( FL_NORMAL_BUTTON, 210, 203, 83, 28,
                                      "Cancel" );
    fl_set_button_shortcut( obj, "#C#c^[", 1 );
    fl_set_object_color( obj, FL_COL1, FL_GREEN );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_SouthEast, FL_SouthEast );

    fs->ready = obj = fl_add_button( FL_RETURN_BUTTON, 210, 233, 83, 28,
                                     "Ready" );
    fl_set_object_color( obj, FL_COL1, FL_GREEN );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_SouthEast, FL_SouthEast );

    fs->prompt = obj = fl_add_text( FL_NORMAL_TEXT, 20, 270, 264, 18,
                                    "File name:" );
    fl_set_object_lalign( obj, fl_to_inside_lalign( FL_ALIGN_LEFT ) );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_SouthWest, FL_SouthWest );

    fs->input = obj = fl_add_input( FL_NORMAL_INPUT, 30, 290, 235, 27, "" );
    fl_set_object_boxtype( obj, FL_SHADOW_BOX );
    fl_set_object_color( obj, FL_WHITE, FL_WHITE );
    fl_set_object_resize( obj, FL_RESIZE_X );
    fl_set_object_gravity( obj, FL_SouthWest, FL_SouthEast );
    fl_set_object_callback( obj, input_cb, 0 );
    fl_set_object_return( obj, FL_RETURN_CHANGED );

    fs->browser = obj = fl_add_browser( FL_HOLD_BROWSER, 15, 80, 185, 180, "" );
    fl_set_object_callback( obj, select_cb, 0 );
    fl_set_browser_dblclick_callback( obj, select_cb, 1 );
    fl_set_object_resize( obj, FL_RESIZE_ALL );
    fl_set_object_gravity( obj, FL_NorthWest, FL_SouthEast );
    obj->click_timeout = FL_CLICK_TIMEOUT;

    fs->appbuttgrp = fl_bgn_group( );

    fs->appbutt[ 0 ] = fl_add_button( FL_NORMAL_BUTTON, 210, 114, 83, 28, "" );
    fs->appbutt[ 1 ] = fl_add_button( FL_NORMAL_BUTTON, 210, 142, 83, 28, "" );
    fs->appbutt[ 2 ] = fl_add_button( FL_NORMAL_BUTTON, 210, 170, 83, 28, "" );

    fl_end_group( );

    fl_end_form( );

    fs->fselect->fdui = fs;
    fs->fselect->pre_attach = pre_attach;

    fl_set_form_atclose( fs->fselect, fl_goodies_atclose, fs->cancel );

    fli_inverted_y = oldy;
    fl_set_coordunit( oldunit );

    /* These labels sometimes don't fit the above set sizes, so we
       resize the whole file selector box to make them fit */

    fl_fit_object_label( fs->dirlabel, 0, 0 );
    fl_fit_object_label( fs->resbutt, 0, 0 );

    return fs;
}


/***************************************
 ***************************************/

void
fl_set_fselector_filetype_marker( int dir,
                                  int fifo,
                                  int sock,
                                  int cdev,
                                  int bdev )
{
    dirmarker  = dir;
    fifomarker = fifo;
    cdevmarker = cdev;
    bdevmarker = bdev;
    sockmarker = sock;
}


/***************************************
 ***************************************/

void
fl_set_fselector_fontsize( int fsize )
{
    int i;

    if ( ! fs )
        allocate_fselector( 0 );

    fl_freeze_form( fs->fselect );

    fl_set_object_lsize( fs->input,    fsize );
    fl_set_object_lsize( fs->prompt,   fsize );
    fl_set_object_lsize( fs->patbutt,  fsize );
    fl_set_object_lsize( fs->dirbutt,  fsize );
    fl_set_object_lsize( fs->resbutt,  fsize );
    fl_set_object_lsize( fs->cancel,   fsize );
    fl_set_object_lsize( fs->dirlabel, fsize );
    fl_set_object_lsize( fs->patlabel, fsize );
    fl_set_object_lsize( fs->ready,    fsize );
    fl_set_browser_fontsize( fs->browser, fsize );

    for ( i = 0; i < MAX_APPBUTT; i++ )
        fl_set_object_lsize( fs->appbutt[ i ], fsize );

    fl_fit_object_label( fs->dirlabel, 0, 0 );
    fl_fit_object_label( fs->resbutt, 0, 0 );

    fl_unfreeze_form( fs->fselect );
}


/***************************************
 ***************************************/

void
fl_set_fselector_fontstyle( int fstyle )
{
    int i;

    if ( ! fs )
        allocate_fselector( 0 );

    fl_freeze_form( fs->fselect );

    fl_set_object_lstyle( fs->input,    fstyle );
    fl_set_object_lstyle( fs->prompt,   fstyle );
    fl_set_object_lstyle( fs->patbutt,  fstyle );
    fl_set_object_lstyle( fs->dirbutt,  fstyle );
    fl_set_object_lstyle( fs->resbutt,  fstyle );
    fl_set_object_lstyle( fs->cancel,   fstyle );
    fl_set_object_lstyle( fs->dirlabel, fstyle );
    fl_set_object_lstyle( fs->patlabel, fstyle );
    fl_set_object_lstyle( fs->ready,    fstyle );
    fl_set_browser_fontstyle( fs->browser, fstyle );

    for ( i = 0; i < MAX_APPBUTT; i++ )
        fl_set_object_lstyle( fs->appbutt[ i ], fstyle );

    fl_fit_object_label( fs->dirlabel, 0, 0 );
    fl_fit_object_label( fs->resbutt, 0, 0 );

    fl_unfreeze_form( fs->fselect );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
