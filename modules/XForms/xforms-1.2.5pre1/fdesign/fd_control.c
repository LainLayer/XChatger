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
 * \file fd_control.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Form designer Control panel handling
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd/ui_theforms.h"
#include "private/pmenu.h"
#include "private/pchoice.h"

/* All control panel menus, File Object Options etc. have this
 * common structures
 */

typedef struct {
    const char * entry;     /* label     */
    const char * sc;        /* shortcut  */
    void         ( * callback )( FL_OBJECT *,   /* callback functions */
                                 long );
    int          n;         /* func_cb parameter */
    int        * p;         /* binary value      */
} MenuEntry;

extern void exit_cb( FL_OBJECT *,
                     long );
extern void saveforms_cb( FL_OBJECT *,
                          long );

/**** FileMenu ******{*/

static MenuEntry fmenu[ ] =
{
    { " Open",       "Oo#o", loadforms_cb,    0, 0 },
    { " Merge",      "Mm#m", mergeforms_cb,   0, 0 },
    { " Save",       "Ss#s", saveforms_cb,    0, 0 },
    { " Save As %l", "Aa#a", saveforms_as_cb, 0, 0 },
    { " Exit",       "Ee#e", exit_cb,         0, 0 }
};

#define NFM  ( sizeof fmenu / sizeof *fmenu )


/***************************************
 ***************************************/

void
filemenu_callback( FL_OBJECT * ob,
                   long        data  FL_UNUSED_ARG )
{
    int n = fl_get_menu( ob ) - 1;

    if ( n >= 0 && fmenu[ n ].callback )
        fmenu[ n ].callback( 0, 0 );
}


/***************************************
 * Exit the program
 ***************************************/

void
exit_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
         long        arg  FL_UNUSED_ARG )
{
    if ( changed )
    {
        int rep;

        fl_set_choices_shortcut( "Ss#s", "Ee#e", "Rr#r" );
        rep = fl_show_choice( "WARNING", "", "Changes have not been saved.",
                              3, "Save", "Exit", "Return", 1 );
        if ( ( rep == 1 && ! save_forms( NULL ) ) || rep == 3 )
            return;
    }

    fl_finish( );
    exit( 0 );
}


/***************************************
 * Merge a set of forms with the current ones.
 ***************************************/

void
mergeforms_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
               long        arg  FL_UNUSED_ARG )
{
    load_forms( FL_TRUE, NULL );
}


/***************************************
 * Save the current set of forms.
 ***************************************/

void
saveforms_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        arg  FL_UNUSED_ARG )
{
    changed = ! save_forms( loadedfile);
}


/***************************************
 ***************************************/

void
saveforms_as_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
                 long        arg  FL_UNUSED_ARG )
{
    changed = ! save_forms( NULL );
}


/***************************************
 * Load a new set of forms from a file
 ***************************************/

void
loadforms_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        arg  FL_UNUSED_ARG )
{
    if (    changed
         && fl_show_question( "Forms have been changed!\n"
                              "Should I save them?", 1 )
         && ! save_forms( NULL ) )
        return;

    load_forms( FL_FALSE, NULL );
}


/***** End of FileMenu *****/

/* Group Menu entry */

static MenuEntry gmenu[ ] =
{
    { "New group",    "Nn#n", NULL,               7, 0 },
    { "Delete Group", "Dd#d", NULL,               8, 0 },
    { "Rename Group", "Rr#r", changegroupname_cb, 0, 0 }
};

#define NGM ( sizeof gmenu / sizeof *gmenu )


/***************************************
 ***************************************/

void
groupmenu_callback( FL_OBJECT * ob,
                    long        data  FL_UNUSED_ARG )
{
    int n = fl_get_menu( ob ) - 1;

    if ( n >= 0 )
    {
        if ( gmenu[ n ].callback )
            gmenu[ n ].callback( 0, 0 );
        else
            func_cb( 0, gmenu[ n ].n );
    }
}


/* Object menu entry */

static MenuEntry obmenu[ ] =
{
    { "Object Attributes", "Oo#o", 0,  1, 0 },
    { "Lower Object",      "Ll#l", 0,  2, 0 },
    { "Raise Object",      "Rr#r", 0,  3, 0 },
    { "Show Object",       "Ss#s", 0,  5, 0 },
    { "Hide Object",       "Hh#h", 0,  6, 0 },
    { "Cut Object",        "Cc#c", 0, 12, 0 },
    { "Paste Object",      "Pp#p", 0, 10, 0 }
};

#define NOBM  ( sizeof obmenu / sizeof *obmenu )


/***************************************
 ***************************************/

void
objectmenu_callback( FL_OBJECT * ob,
                     long        data  FL_UNUSED_ARG )
{
    int n = fl_get_menu( ob ) - 1;

    if ( n >= 0 )
        func_cb( 0, obmenu[ n ].n );
}


/* form menu entry */

static MenuEntry fmmenu[ ] =
{
    { "New Form",    "Nn#n", addform_cb,    0, 0 },
    { "Delete Form", "Dd#d", deleteform_cb, 0, 0 },
    { "Rename Form", "Rr#r", changename_cb, 0, 0 },
    { "Resize Form", "Ss#s", changesize_cb, 0, 0 }
};

#define NFMM ( sizeof fmmenu / sizeof *fmmenu )


/***************************************
 ***************************************/

void
formmenu_callback( FL_OBJECT * ob,
                   long        data  FL_UNUSED_ARG )
{
    int n = fl_get_menu( ob ) - 1;

    if ( n >= 0 && fmmenu[ n ].callback )
        fmmenu[ n ].callback( 0, 0 );
}


/* Option menu */

static MenuEntry opmenu[ ] =
{
    { "Track Geometry",  "Gg#g", 0, 0, &fd_trackgeometry },
    { "Show Pallette",   "Pp#p", 0, 0, &fd_show_palette  },
    { "Emit %s UI code", "Ee#e", 0, 0, &fdopt.emit_code  },
    { "Emit Callback",   "Cc#c", 0, 0, &fdopt.emit_cb    },
    { "Emit Main",       "Mm#m", 0, 0, &fdopt.emit_main  },
    { "Alt Format",      "Aa#a", 0, 0, &fdopt.altformat  },
    { "FS Compensate ",  "Ff#f", 0, 0, &fdopt.compensate }
};

#define NOPM ( sizeof opmenu / sizeof *opmenu )


/***************************************
 ***************************************/

void
optionmenu_callback( FL_OBJECT * ob,
                     long        data  FL_UNUSED_ARG )
{
    int n = fl_get_menu( ob ) - 1;
    char buf[ 32 ];

    if ( n >= 0 )
    {
        *opmenu[ n ].p = ! *opmenu[ n ].p;
        sprintf( buf, "%s%%%c", opmenu[ n ].entry,
                 *opmenu[ n ].p ? 'B' : 'b' );
        fl_replace_menu_item( fd_control->optionmenu, n + 1, buf );
        ( fd_show_palette ? show_pallette : hide_pallette )( );
    }
}


/***************************************
 ***************************************/

void
reset_pallette_menu_status( void)
{
    fl_set_menu_item_mode( fd_control->optionmenu, 2, FL_PUP_BOX );
    fd_show_palette = 0;
}


/***************************************
 ***************************************/

static void
deactivate_control( FL_FORM * form  FL_UNUSED_ARG,
                    void    * data  FL_UNUSED_ARG )
{
    fl_set_object_lcolor( fd_control->title, FL_SLATEBLUE );
    fl_set_object_lcolor( fd_control->menubar_group, FL_INACTIVE );
    fl_set_object_lcolor( fd_control->shortcut_group, FL_INACTIVE );
    fl_set_object_lcolor( fd_control->fkey_group, FL_INACTIVE );
}


/***************************************
 ***************************************/

static void
activate_control( FL_FORM * form  FL_UNUSED_ARG,
                  void    * data  FL_UNUSED_ARG )
{
    fl_set_object_lcolor( fd_control->title, FL_BLUE );
    fl_set_object_lcolor( fd_control->menubar_group, FL_BLACK );
    fl_set_object_lcolor( fd_control->shortcut_group, FL_BLACK );
    fl_set_object_lcolor( fd_control->fkey_group, FL_BLACK );
}


/***************************************
 * Initialize the control panel by filling in the menu entries
 ***************************************/

void
control_init( FD_control * ui )
{
    static int control_initialized;
    MenuEntry *m,
              *me;
    char buf[ 32 ];
    int i;

    if ( control_initialized )
        return;

    control_initialized = 1;

#ifdef __sgi
    fl_set_object_lsize( ui->filemenu,   FL_SMALL_SIZE );
    fl_set_object_lsize( ui->formmenu,   FL_SMALL_SIZE );
    fl_set_object_lsize( ui->groupmenu,  FL_SMALL_SIZE );
    fl_set_object_lsize( ui->objectmenu, FL_SMALL_SIZE );
    fl_set_object_lsize( ui->optionmenu, FL_SMALL_SIZE );
#endif

    fl_set_form_atdeactivate( ui->control, deactivate_control, ui );
    fl_set_form_atactivate( ui->control, activate_control, ui );

    fl_set_object_dblbuffer( ui->seltype,    1 );
    fl_set_object_dblbuffer( ui->selname,    1 );
    fl_set_object_dblbuffer( ui->selcb,      1 );
    fl_set_object_dblbuffer( ui->sizestatus, 1 );
    fl_set_object_dblbuffer( ui->oristatus,  1 );

    /* File menu */

    for ( m = fmenu, me = m + NFM, i = 1; m < me; m++, i++ )
    {
        fl_addto_menu( ui->filemenu, m->entry );
        fl_set_menu_item_shortcut( ui->filemenu, i, m->sc );
    }

    /* Form menu */

    for ( m = fmmenu, me = m + NFMM, i = 1; m < me; m++, i++ )
    {
        fl_addto_menu( ui->formmenu, m->entry );
        fl_set_menu_item_shortcut( ui->formmenu, i, m->sc );
    }

    /* Group menu */

    for ( m = gmenu, me = m + NGM, i = 1; m < me; m++, i++ )
    {
        fl_addto_menu( ui->groupmenu, m->entry );
        fl_set_menu_item_shortcut( ui->groupmenu, i, m->sc );
    }

    /* Object menu */

    for ( m = obmenu, me = m + NOBM, i = 1; m < me; m++, i++ )
    {
        fl_addto_menu( ui->objectmenu, m->entry );
        fl_set_menu_item_shortcut( ui->objectmenu, i, m->sc );
    }

    /* Option menu.  all are binary items */

    for ( m = opmenu, me = m + NOPM, i = 1; m < me; m++, i++ )
    {
        if ( strncmp( m->entry, "Emit %s", 7 ) == 0 )
        {
            static char tmpbuf[ 128 ];

            sprintf( tmpbuf, m->entry, convertor[ fdopt.language ].lang_name );
            m->entry = tmpbuf;
        }

        sprintf( buf, "%s%%%c", m->entry, * ( m->p ) ? 'B' : 'b' );
        fl_addto_menu( ui->optionmenu, buf );
        fl_set_menu_item_shortcut( ui->optionmenu, i, m->sc );
    }
}


/* Misc. service routines */

/***************************************
 ***************************************/

void
show_geometry( FL_Coord     x,
               FL_Coord     y,
               FL_Coord     w,
               FL_Coord     h )
{
    char buf[ 128 ];
    static FL_Coord lx = -1,
                    ly,
                    lw = -1,
                    lh;

    /* Canonicalize rectangle */

    if ( w < 0 )
    {
        x += w;
        w = -w;
    }

    if ( h < 0 )
    {
        y += h;
        h = -h;
    }

    if ( x != lx || y != ly )
    {
        sprintf( buf, "%dx%d", x, y );
        fl_set_object_label( fd_control->oristatus, buf );
        lx = x;
        ly = y;
    }

    if ( w != lw || h != lh )
    {
        sprintf( buf, "%dx%d", w, h );
        fl_set_object_label( fd_control->sizestatus, buf );
        lw = w;
        lh = h;
    }
}


/***************************************
 ***************************************/

void
show_selmessage( FL_OBJECT * sel[ ],
                 int         n )
{
    char objname[ MAX_VAR_LEN ],
         cbname[ MAX_VAR_LEN ],
         argname[ MAX_VAR_LEN ];
    char buf[ MAX_VAR_LEN ];

    get_object_name( sel[ 0 ], objname, cbname, argname );
    *buf = '\0';

    if ( n == 1 )
        sprintf( buf, "%s",
                 find_type_name( sel[ 0 ]->objclass, sel[ 0 ]->type ) );
    else
    {
        int cnt = n,
            i;

        for ( i = 0; i < n; i++ )
            if (    sel[ i ]->objclass == FL_BEGIN_GROUP
                 || sel[ i ]->objclass == FL_END_GROUP )
                cnt--;

        sprintf( buf, "%d object selected", cnt );
    }

    fl_set_object_label( fd_control->seltype, buf );

    if ( n == 1 )
        sprintf( buf, "%s", *objname ? objname : "<no name>" );
    else
        *buf = '\0';

    fl_set_object_label( fd_control->selname, buf );

    if ( n == 1 )
    {
        if ( * cbname )
            sprintf( buf, "%s(%s)", cbname, argname );
        else
            strcpy( buf, "<no callback>" );
    }
    else
        *buf = '\0';

    fl_set_object_label( fd_control->selcb, buf );
}


/********* Callback routines for the control panel  ***************/

/*
 * Form designer itself does not use resource settings, but when testing
 * the newly created forms, resources are turned on. At the moment we
 * only allow button label size to be changed
 */

FL_FORM *thetestform;

typedef struct {
    int x,
        y,
        w,
        h;
} GEOM;

static short *osize = NULL;
static GEOM *oldgeom = NULL;
static FL_Coord formw,
                formh;           /* original form size */


/***************************************
 ***************************************/

static void
fix_button_label_size( FL_FORM * form,
                       int       save )
{
    FL_OBJECT *ob;
    int i;

    if ( fd_buttonLabelSize == 0 )
        return;

    if ( save )
    {
        for ( i = 0, ob = form->first; ob; ob = ob->next )
            if ( ob->objclass == FL_BUTTON )
                i++;

        osize = fl_realloc( osize, i * sizeof *osize );
    }

    for ( i = 0, ob = form->first; ob; ob = ob->next )
    {
        if ( ob->objclass == FL_BUTTON )
        {
            if ( save )
            {
                osize[ i++ ] = ob->lsize;
                if ( ob->lsize == FL_NORMAL_FONT )
                    ob->lsize = fd_buttonLabelSize;
            }
            else
                ob->lsize = osize[ i++ ];
        }
    }

    if ( ! save )
        fli_safe_free( osize );
}


/***************************************
 ***************************************/

static void
fix_menu_etc( FL_FORM * form,
              int       save )
{
    FL_OBJECT *ob;
    int i;

    for ( ob = form->first; ob; ob = ob->next )
    {
        if (    ob->objclass != FL_MENU
             && ob->objclass != FL_CHOICE
             && ob->objclass != FL_BROWSER
             && ! ISBUTTON( ob->objclass ) )
            continue;

        if ( ob->objclass == FL_MENU )
        {
            FLI_MENU_SPEC *sp = ob->spec;

            if ( save )
            {
                if ( sp->numitems > 0 )
                    for ( i = 1; i <= sp->numitems; i++ )
                        fli_safe_free( sp->cb[ i ] );
                else
                {
                    fl_addto_menu( ob, "menuitem 1" );
                    fl_addto_menu( ob, "menuitem 2" );
                    fl_addto_menu( ob, "menuitem 3" );
                    fl_addto_menu( ob, "menuitem 4" );
                }
            }
            else
            {
                SuperSPEC *ssp = get_superspec( ob );

                if ( sp->numitems == ssp->nlines )
                    for ( i = 1; i <= sp->numitems; i++ )
                        if ( ssp->callback[ i ] )
                            sp->cb[ i ] =
                                  ( FL_PUP_CB ) fl_strdup( ssp->callback[ i ] );
                        else
                            sp->cb[ i ] = NULL;
                else
                    fl_clear_menu( ob );
            }
        }
        else if ( ob->objclass == FL_CHOICE )
        {
            FLI_CHOICE_SPEC *sp = ob->spec;

            if ( save )
            {
                if ( sp->numitems == 0 )
                {
                    fl_addto_choice( ob, "choice 1" );
                    fl_addto_choice( ob, "choice 2" );
                    fl_addto_choice( ob, "choice 3" );
                    fl_addto_choice( ob, "choice 4" );
                }
            }
            else
            {
                SuperSPEC *ssp = get_superspec( ob );

                if ( sp->numitems != ssp->nlines )
                    fl_clear_choice( ob );
            }
        }
        else if ( ob->objclass == FL_BROWSER )
        {
            int nlines = fl_get_browser_maxline( ob );

            if ( save )
            {
                if ( nlines == 0 )
                {
                    char buf[ 100 ];

                    for ( i = 0; i < 20; i++ )
                    {
                        sprintf( buf, "browser line %d", i + 1 );
                        fl_add_browser_line( ob, buf );
                    }
                }
            }
            else
            {
                SuperSPEC *ssp = get_superspec( ob );

                if ( nlines != ssp->nlines )
                    fl_clear_browser( ob );
            }
        }
        else if ( ISBUTTON( ob->objclass ) )
        {
            if ( save )
                ob->u_ldata = ( ( FL_BUTTON_SPEC * ) ob->spec )->val;
            else
                ( ( FL_BUTTON_SPEC * ) ob->spec )->val = ob->u_ldata;
        }
    }
}


/***************************************
 * Start a test of the current form
 ***************************************/

void
test_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
         long        arg  FL_UNUSED_ARG )
{
    int i;
    FL_OBJECT *ob;
    GEOM *p;
    int resizeable;

    if ( cur_form == NULL )
        return;

    fl_deactivate_form( fd_control->control );
    thetestform = cur_form;

    /* During test, accumulation error might result. Save the old size */

    formw = cur_form->w;
    formh = cur_form->h;

    for ( i = 0, ob = cur_form->first; ob; ob = ob->next, i++ )
        /* empty */ ;

    p = oldgeom = fl_realloc( oldgeom, i * sizeof *p );

    for ( ob = cur_form->first; ob; ob = ob->next, i++, p++ )
    {
        if ( ! ob->parent )
            spec_to_superspec( ob );

        p->x = ob->x;
        p->y = ob->y;
        p->w = ob->w;
        p->h = ob->h;
    }

    /* Change button label size to the one requested */

    fix_button_label_size( thetestform, 1 );

    fix_menu_etc( thetestform, 1 );

    cur_form = NULL;
    redraw_the_form( 1 );

    fl_clear_browser( fd_test->browser );

    resizeable = strstr( get_placement( thetestform ), "FREE" ) != NULL;

    if ( resizeable )
    {
        fl_set_form_minsize( thetestform, formw >= 10 ? formw / 2 : formw,
                             formh >= 10 ? formh / 2 : formh );
        fl_set_form_maxsize( thetestform, fl_scrw, fl_scrh );
    }
    else
    {
        fl_set_form_minsize( thetestform, formw, formh );
        fl_set_form_maxsize( thetestform, formw, formh );
    }

    fl_show_form( thetestform,
                  resizeable ? FL_PLACE_CENTERFREE : FL_PLACE_CENTER,
                  FL_FULLBORDER, "Test Form" );

    fl_show_form( fd_test->test, FL_PLACE_POSITION | FL_PLACE_FREE,
                  FL_FULLBORDER, "Test" );
}


/***************************************
 * Ends a testing session
 ***************************************/

void
stoptest_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
             long        arg  FL_UNUSED_ARG )
{
    FL_OBJECT *ob;
    GEOM *p = oldgeom;

    if ( thetestform == NULL )
        return;

    fl_hide_form( fd_test->test );
    fl_hide_form( thetestform );

    fix_button_label_size( thetestform, 0 );

    fix_menu_etc( thetestform, 0 );

    cur_form = thetestform;
    thetestform = NULL;

    fl_set_form_size( cur_form, formw, formh );

    for ( ob = cur_form->first; ob; ob = ob->next, p++ )
    {
        if ( ! ob->parent )
            superspec_to_spec( ob );

        ob->x = p->x;
        ob->y = p->y;
        ob->w = p->w;
        ob->h = p->h;
    }

    fli_safe_free( oldgeom );

    redraw_the_form( 0 );
    fl_activate_form( fd_control->control );
}


/***************************************
 * Shows the align form
 ***************************************/

void
align_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
          long        arg  FL_UNUSED_ARG )
{
    if ( fd_align->align->visible )
        fl_hide_form( fd_align->align );
    else
    {
        fl_show_form( fd_align->align, FL_PLACE_MOUSE, FL_FULLBORDER,
                      "Alignments" );
        XRaiseWindow( flx->display, fd_align->align->window );
    }
}


/***************************************
 * Stop showing the align window
 ***************************************/

void
exitalign_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        arg  FL_UNUSED_ARG )
{
    fl_hide_form( fd_align->align );
}


/***************************************
 * Does some alignment action
 ***************************************/

void
doalign_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
            long        arg )
{
    if ( fd_align->vdata )
        free_dupped_selection( fd_align->vdata );
    fd_align->vdata = dup_selection( );
    align_selection( arg );
}


/***************************************
 ***************************************/

void
undoalign_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
              long        arg  FL_UNUSED_ARG )
{
    if ( fd_align->vdata )
    {
        set_selection( fd_align->vdata );

        /* Only allow undo once */

        free_dupped_selection( fd_align->vdata );
        fd_align->vdata = NULL;
    }
}


/***************************************
 ***************************************/

void
snap_cb( FL_OBJECT * obj,
         long        arg  FL_UNUSED_ARG )
{
    set_step_size( fl_get_counter_value( obj ) );
}

/***** End of alignment stuff */


/***************************************
 * The user pressed one of the function keys while in the main form
 ***************************************/

void
func_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
         long        arg )
{
    switch ( arg )
    {
        case 1:
            change_selection( );
            redraw_the_form( 0 );
            break;

        case 2:
            lower_selection( );
            redraw_the_form( 0 );
            break;

        case 3:
            raise_selection( );
            redraw_the_form( 0 );
            break;

        case 4:
            select_all( );
            redraw_the_form( 0 );
            break;

        case 5:
            show_selection( );
            redraw_the_form( 0 );
            break;

        case 6:
            hide_selection( );
            redraw_the_form( 0 );
            break;

        case 7:
            group_selection( );
            break;

        case 8:
            flatten_selection( );
            break;

        case 9:
            copy_selection( );
            break;

        case 10:
            paste_selection( );
            redraw_the_form( 0 );
            break;

        case 11:
            next_selection( );
            break;

        case 12:
            cut_selection( );
            redraw_the_form( 0 );
            break;
    }
}


/***************************************
 ***************************************/

static void
draw_centering_symbol( FL_Coord x,
                       FL_Coord y,
                       FL_Coord w,
                       FL_Coord h,
                       int      angle,
                       FL_COLOR col )
{
    int delta = 4;

    if ( angle == 0 || angle == 180 )
    {
        fl_draw_symbol( "@->", x, y, w / 2 + delta, h, col );
        fl_draw_symbol( "@<-", x + w / 2 - delta, y, w / 2 + delta, h, col );
    }
    else
    {
        fl_draw_symbol( "@2->", x, y + 1, w, h / 2 + delta, col );
        fl_draw_symbol( "@8->", x, y + h / 2 - delta - 1,
                        w, h / 2 + delta - 1, col );
    }
}


/***************************************
 ***************************************/

void
init_align( void )
{
    fl_add_symbol( "-><-", draw_centering_symbol, 0 );
    fl_set_object_label( fd_align->hcenter, "@-><-" );
    fl_set_object_label( fd_align->vcenter, "@8-><-" );

    fl_set_object_helper( fd_align->left,    "Flush left" );
    fl_set_object_helper( fd_align->hcenter, "Center horizontally" );
    fl_set_object_helper( fd_align->hequal,  "Equal horizontal distance" );
    fl_set_object_helper( fd_align->right,   "Flush right" );
    fl_set_object_helper( fd_align->top,     "Flush top" );
    fl_set_object_helper( fd_align->bottom,  "Flush bottom" );
    fl_set_object_helper( fd_align->vcenter, "Center vertically" );
    fl_set_object_helper( fd_align->vequal,  "Equal vertical distance" );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
