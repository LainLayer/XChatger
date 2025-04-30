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
 * \file fd_pallette.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  handles the object pallette
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd/pallette.h"

#include <stdlib.h>

static FD_pmain *pmain;

typedef struct {
    FL_OBJECT * ob;        /* the object (radio button) handle */
    int         cls;       /* the obj class it represents      */
} Entry;

static Entry *entries;
static int nentries;


/***************************************
 ***************************************/

static void
init_entry_table( FL_FORM * form )
{
    FL_OBJECT *ob;
    int i;

    if ( ! entries )
        entries = fl_calloc( 1, MAXCLASSES * sizeof *entries );

    /* we obtain the class by looking at the callback function */

    for ( i = 0, ob = form->first; i < MAXCLASSES && ob; ob = ob->next, i++ )
        if ( ob->object_callback )
        {
            entries[ nentries ].ob = ob;
            entries[ nentries ].cls = ob->argument;
            nentries++;
        }

    if ( i >= MAXCLASSES )
        fprintf( stderr, "fd_pallette - Internal Error: MAXCLASSES "
                 "too small?\n");
}


/***************************************
 ***************************************/

static FL_FORM *
create_all( void )
{
    FD_buttform *bf;
    FD_staticform *sf;
    FD_valuatorform *vf;
    FD_choiceform *cf;
    FD_miscform *mf;

    if ( pmain )
        return pmain->pmain;

    pmain = create_form_pmain( );
    bf = create_form_buttform( );
    sf = create_form_staticform( );
    vf = create_form_valuatorform( );
    cf = create_form_choiceform( );
    mf = create_form_miscform( );

    fl_addto_tabfolder( pmain->folder, " Static ", sf->staticform );
    init_entry_table( sf->staticform );
    fl_addto_tabfolder( pmain->folder, " Button ", bf->buttform );
    init_entry_table( bf->buttform );
    fl_addto_tabfolder( pmain->folder, " Valuator ", vf->valuatorform );
    init_entry_table( vf->valuatorform );
    fl_addto_tabfolder( pmain->folder, " Choice ", cf->choiceform );
    init_entry_table( cf->choiceform );
    fl_addto_tabfolder( pmain->folder, " Misc. ", mf->miscform );
    init_entry_table( mf->miscform );

    return pmain->pmain;
}


/***************************************
 ***************************************/

void
dismiss_pallete( FL_OBJECT * ob,
                 long        data  FL_UNUSED_ARG )
{
    fl_hide_form( ob->form );
    reset_pallette_menu_status( );
}


/***************************************
 ***************************************/

void
hide_pallette( void )
{
    FL_FORM *form = create_all( );

    if ( form->visible )
        fl_hide_form( form );
}


/***************************************
 ***************************************/

void
show_pallette( void )
{
    FL_FORM *form = create_all( );
    static int first = 1;

    if ( first )
    {
        fl_set_form_position( form, -form->w - 50, 20 );
        first = 0;
    }

    select_pallette_entry( cur_class );

    fl_show_form( form, FL_PLACE_POSITION, FL_TRANSIENT, "Pallette" );
}


/***************************************
 * All pallette entries are radio buttons
 ***************************************/

void
pallette_entry_callback( FL_OBJECT * ob,
                         long        data )
{
    if ( pmain->vdata && ( ( FL_OBJECT * ) pmain->vdata )->form != ob->form )
        fl_set_button( pmain->vdata, 0 );

    pmain->vdata = ob;
    pmain->ldata = data;

    /* selects the object in the object browser */

    select_object_by_class( data );
}


/***************************************
 ***************************************/

void
reset_pallette( void )
{
    if ( pmain && pmain->vdata )
    {
        fl_set_button( pmain->vdata, 0 );
        pmain->vdata = 0;
    }
}


/***************************************
 * This function will be called on object class browser (de)selections
 ***************************************/

void
select_pallette_entry( int cls )
{
    int i;

    if ( ! entries || cls < 0 )
        return;

    for ( i = 0; i < nentries; i++ )
        if ( entries[ i ].cls == cls )
        {
            fl_set_folder( pmain->folder, entries[ i ].ob->form );
            fl_set_button( entries[ i ].ob, 1 );
            break;
        }
}


#include "fd/pallette.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
