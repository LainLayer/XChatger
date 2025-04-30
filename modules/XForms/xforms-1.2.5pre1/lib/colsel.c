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
 * \file colsel.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Select a color
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


typedef struct
{
     FL_FORM *   colorform;
     FL_OBJECT * col[ 64 ];
     FL_OBJECT * next,
               * prev,
               * cancel;
     FL_OBJECT * cindex;
} COLSEL;


static COLSEL colsel;
static COLSEL *cs = &colsel;


/***************************************
 ***************************************/

static void
create_colorform( void )
{
    int i, j;

    if ( cs->colorform )
        return;

    cs->colorform = fl_bgn_form( FL_UP_BOX, 240, 220 );

    for ( i = 0; i < 8; i++ )
        for ( j = 0; j < 8; j++ )
        {
            cs->col[ 8 * i + j ] = fl_add_button( FL_NORMAL_BUTTON, 40 + j * 20,
                                                  10 + i * 20, 20, 20, "" );
            fl_set_object_boxtype( cs->col[ 8 * i + j ], FL_BORDER_BOX );
            fl_set_object_lcolor( cs->col[ 8 * i + j ], 7 );
        }

    cs->prev = fl_add_button( FL_NORMAL_BUTTON, 10, 10, 30, 160, "@4" );
    cs->next = fl_add_button( FL_NORMAL_BUTTON, 200, 10, 30, 160, "@6" );
    cs->cancel = fl_add_button( FL_NORMAL_BUTTON, 80, 180, 140, 30, "Cancel" );
    cs->cindex = fl_add_text( FL_NORMAL_TEXT, 5, 180, 70, 30, "Cancel" );
    fl_set_object_lsize( cs->cindex,FL_TINY_SIZE );
    fl_end_form( );
}


extern int flrectboundcolor;


/***************************************
 * initializes the colors
 ***************************************/

static void
init_colors( int cc,
             int thecol )
{
    int i;
    const char *cn;

    fl_freeze_form( cs->colorform );
    for ( i = 0; i < 64; i++ )
    {
        fl_set_object_color( cs->col[ i ], cc + i, cc + i );
        fl_set_object_label( cs->col[ i ], "" );
        if ( thecol == cc + i )
            fl_set_object_label( cs->col[ i ], "@9plus" );
    }

    cn = fli_query_colorname( thecol );
    fl_set_object_label( cs->cindex, cn + ( cn[ 0 ] == 'F' ? 3 : 0 ) );
    fl_unfreeze_form( cs->colorform );
}


/***************************************
 ***************************************/

static int
atclose( FL_FORM * form,
         void *    ev  FL_UNUSED_ARG )
{
    fl_trigger_object( form->u_vdata );
    return FL_IGNORE;
}


/***************************************
 * Shows a colormap color selector from which the user can select a color.
 ***************************************/

int
fl_show_colormap( int oldcol )
{
    FL_OBJECT *ob;
    int i,
        cc,
        ready = 0,
        thecol;
    int s =  flrectboundcolor;

    flrectboundcolor = FL_BOTTOM_BCOL;

    if ( oldcol == FL_NoColor )
        oldcol = FL_COL1;

    cc = 64 * ( oldcol / 64 );
    thecol = oldcol;

    create_colorform( );
    cs->colorform->u_vdata = cs->cancel;
    fl_set_form_atclose( cs->colorform, atclose, 0 );
    init_colors( cc, thecol );
    fl_set_object_color( cs->cancel, thecol, thecol );
    fl_deactivate_all_forms( );

    fl_show_form( cs->colorform, FL_PLACE_ASPECT, FL_TRANSIENT, "Colormap" );

    while ( ! ready )
    {
        ob = fl_do_only_forms( );
        if ( ob == cs->prev && cc >= 64 )
        {
            cc -= 64;
            init_colors( cc, thecol );
        }
        else if ( ob == cs->next && cc + 64 < FL_MAX_COLS )
        {
            cc += 64;
            init_colors( cc, thecol );
        }
        else if ( ob == cs->cancel )
            ready = 1;
        else
            for ( i = 0; i < 64; i++ )
                if ( ob == cs->col[ i ] )
                {
                    ready = 1;
                    thecol = cc + i;
                }
    }
    fl_hide_form( cs->colorform );
    fl_activate_all_forms( );
    flrectboundcolor = s;
    return thecol;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
