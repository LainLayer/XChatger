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
 * \file fd_super.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * translation between superspec and spec
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"

#include "private/pslider.h"
#include "private/pbrowser.h"
#include "private/ppositioner.h"
#include "private/pcounter.h"
#include "private/pspinner.h"
#include "private/pscrollbar.h"
#include "private/pdial.h"
#include "private/pxyplot.h"
#include "private/pchoice.h"
#include "private/pmenu.h"
#include "private/pinput.h"


/***************************************
 ***************************************/

SuperSPEC *
get_superspec( FL_OBJECT * ob )
{
    SuperSPEC *sp = ob->u_vdata;

    return sp ? sp : spec_to_superspec( ob );
}


/***************************************
 ***************************************/

SuperSPEC *
spec_to_superspec( FL_OBJECT * obj )
{
    SuperSPEC *ssp;
    int i;
    int n;

    if ( ! obj->u_vdata )
    {
        obj->u_vdata = ssp = fl_calloc( 1, sizeof *ssp );

        ssp->content     = NULL;
        ssp->shortcut    = NULL;
        ssp->callback    = NULL;
        ssp->mode        = NULL;
        ssp->mval        = NULL;
        ssp->misc_char   = NULL;

        ssp->new_menuapi = 0;
        ssp->nlines      = 0;
    }
    else
        ssp = obj->u_vdata;

    if ( obj->objclass == FL_BROWSER )
    {
        FLI_BROWSER_SPEC *sp = obj->spec;

        ssp->h_pref = sp->h_pref;
        ssp->v_pref = sp->v_pref;

        for ( i = 1; i <= ssp->nlines; i++ )
            fl_free( ssp->content[ i ] );

        n = ssp->nlines = fl_get_browser_maxline( obj );

        ssp->content  = fl_realloc( ssp->content,
                                    ( n + 1 ) * sizeof *ssp->content );

        for ( i = 1; i <= n; i++ )
            ssp->content[ i ] = fl_strdup( fl_get_browser_line( obj, i ) );
    }
    else if ( obj->objclass == FL_CHOICE )
    {
        FLI_CHOICE_SPEC *sp = obj->spec;

        for ( i = 1; i <= ssp->nlines; i++ )
        {
            fl_free( ssp->content[ i ] );
            fl_free( ssp->shortcut[ i ] );
        }

        n = ssp->nlines = sp->numitems;

        ssp->content  = fl_realloc( ssp->content,
                                    ( n + 1 ) * sizeof *ssp->content );
        ssp->shortcut = fl_realloc( ssp->shortcut,
                                    ( n + 1 ) * sizeof *ssp->shortcut );
        ssp->mode     = fl_realloc( ssp->mode,
                                    ( n + 1 ) * sizeof *ssp->mode );

        ssp->align   = sp->align;
        ssp->int_val = sp->val;

        for ( i = 1; i <= n; i++ )
        {
            ssp->content[ i ] = fl_strdup( fl_get_choice_item_text( obj, i ) );

            if ( sp->shortcut[ i ] )
                ssp->shortcut[ i ] = fl_strdup( sp->shortcut[ i ] );
            else
                ssp->shortcut[ i ] = NULL;
        }

        memcpy( ssp->mode, sp->mode, ( n + 1 ) * sizeof *ssp->mode );

    }
    else if ( obj->objclass == FL_MENU )
    {
        FLI_MENU_SPEC *sp = obj->spec;

        for ( i = 1; i <= ssp->nlines; i++ )
        {
            fl_free( ssp->content[ i ] );
            fl_free( ssp->shortcut[ i ] );
            fl_free( ssp->callback[ i ] );
        }

        n = ssp->nlines = sp->numitems;

        ssp->content  = fl_realloc( ssp->content,
                                    ( n + 1 ) * sizeof *ssp->content );
        ssp->shortcut = fl_realloc( ssp->shortcut,
                                    ( n + 1 ) * sizeof *ssp->shortcut );
        ssp->callback = fl_realloc( ssp->callback,
                                    ( n + 1 ) * sizeof *ssp->callback );
        ssp->mode     = fl_realloc( ssp->mode,
                                    ( n + 1 ) * sizeof *ssp->mode );
        ssp->mval     = fl_realloc( ssp->mval,
                                    ( n + 1 ) * sizeof *ssp->mval );

        for ( i = 1; i <= n; i++ )
        {
            ssp->content[ i ] =
                      fl_strdup( fl_get_menu_item_text( obj, sp->mval[ i ] ) );

            if ( sp->shortcut[ i ] )
                ssp->shortcut[ i ] = fl_strdup( sp->shortcut[ i ] );
            else
                ssp->shortcut[ i ] = NULL;

            if ( sp->cb[ i ] )
                ssp->callback[ i ] = fl_strdup( ( char * ) sp->cb[ i ] );
            else
                ssp->callback[ i ] = NULL;
        }

        memcpy( ssp->mode, sp->mode, ( n + 1 ) * sizeof *ssp->mode );
        memcpy( ssp->mval, sp->mval, ( n + 1 ) * sizeof *ssp->mval );
        
    }
    else if (    obj->objclass == FL_SLIDER
              || obj->objclass == FL_VALSLIDER
              || obj->objclass == FL_THUMBWHEEL )
    {
        FLI_SLIDER_SPEC *sp = obj->spec;

        ssp->val    = sp->val;
        ssp->min    = sp->min;
        ssp->max    = sp->max;
        ssp->step   = sp->step;
        ssp->prec   = sp->prec;
        ssp->ldelta = sp->ldelta;
        ssp->rdelta = sp->rdelta;
        ssp->slsize = sp->slsize;
    }
    else if (    ISBUTTON( obj->objclass )
              || obj->objclass == FL_PIXMAP
              || obj->objclass == FL_BITMAP )
    {
        FL_BUTTON_SPEC *sp = obj->spec;

        ssp->mbuttons = 0;
        for ( i = 0; i < 5; i++ )
            if ( sp->react_to[ i ] )
                ssp->mbuttons |= 1 << i; 

        ssp->int_val = sp->val;
    }
    else if ( obj->objclass == FL_POSITIONER )
    {
        FLI_POSITIONER_SPEC *sp = obj->spec;

        ssp->xstep = sp->xstep;
        ssp->ystep = sp->ystep;
        ssp->xmin  = sp->xmin;
        ssp->xmax  = sp->xmax;
        ssp->xval  = sp->xval;
        ssp->ymin  = sp->ymin;
        ssp->ymax  = sp->ymax;
        ssp->yval  = sp->yval;
    }
    else if ( obj->objclass == FL_COUNTER )
    {
        FLI_COUNTER_SPEC *sp = obj->spec;

        ssp->val   = sp->val;
        ssp->lstep = sp->lstep;
        ssp->sstep = sp->sstep;
        ssp->min   = sp->min;
        ssp->max   = sp->max;
        ssp->prec  = sp->prec;
    }
    else if ( obj->objclass == FL_DIAL )
    {
        FLI_DIAL_SPEC *sp = obj->spec;

        ssp->min       = sp->min;
        ssp->max       = sp->max;
        ssp->val       = sp->val;
        ssp->step      = sp->step;
        ssp->thetai    = sp->thetai;
        ssp->thetaf    = sp->thetaf;
        ssp->direction = sp->direction;
    }
    else if ( obj->objclass == FL_XYPLOT )
    {
        FLI_XYPLOT_SPEC *sp = obj->spec;

        ssp->xmajor         = sp->xmajor;
        ssp->xminor         = sp->xminor;
        ssp->ymajor         = sp->ymajor;
        ssp->yminor         = sp->yminor;
        ssp->xscale         = sp->xscale;
        ssp->yscale         = sp->yscale;
        ssp->xgrid          = sp->xgrid;
        ssp->ygrid          = sp->ygrid;
        ssp->grid_linestyle = sp->grid_linestyle;
        ssp->xbase          = sp->xbase;
        ssp->ybase          = sp->ybase;
        ssp->mark_active    = sp->mark_active;
    }
    else if ( obj->objclass == FL_SCROLLBAR )
    {
        FLI_SCROLLBAR_SPEC *scbsp = obj->spec;
        FLI_SLIDER_SPEC *sp = scbsp->slider->spec;

        ssp->val    = sp->val;
        ssp->min    = sp->min;
        ssp->max    = sp->max;
        ssp->prec   = sp->prec;
        ssp->step   = sp->step;
        ssp->slsize = sp->slsize;
        ssp->ldelta = sp->ldelta;
        ssp->rdelta = sp->rdelta;
    }
    else if ( obj->objclass == FL_SPINNER )
    {
        FLI_SPINNER_SPEC *sp = obj->spec;

        ssp->val    = fl_get_spinner_value( obj );
        fl_get_spinner_bounds( obj, &ssp->min, &ssp->max );
        ssp->step   = fl_get_spinner_step( obj );
        ssp->prec   = fl_get_spinner_precision( obj );
        ssp->orient = sp->orient;
    }

    return ssp;
}


/***************************************
 ***************************************/

void *
superspec_to_spec( FL_OBJECT * obj )
{
    void *v = obj->spec;
    SuperSPEC *ssp = obj->u_vdata;
    int i = 0;

    if ( ! ssp )
        return v;

    if ( obj->objclass == FL_BROWSER )
    {
        FLI_BROWSER_SPEC *sp = obj->spec;

        fl_clear_browser( obj );

        sp->h_pref = ssp->h_pref;
        sp->v_pref = ssp->v_pref;

        for ( i = 1; i <= ssp->nlines; i++ )
            fl_addto_browser( obj, ssp->content[ i ] );
    }
    else if ( obj->objclass == FL_CHOICE )
    {
        fl_clear_choice( obj );

        ( ( FLI_CHOICE_SPEC * ) obj->spec)->align = ssp->align;

        for ( i = 1; i <= ssp->nlines; i++ )
        {
            fl_addto_choice( obj, ssp->content[ i ] );
            if ( ssp->shortcut[ i ] )
                fl_set_choice_item_shortcut( obj, i, ssp->shortcut[ i ] );
            fl_set_choice_item_mode( obj, i, ssp->mode[ i ] );
        }

        if ( ssp->nlines >= ssp->int_val )
            fl_set_choice( obj, ssp->int_val );
    }
    else if ( obj->objclass == FL_MENU )
    {
        fl_clear_menu( obj );

        for ( i = 1; i <= ssp->nlines; i++ )
        {
            fl_addto_menu( obj, ssp->content[ i ] );
            if ( ssp->shortcut[ i ] )
                fl_set_menu_item_shortcut( obj, i, ssp->shortcut[ i ] );
            if ( ssp->callback[ i ] )
                fl_set_menu_item_callback( obj, i,
                               ( FL_PUP_CB ) fl_strdup( ssp->callback[ i ] ) );
            fl_set_menu_item_mode( obj, i, ssp->mode[ i ] );
            if ( ssp->mval[ i ] != i )
                fl_set_menu_item_id( obj, i, ssp->mval[ i ] );
        }
    }
    else if (    obj->objclass == FL_SLIDER
              || obj->objclass == FL_VALSLIDER
              || obj->objclass == FL_THUMBWHEEL)
    {
        FLI_SLIDER_SPEC *sp = obj->spec;

        sp->val    = ssp->val;
        sp->min    = ssp->min;
        sp->max    = ssp->max;
        sp->step   = ssp->step;
        sp->prec   = ssp->prec;
        sp->ldelta = ssp->ldelta;
        sp->rdelta = ssp->rdelta;
        sp->slsize = ssp->slsize;
    }
    else if (    ISBUTTON( obj->objclass )
              || obj->objclass == FL_PIXMAP
              || obj->objclass == FL_BITMAP )
    {
        FL_BUTTON_SPEC *sp = obj->spec;

        for ( i = 0; i < 5; i++ )
            sp->react_to[ i ] = ( ssp->mbuttons & ( 1 << i ) ) != 0;
        if ( ISBUTTON( obj->objclass ) )
            fl_set_button_mouse_buttons( obj, ssp->mbuttons );

        sp->val = ssp->int_val;

        if ( ISBUTTON( obj->objclass ) )
            fl_set_button( obj, sp->val );
    }
    else if ( obj->objclass == FL_POSITIONER )
    {
        FLI_POSITIONER_SPEC *sp = obj->spec;

        sp->xstep = ssp->xstep;
        sp->ystep = ssp->ystep;
        sp->xmin  = ssp->xmin;
        sp->xmax  = ssp->xmax;
        sp->xval  = ssp->xval;
        sp->ymin  = ssp->ymin;
        sp->ymax  = ssp->ymax;
        sp->yval  = ssp->yval;
    }
    else if ( obj->objclass == FL_COUNTER )
    {
        FLI_COUNTER_SPEC *sp = obj->spec;

        sp->val   = ssp->val;
        sp->sstep = ssp->sstep;
        sp->lstep = ssp->lstep;
        sp->min   = ssp->min;
        sp->max   = ssp->max;
        sp->prec  = ssp->prec;
    }
    else if ( obj->objclass == FL_SPINNER )
    {
        FLI_SPINNER_SPEC *sp = obj->spec;

        fl_set_spinner_value( obj, ssp->val );
        fl_set_spinner_bounds( obj, ssp->min, ssp->max );
        fl_set_spinner_step( obj, ssp->step );
        fl_set_spinner_precision( obj, ssp->prec );
        sp->orient = ssp->orient;
    }
    else if ( obj->objclass == FL_DIAL )
    {
        FLI_DIAL_SPEC *sp = obj->spec;

        sp->min       = ssp->min;
        sp->max       = ssp->max;
        sp->val       = ssp->val;
        sp->step      = ssp->step;
        sp->thetai    = ssp->thetai;
        sp->thetaf    = ssp->thetaf;
        sp->direction = ssp->direction;
    }
    else if ( obj->objclass == FL_XYPLOT )
    {
        FLI_XYPLOT_SPEC *sp = obj->spec;

        sp->xmajor         = ssp->xmajor;
        sp->xminor         = ssp->xminor;
        sp->ymajor         = ssp->ymajor;
        sp->yminor         = ssp->yminor;
        sp->xscale         = ssp->xscale;
        sp->yscale         = ssp->yscale;
        sp->xgrid          = ssp->xgrid;
        sp->ygrid          = ssp->ygrid;
        sp->xbase          = ssp->xbase;
        sp->ybase          = ssp->ybase;
        sp->grid_linestyle = ssp->grid_linestyle;
        sp->mark_active    = ssp->mark_active;
    }
    else if ( obj->objclass == FL_SCROLLBAR )
    {
        FLI_SCROLLBAR_SPEC *scbsp = obj->spec;
        FLI_SLIDER_SPEC *sp = scbsp->slider->spec;

        sp->val    = ssp->val;
        sp->min    = ssp->min;
        sp->max    = ssp->max;
        sp->prec   = ssp->prec;
        sp->step   = ssp->step;
        sp->slsize = ssp->slsize;
        sp->ldelta = ssp->ldelta;
        sp->rdelta = ssp->rdelta;
    }
    else if ( obj->objclass == FL_SLIDER )
    {
        FLI_SPINNER_SPEC *sp = obj->spec;

        ssp->val    = fl_get_spinner_value( obj );
        fl_get_spinner_bounds( obj, &ssp->min, &ssp->max );
        ssp->step   = fl_get_spinner_step( obj );
        ssp->prec   = fl_get_spinner_precision( obj );
        ssp->orient = sp->orient;
    }
    else if ( obj->objclass == FL_INPUT )
    {
        /* Simply reset some attributes of the object to the defaults -
           this makes only sense when, during testing, text was entered
           into the input field and new we need to get rid of it */

        FLI_INPUT_SPEC *sp = obj->spec;

        sp->position = -1;
        sp->endrange = -1;
        sp->lines    = sp->ypos = 1;
        *sp->str     = '\0';
    }

    return v;
}


/***************************************
 ***************************************/

void
copy_superspec( FL_OBJECT * target,
                FL_OBJECT * src )
{
    SuperSPEC *t = fl_malloc( sizeof *t ),
              *s = get_superspec( src );
    int i;

    t->mode      = NULL;
    t->content   = NULL;;
    t->shortcut  = NULL;
    t->callback  = NULL;
    t->misc_char = NULL;

    *t = *s;

    t->content  = NULL;
    t->shortcut = NULL;
    t->callback = NULL;
    t->mode     = NULL;
    t->mval     = NULL;

    /* Take care of pointers in the SuperSPEC */

    if ( s->nlines )
    {
        int cnt = s->nlines + 1;

        t->content = s->content ?
                     fl_malloc( cnt * sizeof * t->content) : NULL;

        t->shortcut = s->shortcut ?
                      fl_malloc( cnt * sizeof *t->shortcut ) : NULL;

        t->callback = s->callback ?
                      fl_malloc( cnt * sizeof *t->callback ) : NULL;

        t->mode = s->mode ? fl_malloc( cnt * sizeof *t->mode ) : NULL;

        t->mval = s->mval ?
                  fl_malloc( cnt * sizeof *t->mval ) : NULL;
    }

    for ( i = 1; i <= s->nlines; i++ )
    {
        if ( t->content )
            t->content[ i ] = s->content[ i ] ?
                              fl_strdup( s->content[ i ] ) : NULL;

        if ( t->shortcut )
            t->shortcut[ i ] = s->shortcut[ i ] ?
                               fl_strdup( s->shortcut[ i ] ) : NULL;

        if ( t->callback )
            t->callback[ i ] = s->callback[ i ] ?
                               fl_strdup( s->callback[ i ] ) : NULL;
    }

    if ( t->mode )
        memcpy( t->mode, s->mode, ( s->nlines + 1 ) * sizeof *t->mode );

    if ( t->mval )
        memcpy( t->mval, s->mval, ( s->nlines + 1 ) * sizeof *t->mval );

    if ( t->misc_char )
        t->misc_char = fl_strdup( s->misc_char );

    free_superspec( target );
    target->u_vdata = t;
}


/***************************************
 ***************************************/

void
free_superspec( FL_OBJECT * obj )
{
    SuperSPEC *ssp = obj->u_vdata;
    int i;

    if ( ! ssp )
        return;

    for ( i = 1; i <= ssp->nlines; ++i )
    {
        if ( ssp->content )
            fl_free( ssp->content[ i ] );
        if ( ssp->shortcut )
            fl_free( ssp->shortcut[ i ] );
        if ( ssp->callback )
            fl_free( ssp->callback[ i ] );
    }

    fl_free( ssp->misc_char );
    fl_free( ssp->mode );
    fl_free( ssp->mval );
    fl_free( ssp->content );
    fl_free( ssp->shortcut );
    fl_free( ssp->callback );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
