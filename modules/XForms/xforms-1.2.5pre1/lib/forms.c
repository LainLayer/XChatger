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
 * \file forms.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  Main event dispatcher.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include "include/forms.h"
#include "flinternal.h"
#include "private/flvasprintf.h"


#define PointToPixel( a )     FL_crnd( ( a ) * fl_dpi / 72.0   )
#define MMToPixel( a )        FL_crnd( ( a ) * fl_dpi / 25.4   )
#define CMMToPixel( a )       FL_crnd( ( a ) * fl_dpi / 2540.0 )
#define CPointToPixel( a )    FL_crnd( ( a ) * fl_dpi / 7200.0 )

static FL_FORM * create_new_form( FL_Coord,
                                  FL_Coord );
static void force_visible( FL_FORM * );
static void set_form_property( FL_FORM *,
                               unsigned int );
static void get_decoration_sizes_from_wm( Atom ,
                                          FL_FORM *,
                                          int *,
                                          int *,
                                          int *,
                                          int * );
static void get_decorations_sizes_from_parent( FL_FORM *,
                                               int *,
                                               int *,
                                               int *,
                                               int * );


static FL_FORM * fli_mainform;
static int nomainform;
static int reopened_group = 0;

FL_FORM * fli_fast_free_object = NULL;    /* exported to objects.c */

static int has_initial;


/***************************************
 * Returns the index of a form in the list of visible forms
 * (or -1 if the form isn't in this list)
 ***************************************/

int
fli_get_visible_forms_index( FL_FORM * form )
{
    int i;

    for ( i = 0; i < fli_int.formnumb; i++ )
        if ( fli_int.forms[ i ] == form )
            return i;

    return -1;
}


/***************************************
 * Returns the index of a form in the list of hidden forms
 * (or -1 if the form isn't in this list)
 ***************************************/

static int
get_hidden_forms_index( FL_FORM * form )
{
    int i;

    for ( i = fli_int.formnumb;
          i < fli_int.formnumb + fli_int.hidden_formnumb; i++ )
        if ( fli_int.forms[ i ] == form )
            return i;

    return -1;
}


/***************************************
 * Extend the list of forms by one element and appends the
 * new forms address (listing it as invisible)
 ***************************************/

static void
add_form_to_hidden_list( FL_FORM * form )
{
    fli_int.forms = realloc( fli_int.forms,
                             ( fli_int.formnumb + fli_int.hidden_formnumb + 1 )
                             * sizeof *fli_int.forms );
    fli_int.forms[ fli_int.formnumb + fli_int.hidden_formnumb++ ] = form;
}


/***************************************
 * Moves a form from the list of hidden to the list of visible forms
 ***************************************/

static int
move_form_to_visible_list( FL_FORM * form )
{
    int i;

    /* Find the index of the hidden form */

    if (    fli_int.hidden_formnumb == 0
         || ( i = get_hidden_forms_index( form ) ) < 0 )
    {
        M_err( "move_form_to_visble_list", "Form not in hidden list" );
        return -1;
    }
        
    /* If it's not at the very start of the hidden list exchange it
       with the one at the start */

    if ( i != fli_int.formnumb )
    {
        fli_int.forms[ i ] = fli_int.forms[ fli_int.formnumb ];
        fli_int.forms[ fli_int.formnumb ] = form;
    }

    fli_int.hidden_formnumb--;

    if ( form->num_auto_objects > 0 )
        fli_int.auto_count++;

    return ++fli_int.formnumb;
}


/***************************************
 * Moves a form from the list of visible to the list of hidden forms
 ***************************************/

static int
move_form_to_hidden_list( FL_FORM * form )
{
    int i;

    /* Find the index of the form to be moved to the hidden list */

    if (    fli_int.formnumb == 0
         || ( i = fli_get_visible_forms_index( form ) ) < 0 )
    {
        M_err( "move_form_to_hidden_list", "Form not in visible list" );
        return -1;
    }

    /* Unless the form is the last in the visible list exchange it with
       the form at the end of the visible list */

    if ( i != --fli_int.formnumb )
    {
        fli_int.forms[ i ] = fli_int.forms[ fli_int.formnumb ];
        fli_int.forms[ fli_int.formnumb ] = form;
    }

    fli_int.hidden_formnumb++;

    if ( form->num_auto_objects > 0 )
    {
        if ( fli_int.auto_count == 0 )
            M_err( "move_form_to_hidden_list", "Bad auto count" );
        else
            fli_int.auto_count--;
    }

    return fli_int.formnumb;
}


/***************************************
 * Removes a form from the list of hidden forms,
 * shortening the list in the process
 ***************************************/

int
remove_form_from_hidden_list( FL_FORM * form )
{
    int i;

    /* Find the index of the form to be removed completely from the
       hidden list */

    if (    fli_int.hidden_formnumb == 0
         || ( i = get_hidden_forms_index( form ) ) < 0 )
    {
        M_err( "remove_form_from_hidden_list", "Form not in hidden list" );
        return -1;
    }

    /* If it's not the form at the end of the hidden list exchange it with
       the one at the end */

    if ( i != fli_int.formnumb + --fli_int.hidden_formnumb )
        fli_int.forms[ i ] =
                   fli_int.forms[ fli_int.formnumb + fli_int.hidden_formnumb ];

    /* Shorten the list of visible and hidden forms by one element */

    fli_int.forms = fl_realloc( fli_int.forms,
                                ( fli_int.formnumb + fli_int.hidden_formnumb )
                                * sizeof *fli_int.forms );

    return fli_int.formnumb;
}


/***************************************
 * Returns the (visible) form that's shown in 'win'
 ***************************************/

FL_FORM *
fl_win_to_form( Window win )
{
    int i;

    if ( win == None )
        return NULL;

    for ( i = 0; i < fli_int.formnumb; i++ )
        if ( fli_int.forms[ i ]->window == win )
            return fli_int.forms[ i ];

    return NULL;
}


/***************************************
 * Creates a new, empty form
 ***************************************/

static FL_FORM *
create_new_form( FL_Coord w,
                 FL_Coord h )
{
    FL_FORM *form;

    form = fl_calloc( 1, sizeof *form );

    /* Convert non-pixel unit into pixles */

    switch ( fli_cntl.coordUnit )
    {
        case FL_COORD_PIXEL :
            break;

        case FL_COORD_MM :
            w = MMToPixel( w );
            h = MMToPixel( h );
            break;

        case FL_COORD_POINT :
            w = PointToPixel( w );
            h = PointToPixel( h );
            break;

        case FL_COORD_centiPOINT :
            w = CPointToPixel( w );
            h = CPointToPixel( h );
            break;

        case FL_COORD_centiMM :
            w = CMMToPixel( w );
            h = CMMToPixel( h );
            break;

        default :
            M_err( "create_new_form", "Unknown unit: %d, using pixel",
                   fli_cntl.coordUnit );
            fli_cntl.coordUnit = FL_COORD_PIXEL;
    }

    /* Initialize pointers and non-zero defaults */

    form->w_hr = form->w    = w;
    form->h_hr = form->h    = h;

    form->handle_dec_x      = 0;
    form->handle_dec_y      = 0;

    form->num_auto_objects  = 0;
    form->deactivated       = 1;
    form->form_callback     = NULL;
    form->compress_mask     =   ExposureMask | ButtonMotionMask
                              | PointerMotionMask;
    form->key_callback      = NULL;
    form->push_callback     = NULL;
    form->crossing_callback = NULL;
    form->focusobj          = NULL;
    form->first             = NULL;
    form->last              = NULL;
    form->hotx              = form->hoty = -1;
    form->use_pixmap        = fli_cntl.doubleBuffer;
    form->label             = NULL;
    form->flpixmap          = NULL;
    form->u_vdata           = NULL;
    form->close_callback    = NULL;
    form->close_data        = NULL;
    form->icon_pixmap       = form->icon_mask = None;
    form->in_redraw         = 0;
    form->needs_full_redraw = 1;

    return form;
}


/***************************************
 * Starts a form definition
 ***************************************/

FL_FORM *
fl_bgn_form( int      type,
             FL_Coord w,
             FL_Coord h )
{
    if ( ! fli_no_connection && ! flx->display )
    {
        M_err( "fl_bgn_form", "Missing or failed call of fl_initialize()" );
        exit( 1 );
    }

    /* Check that we're not already in a form definition - the error is
       a serious one and can't be fixed easily as it might be due to a
       bad recursion */

    if ( fl_current_form )
    {
        M_err( "fl_bgn_form", "You forgot to call fl_end_form" );
        exit( 1 );
    }

    /* Create a new form */

    fl_current_form = create_new_form( w, h );

    /* Add it to the list of still hidden forms */

    add_form_to_hidden_list( fl_current_form );

    /* Each form has an empty box, covering the whole form as its first
       object */

    fl_add_box( type, 0, 0, w, h, "" );

    return fl_current_form;
}


/***************************************
 * Ends a form definition
 ***************************************/

void
fl_end_form( void )
{
    FL_FORM * f = fl_current_form;

    if ( ! fl_current_form )
    {
        M_err( "fl_end_form", "No current form" );
        return;
    }

    if ( fli_current_group )
    {
        M_err( "fl_end_form", "You forgot to call fl_end_group." );
        fl_end_group( );
    }

    fl_current_form = NULL;

    /* Now is the proper time for calculating the overlaps of objects */

    fli_recalc_intersections( f );

    if ( f->visible && ! f->frozen )
        fl_redraw_form( f );
}


/***************************************
 * Reopens a form for adding further objects
 ***************************************/

FL_FORM *
fl_addto_form( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_addto_form", "NULL form" );
        return NULL;
    }

    /* We can't open a form for adding objects when another form has already
       been opened for the same purpose */

    if ( fl_current_form && fl_current_form != form )
    {
        M_err( "fl_addto_form", "You forgot to call fl_end_form" );
        return NULL;
    }

    if ( fl_current_form )
        M_warn( "fl_addto_form", "Form was never closed." );

    return fl_current_form = form;
}


/***************************************
 * Starts a group definition by adding an object of type FL_BEGIN_GROUP
 ***************************************/

FL_OBJECT *
fl_bgn_group( void )
{
    static int id = 1;

    if ( ! fl_current_form )
    {
        M_err( "fl_bgn_group", "NULL form" );
        return NULL;
    }

    if ( fli_current_group )
    {
        M_err( "fl_bgn_group", "You forgot to call fl_end_group." );
        fl_end_group( );
    }

    fli_current_group = fl_make_object( FL_BEGIN_GROUP, 0, 0, 10, 10, 0,
                                        "", NULL );
    fli_current_group->group_id = id++;

    /* Temporarily set the object class to something invalid since
       fl_add_object() will not add objects of class FL_BEGIN_GROUP */

    fli_current_group->objclass = FL_INVALID_CLASS;
    fl_add_object( fl_current_form, fli_current_group );
    fli_current_group->objclass = FL_BEGIN_GROUP;

    return fli_current_group;
}


/***************************************
 * Ends a group definition by adding an object of type FL_END_GROUP
 ***************************************/

FL_OBJECT *
fli_end_group( void )
{
    FL_OBJECT *obj;
    int id;

    if ( ! fl_current_form )
    {
        M_err( "fl_end_group", "NULL form" );
        return NULL;
    }

    if ( ! fli_current_group )
    {
        M_err( "fl_end_group", "NULL group." );
        return NULL;
    }

    obj = fli_current_group;
    id = obj->group_id;
    fli_current_group = NULL;

    if ( ! reopened_group )
    {
        obj = fl_make_object( FL_END_GROUP, 0, 0, 0, 0, 0, "", NULL );
        obj->group_id = id;

        /* Temporarily set the object class to something invalid since
           fl_add_object() will not add objects of class FL_END_GROUP */

        obj->objclass = FL_INVALID_CLASS;
        fl_add_object( fl_current_form, obj );
        obj->objclass = FL_END_GROUP;
    }

    if ( reopened_group == 2 )
        fl_end_form( );

    reopened_group = 0;

    return obj;
}


/***************************************
 * Necessary since the public interface function for ending a group
 * doesn't have a return value
 ***************************************/

void
fl_end_group( void )
{
    fli_end_group( );
}


/***************************************
 * "Freezes" all (shown) forms
 ***************************************/

void
fl_freeze_all_forms( void )
{
    int i;

    for ( i = 0; i < fli_int.formnumb; i++ )
        fl_freeze_form( fli_int.forms[ i ] );
}


/***************************************
 * "Unfreezes" all (shown) forms
 ***************************************/

void
fl_unfreeze_all_forms( void )
{
    int i;

    for ( i = 0; i < fli_int.formnumb; i++ )
        fl_unfreeze_form( fli_int.forms[ i ] );
}


/***************************************
 * Corrects the shape of the form based on the shape of its window
 ***************************************/

static void
reshape_form( FL_FORM * form )
{
    FL_Coord w,
             h,
             dummy;
    int top,
        right,
        bottom,
        left;

    if (    ( ! form->handle_dec_x && ! form->handle_dec_y )
         || form->wm_border == FL_NOBORDER )
    {
        fl_get_wingeometry( form->window, &form->x, &form->y, &w, &h );
        fl_set_form_size( form, w, h );
        return;
    }

    fl_get_decoration_sizes( form, &top, &right, &bottom, &left );

    if ( form->handle_dec_x && ! form->handle_dec_y )
    {
        fl_get_wingeometry( form->window, &dummy, &form->y, &w, &h );
        form->x -= left;
    }
    else if ( ! form->handle_dec_x && form->handle_dec_y )
    {
        fl_get_wingeometry( form->window, &form->x, &dummy, &w, &h );
        form->y -= bottom;
    }
    else
    {
        fl_get_wingeometry( form->window, &dummy, &dummy, &w, &h );
        form->x -= left;
        form->y -= bottom;
    }

    XMoveWindow( flx->display, form->window, form->x, form->y );
    fl_set_form_size( form, w, h );
}


/***************************************
 * Scale a form with the given scaling factors and take care of object
 * gravity. This one differs from fl_scale_form() in that we don't
 * reshape the window in any way. Most useful as a follow up to a
 * ConfigureNotify event
 ***************************************/

void
fli_scale_form( FL_FORM * form,
                double    xsc,
                double    ysc )
{
    FL_OBJECT *obj;
    double neww = form->w_hr * xsc,
           newh = form->h_hr * ysc;

    if ( FL_abs( neww - form->w ) < 1 && FL_abs( newh - form->h ) < 1 )
        return;

    form->w_hr = neww;
    form->h_hr = newh;

    form->w = FL_crnd( neww );
    form->h = FL_crnd( newh );

    if ( form->hotx >= 0 || form->hoty >= 0 )
    {
        form->hotx = form->hotx * xsc;
        form->hoty = form->hoty * ysc;
    }

    /* Need to handle different resizing request */

    for ( obj = form->first; obj; obj = obj->next )
    {
        double oldw = obj->fl2 - obj->fl1;
        double oldh = obj->ft2 - obj->ft1;

        /* Special case to keep the center of gravity of objects that have
           no gravity set and aren't to be resized */

        if (    obj->resize == FL_RESIZE_NONE
             && obj->segravity == FL_NoGravity
             && obj->nwgravity == FL_NoGravity )
        {
            obj->fl1 += ( xsc - 1 ) * ( obj->fl1 + 0.5 * oldw );
            obj->ft1 += ( ysc - 1 ) * ( obj->ft1 + 0.5 * oldh );
            obj->fr1 = neww - obj->fl1;
            obj->fb1 = newh - obj->ft1;

            obj->fl2 = obj->fl1 + oldw;
            obj->ft2 = obj->ft1 + oldh;
            obj->fr2 = neww - obj->fl2;
            obj->fb2 = newh - obj->ft2;
        }
        else
        {
            /* In all other cases we recalculate the position of the upper left
               hand and the lower right hand corner of the object relative to
               all the borders of the form enclosing it, taking gravity and
               resizing setting into account. The results sometimes can be
               unexpected but hopefully are logically correct;-) */

            if ( ULC_POS_LEFT_FIXED( obj ) )
                obj->fr1 = neww - obj->fl1;
            else if ( ULC_POS_RIGHT_FIXED( obj ) )
                obj->fl1 = neww - obj->fr1;

            if ( LRC_POS_LEFT_FIXED( obj ) )
                obj->fr2 = neww - obj->fl2;
            else if ( LRC_POS_RIGHT_FIXED( obj ) )
                obj->fl2 = neww - obj->fr2;

            if ( ! HAS_FIXED_HORI_ULC_POS( obj ) )
            {
                if ( HAS_FIXED_HORI_LRC_POS( obj ) )
                {
                    if ( obj->resize & FL_RESIZE_X )
                        obj->fl1 = obj->fl2 - xsc * oldw;
                    else
                        obj->fl1 = obj->fl2 - oldw;
                }
                else
                    obj->fl1 *= xsc;
                    
                obj->fr1 = neww - obj->fl1;
            }

            if ( ! HAS_FIXED_HORI_LRC_POS( obj ) )
            {
                if ( obj->resize & FL_RESIZE_X )
                    obj->fl2 = obj->fl1 + xsc * oldw;
                else
                    obj->fl2 = obj->fl1 + oldw;
    
                obj->fr2 = neww - obj->fl2;
            }
            
            if ( ULC_POS_TOP_FIXED( obj ) )
                obj->fb1 = newh - obj->ft1;
            else if ( ULC_POS_BOTTOM_FIXED( obj ) )
                obj->ft1 = newh - obj->fb1;

            if ( LRC_POS_TOP_FIXED( obj ) )
                obj->fb2 = newh - obj->ft2;
            else if ( LRC_POS_BOTTOM_FIXED( obj ) )
                obj->ft2 = newh - obj->fb2;

            if ( ! HAS_FIXED_VERT_ULC_POS( obj ) )
            {
                if ( HAS_FIXED_VERT_LRC_POS( obj ) )
                {
                    if ( obj->resize & FL_RESIZE_Y )
                        obj->ft1 = obj->ft2 - ysc * oldh;
                    else
                        obj->ft1 = obj->ft2 - oldh;
                }
                else
                    obj->ft1 *= ysc;

                obj->fb1 = newh - obj->ft1;
            }

            if ( ! HAS_FIXED_VERT_LRC_POS( obj ) )
            {
                if ( obj->resize & FL_RESIZE_Y )
                    obj->ft2 = obj->ft1 + ysc * oldh;
                else
                    obj->ft2 = obj->ft1 + oldh;
    
                obj->fb2 = newh - obj->ft2;
            }
        }

        obj->x = FL_crnd( obj->fl1 );
        obj->y = FL_crnd( obj->ft1 );
        obj->w = FL_crnd( obj->fl2 - obj->fl1 );
        obj->h = FL_crnd( obj->ft2 - obj->ft1 );
    }

    /* Only notify objects now - parent objects might have to adjust
       sizes and positions of child objects and when objects get the
       resize notice immediately after resizing above then the parent
       object gets it first, sets a different size for the child, which
       then is overwritten */

    for ( obj = form->first; obj; obj = obj->next )
        fli_handle_object( obj, FL_RESIZED, 0, 0, 0, NULL, 0 );

    fli_recalc_intersections( form );
}


/***************************************
 * Externally visible routine to scale a form. Needs to reshape the window.
 ***************************************/

void
fl_scale_form( FL_FORM * form,
               double    xsc,
               double    ysc )
{
    if ( ! form )
    {
        M_err( "fl_scale_form", "NULL form" );
        return;
    }

    if (    FL_crnd( form->w_hr * xsc ) == form->w
         && FL_crnd( form->h_hr * ysc ) == form->h )
        return;

    fli_scale_form( form, xsc, ysc );

    /* Resize the window */

    if ( form->visible == FL_VISIBLE )
        fl_winresize( form->window, form->w, form->h );
}


/***************************************
 * Sets lower limits for the width and height of a form
 ***************************************/

void
fl_set_form_minsize( FL_FORM * form,
                     FL_Coord  w,
                     FL_Coord  h )
{
    if ( ! form )
    {
        M_err( "fl_set_form_minsize", "Null form" );
        return;
    }

    fl_winminsize( form->window, w, h );
}


/***************************************
 * Sets upper limits for the width and height of a form
 ***************************************/

void
fl_set_form_maxsize( FL_FORM * form,
                     FL_Coord  w,
                     FL_Coord  h )
{
    if ( ! form )
    {
        M_err( "fl_set_form_maxsize", "NULL form" );
        return;
    }

    fl_winmaxsize( form->window, w, h );
}


/***************************************
 * Switches double buffering for forms on or off (with double buffering
 * on we draw first to a pixmap for the form before copying that to the
 * forms window - can reduces flickering)
 ***************************************/

void
fl_set_form_dblbuffer( FL_FORM * form,
                       int       yesno )
{
    if ( ! form )
    {
        M_err( "fl_set_form_dblbuffer", "NULL form" );
        return;
    }

    if ( form->use_pixmap == yesno )
        return;

    /* If the form is currently frozen the redraw on unfreeze will only
       draw those objects that have been changed and thus have their
       'redraw' flag set. But when switching double buffering on there's
       no pixmap yet that already contains the non-modified objects. Thus
       in this case we must make sure all objects of the form get redrawn. */

    if ( yesno && form->frozen )
        form->needs_full_redraw = 1;

    form->use_pixmap = yesno;
}


/***************************************
 * Sets the size of a form
 ***************************************/

void
fl_set_form_size( FL_FORM * form,
                  FL_Coord  w,
                  FL_Coord  h )
{
    if ( ! form )
    {
        M_err( "fl_set_form_size", "NULL form" );
        return;
    }

    if ( w != form->w || h != form->h )
        fl_scale_form( form, w / form->w_hr, h / form->h_hr );
}


/***************************************
 * Sets the position of a form
 ***************************************/

void
fl_set_form_position( FL_FORM * form,
                      FL_Coord  x,
                      FL_Coord  y )
{
    FL_Coord oldx,
             oldy;

    if ( ! form )
    {
        M_err( "fl_set_form_position", "NULL form" );
        return;
    }

    oldx = form->x;
    oldy = form->y;

    /* Negative values for x or y are interpreted as meaning that the
       position is that of the right or bottom side of the form relative
       to the right or bottom side to the screen. May have to be corrected
       for the right or bottom border decoration widths. */

    if ( x >= 0 )
    {
        form->x = x;
        form->handle_dec_x = 0;
    }
    else
    {
        form->x = fl_scrw - form->w + x;
        form->handle_dec_x = 1;
    }

    if ( y >= 0 )
    {
        form->y = y;
        form->handle_dec_y = 0;
    }
    else
    {
        form->y = fl_scrh - form->h + y;
        form->handle_dec_y = 1;
    }

    /* If the form is already shown move it */

    if ( form->visible == FL_VISIBLE )
    {
        int bottom = 0,
            left = 0,
            dummy;

        if (    ( form->handle_dec_x || form->handle_dec_y )
             && form->wm_border != FL_NOBORDER )
        {
            fl_get_decoration_sizes( form, &dummy, &dummy, &bottom, &left );

            if ( form->handle_dec_x )
                form->x -= left;

            if ( form->handle_dec_y )
                form->y -= bottom;
        }

        form->handle_dec_x = form->handle_dec_y = 0;

        if ( oldx != form->x || oldy != form->y )
            XMoveWindow( flx->display, form->window, form->x, form->y );
    }
}


/***************************************
 * Sets the background color of the form - a bit of a hack since it
 * actually uses the first or second object of the form...
 ***************************************/

void
fl_set_form_background_color( FL_FORM * form,
                              FL_COLOR  color )
{
    if ( ! form )
    {
        M_err( "fl_set_forms_background_color", "NULL form" );
        return;
    }

    /* If the empty box that all forms get as their first object on creation
       does not exist anymore we can't set a background color */

    if ( ! form->first )
    {
        M_err( "fl_set_forms_background_color", "Form has no background" );
        return;
    }

    /* If there's no other object except the empty box or the first object
       isn't an empty box anymore set the color for this first object, otherwise
       for the next object. */

    if ( ! form->first->next || form->first->boxtype != FL_NO_BOX )
        fl_set_object_color( form->first, color, form->first->col2 );
    else
        fl_set_object_color( form->first->next, color,
                             form->first->next->col2 );
}


/***************************************
 * Returns the background color used for the form
 ***************************************/

FL_COLOR
fl_get_form_background_color( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_get_forms_background_color", "NULL form" );
        return FL_COL1;
    }

    /* If the empty box that all forms get as their first object on creation
       does not exist anymore we can't set a background color */

    if ( ! form->first )
    {
        M_err( "fl_get_forms_background_color", "Form has no background" );
        return FL_COL1;
    }

    if ( form->first->boxtype != FL_NO_BOX || ! form->first->next )
        return form->first->col1;
    else
        return form->first->next->col1;
}


/***************************************
 * Sets the position of the hotspot of a form
 ***************************************/

void
fl_set_form_hotspot( FL_FORM * form,
                     FL_Coord  x,
                     FL_Coord  y )
{
    if ( ! form )
    {
        M_err( "fl_set_form_hotspot", "NULL form" );
        return;
    }

    form->hotx = x;
    form->hoty = y;
}


/***************************************
 * Sets the position of the hotspot of a form
 * to the center of one of its objects
 ***************************************/

void
fl_set_form_hotobject( FL_FORM   * form,
                       FL_OBJECT * obj )
{
    if ( ! form  )
    {
        M_err( "fl_set_form_hotobject", "NULL form" );
        return;
    }

    if ( ! obj )
    {
        M_err( "fl_set_form_hotobject", "NULL object" );
        return;
    }

    if ( obj->form != form )
    {
        M_err( "fl_set_form_hotobject", "Object not part of form" );
        return;
    }

    fl_set_form_hotspot( form, obj->x + obj->w / 2, obj->y + obj->h / 2 );
}


/***************************************
 * Try to make sure a form is completely visible on the screen
 ***************************************/

static void
force_visible( FL_FORM * form )
{
    if ( form->x > fl_scrw - form->w )
        form->x = fl_scrw - form->w;

    if ( form->x < 0 )
        form->x = 0;

    if ( form->y > fl_scrh - form->h )
        form->y = fl_scrh - form->h;

    if ( form->y < 0 )
        form->y = 0;
}


/***************************************
 * Sets the name (label) of the form. If the form
 * is shown it's also the form's window title.
 ***************************************/

void
fl_set_form_title( FL_FORM *    form,
                   const char * name )
{
    if ( ! form )
    {
        M_err( "fl_set_form_title", "NULL form" );
        return;
    }

    if ( form->label != name )
    {
        if ( form->label )
            fl_free( form->label );
        form->label = fl_strdup( name ? name : "" );
    }

    if ( form->window )
        fl_wintitle( form->window, form->label );
}


/***************************************
 * Sets the name (label) of the form using a format string
 ***************************************/

void
fl_set_form_title_f( FL_FORM *    form,
                     const char * fmt,
                     ... )
{
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    fl_set_form_title( form, buf );
    fl_free( buf );
}   


/***************************************
 * Creates the window for a form (but doesn't show it yet, use
 * fl_show_form_window() for that), returns the window handle
 ***************************************/

Window
fl_prepare_form_window( FL_FORM    * form,
                        int          place,
                        int          border,
                        const char * name )
{
    long screenw,
         screenh,
         dont_fix_size = 0;
    FL_Coord mx,
             my;

    if ( border == 0 )
        border = FL_FULLBORDER;

    if ( fl_current_form )
    {
        M_err( "fl_prepare_form_window", "You forgot to call fl_end_form() %s",
               name ? name : "" );
        fl_current_form = NULL;
    }

    if ( ! form )
    {
        M_err( "fl_prepare_form", "NULL form" );
        return None;
    }

    if ( form->visible != FL_INVISIBLE )
        return form->window;

    /* Try to move the form from the part of the list for hidden forms to
       that at the start for visible forms */

    move_form_to_visible_list( form );

    if ( form->label != name )
    {
        if ( form->label )
            fl_free( form->label );
        form->label = fl_strdup( name ? name : "" );
    }

    if ( border == FL_NOBORDER )
        fli_int.unmanaged_count++;

    form->wm_border = border;
    form->deactivated = 0;
    screenw = fl_scrw;
    screenh = fl_scrh;

    fl_get_mouse( &mx, &my, &fli_int.keymask );

    if ( ( dont_fix_size = place & FL_FREE_SIZE ) )
        place &= ~ FL_FREE_SIZE;

    if ( place == FL_PLACE_SIZE )
        fl_pref_winsize( form->w, form->h );
    else if ( place == FL_PLACE_ASPECT )
        fl_winaspect( 0, form->w, form->h );
    else if ( place == FL_PLACE_POSITION )
    {
        fl_pref_winposition( form->x, form->y );
        fl_initial_winsize( form->w, form->h );
    }
    else if ( place != FL_PLACE_FREE )
    {
        FL_COORD nmx,
                 nmy;

        switch ( place )
        {
            case FL_PLACE_CENTER:
            case FL_PLACE_FREE_CENTER:
                form->x = ( screenw - form->w ) / 2;
                form->y = ( screenh - form->h ) / 2;
                break;

            case FL_PLACE_MOUSE:
                form->x = mx - form->w / 2;
                form->y = my - form->h / 2;
                break;

            case FL_PLACE_FULLSCREEN:
                form->x = 0;
                form->y = 0;
                fl_set_form_size( form, screenw, screenh );
                break;

            case FL_PLACE_HOTSPOT:
                if ( form->hotx < 0 || form->hoty < 0 )    /* not set */
                {
                    form->hotx = form->w / 2;
                    form->hoty = form->h / 2;
                }

                form->x = mx - form->hotx;
                form->y = my - form->hoty;

                force_visible( form );

                nmx = form->x + form->hotx;
                nmy = form->y + form->hoty;

                if ( nmx != mx || nmy != my )
                    fl_set_mouse( nmx, nmy );

                break;

            case FL_PLACE_GEOMETRY :
                if ( form->x < 0 )
                {
                    form->x = screenw - form->w + form->x;
                    form->handle_dec_x = 1;
                }
                if ( form->y < 0 )
                {
                    form->y = screenh - form->h + form->y;
                    form->handle_dec_y = 1;
                }
                break;
        }

        /* Final check. Make sure form is visible */

        if ( place != FL_PLACE_GEOMETRY )
            force_visible( form );

        if ( dont_fix_size && place != FL_PLACE_GEOMETRY )
            fl_initial_wingeometry( form->x, form->y, form->w, form->h );
        else
            fl_pref_wingeometry( form->x, form->y, form->w, form->h );
    }
    else if ( place == FL_PLACE_FREE )
    {
        fl_initial_winsize( form->w, form->h );
        if ( has_initial )
            fl_initial_wingeometry( form->x, form->y, form->w, form->h );
    }
    else
    {
        M_err( "fl_prepare_form_window", "Unknown requests: %d", place );
        fl_initial_wingeometry( form->x, form->y, form->w, form->h );
    }

    /* Window managers typically do not allow dragging transient windows */

    if ( border != FL_FULLBORDER )
    {
        if ( place == FL_PLACE_ASPECT || place == FL_PLACE_FREE )
        {
            form->x = mx - form->w / 2;
            form->y = my - form->h / 2;
            force_visible( form );
            fl_initial_winposition( form->x, form->y );
        }

        if ( border == FL_NOBORDER )
            fl_noborder( );
        else
            fl_transient( );
    }

    if ( place == FL_PLACE_ICONIC )
        fl_initial_winstate( IconicState );
    if ( form->icon_pixmap )
        fl_winicon( 0, form->icon_pixmap, form->icon_mask );

    has_initial = 0;
    fli_init_colormap( fl_vmode );

    form->window = fli_create_window( fl_root, fli_colormap( fl_vmode ), name );
    fl_winicontitle( form->window, name );

    if ( border == FL_FULLBORDER || form->prop & FLI_COMMAND_PROP )
        set_form_property( form, FLI_COMMAND_PROP );

    return form->window;
}


/***************************************
 ***************************************/

Window
fl_prepare_form_window_f( FL_FORM    * form,
                          int          place,
                          int          border,
                          const char * fmt,
                          ... )
{
    Window w;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    w = fl_prepare_form_window( form, place, border, buf );
    fl_free( buf );
    return w;
}


/***************************************
 * Maps (displays) a form's window created with fl_prepare_form_window()
 ***************************************/

Window
fl_show_form_window( FL_FORM * form )
{
    FL_OBJECT *obj;

    if ( ! form  )
    {
        M_err( "fl_show_form_window", "NULL form" );
        return None;
    }

    if ( form->window == None || form->visible != FL_INVISIBLE )
        return form->window;

    fl_winshow( form->window );
    form->visible = FL_VISIBLE;
    reshape_form( form );
    fl_redraw_form( form );

    /* TODO: somehow formbrowser objects get drawn incorrectly the first
       time round so, for the time being, we redraw it once again... */

    for ( obj = form->first; obj; obj = obj->next )
        if ( obj->objclass == FL_FORMBROWSER )
            fl_redraw_object( obj );

    /* Check if there's an object we can make the object that has the focus,
       it must be an input object and be active and visible */

    if ( ! form->focusobj )
        for ( obj = form->first; obj; obj = obj->next )
            if ( obj->input && obj->active && obj->visible )
            {
                fl_set_focus_object( form, obj );
                break;
            }

    return form->window;
}


/***************************************
 * Makes a new form visible by creating a window for it
 * and mapping it. Returns the form's window handle.
 ***************************************/

Window
fl_show_form( FL_FORM *    form,
              int          place,
              int          border,
              const char * name )
{
    if ( ! form  )
    {
        M_err( "fl_show_form", "NULL form" );
        return None;
    }

    fl_prepare_form_window( form, place, border, name );
    form->in_redraw = 0;
    return fl_show_form_window( form );
}


/***************************************
 ***************************************/

Window
fl_show_form_f( FL_FORM    * form,
                int          place,
                int          border,
                const char * fmt,
                ... )
{
    Window w;
    char *buf;

    EXPAND_FORMAT_STRING( buf, fmt );
    w = fl_show_form( form, place, border, buf );
    fl_free( buf );
    return w;
}


/***************************************
 * Hides a particular form by unmapping and destroying its window
 ***************************************/

static void
close_form_window( Window win )
{
    XEvent xev;

    XUnmapWindow( flx->display, win );
    XDestroyWindow( flx->display, win );
    XSync( flx->display, 0 );

    while ( XCheckWindowEvent( flx->display, win, AllEventsMask, &xev ) )
        fli_xevent_name( "Eaten", &xev );

    /* Give subwindows a chance to handle destroy event promptly, take care
       the window of the form doesn't exist anymore! */

    while ( XCheckTypedEvent( flx->display, DestroyNotify, &xev ) )
    {
        FL_FORM *form;

        if ( ( form = fli_find_event_form( &xev ) ) )
        {
            form->window = None;
            fl_hide_form( form );
        }
        else
            fl_XPutBackEvent( &xev );
    }
}


/***************************************
 ***************************************/

static FL_FORM *
property_set( unsigned int prop )
{
    int i;

    for ( i = 0; i < fli_int.formnumb; i++ )
        if (    fli_int.forms[ i ]->prop & prop
             && fli_int.forms[ i ]->prop & FLI_PROP_SET )
            return fli_int.forms[ i ];

    return NULL;
}


/***************************************
 ***************************************/

static void
set_form_property( FL_FORM *    form,
                   unsigned int prop )
{
    if ( ! form  )
    {
        M_err( "set_form_property", "NULL form" );
        return;
    }

    if ( property_set( prop ) )
        return;

    if ( ! ( prop & FLI_COMMAND_PROP ) )
    {
        M_err( "set_form_property", "Unknown form property request %u",
               prop );
        return;
    }

    if ( form->window )
    {
        fli_set_winproperty( form->window, FLI_COMMAND_PROP );
        form->prop |= FLI_PROP_SET;
    }

    form->prop |= FLI_COMMAND_PROP;
    fli_mainform = form;
}


/***************************************
 ***************************************/

void
fl_hide_form( FL_FORM * form )
{
    Window owin;
    FL_OBJECT *o;

    if ( ! form )
    {
        M_err( "fl_hide_form", "NULL form" );
        return;
    }

    if ( fli_get_visible_forms_index( form ) < 0 )
    {
        M_err( "fl_hide_form", "Hiding unknown form" );
        return;
    }

    if ( form->visible == FL_BEING_HIDDEN )
    {
        M_err( "fl_hide_form", "Recursive call?" );
        return;
    }

    form->visible = FL_BEING_HIDDEN;
    fli_set_form_window( form );

    /* Checking mouseobj->form is necessary as it might be deleted from a
       form */

    if ( fli_int.mouseobj && fli_int.mouseobj->form == form )
    {
        fli_handle_object( fli_int.mouseobj, FL_LEAVE, 0, 0, 0, NULL, 1 );
        fli_int.mouseobj = NULL;
    }

    if ( fli_int.pushobj && fli_int.pushobj->form == form )
    {
        fli_handle_object( fli_int.pushobj, FL_RELEASE, 0, 0, 0, NULL, 1 );
        fli_int.pushobj = NULL;
    }

    if ( form->focusobj )
    {
        fli_handle_object( form->focusobj, FL_UNFOCUS, 0, 0, 0, NULL, 0 );
        form->focusobj = NULL;
    }

    /* Get canvas objects to unmap their windows (but only for those that
       aren't childs, those will be dealt with by their parents) */

    for ( o = form->first; o; o = o->next )
        if (    ( o->objclass == FL_CANVAS || o->objclass == FL_GLCANVAS )
             && ! o->parent )
            fli_unmap_canvas_window( o );

#ifdef DELAYED_ACTION
    fli_object_qflush( form );
#endif

    /* Free backing store pixmap but keep the pointer */

    fli_free_flpixmap( form->flpixmap );

    if ( fli_int.mouseform && fli_int.mouseform->window == form->window )
        fli_int.mouseform = NULL;

    form->deactivated = 1;
    form->visible = FL_INVISIBLE;
    owin = form->window;
    form->window = None;

    fli_hide_tooltip( );

    /* If the forms window is None it already has been closed */

    if ( owin )
        close_form_window( owin );

    if ( flx->win == owin )
        flx->win = None;

    /* Move the form from the part of the list for visible forms to the
       part of hidden forms at the end of the array */

    move_form_to_hidden_list( form );

    if ( form->wm_border == FL_NOBORDER )
    {
        fli_int.unmanaged_count--;
        if ( fli_int.unmanaged_count < 0 )
        {
            M_err( "fl_hide_form", "Bad unmanaged count" );
            fli_int.unmanaged_count = 0;
        }
    }

    /* Need to re-establish command property */

    if ( fli_int.formnumb && form->prop & FLI_COMMAND_PROP )
        set_form_property( *fli_int.forms, FLI_COMMAND_PROP );

    if ( form == fli_int.keyform )
        fli_int.keyform = NULL;
}


/***************************************
 * Frees the memory used by a form, together with all its objects.
 ***************************************/

void
fl_free_form( FL_FORM * form )
{
    /* Check whether ok to free */

    if ( ! form )
    {
        M_err( "fl_free_form", "NULL form" );
        return;
    }

    if ( form->visible == FL_VISIBLE )
    {
        M_warn( "fl_free_form", "Freeing visible form" );
        fl_hide_form( form );
    }

    if ( get_hidden_forms_index( form ) < 0 )
    {
        M_err( "fl_free_form", "Freeing unknown form" );
        return;
    }

    /* Free all objects of the form */

    fli_fast_free_object = form;

    while ( form->first )
        fl_free_object( form->first );

    fli_fast_free_object = NULL;

    if ( form->flpixmap )
    {
        fli_free_flpixmap( form->flpixmap );
        fl_free( form->flpixmap );
    }

    if ( form->label )
    {
        fl_free( form->label );
        form->label = NULL;
    }

    if ( form == fli_mainform )
        fli_mainform = NULL;

    /* Free the form and remove it from the list of existing forms */

    fl_free( form );

    remove_form_from_hidden_list( form );
}


/***************************************
 * Returns if a form is active
 ***************************************/

int
fl_form_is_activated( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_form_is_activated", "NULL form" );
        return 0;
    }

    return form->deactivated == 0;
}


/***************************************
 * Activates a form (form only becomes activated if this function has
 * been called as many times as fl_deactive_form()).
 ***************************************/

void
fl_activate_form( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_activate_form", "NULL form" );
        return;
    }

    if ( form->deactivated )
    {
        form->deactivated--;

        if ( ! form->deactivated && form->activate_callback )
            form->activate_callback( form, form->activate_data );
    }

    if ( form->child )
        fl_activate_form( form->child );
}


/***************************************
 * Deactivates a form (re-activation requires as many calls of
 * fl_activate_form() as there were calls of fl_deactivate_form()).
 ***************************************/

void
fl_deactivate_form( FL_FORM * form )
{
    if ( ! form )
    {
        M_err( "fl_deactivate_form", "NULL form" );
        return;
    }

    if (    ! form->deactivated
         && fli_int.mouseobj
         && fli_int.mouseobj->form == form )
        fli_handle_object( fli_int.mouseobj, FL_LEAVE, 0, 0, 0, NULL, 1 );

    if ( ! form->deactivated && form->deactivate_callback )
        form->deactivate_callback( form, form->deactivate_data );

    form->deactivated++;

    if ( form->child )
        fl_deactivate_form( form->child );
}


/***************************************
 * Installs handler to be called on (final) re-activation of the form
 ***************************************/

FL_FORM_ATACTIVATE
fl_set_form_atactivate( FL_FORM            * form,
                        FL_FORM_ATACTIVATE   cb,
                        void *               data )
{
    FL_FORM_ATACTIVATE old = NULL;

    if ( ! form  )
    {
        M_err( "fl_set_form_atactivate", "NULL form" );
        return NULL;
    }

    old = form->activate_callback;
    form->activate_callback = cb;
    form->activate_data = data;

    return old;
}


/***************************************
 * Installs handler to be called on (first) deactivation of the form
 ***************************************/

FL_FORM_ATDEACTIVATE
fl_set_form_atdeactivate( FL_FORM              * form,
                          FL_FORM_ATDEACTIVATE   cb,
                          void                 * data )
{
    FL_FORM_ATDEACTIVATE old = NULL;

    if ( ! form  )
    {
        M_err( "fl_set_form_atdeactivate", "NULL form" );
        return NULL;
    }

    old = form->deactivate_callback;
    form->deactivate_callback = cb;
    form->deactivate_data = data;

    return old;
}


/***************************************
 * Activates all forms
 ***************************************/

void
fl_activate_all_forms( void )
{
    int i;

    for ( i = 0; i < fli_int.formnumb; i++ )
        fl_activate_form( fli_int.forms[ i ] );
}


/***************************************
 * Deactivates all forms
 ***************************************/

void
fl_deactivate_all_forms( void )
{
    int i;

    for ( i = 0; i < fli_int.formnumb; i++ )
        fl_deactivate_form( fli_int.forms[ i ] );
}


/***************************************
 * Installs handler to be called on close of the form
 ***************************************/

FL_FORM_ATCLOSE
fl_set_form_atclose( FL_FORM         * form,
                     FL_FORM_ATCLOSE   fmclose,
                     void            * data )
{
    FL_FORM_ATCLOSE old;

    if ( ! form  )
    {
        M_err( "fl_set_form_atclose", "NULL form" );
        return NULL;
    }

    old = form->close_callback;
    form->close_callback = fmclose;
    form->close_data = data;

    return old;
}


/***************************************
 * Installs handler to be called on end of application by the user
 * using some window manager method to close a window
 ***************************************/

FL_FORM_ATCLOSE
fl_set_atclose( FL_FORM_ATCLOSE   fmclose,
                void            * data )
{
    FL_FORM_ATCLOSE old = fli_context->atclose;

    fli_context->atclose = fmclose;
    fli_context->close_data = data;

    return old;
}


/***************************************
 ***************************************/

void
fl_set_form_geometry( FL_FORM  * form,
                      FL_Coord   x,
                      FL_Coord   y,
                      FL_Coord   w,
                      FL_Coord   h )
{
    fl_set_form_position( form, x, y );
    fl_set_form_size( form, w, h );

    /* This alters the windowing defaults */

    fl_initial_wingeometry( form->x, form->y, form->w, form->h );
    has_initial = 1;
}


/***************************************
 * Register pre-emptive event handlers
 ***************************************/

FL_RAW_CALLBACK
fl_register_raw_callback( FL_FORM         * form,
                          unsigned long     mask,
                          FL_RAW_CALLBACK   rcb )
{
    FL_RAW_CALLBACK old_rcb = NULL;
    int valid = 0;

    if ( ! form )
    {
        M_err( "fl_register_raw_callback", "Null form" );
        return NULL;
    }

    if ( ( mask & FL_ALL_EVENT ) == FL_ALL_EVENT )
    {
        old_rcb = form->all_callback;
        form->evmask = mask;
        form->all_callback = rcb;
        return old_rcb;
    }

    if ( mask & ( KeyPressMask | KeyReleaseMask ) )
    {
        form->evmask |= mask & ( KeyPressMask | KeyReleaseMask );
        old_rcb = form->key_callback;
        form->key_callback = rcb;
        valid = 1;
    }

    if ( mask & ( ButtonPressMask | ButtonReleaseMask ) )
    {
        form->evmask |= mask & ( ButtonPressMask | ButtonReleaseMask );
        old_rcb = form->push_callback;
        form->push_callback = rcb;
        valid = 1;
    }

    if ( mask & ( EnterWindowMask | LeaveWindowMask ) )
    {
        form->evmask |= mask & ( EnterWindowMask | LeaveWindowMask );
        old_rcb = form->crossing_callback;
        form->crossing_callback = rcb;
        valid = 1;
    }

    if ( mask & ( ButtonMotionMask | PointerMotionMask ) )
    {
        form->evmask |= mask & ( ButtonMotionMask | PointerMotionMask );
        old_rcb = form->motion_callback;
        form->motion_callback = rcb;
        valid = 1;
    }

    if ( ! valid )          /* unsupported mask */
        M_err( "fl_register_raw_callback", "Unsupported mask 0x%x", mask );

    return old_rcb;
}


/***************************************
 ***************************************/

void
fl_set_form_event_cmask( FL_FORM *     form,
                         unsigned long cmask )
{
    if ( form )
        form->compress_mask = cmask;
}


/***************************************
 ***************************************/

unsigned long
fl_get_form_event_cmask( FL_FORM * form )
{
    return form ? form->compress_mask : 0UL;
}


/***************************************
 * Sets the callback routine for the form
 ***************************************/

void
fl_set_form_callback( FL_FORM            * form,
                      FL_FORMCALLBACKPTR   callback,
                      void *               d )
{
    if ( ! form )
    {
        M_err( "fl_set_form_callback", "NULL form" );
        return;
    }

    form->form_callback = callback;
    form->form_cb_data = d;
}


/***************************************
 ***************************************/

void
fl_set_form_icon( FL_FORM * form,
                  Pixmap    p,
                  Pixmap    m )
{
    if ( ! form )
        return;

    form->icon_pixmap = p;
    form->icon_mask = m;
    if ( form->window )
        fl_winicon( form->window, p, m );
}


/***************************************
 ***************************************/

void
fl_set_app_mainform( FL_FORM * form )
{
    fli_mainform = form;
    set_form_property( form, FLI_COMMAND_PROP );
}


/***************************************
 ***************************************/

FL_FORM *
fl_get_app_mainform( void )
{
    return nomainform ? NULL : fli_mainform;
}


/***************************************
 ***************************************/

void
fl_set_app_nomainform( int flag )
{
    nomainform = flag;
}


/***************************************
 * Does a rescale of a form without taking into
 * account object gravity or resize settings
 ***************************************/

static void
simple_form_rescale( FL_FORM * form,
                     double    scale )
{
    FL_OBJECT *obj;

    form->w_hr *= scale;
    form->h_hr *= scale;

    form->w = FL_crnd( form->w_hr );
    form->h = FL_crnd( form->h_hr );

    for ( obj = form->first; obj; obj = obj->next )
        if ( obj->objclass != FL_BEGIN_GROUP && obj->objclass != FL_END_GROUP )
            fli_scale_object( obj, scale, scale );

    fli_recalc_intersections( form );

    fl_redraw_form( form );
}


/***************************************
 * Checks if the label of an object fits into it (after x- and
 * y-margin have been added). If not, all objects and the form
 * are enlarged by the necessary factor (but never by more than
 * a factor of 1.5).
 ***************************************/

void
fl_fit_object_label( FL_OBJECT * obj,
                     FL_Coord    xmargin,
                     FL_Coord    ymargin )
{
    int sw,
        sh,
        osize,
        bw;
    double factor,
           xfactor,
           yfactor;

    if ( fli_no_connection )
        return;

    if (    fl_is_outside_lalign( obj->align )
         || obj->type == FL_BEGIN_GROUP
         || obj->type == FL_END_GROUP
         || obj->parent
         || ! obj->label
         || ! *obj->label
         || *obj->label == '@' )
        return;

    fl_get_string_dimension( obj->lstyle, obj->lsize, obj->label,
                             strlen( obj->label ), &sw, &sh );

    bw = (    obj->boxtype == FL_UP_BOX
           || obj->boxtype == FL_DOWN_BOX
           || obj->boxtype == FL_EMBOSSED_BOX ) ?
        FL_abs( obj->bw ) : 1;

    if (    obj->boxtype == FL_EMBOSSED_BOX )
        bw += bw > 2 ? bw - 2 : 1;

    if (    obj->objclass == FL_BUTTON
          && (    obj->type == FL_RETURN_BUTTON
               || obj->type == FL_MENU_BUTTON ) )
        sw += FL_min( 0.6 * obj->h, 0.6 * obj->w ) - 1;

    if ( obj->objclass == FL_BUTTON && obj->type == FL_LIGHTBUTTON )
        sw += FL_LIGHTBUTTON_MINSIZE + 1;

    if (    sw <= obj->w - 2 * ( bw + xmargin )
         && sh <= obj->h - 2 * ( bw + ymargin ) )
        return;

    if ( ( osize = obj->w - 2 * ( bw + xmargin ) ) <= 0 )
        osize = 1;
    xfactor = ( double ) sw / osize;

    if ( ( osize = obj->h - 2 * ( bw + ymargin ) ) <= 0 )
        osize = 1;
    yfactor = ( double ) sh / osize;

    factor = FL_max( xfactor, yfactor );

    factor = FL_clamp( factor, 1.0, 1.5 );

    /* Scale all objects without taking care of gravity etc. */

    if ( factor > 1.0 )
        simple_form_rescale( obj->form, factor );
}


/***************************************
 ***************************************/

void
fli_recount_auto_objects( void )
{
    int i;

    for ( fli_int.auto_count = i = 0; i < fli_int.formnumb; i++ )
        if ( fli_int.forms[ i ]->num_auto_objects > 0 )
            fli_int.auto_count++;
}


/***************************************
 * Reopens a group to allow addition of further objects
 ***************************************/

FL_OBJECT *
fl_addto_group( FL_OBJECT * group )
{
    if ( ! group )
    {
        M_err( "fl_addto_group", "NULL group." );
        return NULL;
    }

    if ( group->objclass != FL_BEGIN_GROUP )
    {
        M_err( "fl_addto_group", "Parameter is not a group object." );
        return NULL;
    }

    if ( fl_current_form && fl_current_form != group->form )
    {
        M_err( "fl_addto_group",
               "Can't switch to a group on a different form" );
        return NULL;
    }

    if ( fli_current_group && fli_current_group != group )
    {
        M_err( "fl_addto_group", "You forgot to call fl_end_group" );
        return NULL;
    }

    if ( fli_current_group )
        M_warn( "fl_addto_group", "Group was never closed" );

    reopened_group = fl_current_form ? 1 : 2;
    fl_current_form = group->form;
    return fli_current_group = group;
}


/***************************************
 * Returns if a form is visible
 ***************************************/

int
fl_form_is_visible( FL_FORM * form )
{
    if ( ! form )
    {
        M_warn( "fl_form_is_visible", "NULL form" );
        return FL_INVISIBLE;
    }

    return form->window ? form->visible : FL_INVISIBLE;
}


/***************************************
 * Similar to fit_object_label(), but will do it for all objects and
 * has a smaller maximum magnification factor (1.25 instead of 1.5).
 * Mainly intended for compensation for font size variations.
 ***************************************/

double
fl_adjust_form_size( FL_FORM * form )
{
    FL_OBJECT * obj;
    double xfactor,
           yfactor,
           max_factor,
           factor;
    int sw,
        sh,
        osize,
        bw;

    if ( fli_no_connection )
        return 1.0;

    max_factor = factor = 1.0;
    for ( obj = form->first; obj; obj = obj->next )
    {
        if (    fl_is_outside_lalign( obj->align )
             || obj->type == FL_BEGIN_GROUP
             || obj->type == FL_END_GROUP
             || obj->parent
             || ! obj->label
             || ! *obj->label
             || *obj->label == '@' )
            continue;

        fl_get_string_dimension( obj->lstyle, obj->lsize, obj->label,
                                 strlen( obj->label ), &sw, &sh );

        bw = (    obj->boxtype == FL_UP_BOX
               || obj->boxtype == FL_DOWN_BOX
               || obj->boxtype == FL_EMBOSSED_BOX ) ?
             FL_abs( obj->bw ) : 1;

        if (    obj->boxtype == FL_EMBOSSED_BOX )
            bw += bw > 2 ? bw - 2 : 1;

        if (    obj->objclass == FL_BUTTON
             && (    obj->type == FL_RETURN_BUTTON
                  || obj->type == FL_MENU_BUTTON ) )
            sw += FL_min( 0.6 * obj->h, 0.6 * obj->w ) - 1;

        if ( obj->objclass == FL_BUTTON && obj->type == FL_LIGHTBUTTON )
            sw += FL_LIGHTBUTTON_MINSIZE + 1;

        if (    sw <= obj->w - 2 * ( bw + 1 )
             && sh <= obj->h - 2 * ( bw + 1 ))
            continue;

        if ( ( osize = obj->w - 2 * ( bw + 1 ) ) <= 0 )
            osize = 1;
        xfactor = ( double ) sw / osize;

        if ( ( osize = obj->h - 2 * ( bw + 1 ) ) <= 0 )
            osize = 1;
        yfactor = ( double ) sh / osize;

        if ( ( factor = FL_max( xfactor, yfactor ) ) > max_factor )
            max_factor = factor;
    }

    /* Don't scale down and don't scale up by more than a factor of 1.25 */

    max_factor = FL_clamp( max_factor, 1.0, 1.25 );

    /* Scale all objects without taking care of gravity etc. */

    if ( max_factor > 1.0 )
        simple_form_rescale( form, max_factor );

    return max_factor;
}


/***************************************
 ***************************************/

void
fl_raise_form( FL_FORM * form )
{
    if ( form && form->window )
        XRaiseWindow( fl_display, form->window );
    else
        M_err( "fl_raise_form", "NULL form or form window not shown" );
}


/***************************************
 ***************************************/

void
fl_lower_form( FL_FORM * form )
{
    if ( form && form->window )
        XLowerWindow( fl_display, form->window );
    else
        M_err( "fl_lower_form", "NULL form or forn window not shown" );
}


/***************************************
 * Returns the sizes of the "decorations" the window manager puts around
 * a forms window. Returns 0 on success and 1 if the form isn't visible
 * or it's a form embedded into another form.
 * This tries to use the "_NET_FRAME_EXTENTS" atom which resonably recent
 * window managers in principle should set. For those window managers that
 * don't have that atom we try it with the old trick of searching up for
 * the enclosing parent window and using the geometry of this window (but
 * note: this doesn't work with window managers that don't reparent the
 * windows they manage, and we can't recognize that).
 ***************************************/

int
fl_get_decoration_sizes( FL_FORM * form,
                         int     * top,
                         int     * right,
                         int     * bottom,
                         int     * left )
{
    Atom a;

    if (    ! form
         || ! form->window
         || form->visible != FL_VISIBLE
         || form->parent )
        return 1;

    /* If the window manager knows about the '_NET_FRAME_EXTENTS' atom ask
       for the settings for the forms window, otherwise try by looking for
       the size of the enclosing parent window */

    if ( ( a = XInternAtom( fl_get_display( ), "_NET_FRAME_EXTENTS", True ) )
                                                                      != None )
        get_decoration_sizes_from_wm( a, form, top, right, bottom, left );
    else
        get_decorations_sizes_from_parent( form, top, right, bottom, left );

    return 0;
}


/***************************************
 * Gets the decorations sizes via the _NET_FRAME_EXTENTS atom.
 ***************************************/

static
void
get_decoration_sizes_from_wm( Atom      a,
                              FL_FORM * form,
                              int     * top,
                              int     * right,
                              int     * bottom,
                              int     * left )
{
    Atom actual_type;
    int actual_format;
    unsigned long nitems;
    unsigned long bytes_after;
    static unsigned char *prop;

    XGetWindowProperty( fl_get_display( ), form->window, a, 0,
                        4, False, XA_CARDINAL,
                        &actual_type, &actual_format, &nitems,
                        &bytes_after, &prop );

    /* If no properties are returne the window probably has no decorations */

    if (    actual_type == XA_CARDINAL
         && actual_format == 32
         && nitems == 4 )
    {
        *top    = ( ( long * ) prop )[ 2 ];
        *right  = ( ( long * ) prop )[ 1 ];
        *bottom = ( ( long * ) prop )[ 3 ];
        *left   = ( ( long * ) prop )[ 0 ];
    }
    else
        *top = *right =*bottom = *left = 0;
}


/***************************************
 * Tries to get the size of the decorations of a form the traditional
 * way, asuming that the form window is the child of a parent window
 * that encloses also the decoration windows (assuming that the window
 * manager reparents the windows it manages, otherwise we'll report
 * back zero sized decorations without any chance of figuring out that
 * this is wrong;-(
 ***************************************/

static
void
get_decorations_sizes_from_parent( FL_FORM * form,
                                   int     * top,
                                   int     * right,
                                   int     * bottom,
                                   int     * left )
{
    Window cur_win = form->window;
    Window root;
    Window parent;
    Window *childs = NULL;
    XWindowAttributes win_attr;
    XWindowAttributes frame_attr;
    Window wdummy;
    unsigned int udummy;

    /* Get the coordinates and size of the form's window */

    XGetWindowAttributes( fl_get_display( ), cur_win, &win_attr );

    /* Try to get its parent window */

    XQueryTree( fl_get_display( ), cur_win, &root, &parent, &childs,
                &udummy );

    /* Childs aren't used, get rid of them */

    if ( childs )
    {
        XFree( childs );
        childs = NULL;
    }

    /* If there's no parent or the parent window is the root window
       we've got to assume that there are no decorations */

    if ( ! parent || parent == root )
    {
        *top = *right =*bottom = *left = 0;
        return;
    }

    /* Now translate the form window's coordiates (that are relative to
       its parent) to that relative to the root window and then find the
       top-most parent that isn't the root window itself */

    XTranslateCoordinates( fl_get_display( ), parent, root,
                           win_attr.x, win_attr.y,
                           &win_attr.x, &win_attr.y, &wdummy );

    while ( parent && parent != root )
    {
        cur_win = parent;
        XQueryTree( fl_get_display( ), cur_win, &root, &parent, &childs,
                    &udummy );

        if ( childs )
        {
            XFree( childs );
            childs = NULL;
        }
    }

    /* Get the cordinates and sizes of the top-most window... */

    XGetWindowAttributes( fl_get_display( ), cur_win, &frame_attr );

    /* ...and finally calculate the decoration sizes */

    *top    = win_attr.y - frame_attr.y;
    *left   = win_attr.x - frame_attr.x;
    *bottom = frame_attr.height - win_attr.height - *top;
    *right  = frame_attr.width  - win_attr.width  - *left;
}


/***************************************
 * Returns if a form window is in iconified state
 ***************************************/

int
fl_form_is_iconified( FL_FORM * form )
{
    XWindowAttributes xwa;

    if ( ! form )
    {
        M_err( "fl_form_is_iconified", "NULL form" );
        return 0;
    }

    if ( ! form->window || form->visible == FL_INVISIBLE )
        return 0;

    XGetWindowAttributes( fl_get_display( ), form->window, &xwa );

    return xwa.map_state != IsViewable;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
