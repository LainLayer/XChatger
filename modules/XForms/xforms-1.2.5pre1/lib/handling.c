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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include "include/forms.h"
#include "flinternal.h"


static void do_interaction_step( int );
static int get_next_event_or_idle( int,
                                   FL_FORM **,
                                   XEvent * );
static void handle_keyboard_event( XEvent * xev,
                                   int      formevent );
static void handle_EnterNotify_event( FL_FORM * );
static void handle_LeaveNotify_event( void );
static void handle_MotionNotify_event( FL_FORM * );
static void handle_ButtonPress_event( FL_FORM * evform );
static void handle_ButtonRelease_event( FL_FORM * evform );
static void handle_Expose_event( FL_FORM *,
                                 FL_FORM ** );
static void handle_ConfigureNotify_event( FL_FORM *,
                                          FL_FORM ** );
static void handle_ClientMessage_event( FL_FORM * form,
                                        void    * xev );
static int form_event_queued( XEvent *,
                              int );

/* Waiting time (in ms) for fl_check_forms() and fl_check_only_forms().
   Originally this value was 10 ms. */

#define SHORT_PAUSE   1


/* How frequently to generate FL_STEP event, in milliseconds is set here.
 * These are modified if an idle callback exists */

static int delta_msec = FLI_TIMER_RES;
static XEvent st_xev;

extern void ( * fli_handle_signal )( void );       /* defined in signal.c */
extern int ( * fli_handle_clipboard )( void * );   /* defined in clipboard.c */

/* When set results in behaviour as in version 1.0.90 and before where
   clicking on a non-input object didn't make an input object lose focus
   shortly and thus no "end of editing" was signaled to the user */

static int end_event_for_input = FL_INPUT_END_EVENT_ALWAYS;


/***************************************
 * Function for switching between "old" and "new" input handling
 * when another non-input object is clicked on
 ***************************************/

int
fl_input_end_return_handling( int type )
{
    int old_end_event_for_input = end_event_for_input;

    end_event_for_input = type;
    return old_end_event_for_input;
}


/***************************************
 ***************************************/

static int
fli_XLookupString( XKeyEvent * xkey,
                   char      * buf,
                   int         buflen,
                   KeySym    * ks )
{
    int len = INT_MIN;

    if ( ! fli_context->xic )
        len = XLookupString( xkey, buf, buflen, ks, 0 );
    else
    {
        Status status;

        len = XmbLookupString( fli_context->xic, xkey, buf, buflen, ks,
                               &status );

        if ( status == XBufferOverflow )
            len = -len;
    }

    return len;
}


/***************************************
 * Converts 'state' member of the 'xkey' member of an XEvent
 * into the corresponding mouse button number
 ***************************************/

static int
xmask2button( unsigned int mask )
{
    if ( mask & Button1Mask )
        return FL_LEFT_MOUSE;

    if ( mask & Button2Mask )
        return FL_MIDDLE_MOUSE;

    if ( mask & Button3Mask )
        return FL_RIGHT_MOUSE;

    if ( mask & Button4Mask )
        return FL_SCROLLUP_MOUSE;

    if ( mask & Button5Mask )
        return FL_SCROLLDOWN_MOUSE;

    return 0;
}


/***************************************
 * A radio object is pushed
 ***************************************/

void
fli_do_radio_push( FL_OBJECT * obj,
                   FL_Coord    x,
                   FL_Coord    y,
                   int         key,
                   void      * xev,
                   int         no_callbacks )
{
    FL_OBJECT *o = obj;

    if ( ! obj || ! obj->radio )
        return;

    /* If this radio button does not belong to any group we have to search
       the entire form, otherwise just treat the members of the group */

    if ( obj->group_id == 0 )
    {
        for ( o = obj->form->first; o; o = o->next )
            if (    o != obj
                 && o->radio
                 && o->group_id == 0
                 && fl_get_button( o ) )
            {
                fli_handle_object( o, FL_RELEASE, x, y, key, xev, 0 );
                break;
            }
    }
    else
    {
        while ( o->prev && o->prev->objclass != FL_BEGIN_GROUP )
            o = o->prev;

        for ( ; o && o->objclass != FL_END_GROUP; o = o->next )
            if ( o != obj && o->radio && fl_get_button( o ) )
            {
                fli_handle_object( o, FL_RELEASE, x, y, key, xev, 0 );
                break;
            }
    }

    if ( ! no_callbacks )
        fli_handle_object( obj, FL_PUSH, x, y, key, xev, 1 );
}


/***************************************
 ***************************************/

static int
do_shortcut( FL_FORM  * form,
             int        key,
             FL_Coord   x,
             FL_Coord   y,
             XEvent   * xev )
{
    int key1,
        key2;
    FL_OBJECT *obj;
    long *s;

    key1 = key2 = key;

    /* Check for ALT modifier key */

    if ( fl_keypressed( XK_Alt_L ) || fl_keypressed( XK_Alt_R ) )
    {
        if ( key < 256 )
        {
            key1 = FL_ALT_MASK + ( islower( ( int ) key ) ?
                                   toupper( ( int ) key ) : key );
            key2 = FL_ALT_MASK + key;
        }
        else
            key1 = key2 = FL_ALT_MASK + key;
    }

    M_info( "do_shortcut", "win = %ld key = %d %d %d",
            form->window, key, key1, key2 );

    /* Check if an object has this as a shortcut */

    for ( obj = form->first; obj; obj = obj->next )
    {
        if ( ! obj->shortcut || ! obj->active || ! obj->visible)
            continue;

        for ( s = obj->shortcut; *s; s++ )
        {
            if ( *s != key1 && *s != key2 )
                continue;

            if ( obj->objclass == FL_INPUT )
            {
                if ( obj != form->focusobj )
                {
                    fli_handle_object( form->focusobj, FL_UNFOCUS,
                                       x, y, 0, xev, 1 );
                    fli_handle_object( obj, FL_FOCUS, x, y, 0, xev, 1 );
                }
            }
            else
            {
                if ( obj->radio )
                {
                    int b;
                    FL_BUTTON_STRUCT *sp = obj->spec;

                    for ( b = FL_MBUTTON1; b <= FL_MBUTTON5; ++b )
                        if ( sp->react_to[ b - 1 ] )
                            break;

                    if ( b > FL_MBUTTON5 )
                        break;

                    fli_do_radio_push( obj, x, y, b, xev, 0 );
                }

                XAutoRepeatOff( flx->display );
                if ( ! obj->radio )
                    fli_handle_object( obj, FL_SHORTCUT, x, y, key1, xev, 1 );
                fli_context->mouse_button = FL_SHORTCUT + key1;

                /* This is not exactly correct as shortcut might quit,
                   fl_finish() will restore the keyboard state */

                if ( fli_keybdcontrol.auto_repeat_mode == AutoRepeatModeOn )
                    XAutoRepeatOn( flx->display );
            }

            return 1;
        }
    }

    return 0;
}


/***************************************
 ***************************************/

int
fli_do_shortcut( FL_FORM  * form,
                 int        key,
                 FL_Coord   x,
                 FL_Coord   y,
                 XEvent   * xev )
{
    int ret = do_shortcut( form, key, x, y, xev );

    if ( ! ret )
    {
        if ( form->child )
            ret = do_shortcut( form->child, key, x, y, xev );
        if ( ! ret && form->parent )
            ret = do_shortcut( form->parent, key, x, y, xev );
    }

    return ret;
}


/***************************************
 ***************************************/

static void
handle_keyboard( FL_FORM  * form,
                 int        key,
                 FL_Coord   x,
                 FL_Coord   y,
                 void     * xev )
{
    FL_OBJECT *obj,
              *special;

    /* Always check shortcut first */

    if ( fli_do_shortcut( form, key, x, y, xev ) )
        return;

    /* Focus policy is done as follows: Input object has the highest
       priority. Next comes the object that wants special keys, finally
       followed by 'mouseobj', having the lowest proiority. */

    special = fli_find_first( form, FLI_FIND_KEYSPECIAL, 0, 0 );
    obj = special ?
          fli_find_object( special->next, FLI_FIND_KEYSPECIAL, 0, 0 ) : NULL;

    /* If two or more objects want keyboard input none will get it and
       keyboard input will go to mouseobj instead */

    if ( obj && obj != special )
        special = fli_int.mouseobj;

    if ( form->focusobj )
    {
        FL_OBJECT *focusobj = form->focusobj;

        /* Handle special keys first */

        if ( key > 255 )
        {
            if (    IsLeft( key )
                 || IsRight( key )
                 || IsHome( key )
                 || IsEnd( key ) )
                fli_handle_object( focusobj, FL_KEYPRESS, x, y, key, xev, 1 );
            else if (    (    IsUp( key )
                           || IsDown( key )
                           || IsPageUp( key )
                           || IsPageDown( key ) )
                      && focusobj->wantkey & FL_KEY_TAB )
                fli_handle_object( focusobj, FL_KEYPRESS, x, y, key, xev, 1 );
            else if ( special && special->wantkey & FL_KEY_SPECIAL )
            {
                /* Moving the cursor in input field that does not have focus
                   looks weird */

                if ( special->objclass != FL_INPUT )
                    fli_handle_object( special, FL_KEYPRESS,
                                       x, y, key, xev, 1 );
            }
            else if ( key == XK_BackSpace || key == XK_Delete )
                fli_handle_object( focusobj, FL_KEYPRESS, x, y, key, xev, 1 );
            return;
        }

        /* The <Tab> and <Return> keys move the focus to the next or previous
           input object (depending on <SHIFT> being pressed also, and for
           <Return> only if the current focus object hasn't set FL_KEY_TAB as
           it's the case for  multiline input objects) */

        if (    key == '\t'
             || ( key == '\r' && ! ( focusobj->wantkey & FL_KEY_TAB ) ) )
        {
            fli_handle_object( focusobj, FL_UNFOCUS, x, y, 0, xev, 1 );

            if ( ( ( XKeyEvent * ) xev )->state & fli_context->navigate_mask )
            {
                if ( ! ( obj = fli_find_object_backwards( focusobj->prev,
                                                          FLI_FIND_INPUT,
                                                          0, 0 ) ) )
                    obj = fli_find_last( form, FLI_FIND_INPUT, 0, 0 );
            }
            else                                      /* search forward */
            {
                if ( ! ( obj = fli_find_object( focusobj->next,
                                                FLI_FIND_INPUT, 0, 0 ) ) )
                        
                    obj = fli_find_first( form, FLI_FIND_INPUT, 0, 0 );
            }
                
            fli_handle_object( obj, FL_FOCUS, x, y, 0, xev, 1 );
        }
        else if ( focusobj->wantkey != FL_KEY_SPECIAL )
            fli_handle_object( focusobj, FL_KEYPRESS, x, y, key, xev, 1 );
        return;
    }

    /* Keyboard input is not wanted */

    if ( ! special || special->wantkey == 0 )
        return;

    /* Space is an exception for browser */

    if (   (    ( key > 255 || key == ' ' )
             && special->wantkey & FL_KEY_SPECIAL )
         || ( key < 255 && special->wantkey & FL_KEY_NORMAL )
         || ( special->wantkey == FL_KEY_ALL ) )
        fli_handle_object( special, FL_KEYPRESS, x, y, key, xev, 1 );
}


/***************************************
 * Updates a form according to an event
 ***************************************/

void
fli_handle_form( FL_FORM * form,
                 int       event,
                 int       key,
                 XEvent  * xev )
{
    FL_OBJECT *obj = NULL;
    FL_Coord x,
             y;

    if ( ! form || form->visible != FL_VISIBLE )
        return;

    if ( form->deactivated && event != FL_DRAW )
        return;

    if (    form->parent_obj
         && ! form->parent_obj->active
         && event != FL_DRAW )
        return;

    if ( event != FL_STEP )
        fli_set_form_window( form );

    if ( fli_int.query_age > 0 && fli_int.mouseform )
    {
        fl_get_form_mouse( fli_int.mouseform, &fli_int.mousex, &fli_int.mousey,
                           &fli_int.keymask );
        if ( event != FL_KEYPRESS )
            key = xmask2button( fli_int.keymask );
        fli_int.query_age = 0;
    }

    x = fli_int.mousex;
    y = fli_int.mousey;

    /* Except for step and draw events search for the object the event is
       for */

    if ( event != FL_STEP && event != FL_DRAW )
        obj = fli_find_last( form, FLI_FIND_MOUSE, x, y );

    switch ( event )
    {
        case FL_DRAW:       /* form must be redrawn completely */
            fl_redraw_form( form );
            break;

        case FL_ENTER:      /* mouse did enter the form */
            fli_int.mouseobj = obj;
            fli_handle_object( fli_int.mouseobj, FL_ENTER, x, y, 0, xev, 1 );
            break;

        case FL_LEAVE:      /* mouse left the form */
            fli_handle_object( fli_int.mouseobj, FL_LEAVE, x, y, 0, xev, 1 );
            if ( fli_int.pushobj == fli_int.mouseobj )
                fli_int.pushobj = NULL;
            fli_int.mouseobj = NULL;
            break;

        case FL_PUSH:       /* mouse button was pushed inside the form */
            /* Change focus: If an input object has the focus make it lose it
               (and thus report changes) and then set the focus to either the
               object that got pushed (if it's an input object) or back to the
               original one. Then we have to recheck that the object the
               FL_PUSH was for is still active - it may have become deactivated
               due to the handler for the object that became unfocused! */

            if ( obj )
            {
                if (    form->focusobj
                     && form->focusobj != obj
                     && ( obj->input || end_event_for_input ) )
                {
                    FL_OBJECT *old_focusobj = form->focusobj;

                    fli_handle_object( old_focusobj, FL_UNFOCUS,
                                       x, y, key, xev, 1 );

                    if ( ! obj->input || ! obj->active )
                        fli_handle_object( old_focusobj, FL_FOCUS,
                                           x, y, key, xev, 1 );
                }

                if ( obj->input && obj->active )
                    fli_handle_object( obj, FL_FOCUS, x, y, key, xev, 1 );
            }

            if ( form->focusobj )
                fli_int.keyform = form;

            if ( ! obj || ! obj->active )
                break;

            if (    ! obj->radio
                 && (    ! obj->input
                      || ( obj->input && obj->active && obj->focus ) ) )
            {
                fli_int.pushobj = obj;
                fli_handle_object( obj, FL_PUSH, x, y, key, xev, 1 );
            }
            else if ( obj->radio )
            {
                FL_BUTTON_STRUCT *sp = obj->spec;

                if ( sp->react_to[ key - 1 ] )
                    fli_do_radio_push( obj, x, y, key, xev, 0 );
            }
            break;

        case FL_RELEASE :       /* mouse button was released inside the form */
            if ( fli_int.pushobj )
            {
                obj = fli_int.pushobj;
                fli_int.pushobj = NULL;

                if ( ! obj->radio )
                    fli_handle_object( obj, FL_RELEASE, x, y, key, xev, 1 );
            }
            break;

        case FL_MOTION:          /* mouse position changed in the form */
            /* "Pushable" objects always get FL_MOTION events. Since there's
               no direct EnterNotify or LeaveNotify event for objects we
               "fake" them when an object gets entered or left. */

            if ( fli_int.pushobj != NULL )
                fli_handle_object( fli_int.pushobj, FL_MOTION, x, y, key,
                                   xev, 1 );
            else if ( obj != fli_int.mouseobj )
            {
                fli_handle_object( fli_int.mouseobj, FL_LEAVE, x, y, 0,
                                   xev, 1 );
                fli_handle_object( fli_int.mouseobj = obj, FL_ENTER,
                                   x, y, 0, xev, 1 );
            }

            /* Objects can declare that they want FL_MOTION events even
               though they're not "pushable" objects e.g. because they
               have some internal structure that depends on the mouse
               position (e.g. choice and counter objects). */

            if ( obj != fli_int.pushobj && obj && obj->want_motion )
                fli_handle_object( obj, FL_MOTION, x, y, key, xev, 1 );

            break;

        case FL_KEYPRESS:      /* key was pressed */
            handle_keyboard( form, key, x, y, xev );
            break;

        case FL_STEP:          /* simple step */
            obj = fli_find_first( form, FLI_FIND_AUTOMATIC, 0, 0 );

            if ( obj )
                fli_set_form_window( form );    /* set only if required */

            while ( obj )
            {
                fli_handle_object( obj, FL_STEP, x, y, 0, xev, 1 );
                obj = fli_find_object( obj->next, FLI_FIND_AUTOMATIC, 0, 0 );
            }
            break;

        case FL_UPDATE:
            /* "Pushable" objects may request an FL_UPDATE event by an
               artificial (but not very precise) timer.*/

            if ( fli_int.pushobj && fli_int.pushobj->want_update )
                fli_handle_object( fli_int.pushobj, FL_UPDATE, x, y, key,
                                   xev, 1 );
            break;

        case FL_MOVEORIGIN:
        case FL_OTHER:
            /* Need to dispatch it through all objects and monitor the status
               of forms as it may get closed */

            for ( obj = form->first; obj && form->visible == FL_VISIBLE;
                  obj = obj->next )
                if ( obj->visible )
                    fli_handle_object( obj, event, x, y, key, xev, 0 );
            break;
    }
}


static int preemptive_consumed( FL_FORM *,
                                int,
                                XEvent * );

/***************************************
 * Given an X event check for which of our forms it is
 ***************************************/

FL_FORM *
fli_find_event_form( XEvent * xev )
{
    return fl_win_to_form( ( ( XAnyEvent * ) xev )->window );
}


/***************************************
 ***************************************/

const XEvent *
fl_last_event( void )
{
    return &st_xev;
}


static int ignored_fake_configure;


/***************************************
 ***************************************/

static int
button_is_really_down( void )
{
    FL_Coord x,
             y;
    unsigned int km;

    fl_get_mouse( &x, &y, &km );

    return button_down( km );
}


/***************************************
 * Handle all events in the queue and flush output buffer
 ***************************************/

void
fli_treat_interaction_events( int wait_io )
{
    XEvent xev;

        if ( fl_display == None )
            return;

    /* If no event is present output buffer will be flushed. If one exists
       XNextEvent() in do_interaction_step() will flush the output buffer */

    do
        do_interaction_step( wait_io );
    while ( form_event_queued( &xev, QueuedAfterFlush ) );
}


/***************************************
 ***************************************/

static void
do_interaction_step( int wait_io )
{
    FL_FORM *evform = NULL;
    static FL_FORM *redraw_form = NULL;

    if ( ! get_next_event_or_idle( wait_io, &evform, &st_xev ) )
        return;

    /* Got an event for one of the forms */

#if FL_DEBUG >= ML_WARN
    if ( st_xev.type != MotionNotify || fli_cntl.debug > 2 )
        fli_xevent_name( "MainLoop", &st_xev );
#endif

    fli_compress_event( &st_xev, evform->compress_mask );

    fli_int.query_age++;

    /* Run user raw callbacks for events, we're done if we get told that
       we're not supposed to do anything else with the event */

    if ( preemptive_consumed( evform, st_xev.type, &st_xev ) )
        return;

    /* Otherwise we need to handle the event ourself... */

    switch ( st_xev.type )
    {
        case MappingNotify:
            XRefreshKeyboardMapping( ( XMappingEvent * ) &st_xev );
            break;

        case FocusIn:
            if ( evform->focusobj )
                fli_int.keyform = evform;

            if ( fli_context->xic )
                XSetICValues( fli_context->xic,
                              XNFocusWindow, st_xev.xfocus.window,
                              XNClientWindow, st_xev.xfocus.window,
                              ( char * ) NULL );
            break;

        case FocusOut:
            fli_int.keyform = NULL;
            break;

        case KeyPress:
            handle_keyboard_event( &st_xev, FL_KEYPRESS );
            break;

        case KeyRelease:
            handle_keyboard_event( &st_xev, FL_KEYRELEASE );
            break;

        case EnterNotify:
            handle_EnterNotify_event( evform );
            break;

        case LeaveNotify:
            handle_LeaveNotify_event( );
            break;

        case MotionNotify:
            handle_MotionNotify_event( evform );
            break;

        case ButtonPress:
            handle_ButtonPress_event( evform );
            break;

        case ButtonRelease:
            handle_ButtonRelease_event( evform );
            break;

        case Expose:
            handle_Expose_event( evform, &redraw_form );
            break;

        case ConfigureNotify:
            handle_ConfigureNotify_event( evform, &redraw_form );
            break;

        case ClientMessage:
            handle_ClientMessage_event( evform, &st_xev );
            break;

        case DestroyNotify: /* only sub-form gets this due to parent destroy */
            fl_hide_form( evform );
            break;

        case SelectionClear:
        case SelectionRequest:
        case SelectionNotify:
            if ( ! fli_handle_clipboard || fli_handle_clipboard( &st_xev ) < 0 )
                fli_handle_form( evform, FL_OTHER, 0, &st_xev );
            break;

        default:
            fli_handle_form( evform, FL_OTHER, 0, &st_xev );
            break;
    }
}


/***************************************
 ***************************************/

void
fli_handle_idling( XEvent * xev,
                   long     msec,
                   int      do_idle_cb )
{
    static int within_idle_cb = 0;   /* Flag used to avoid an idle callback
                                        being called from within itself */

    /* Sleep a bit while being on the lookout for async IO events */

    fli_watch_io( fli_context->io_rec, msec );

    /* Deal with signals */

    if ( fli_handle_signal )
        fli_handle_signal( );

    /* Make sure we have an up-to-date set of data for the mouse position
       and the state of the keyboard and mouse buttons */

    if ( fli_int.query_age > 0 && fli_int.mouseform )
    {
        fl_get_form_mouse( fli_int.mouseform, &fli_int.mousex, &fli_int.mousey,
                           &fli_int.keymask );
        fli_int.query_age = 0;
        xev->xmotion.time = CurrentTime;
    }
    else
        xev->xmotion.time += msec;

    /* FL_UPDATE and automatic handlers as well as idle callbacks get a
       synthetic MotionNotify event. Make it up, then call the handler. */

    xev->type            = MotionNotify;
    xev->xany.window     = fli_int.mouseform ?
                           fli_int.mouseform->window : None;
    xev->xany.send_event = 1;
    xev->xmotion.state   = fli_int.keymask;
    xev->xmotion.x       = fli_int.mousex;
    xev->xmotion.y       = fli_int.mousey;
    xev->xmotion.is_hint = 0;

    /* We need to send an FL_UPDATE while a mouse button is down to "pushable"
       objects that want it (currently touch button, slider, choice, textbox
       and counter objects) */

    if (    button_down( fli_int.keymask )
         && fli_int.pushobj
         && fli_int.pushobj->want_update
         && fli_int.mouseform )
        fli_handle_form( fli_int.mouseform, FL_UPDATE,
                         xmask2button( fli_int.keymask ), xev );

    /* Handle automatic tasks */

    if ( fli_int.auto_count )
    {
        int i;

        for ( i = 0; i < fli_int.formnumb; i++ )
            if ( fli_int.forms[ i ]->num_auto_objects )
                fli_handle_form( fli_int.forms[ i ], FL_STEP, 0, xev );
    }

    /* If there's a user idle callback invoke it (unless we got called with
       'do_idle_cb' set to false or we're already running the idle callback) */

    if (    do_idle_cb
         && ! within_idle_cb
         && fli_context->idle_rec
         && fli_context->idle_rec->callback )
    {
        within_idle_cb = 1;
        fli_context->idle_rec->callback( xev, fli_context->idle_rec->data );
        within_idle_cb = 0;
    }
}


/***************************************
 ***************************************/

static int
get_next_event_or_idle( int        wait_io,
                        FL_FORM ** form,
                        XEvent   * xev )
{
    static unsigned int cnt = 0;
    long msec;

    /* Timeouts should be as precise as possible, so check them each time
       round. Since they may dictate how long we're going to wait if there
       is no event determine how how much time we will have to wait now */

    if ( ! wait_io )
        msec = SHORT_PAUSE;
    else if (    fli_int.auto_count
              || fli_int.pushobj
              || fli_context->idle_rec )
        msec = delta_msec;
    else
        msec = FL_min( delta_msec * 3, 300 );

    if ( fli_context->timeout_rec )
        fli_handle_timeouts( &msec );

    /* Skip checking for an X event after 10 events, thus giving X events
       a 10:1 priority over async IO, UPDATE events, automatic handlers and
       idle callbacks etc. */

    if ( ++cnt % 11 && XEventsQueued( flx->display, QueuedAfterFlush ) )
    {
        XNextEvent( flx->display, xev );

        /* There might be an input manager that wants the event - FilterEvent()
           returns true if this is the case and we are supposed to disregard
           the event */

        if ( fli_context->xic && XFilterEvent( xev, None ) )
            return 0;

        /* Find the form the event is for - if it's for one of "our" forms just
           return, indicating that there;s something to be done, otherwise it
           must be for e.g. a canvas window and thus has be put on the internal
           event queue */

        if ( ( *form = fli_find_event_form( xev ) ) != NULL )
            return 1;

        /* Please note: we do event compression before the user ever sees the
           events. This is a bit questionable, at least for mouse movements,
           since a user may want to get all events (e.g. because s/he wants
           to draw something exactly following the mouse movements). If this
           would be changed then care would have to be taken that in the mask
           for MotionNotify PointerMotionHintMask is *not* set (see the
           fli_xevent_to_mask() function in appwin.c) since that keeps most
           motion events from coming through! */

        fli_compress_event( xev,
                              ExposureMask
                            | PointerMotionMask
                            | ButtonMotionMask );

        fl_XPutBackEvent( xev );
    }
    else
    {
        cnt = 0;
        fli_handle_idling( &st_xev, msec, 1 );
    }

    return 0;
}


/***************************************
 * Handling for KeyPress and KeyRelease events (indicated by either FL_KEYPRESS
 * or FL_KEYRELEASE as the second argument)
 ***************************************/

static void
handle_keyboard_event( XEvent * xev,
                       int      formevent )
{
    Window win = xev->xkey.window;
    KeySym keysym = 0;
    unsigned char keybuf[ 227 ];
    int kbuflen;

    fli_int.mousex    = xev->xkey.x;
    fli_int.mousey    = xev->xkey.y;
    fli_int.keymask   = xev->xkey.state;
    fli_int.query_age = 0;

    /* Before doing anything save the current modifiers key for the handlers */

    if (    win
         && (    ! fli_int.keyform
              || fli_get_visible_forms_index( fli_int.keyform ) < 0 ) )
        fli_int.keyform = fl_win_to_form( win );

    /* Switch keyboard input only if different top-level form */

    if ( fli_int.keyform && fli_int.keyform->window != win )
    {
        M_warn( "handle_keyboard_event", "pointer/keybd focus differ" );

        if (    fli_int.keyform->child
             && fli_int.keyform->child->window != win
             && fli_int.keyform->parent
             && fli_int.keyform->parent->window != win )
            fli_int.keyform = fl_win_to_form( win );
    }

    if ( ! fli_int.keyform )
        return;

    kbuflen = fli_XLookupString( ( XKeyEvent * ) xev, ( char * ) keybuf,
                                 sizeof keybuf, &keysym );

    if ( kbuflen < 0 )
    {
        if ( kbuflen != INT_MIN )
            M_err( "handle_keyboard_event", "keyboad buffer overflow?" );
        else
            M_err( "handle_keyboard_event", "fli_XLookupString failed?" );

        return;
    }

    /* Ignore modifier keys as they don't cause action and are taken care
       of by the lookupstring routine */

    if ( IsModifierKey( keysym ) )
        /* empty */ ;
    else if ( IsTab( keysym ) )
    {
        /* Fake a tab key, on some systems shift+tab do not generate a tab */

        fli_handle_form( fli_int.keyform, formevent, '\t', xev );
    }
    else if ( IsCursorKey( keysym ) || kbuflen == 0 )
        fli_handle_form( fli_int.keyform, formevent, keysym, xev );
    else
    {
        unsigned char *ch;

        /* All regular keys, including mapped strings */

        for ( ch = keybuf; ch < keybuf + kbuflen && fli_int.keyform; ch++ )
            fli_handle_form( fli_int.keyform, formevent, *ch, xev );
    }
}


/***************************************
 * Handling of EnterNotiy events
 ***************************************/

static void
handle_EnterNotify_event( FL_FORM * evform )
{
    Window win = st_xev.xany.window;

    fli_int.mousex    = st_xev.xcrossing.x;
    fli_int.mousey    = st_xev.xcrossing.y;
    fli_int.keymask   = st_xev.xcrossing.state;
    fli_int.query_age = 0;

    if (    button_down( fli_int.keymask )
         && st_xev.xcrossing.mode != NotifyUngrab )
        return;

    if ( fli_int.mouseform )
        fli_handle_form( fli_int.mouseform, FL_LEAVE,
                         xmask2button( fli_int.keymask ), &st_xev );

    if ( evform )
    {
        fli_int.mouseform = evform;

        /* This is necessary because the window might be un-managed. To be
           friendly to other applications, grab focus only if absolutely
           necessary */

        if (    ! fli_int.mouseform->deactivated
             && ! st_xev.xcrossing.focus && fli_int.unmanaged_count > 0 )
        {
            fli_check_key_focus( "EnterNotify", win );
            fl_winfocus( win );
        }

        fli_handle_form( fli_int.mouseform, FL_ENTER,
                         xmask2button( fli_int.keymask ), &st_xev );
    }
#if FL_DEBUG >= ML_DEBUG
    else
        M_err( "handle_EnterNotify_event", "Null form" );
#endif
}


/***************************************
 * Handling of LeaveNotiy events
 ***************************************/

static void
handle_LeaveNotify_event( void )
{
    fli_int.mousex    = st_xev.xcrossing.x;
    fli_int.mousey    = st_xev.xcrossing.y;
    fli_int.keymask   = st_xev.xcrossing.state;
    fli_int.query_age = 0;

    if (    button_down( fli_int.keymask )
         && st_xev.xcrossing.mode == NotifyNormal )
        return;

    /* olvwm sends LeaveNotify with NotifyGrab whenever button is clicked,
       ignore it. Due to Xpopup grab, (maybe Wm bug?), end grab can also
       generate this event. We can tell these two situations by doing a real
       button_down test (as opposed to relying on the keymask in event) */

    if ( st_xev.xcrossing.mode == NotifyGrab && button_is_really_down( ) )
        return;

    if ( ! fli_int.mouseform )
        return;

    fli_handle_form( fli_int.mouseform, FL_LEAVE,
                     xmask2button( fli_int.keymask ), &st_xev );
}


/***************************************
 * Handling of MotionNotify events
 ***************************************/

static void
handle_MotionNotify_event( FL_FORM * evform )
{
    Window win = st_xev.xany.window;

    fli_int.keymask   = st_xev.xmotion.state;
    fli_int.mousex    = st_xev.xmotion.x;
    fli_int.mousey    = st_xev.xmotion.y;
    fli_int.query_age = 0;

    if ( ! fli_int.mouseform )
    {
        M_warn( "handle_MotionNotify_event", "event win = %ld", win );
        return;
    }

    /* If there's an object that has the mouse focus but the event isn't for
       the form of this object the mouse position reported is not relative
       to that window and we need to adjust it. */

    if ( fli_int.mouseform->window != win )
    {
        fli_int.mousex += evform->x - fli_int.mouseform->x;
        fli_int.mousey += evform->y - fli_int.mouseform->y;
    }

    fli_handle_form( fli_int.mouseform, FL_MOTION,
                     xmask2button( fli_int.keymask ), &st_xev );
}


/***************************************
 * Handling of ButttonPress events
 ***************************************/

static void
handle_ButtonPress_event( FL_FORM * evform  FL_UNUSED_ARG )
{
    fli_int.mousex  = st_xev.xbutton.x;
    fli_int.mousey  = st_xev.xbutton.y;
    fli_int.keymask = st_xev.xbutton.state
        | ( Button1Mask << ( st_xev.xbutton.button - 1 ) );
    fli_int.query_age = 0;

    fli_context->mouse_button = st_xev.xbutton.button;
    if ( metakey_down( fli_int.keymask ) && st_xev.xbutton.button == 2 )
        fli_print_version( 1 );
    else
        fli_handle_form( fli_int.mouseform, FL_PUSH,
                         st_xev.xbutton.button, &st_xev );
}


/***************************************
 * Handling of ButttonRelease events
 ***************************************/

static void
handle_ButtonRelease_event( FL_FORM * evform )
{
    fli_int.mousex  = st_xev.xbutton.x;
    fli_int.mousey  = st_xev.xbutton.y;
    fli_int.keymask =   st_xev.xbutton.state
                      & ~ ( Button1Mask << ( st_xev.xbutton.button - 1 ) );
    fli_int.query_age = 0;

    fli_context->mouse_button = st_xev.xbutton.button;

    /* Before the button was released (but after the press) a new form window
       may have been created, just below the mouse. In that case the mouse
       form, which is the one to receive the release event isn't the one that
       actually gets the event - it goes instead to the newly opened form
       window. And in this case the coordinates of where the mouse was release
       are relative to the new window but all the functions called for the
       object in the original mouse form expect them to be relative to the
       previous form. Thus we need to adjust these coordinates to be relative
       to the original mouse form window instead of the window opened since
       the mouse press. Thanks to Werner Heisch for finding this weired
       problem... */

    if ( fli_int.mouseform )
    {
        if ( fli_int.mouseform != evform )
        {
            st_xev.xbutton.x = fli_int.mousex +=
                                              evform->x - fli_int.mouseform->x;
            st_xev.xbutton.y = fli_int.mousey +=
                                              evform->y - fli_int.mouseform->y;
        }

        fli_handle_form( fli_int.mouseform, FL_RELEASE,
                         st_xev.xbutton.button, &st_xev );
    }

    fli_int.mouseform = evform;
}


/***************************************
 * Handling of Expose events
 ***************************************/

static void
handle_Expose_event( FL_FORM  * evform,
                     FL_FORM ** redraw_form )
{
    if ( ! evform )
        return;

    /* If 'redraw_form' is the same as 'evform' we actually got a
       ConfigureNotify before that isn't handled yet and the data for the
       Exposure event must be modified - set clipping to the complete area
       of the form since we got to redraw it completely. */

    if ( *redraw_form == evform )
    {
        st_xev.xexpose.x = 0;
        st_xev.xexpose.y = 0;
        st_xev.xexpose.width  = evform->w;
        st_xev.xexpose.height = evform->h;
        *redraw_form = NULL;
    }
    else
    {
        if ( st_xev.xexpose.x + st_xev.xexpose.width > evform->w )
            st_xev.xexpose.width = evform->w - st_xev.xexpose.x;
        if ( st_xev.xexpose.y + st_xev.xexpose.height > evform->h )
            st_xev.xexpose.height = evform->h - st_xev.xexpose.y;
    }

    fli_set_global_clipping( st_xev.xexpose.x, st_xev.xexpose.y,
                             st_xev.xexpose.width, st_xev.xexpose.height );

    /* Run into trouble by ignoring configure notify */

    if ( ignored_fake_configure )
    {
        FL_Coord neww,
                 newh;

        M_warn( "handle_Expose_event", "Run into trouble - correcting it" );
        fl_get_winsize( evform->window, &neww, &newh );
        fli_scale_form( evform, ( double ) neww / evform->w,
                        ( double ) newh / evform->h );
        ignored_fake_configure = 0;
    }

    fli_handle_form( evform, FL_DRAW, 0, &st_xev );

    fli_unset_global_clipping( );
}


/***************************************
 * Handling of ConfigureNotify events
 ***************************************/

static void
handle_ConfigureNotify_event( FL_FORM  * evform,
                              FL_FORM ** redraw_form )
{
    Window win = st_xev.xany.window;
    int old_w = evform->w;
    int old_h = evform->h;

    if ( ! evform )
        return;

    if ( ! st_xev.xconfigure.send_event )
        fl_get_winorigin( win, &evform->x, &evform->y );
    else
    {
        evform->x = st_xev.xconfigure.x;
        evform->y = st_xev.xconfigure.y;
        M_warn( "handle_ConfigureNotify_event", "WMConfigure:x = %d y = %d"
                "w = %d h = %d", evform->x, evform->y, st_xev.xconfigure.width,
                st_xev.xconfigure.height );
    }

    /* mwm sends bogus ConfigureNotify randomly without following up with a
       redraw event, but it does set send_event. The check is somewhat
       dangerous, use 'ignored_fake_configure' to make sure when we got expose
       we can respond correctly. The correct fix is always to get window
       geometry in Expose handler, but that has a two-way traffic overhead */

    ignored_fake_configure =    st_xev.xconfigure.send_event
                             && (    st_xev.xconfigure.width  != evform->w
                                  || st_xev.xconfigure.height != evform->h );

    /* Dragging a form across the screen changes its absolute x, y coords.
       Objects that themselves contain forms should ensure that they are up to
       date. */

    fli_handle_form( evform, FL_MOVEORIGIN, 0, &st_xev );

    if ( st_xev.xconfigure.send_event )
        return;

    /* Can't just set form->{w,h}. Need to take care of obj gravity */

    fli_scale_form( evform, ( double ) st_xev.xconfigure.width  / evform->w,
                    ( double ) st_xev.xconfigure.height / evform->h );

    /* If both the width and the height got smaller (or one got smaller and
       the other one remained unchanged) we're not going to get an Expose
       event, so we need to redraw the form. If only one of the lengths got
       smaller or remained unchanged while the other got larger the next
       (compressed) Expose event will only cover the added part. In this
       case store the forms address so on the next Expose event we receive
       for it its full area will be redrawn. */

    if ( evform->w <= old_w && evform->h <= old_h )
        fl_redraw_form( evform );
    else if ( ! ( evform->w > old_w && evform->h > old_h ) ) 
        *redraw_form = evform;
}


/***************************************
 * Handling of ClientMessage events, intercepts WM_DELETE_WINDOW messages
 ***************************************/

static void
handle_ClientMessage_event( FL_FORM * form,
                            void    * xev )
{
    XClientMessageEvent *xcm = xev;
    static Atom atom_protocol;
    static Atom atom_del_win = None;

    if ( ! atom_del_win )
    {
        atom_protocol = XInternAtom( xcm->display, "WM_PROTOCOLS", 0 );
        atom_del_win = XInternAtom( xcm->display, "WM_DELETE_WINDOW", 0 );
    }

    /* On message for deletion of top-level window quit unless handlers are
       installed */

    if (    xcm->message_type == atom_protocol
         && ( Atom ) xcm->data.l[ 0 ] == atom_del_win )
    {
        if ( form->close_callback )
        {
            if (    form->close_callback( form, form->close_data ) != FL_IGNORE
                 && form->visible == FL_VISIBLE )
                fl_hide_form( form );

            if ( form->sort_of_modal )
                fl_activate_all_forms( );
        }
        else if ( fli_context->atclose )
        {
            if ( fli_context->atclose( form,
                                       fli_context->close_data ) != FL_IGNORE )
                exit( 1 );
        }
        else
            exit( 1 );
    }
    else    /* pump it through current form */
        fli_handle_form( form, FL_OTHER, 0, xev );
}


/***************************************
 * Checks all forms. Does not wait.
 ***************************************/

FL_OBJECT *
fl_check_forms( void )
{
    FL_OBJECT *obj;

    if ( ! ( obj = fli_object_qread( ) ) )
    {
        fli_treat_interaction_events( 0 );
        fli_treat_user_events( );
        obj = fli_object_qread( );

        if ( fl_display == None )
            return NULL;
    }

    return obj;
}


/***************************************
 * Same as fl_check_forms() but never returns FL_EVENT.
 ***************************************/

FL_OBJECT *
fl_check_only_forms( void )
{
    FL_OBJECT *obj;

    if ( ! ( obj = fli_object_qread( ) ) )
    {
        fli_treat_interaction_events( 0 );
        obj = fli_object_qread( );

        if ( fl_display == None )
            return NULL;
    }

    return obj;
}


/***************************************
 * Checks all forms and keeps checking as long as nothing happens.
 ***************************************/

FL_OBJECT *
fl_do_forms( void )
{
    FL_OBJECT *obj;

   while ( ! ( obj = fli_object_qread( ) ) )
    {
        fli_treat_interaction_events( 1 );
        fli_treat_user_events( );

        if ( fl_display == None )
            return NULL;
    }

    return obj;
}


/***************************************
 * Same as fl_do_forms() but never returns FL_EVENT.
 ***************************************/

FL_OBJECT *
fl_do_only_forms( void )
{
    FL_OBJECT *obj;

    while ( ! ( obj = fli_object_qread( ) ) )
    {
        fli_treat_interaction_events( 1 );

        if ( fl_display == None )
            return NULL;
    }

    if ( obj == FL_EVENT )
        M_warn( "fl_do_only_forms", "Shouldn't happen" );

    return obj;
}


/***************************************
 ***************************************/

static int
form_event_queued( XEvent * xev,
                   int      mode )
{
    if ( fl_display == None )
        return 0;

    if ( XEventsQueued( flx->display, mode ) )
    {
        XPeekEvent( flx->display, xev );
        return fli_find_event_form( xev ) != NULL;
    }

    return 0;
}


/***************************************
 ***************************************/

static int
preemptive_consumed( FL_FORM * form,
                     int       type,
                     XEvent  * xev )
{
    if ( ! form || ! form->evmask || form->deactivated )
        return 0;

    if (    ( form->evmask & FL_ALL_EVENT ) == FL_ALL_EVENT
         && form->all_callback )
        return form->all_callback( form, xev );

    switch ( type )
    {
        case ButtonPress:
            if (    form->evmask & ButtonPressMask
                 && form->push_callback )
                return form->push_callback( form, xev );
            break;

        case ButtonRelease:
            if (    form->evmask & ButtonReleaseMask
                 && form->push_callback )
                return form->push_callback( form, xev );
            break;

        case KeyPress:
            if (    form->evmask & KeyPressMask
                 && form->key_callback )
                return form->key_callback( form, xev );
            break;

        case KeyRelease:
            if (    form->evmask & KeyRelease
                 && form->key_callback )
                return form->key_callback( form, xev );
            break;

        case EnterNotify:
            if (    form->evmask & EnterWindowMask
                 && form->crossing_callback )
                return form->crossing_callback( form, xev );
            break;

        case LeaveNotify:
            if (    form->evmask & LeaveWindowMask
                 && form->crossing_callback )
                return form->crossing_callback( form, xev );
            break;

        case MotionNotify:
            if (    form->evmask & ( ButtonMotionMask | PointerMotionMask )
                 && form->motion_callback )
                return form->motion_callback( form, xev );
    }

    return 0;
}


/***************************************
 * Returns the current state of the mouse buttons
 ***************************************/

long
fl_mouse_button( void )
{
    return fli_context->mouse_button;
}


/***************************************
 * Returns the event currently being handled - only makes sense to
 * call this from within an object or form callback.
 ***************************************/

int
fl_current_event( void )
{
    return fli_context->last_event;
}


/***************************************
 ***************************************/

FLI_TARGET *
fli_internal_init( void )
{
    static FLI_TARGET *default_flx;

    if ( ! default_flx )
        default_flx = fl_calloc( 1, sizeof *default_flx );

    return flx = default_flx;
}


/***************************************
 * fl_display is exposed to the outside world. Bad
 ***************************************/

void
fli_switch_target( FLI_TARGET * newtarget )
{
    flx = newtarget;
    fl_display = flx->display;
}


/***************************************
 ***************************************/

void
fli_restore_target( void )
{
    fli_internal_init( );
    fl_display = flx->display;
}


/***************************************
 * Currently only a single idle callback is support
 ***************************************/

static void
add_idle_callback( FL_APPEVENT_CB   cb,
                   void           * data )
{
    if ( ! cb )
    {
        fli_safe_free( fli_context->idle_rec );
        return;
    }

    if ( ! fli_context->idle_rec )
        fli_context->idle_rec = fl_malloc( sizeof *fli_context->idle_rec );

    fli_context->idle_rec->callback = cb;
    fli_context->idle_rec->data = data;
}


/***************************************
 * Sets an idle callback
 ***************************************/

FL_APPEVENT_CB
fl_set_idle_callback( FL_APPEVENT_CB   callback,
                      void           * user_data )
{
    FL_APPEVENT_CB old =
                 fli_context->idle_rec ? fli_context->idle_rec->callback : NULL;

    add_idle_callback( callback, user_data );

    /* If we have idle callbacks, decrease the wait time */

    delta_msec = FLI_TIMER_RES * ( callback ? 0.8 : 1.0 );
    fli_context->idle_delta = delta_msec;

    return old;
}


/***************************************
 ***************************************/

void
fl_set_idle_delta( long delta )
{
    if ( delta < 0 )
        delta = FLI_TIMER_RES;
    else if ( delta == 0 )
        delta = FLI_TIMER_RES / 10;

    delta_msec = delta;
    fli_context->idle_delta = delta;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
