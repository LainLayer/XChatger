/*
 *  This file is part of XForms.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with XForms; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 59 Temple Place - Suite 330, Boston,
 *  MA 02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>


/***************************************
 ***************************************/

void
done_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

int
style_cb( FL_POPUP_RETURN *r )
{
    int style,
        size,
        mod;

    fl_popup_entry_get_font( r->user_data, &style, &size );
    mod = style & ( FL_SHADOW_STYLE | FL_ENGRAVED_STYLE | FL_EMBOSSED_STYLE );
    fl_popup_entry_set_font( r->user_data, r->val | mod, size );
    return FL_IGNORE;
}


/***************************************
 ***************************************/

int
size_cb( FL_POPUP_RETURN *r )
{
    int style;

    fl_popup_entry_get_font( r->user_data, &style, NULL );
    fl_popup_entry_set_font( r->user_data, style, r->val );
    fl_popup_get_title_font( r->user_data, &style, NULL );
    fl_popup_set_title_font( r->user_data, style, r->val );
    return FL_IGNORE;
}


/***************************************
 ***************************************/

int
mod_cb( FL_POPUP_RETURN *r )
{
    int style,
        size;

    fl_popup_entry_get_font( r->user_data, &style, &size );
    style &= ~ ( FL_SHADOW_STYLE | FL_ENGRAVED_STYLE | FL_EMBOSSED_STYLE );
    fl_popup_entry_set_font( r->user_data, style | r->val, size );
    return FL_IGNORE;
}


/***************************************
 ***************************************/

int
pol_cb( FL_POPUP_RETURN *r )
{
    FL_POPUP_ENTRY *e;

    for ( e = r->popup->entries; e != NULL; e = e->next )
        if ( e != r->entry )
            fl_popup_entry_clear_state( e, FL_POPUP_CHECKED );
    fl_popup_set_policy( r->user_data, r->val );
    return FL_IGNORE;
}


/***************************************
 ***************************************/

void
do_pup( FL_OBJECT * obj,
        long        q  FL_UNUSED_ARG )
{
    static FL_POPUP *m = NULL,
                    *sm1,
                    *sm2,
                    *sm3,
                    *sm4;

    if ( m == NULL )
    {
        m   = fl_popup_add( FL_ObjWin( obj ), "Popup" );
        sm1 = fl_popup_add( FL_ObjWin( obj ), NULL );
        sm2 = fl_popup_add( FL_ObjWin( obj ), NULL );
        sm3 = fl_popup_add( FL_ObjWin( obj ), NULL );
        sm4 = fl_popup_add( FL_ObjWin( obj ), NULL );

        fl_popup_add_entries( sm4, "FL_POPUP_NORMAL_SELECT%T%x%u%f",
                              FL_POPUP_NORMAL_SELECT, m, pol_cb );
        fl_popup_add_entries( sm4, "FL_POPUP_DRAG_SELECT%t%x%u%f",
                              FL_POPUP_DRAG_SELECT, m, pol_cb );

        fl_popup_add_entries( sm3, "None%x%R%u%f",
                              0, 1, m, mod_cb );
        fl_popup_add_entries( sm3, "FL_SHADOW_STYLE%x%r%u%f",
                              FL_SHADOW_STYLE, 1, m, mod_cb );
        fl_popup_add_entries( sm3, "FL_ENGRAVED_STYLE%x%r%u%f",
                              FL_ENGRAVED_STYLE, 1, m, mod_cb );
        fl_popup_add_entries( sm3, "FL_EMBOSSED_STYLE%x%r%u%f",
                              FL_EMBOSSED_STYLE, 1, m, mod_cb );

        fl_popup_add_entries( sm1, "FL_NORMAL_STYLE%Sn%x%R%u%f%s",
                              FL_NORMAL_STYLE, 1, m, style_cb, "n" );
        fl_popup_add_entries( sm1, "FL_BOLD_STYLE%Sb%x%r%u%f%s",
                              FL_BOLD_STYLE, 1, m, style_cb, "b" );
        fl_popup_add_entries( sm1, "FL_ITALIC_STYLE%Si%x%r%u%f%s",
                              FL_ITALIC_STYLE, 1, m, style_cb, "i" );
        fl_popup_add_entries( sm1, "FL_BOLDITALIC_STYLE%SI%x%r%u%f%s",
                              FL_BOLDITALIC_STYLE, 1, m, style_cb, "I" );
        fl_popup_add_entries( sm1, "%l|Font modifier%SCtrl-M%m%s", sm3, "^m" );

        fl_popup_add_entries( sm2, "FL_TINY_SIZE%x%r%u%f",
                              FL_TINY_SIZE, 1, m, size_cb );
        fl_popup_add_entries( sm2, "FL_SMALL_SIZE%x%r%u%f",
                              FL_SMALL_SIZE, 1, m, size_cb );
        fl_popup_add_entries( sm2, "FL_NORMAL_SIZE%x%R%u%f",
                              FL_NORMAL_SIZE, 1, m, size_cb );
        fl_popup_add_entries( sm2, "FL_MEDIUM_SIZE%x%r%u%f",
                              FL_MEDIUM_SIZE, 1, m, size_cb );
        fl_popup_add_entries( sm2, "FL_LARGE_SIZE%x%r%u%f",
                              FL_LARGE_SIZE, 1, m, size_cb );
        fl_popup_add_entries( sm2, "FL_HUGE_SIZE%x%r%u%f",
                              FL_HUGE_SIZE, 1, m, size_cb );

        fl_popup_add_entries( m, "Font style%m", sm1 );
        fl_popup_add_entries( m, "Font size%m", sm2 );
        fl_popup_add_entries( m, "Policy%m", sm4 );

        fl_popup_set_min_width( m, 100 );
    }

    if ( fl_get_button_numb( obj ) >= FL_SHORTCUT )
        fl_popup_set_position( m, obj->form->x + obj->x,
                               obj->form->y + obj->y + obj->h );

    fl_popup_do( m );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *obj;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 260, 210 );

    fl_add_box( FL_UP_BOX, 0, 0, 260, 210, "" );

    obj = fl_add_button( FL_NORMAL_BUTTON, 150, 150, 90, 35, "Done" );
    fl_set_object_callback( obj, done_cb, 0 );

    obj = fl_add_button( FL_MENU_BUTTON, 30, 90, 100, 30, "Popup" );
    fl_set_button_shortcut( obj, "Pp#p", 1 );
    fl_set_object_callback( obj, do_pup, 0 );

    fl_end_form( );

    /* initialize */

    fl_show_form( form, FL_PLACE_MOUSE, FL_TRANSIENT, "New Popup Demo" );

    fl_do_forms( );

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
