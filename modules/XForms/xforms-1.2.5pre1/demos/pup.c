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


/* Demo: complete pop-ups.
 * test font/cursor change
 * test attaching pup to menu
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

static FL_FORM * pup;

static FL_OBJECT * done,
                 * pret,
                 * b1,
                 * b2,
                 * b3,
                 * menu;

static void create_form_pup( void );

static void init_menu( void );

static int post( FL_OBJECT *, 
                 int,
                 FL_Coord,
                 FL_Coord,
                 int,
                 void * );


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_IOPT aa;
    unsigned int mask = FL_PDVisual;

    aa.vclass = FL_DefaultVisual;
    fl_set_defaults( mask, &aa );

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    create_form_pup( );

    /* Initialize */

    fl_set_object_posthandler( b1, post );
    fl_set_object_posthandler( b2, post );
    fl_set_object_posthandler( b3, post );

    fl_show_form( pup, FL_PLACE_MOUSE, FL_TRANSIENT, "PupDemo" );
    init_menu( );

    fl_do_forms( );     /* never returns */

    return 0;
}


/***************************************
 * post-handler
 ***************************************/

static int
post( FL_OBJECT * ob,
      int         ev,
      FL_Coord    mx   FL_UNUSED_ARG,
      FL_Coord    my   FL_UNUSED_ARG,
      int         key  FL_UNUSED_ARG,
      void      * xev  FL_UNUSED_ARG )
{
    static int n1 = -1,
               n2 = -1;

    if ( n1 == -1 )
    {
        n1 = fl_defpup( FL_ObjWin( ob ), "line1|line2" );
        fl_setpup_shadow( n1, 0 );
        fl_setpup_bw( n1, 0 );
        fl_setpup_pad( n1, 3, 0 );

        n2 = fl_defpup( FL_ObjWin( ob ), "button1|button2" );
        fl_setpup_shadow( n2, 0 );
        fl_setpup_bw( n2, -1 );
        fl_setpup_pad( n2, 3, 0 );
    }

    if ( ev == FL_ENTER )
    {
        if ( ob == b3 )
            fl_show_oneliner( "button3", ob->form->x + ob->x + 5,
                              ob->form->y + ob->y + ob->h + 5 );
        else
        {
            fl_setpup_position( ob->form->x+ob->x,
                                ob->form->y + ob->y + ob->h + 5 );
            fl_showpup( ob == b1 ? n1 : n2 );
       }
    }
    else if ( ev == FL_LEAVE )
    {
        if ( ob == b3 )
            fl_hide_oneliner( );
        else
            fl_hidepup( ob == b1 ? n1 : n2 );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
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

static int
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

static int
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

static int
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

static void
do_pup( FL_OBJECT * ob,
        long        q  FL_UNUSED_ARG )
{
    static FL_POPUP *m = NULL,
                    *sm1,
                    *sm2,
                    *sm3,
                    *sm4;

    if ( m == NULL )
    {
        m   = fl_popup_add( FL_ObjWin( ob ), "Popup" );
        sm1 = fl_popup_add( FL_ObjWin( ob ), NULL );
        sm2 = fl_popup_add( FL_ObjWin( ob ), NULL );
        sm3 = fl_popup_add( FL_ObjWin( ob ), NULL );
        sm4 = fl_popup_add( FL_ObjWin( ob ), NULL );

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
        fl_popup_add_entries( sm1, "%l|Font modifier%Sm%m%s", sm3, "m" );

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

    if ( fl_get_button_numb( ob ) >= FL_SHORTCUT )
        fl_popup_set_position( m, ob->form->x + ob->x,
                               ob->form->y + ob->y + ob->h );

    fl_popup_do( m );
}


/***************************************
 ***************************************/

static void
init_menu( void )
{
    FL_POPUP *mm,
             *smm;

    mm = fl_popup_add( fl_default_win( ), NULL );
    smm = fl_popup_add( fl_default_win( ), NULL );

    fl_popup_add_entries( smm, "SubItem1%x|SubItem2%x|SubItem3%x", 11, 12, 13 );
    fl_popup_add_entries( mm, "MenuItem1|MenuItem2%m|MenuItem3", smm );

    fl_set_nmenu_popup( menu, mm );
}


/***************************************
 ***************************************/

static void
do_menu( FL_OBJECT * ob,
         long        data  FL_UNUSED_ARG )
{
    char buf[ 128 ];
    FL_POPUP_RETURN *ret = fl_get_nmenu_item( ob );

    if ( ret->val >= 0 )
        sprintf( buf, "%ld (%s)", ret->val, ret->text );
    else
        sprintf( buf, "%ld", ret->val );

    fl_set_object_label( pret, buf );
}


/***************************************
 ***************************************/

static void
done_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

static void
do_nothing( FL_OBJECT * ob    FL_UNUSED_ARG,
            long        data  FL_UNUSED_ARG )
{
}


/***************************************
 ***************************************/

static void
create_form_pup( void )
{
    FL_OBJECT *obj;

    if ( pup )
        return;

    pup = fl_bgn_form( FL_UP_BOX, 260, 210 );

    fl_add_box( FL_UP_BOX, 0, 0, 260, 210, "" );

    done = obj = fl_add_button( FL_NORMAL_BUTTON, 150, 150, 90, 35, "Done" );
    fl_set_object_callback( obj, done_cb, 0 );

    obj = fl_add_button( FL_MENU_BUTTON, 30, 90, 100, 30, "PopUp" );
    fl_set_button_shortcut( obj, "Pp#p", 1 );
    fl_set_object_callback( obj, do_pup, 0 );

    menu = obj = fl_add_nmenu( FL_NORMAL_NMENU, 160, 95, 60, 25, "Menu" );
    fl_set_button_shortcut( obj, "Mm#m", 1 );
    fl_set_object_callback( obj, do_menu, 0 );

    pret = obj = fl_add_text( FL_NORMAL_TEXT, 20, 60, 220, 30, "" );
    fl_set_object_lalign( obj, FL_ALIGN_CENTER );

    b1 = fl_add_button( FL_NORMAL_BUTTON,   20, 10, 60, 30, "Button1" );
    fl_set_object_callback( b1, do_nothing, 0 );
    b2 = fl_add_button( FL_NORMAL_BUTTON,   90, 10, 60, 30, "Button2" );
    fl_set_object_callback( b2, do_nothing, 0 );
    b3 = fl_add_button( FL_NORMAL_BUTTON,  160, 10, 60, 30, "Button3" );
    fl_set_object_callback( b3, do_nothing, 0 );

    fl_end_form( );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
