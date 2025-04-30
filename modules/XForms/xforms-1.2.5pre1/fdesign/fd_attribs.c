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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include "fd_main.h"
#include "fd_spec.h"
#include "fd_iconinfo.h"


/* Pointer to object currently being edited */

static FL_OBJECT * curobj;

static void save_edited_object( FL_OBJECT * obj );
static void restore_edited_object( FL_OBJECT * obj );
static void attrib_init( FD_generic_attrib * ui );
static int validate_attributes( FL_OBJECT * obj );
static void readback_attributes( FL_OBJECT * obj );
static void copy_shortcut( FL_OBJECT * dest,
                           FL_OBJECT * src );
static void cleanup_saved_object( void );
static void show_attributes( const FL_OBJECT * obj );
static int valid_c_identifier( const char * s );
static void add_font_choice( const char * p );
static int validate_cvar_name( FL_OBJECT * obj,
                               const char * w );


/* Structuure for storing the initial state of the object */

static struct {
	FL_OBJECT * obj;
	char        name[ MAX_VAR_LEN ];
	char        cbname[ MAX_VAR_LEN ];
	char        argname[ MAX_VAR_LEN ];
} saved_object;


/* Font sizes, need to do this because of symbolic names */

static FL_OBJECT *fnts;

typedef struct {
    int    size;
    char * name,
         * sc;
} Fsizes;

static Fsizes fsizes[ ] =
{
    { FL_TINY_SIZE,   "Tiny",     "Tt#t" },
    { FL_SMALL_SIZE,  "Small",    "Ss#s" },
    { FL_NORMAL_SIZE, "Normal",   "Nn#n" },
    { FL_MEDIUM_SIZE, "Medium",   "Mm#m" },
    { FL_LARGE_SIZE,  "Large",    "Ll#l" },
    { FL_HUGE_SIZE,   "Huge",     "Hh#h" },
    { 11,             "Variable", ""     }
};

#define NFSIZE ( sizeof fsizes / sizeof *fsizes )

/* Character used for newline */

#define NL 0x0a



/***************************************
 * Displays and do interaction with the form for changing object attributes.
 * 'all' indicates whether label, name, etc. should also be changed and is
 * only set when only a single object is to selected for changing.
 ***************************************/

int
change_object( FL_OBJECT * obj,
               int         all )
{
    FL_OBJECT *retobj;
    FD_generic_attrib *ui = fd_generic_attrib;
    FL_FORM * spec_form = NULL;

    attrib_init( ui );

    /* Save current attributes for later restore */

    curobj = obj;
    save_edited_object( obj );

    /* Show only required parts */

    if ( all )
    {
        fl_show_object( ui->labelobj  );
        fl_show_object( ui->scobj     );
        fl_show_object( ui->nameobj   );
        fl_show_object( ui->cbnameobj );
        fl_show_object( ui->argobj    );

        if ( ( spec_form = create_spec_form( curobj ) ) )
        {
            FL_OBJECT *t;

            t = fl_addto_tabfolder( fd_attrib->attrib_folder,
                                    "Spec", spec_form );
            fl_set_object_shortcut( t, "#S", 1 );
        }
    }
    else
    {
        fl_hide_object( ui->labelobj  );
        fl_hide_object( ui->scobj     );
        fl_hide_object( ui->nameobj   );
        fl_hide_object( ui->cbnameobj );
        fl_hide_object( ui->argobj    );
    }

    /* Show attributes of the current object */

    show_attributes( obj );

    /* Do interaction */

    fl_deactivate_all_forms( );

    /* Disable selection */

    no_selection = 1;

    fl_show_form( fd_attrib->attrib, FL_PLACE_GEOMETRY, FL_FULLBORDER,
                  "Attributes" );
    fl_set_app_mainform( fd_attrib->attrib );

    /* Both cancel and readyobj should have their own callbacks, so we don't
       need to call fl_do_forms(), but since attribute editing can't be
       invoked for more than one item at a time we need to block the
       process_xevent. TODO */

    do
    {
        XEvent xev;

        retobj = fl_do_forms( );
        if ( retobj == FL_EVENT )
            fl_XNextEvent( &xev );
    } while ( ! (    (    retobj == fd_attrib->readyobj
                       && validate_attributes( curobj ) )
                  || retobj == fd_attrib->cancelobj ) );

    if ( retobj == fd_attrib->cancelobj )
    {
        restore_edited_object( obj );
        redraw_the_form( 0 );
    }
    else
    {
        reread_spec_form( obj );
        readback_attributes( obj );
        spec_to_superspec( obj );
    }

    cleanup_saved_object( );

    fl_set_app_mainform( fd_control->control );
    fl_set_folder_bynumber( fd_attrib->attrib_folder, 1 );
    if ( spec_form )
        fl_delete_folder( fd_attrib->attrib_folder, spec_form );
    fl_hide_form( fd_attrib->attrib );
    fl_activate_all_forms( );

    no_selection = 0;

    return retobj == fd_attrib->readyobj;
}


/***************************************
 * Called on switching between "Generic" and "Spec" folder
 ***************************************/

void
folder_switch_cb( FL_OBJECT * obj,
                  long        data  FL_UNUSED_ARG )
{
    int active = fl_get_active_folder_number(
                        ( ( FD_attrib * ) obj->form->fdui )->attrib_folder );

    if ( active == 1 )
        reread_spec_form( curobj );
    else
    {
        readback_attributes( curobj );
        prepare_spec_form( curobj );
    }
}


/***************************************
 * Callback for most of the objects for setting generic attributes
 * (instead of having one for each of them) - evaluates the settings
 * from all the objects in the generic attributes form and sets the
 * object accordingly.
 ***************************************/

void
apply_cb( FL_OBJECT * obj  FL_UNUSED_ARG,
          long        arg  FL_UNUSED_ARG )
{
    readback_attributes( curobj );
    show_attributes( curobj );
}


/***************************************
 * Callback for the "Restore" button
 ***************************************/

void
restore_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
            long        data  FL_UNUSED_ARG )
{
    restore_edited_object( curobj );
    show_attributes( curobj );
    redraw_the_form( 0 );
}


/***************************************
 * Stores all information about the initial settings of the object
 * being edited (for restoring it)
 ***************************************/

static void
save_edited_object( FL_OBJECT * obj )
{
    /* Get memory for the object to save and copy everything */

	/* Now get memory for the saved object and store what it contains */

    saved_object.obj = fl_malloc( sizeof *saved_object.obj );
    *saved_object.obj = *obj;
    saved_object.obj->spec = NULL;

	/* Get the objects name, name of the callback function and
	   the argument string and store them */

    get_object_name( obj, saved_object.name, saved_object.cbname,
					 saved_object.argname );

	/* Now get memory for the saved object, store what it contains and
       also save the label and the shortcut for real */

    /* Make a copy of allocated memory in the obejct */

	saved_object.obj->label = fl_strdup( obj->label );
	copy_shortcut( saved_object.obj, obj );

    saved_object.obj->u_vdata = saved_object.obj->c_vdata = NULL;

    copy_superspec( saved_object.obj, obj );
    copy_iconinfo( saved_object.obj, obj );
}


/***************************************
 * Restores the object state to what it was when editing started
 ***************************************/

static void
restore_edited_object( FL_OBJECT * obj )
{
    void *sp = obj->spec;

    fl_free( obj->label );
    fl_free( obj->shortcut );

    free_superspec( obj );
    free_iconinfo( obj );

	*obj = *saved_object.obj;
    obj->spec = sp;

	obj->label = fl_strdup( saved_object.obj->label );
	copy_shortcut( obj, saved_object.obj );

    obj->u_vdata = obj->c_vdata = NULL;

    copy_superspec( obj, saved_object.obj );
    superspec_to_spec( obj );

    copy_iconinfo( obj, saved_object.obj );
    restore_spec( obj );

    set_object_name( obj, saved_object.name, saved_object.cbname,
					 saved_object.argname );

    /* It the "Spec" folder is currently been shown set its content to
       the restored object settings and redraw it */

    if ( fl_get_active_folder_number( fd_attrib->attrib_folder ) == 2 )
    {
        prepare_spec_form( obj );
        fl_redraw_object( fd_attrib->attrib_folder );
    }
}


/***************************************
 * Remove all data allocated in the structure for saving the objects
 * initial state
 ***************************************/

static void
cleanup_saved_object( void )
{
    if ( ! saved_object.obj )
        return;

	fl_free( saved_object.obj->label );
	fl_free( saved_object.obj->shortcut );
    free_superspec( saved_object.obj );
    free_iconinfo( saved_object.obj );
    fli_safe_free( saved_object.obj );
}


/***************************************
 * Initialize the form used for editing the objects attributes, needs to
 * be run only once
 ***************************************/

static void
attrib_init( FD_generic_attrib * ui )
{
    static int attrib_initialized;
    int i;
    VN_pair *vp;

    if ( attrib_initialized )
        return;

    attrib_initialized = 1;

    fl_clear_choice( ui->boxobj );
    for ( i = 1, vp = vn_btype; vp->val >= 0; vp++, i++ )
    {
        fl_addto_choice( ui->boxobj, vp->shown );
        fl_set_choice_item_shortcut( ui->boxobj, i, vp->hotkey );
    }

    fl_set_object_return( ui->nameobj, FL_RETURN_END );
    fl_set_object_return( ui->cbnameobj, FL_RETURN_END );

    /* Resize */

    fl_set_choice_fontsize( ui->resize, fd_align_fontsize );
    for ( vp = vn_resize; vp->val >= 0; vp++ )
        fl_addto_choice( ui->resize, vp->name + 3 );

    /* Gravity. Due to compatibility issues there are more than is needed
	   in vn_gravity */

    for ( i = 0, vp = vn_gravity; vp->val >= 0 && i < 9; vp++, i++ )
    {
        fl_addto_choice( ui->nwgravity, vp->name + 3 );
        fl_addto_choice( ui->segravity, vp->name + 3 );
    }

    /* Align (only show the first 9 elements of 'vn_align' the rest is
       in there for backward compatibility reasons when reading in a file) */

    fl_set_choice_fontsize( ui->align, fd_align_fontsize );
    for ( vp = vn_align, i = 0; vp->val >= 0 && i < 9; vp++, i++ )
        fl_addto_choice( ui->align, vp->name + 9 );
    fl_addto_choice( ui->inside, "Inside|Outside" );

    /* Font stuff */

    fnts = ui->fontobj;
    fl_enumerate_fonts( add_font_choice, 1 );
    fl_addto_choice( ui->styleobj, "Normal|Shadow|Engraved|Embossed" );

    /* Size */

    for ( i = 0; i < ( int ) NFSIZE; i++ )
    {
        if ( fsizes[ i ].size == FL_NORMAL_SIZE )
        {
            fsizes[ i ].name = "Normal";
            fsizes[ i ].sc = "Nn#n";
        }

        fl_addto_choice_f( ui->sizeobj,
                           "%2d  %s%%r1", fsizes[ i ].size, fsizes[ i ].name );
        fl_set_choice_item_shortcut( ui->sizeobj, i + 1, fsizes[ i ].sc );
    }
}


/***************************************
 * Sets up the "Generic" attributes form with the properties of the
 * object currently being edited
 ***************************************/

static void
show_attributes( const FL_OBJECT * obj )
{
    char objname[ MAX_VAR_LEN ],
         cbname[  MAX_VAR_LEN ],
         argname[ MAX_VAR_LEN ];
    char *label;
    int i,
        lstyle,
        spstyle,
        oksize,
        align = fl_to_outside_lalign( obj->align );
    static char othersize[ 32 ];

    fl_freeze_form( fd_generic_attrib->generic_attrib );

    /* Fill in list of types */

    fl_clear_choice( fd_generic_attrib->typeobj );
    fl_set_choice_fontsize( fd_generic_attrib->typeobj, fd_type_fontsize );

    if ( obj->objclass != FL_BOX )
    {
        for ( i = 0; i < find_class_maxtype( obj->objclass ); i++ )
            fl_addto_choice_f( fd_generic_attrib->typeobj,
                               "%s%%r1", find_type_name( obj->objclass, i ) );

        fl_set_choice( fd_generic_attrib->typeobj, obj->type + 1 );
    }

    /* Fill in settings */

	/* a) boxtype */

    fl_set_choice( fd_generic_attrib->boxobj, obj->boxtype + 1 );

	/* b) label alignment */

    fl_set_choice_text( fd_generic_attrib->align, align_name( align, 0 ) + 9 );
    fl_set_choice( fd_generic_attrib->inside,
                   fl_is_outside_lalign( obj->align ) + 1 );

	/* c) label font and style */

    lstyle  = obj->lstyle % FL_SHADOW_STYLE;
    spstyle = obj->lstyle / FL_SHADOW_STYLE;

    if ( spstyle >= 3 )
        spstyle = 3;

    fl_set_choice( fd_generic_attrib->fontobj, lstyle + 1 );
    fl_set_choice( fd_generic_attrib->styleobj, spstyle + 1 );

	/* d) label font size */

    for ( oksize = i = 0; ! oksize && i < ( int ) NFSIZE; i++ )
        if ( ( oksize = ( obj->lsize == fsizes[ i ].size ) ) )
            fl_set_choice( fd_generic_attrib->sizeobj, i + 1 );

    if ( ! oksize )
    {
        sprintf( othersize, "%d (Variable)", obj->lsize );
        fsizes[ NFSIZE - 1 ].size = obj->lsize;
        fsizes[ NFSIZE - 1 ].name = othersize;
        fl_replace_choice( fd_generic_attrib->sizeobj, NFSIZE, othersize );
        fl_set_choice( fd_generic_attrib->sizeobj, NFSIZE );
    }

    /* e) gravity settings */

    fl_set_choice_text( fd_generic_attrib->nwgravity,
                        gravity_name( obj->nwgravity ) + 3 );
    fl_set_choice_text( fd_generic_attrib->segravity,
                        gravity_name( obj->segravity ) + 3 );

	/* f) resize behaviour */

    fl_set_choice_text( fd_generic_attrib->resize,
                        resize_name( obj->resize ) + 3 );

	/* g) Label string */

    label = get_label( obj, 0 );
    fl_set_input( fd_generic_attrib->labelobj, label );
    fl_free( label );

	/* h) name, callback function name and argument */

    get_object_name( obj, objname, cbname, argname );

    fl_set_input( fd_generic_attrib->nameobj, objname );
    fl_set_input( fd_generic_attrib->cbnameobj, cbname );
    fl_set_input( fd_generic_attrib->argobj, argname );

	/* h) shortcut */

    fl_set_input( fd_generic_attrib->scobj, get_shortcut_string( obj ) );

	/* i) object and label colors */

    fl_set_object_color( fd_generic_attrib->col1obj, obj->col1, obj->col1 );
    fl_set_object_color( fd_generic_attrib->col2obj, obj->col2, obj->col2 );
    fl_set_object_color( fd_generic_attrib->lcolobj, obj->lcol, obj->lcol );

    fl_unfreeze_form( fd_generic_attrib->generic_attrib );
}


/***************************************
 * Sets the objects attributes from  the content of the "Generic" attributes
 * form
 ***************************************/

static void
readback_attributes( FL_OBJECT * obj )
{
    int v1, v2;
    char * name,
         * cbname;
    char tmpbuf[ 128 ];

    obj->boxtype = fl_get_choice( fd_generic_attrib->boxobj ) - 1;

    /* Take care: for some objects the "Type" choice is empty! */

    if (    ( v1 = fl_get_choice( fd_generic_attrib->typeobj ) - 1 ) >= 0
         && v1 != obj->type )
        spec_change_type( obj, v1 );

    /* Label style consists of two parts */

    v1 = fl_get_choice( fd_generic_attrib->fontobj ) - 1;
    v2 = fl_get_choice( fd_generic_attrib->styleobj ) - 1;
    v1 += v2 == 3 ? FL_EMBOSSED_STYLE : ( v2 * FL_SHADOW_STYLE );
    fl_set_object_lstyle( obj, v1 );

    fl_set_object_color( obj, fd_generic_attrib->col1obj->col1,
                         fd_generic_attrib->col2obj->col1 );

    fl_set_object_lcol( obj, fd_generic_attrib->lcolobj->col1 );

    sprintf( tmpbuf, "FL_ALIGN_%s",
             fl_get_choice_text( fd_generic_attrib->align ) );
    v1 = align_val( tmpbuf );

    if ( fl_get_choice( fd_generic_attrib->inside ) == 1 )
        v1 = fl_to_inside_lalign( v1 );
    else
        v1 = fl_to_outside_lalign( v1 );

    fl_set_object_lalign( obj, v1 );

    sprintf( tmpbuf, "FL_%s",
             fl_get_choice_text( fd_generic_attrib->nwgravity ) );
    v1 = gravity_val( tmpbuf );

    sprintf( tmpbuf, "FL_%s",
             fl_get_choice_text( fd_generic_attrib->segravity ) );
    v2 = gravity_val( tmpbuf );

    fl_set_object_gravity( obj, v1, v2 );
       
    /* Set resize property after making sure it fits with the gravity
       settings */

    sprintf( tmpbuf, "FL_%s", fl_get_choice_text( fd_generic_attrib->resize ) );
    fl_set_object_resize( obj, check_resize( resize_val( tmpbuf ),
                                             obj->nwgravity, obj->segravity ) );

    fl_set_object_lsize( obj, fsizes[ fl_get_choice(
                                      fd_generic_attrib->sizeobj ) - 1 ].size );

    set_label( obj, fl_get_input( fd_generic_attrib->labelobj ) );
    set_shortcut( obj, fl_get_input( fd_generic_attrib->scobj ) );

    name = fl_strdup( fl_get_input( fd_generic_attrib->nameobj ) );
    cbname = fl_strdup( fl_get_input( fd_generic_attrib->cbnameobj ) );

    if ( ! valid_c_identifier( name ) )
        *name = '\0';

    if ( ! valid_c_identifier( cbname ) )
        *cbname = '\0';

    set_object_name( obj, name, cbname,
                     fl_get_input( fd_generic_attrib->argobj ) );

    fl_free( cbname );
    fl_free( name );

    redraw_the_form( 0 );
}


/***************************************
 * Turns the string from the label input field into a string suitable for
 * an object label (taking care of newlines and shortcut markers) and
 * the sets the label of the object being edited.
 ***************************************/

void
set_label( FL_OBJECT  * obj,
           const char * str )
{
    int i = 0,
        j = 0;
    char *tmpstr = fl_malloc( strlen( str ) + 1 );

    *tmpstr = '\0';

    do
    {
        if ( str[ i ] == '\\' && str[ i + 1 ] == 'n' )
        {
            tmpstr[ j++ ] = NL;
            i++;
        }
        else if ( str[ i ] == '\\' && strncmp( str + i + 1, "010", 3 ) == 0 )
        {
            if ( ! obj->shortcut || ! *obj->shortcut )
                tmpstr[ j++ ] = *fl_ul_magic_char;
            i += 3;
        }
        else
            tmpstr[ j++ ] = str[ i ];
    } while ( str[ i++ ] );

    fl_set_object_label( obj, tmpstr );
    fl_free( tmpstr );
}


/***************************************
 * Sets the shortcut of the object being edited.
 ***************************************/

void
set_shortcut( FL_OBJECT  * obj,
              const char * sc )
{
    if (    obj->type != FL_RETURN_BUTTON
         && obj->type != FL_HIDDEN_RET_BUTTON )
        fl_set_object_shortcut( obj, sc, 1 );
}


/* if \ preceeds c, \ does not need quote */

#define Ok( c ) \
    ( c== '"' || c== '\\' || c == 't' || c == 'n' \
      || isdigit( ( unsigned char )  c ) )


/***************************************
 * Decides if label need quotes ('\')
 ***************************************/

static int
need_quote( const char * s,
            int          i )
{
    int c = s[ i ],
        p =  i ? s[ i - 1 ] : 0,     /* prev char */
        n = *s ? s[ i + 1 ] : 0;     /* next char */

    if ( c == '"' && p != '\\' )
        return 1;
    else if ( c == '\\' && p != '\\' )
        return ! isdigit( ( unsigned char ) n ) && ! Ok( n );
    else
        return 0;
}


/***************************************
 * Takes an objects label string and converts it into a string suitable
 * for setting as the content of the label input field
 ***************************************/

char *
get_label( const FL_OBJECT * obj,
           int               c_source )
{
    int i = 0,
        j = 0;
    const char *label = obj->label;
    int len = strlen( label );
    int tlen = len + 1;
    char *tmpstr = fl_malloc( tlen );

    for ( i = 0; i < len; i++ )
    {
        if ( label[ i ] == NL )
        {
            tmpstr = fl_realloc( tmpstr, tlen += 1 );
            tmpstr[ j++ ] = '\\';
            tmpstr[ j++ ] = 'n';
        }
        else if ( label[ i ] == *fl_ul_magic_char )
        {
            if ( ! obj->shortcut || ! *obj->shortcut )
            {
                tmpstr = fl_realloc( tmpstr, tlen += 3 );
                tmpstr[ j++ ] = '\\';
                tmpstr[ j++ ] = '0';
                tmpstr[ j++ ] = '1';
                tmpstr[ j++ ] = '0';
            }
        }
        else if ( c_source && need_quote( label, i ) )
        {
            tmpstr = fl_realloc( tmpstr, tlen += 1 );
            tmpstr[ j++ ] = '\\';
            tmpstr[ j++ ] = label[ i ];
        }
        else
            tmpstr[ j++ ] = label[ i ];
    }

    tmpstr[ j ] = '\0';

    return tmpstr;
}


/***************************************
 * Convert shortcut into string representation.
 * ESC -> ^[, F1 -> &1 etc.
 ***************************************/

static int
special_key( int    key,
             char * outbuf )
{
    char *start = outbuf;

    if ( key >= XK_F1 && key <= XK_F30 )
    {
        int p = ( key - XK_F1 + 1 ) / 10,
            q = ( key - XK_F1 + 1 ) % 10;

        *outbuf++ = '&';
        if ( p )
            *outbuf++ = '0' + p;
        *outbuf++ = '0' + q;
    }
    else if ( IsUp( key ) )
    {
        *outbuf++ = '&';
        *outbuf++ = 'A';
    }
    else if ( IsDown( key ) )
    {
        *outbuf++ = '&';
        *outbuf++ = 'B';
    }
    else if ( IsRight( key ) )
    {
        *outbuf++ = '&';
        *outbuf++ = 'C';
    }
    else if ( IsLeft( key ) )
    {
        *outbuf++ = '&';
        *outbuf++ = 'D';
    }
    else
        *outbuf++ = key;

    *outbuf = '\0';

    return outbuf - start;
}


/***************************************
 * Converts the objects shortcut string into a string suitable for
 * setting as the content of the shortcut input object
 ***************************************/

char *
get_shortcut_string( const FL_OBJECT * obj )
{
    static char tmps[ 127 ];
    char *p = tmps;
    long *sc = obj->shortcut;
    int n;

    for ( *p = '\0'; sc && *sc; sc++ )
    {
        if ( *sc >= FL_ALT_MASK )
        {
            *p++ = '#';
            n = special_key( *sc - FL_ALT_MASK, p );
            p += n;
        }
        else if ( *sc == '#' || *sc == '&' || *sc == '^' )  /* prefixed w/ ^ */
        {
            *p++ = '^';
            *p++ = *sc;
        }
        else if ( *sc < 30 )
        {
            *p++ = '^';
            if ( *sc <= 'Z' )
                *p++ = 'A' + *sc - 1;
            else if ( *sc == 27 )   /* Escape */
                *p++ = '[';
        }
        else if ( *sc > 255 )
        {
            n = special_key( *sc, p );
            p += n;
        }
        else
            *p++ = *sc;
    }

    *p = '\0';

    return tmps;
}


/***************************************
 * Callback for fl_enumerate_fonts() used in intializing the form
 ***************************************/

static void
add_font_choice( const char * p )
{
    fl_addto_choice( fnts, p );
}


/***************************************
 * Callback routine for getting a color from the user
 ***************************************/

void
setcolor_cb( FL_OBJECT * obj,
             long        arg  FL_UNUSED_ARG )
{
    int col1 = fl_show_colormap( obj->col1 );

    fl_set_object_color( obj, col1, col1 );
    readback_attributes( curobj );
}


/***************************************
 * Validates the name of the object and the callback function
 ***************************************/

static int
validate_attributes( FL_OBJECT * obj )
{
    FL_OBJECT *o;
    const char *name,
               *cn;

    if (    ! validate_cvar_name( fd_generic_attrib->nameobj, "object name" )
         || ! validate_cvar_name( fd_generic_attrib->cbnameobj, "callback" ) )
        return 0;

    name = fl_get_input( fd_generic_attrib->nameobj );

    if ( ! name || ! *name )
        return 1;

    /* Make sure the name diesn't clash with its forms name */

    if ( ( cn = get_form_name( obj->form ) ) && ! strcmp( name, cn ) )
    {
        fl_show_alert( "Error", "Invalid C identifier:",
                       "Object has same name as the form it belongs to!", 0 );
        fl_set_focus_object( fd_generic_attrib->nameobj->form,
                             fd_generic_attrib->nameobj );
        return 0;
    }

    /* Make sure the name doesn clash with the name of another object in
       the form it belongs to */

    for ( o = obj->form->first; o; o = o->next )
        if (    o != obj
             && ( cn = get_object_c_name( o ) )
             && ! strcmp( name, cn ) )
        {
            fl_show_alert( "Error", "Invalid C identifier:",
                           "Object has sam name as another one!", 0 );
            fl_set_focus_object( fd_generic_attrib->nameobj->form,
                                 fd_generic_attrib->nameobj );
            return 0;
        }

	return 1;
}


/***************************************
 ***************************************/

void
validate_cvar_name_cb( FL_OBJECT * obj,
                       long        data )
{
    validate_cvar_name( obj, data == 0 ? "object name" : "callback" );
}


/***************************************
 * Checks if the string of an input field  is a valid C indentifier
 ***************************************/

static int
validate_cvar_name( FL_OBJECT  * obj,
                    const char * w )
{
    const char *s = fl_get_input( obj );

    if ( valid_c_identifier( s ) )
		return 1;

	/* If something's wrong switch to the form with the generic attributs,
	   since there's were the input fields with the name and the callback
	   function are */

	fl_set_folder_bynumber( fd_attrib->attrib_folder, 1 );

	if ( ! w || ! *w )
        fl_show_alert_f( 0, "Error\fInvalid C identifier:\n'%s'", s );
    else
        fl_show_alert_f( 0, "Error\fInvalid C identifier\nfor %s: '%s'", w, s );

	fl_set_focus_object( obj->form, obj );
	return 0;
}


/* Check for obvious errors */

#define OK_letter( c )    (    *c == '_'                       \
                            || *c == '['                       \
                            || *c == ']'                       \
                            || * c== '.'                       \
                            || ( *c == ':' && *++c == ':' )    \
                            || ( *c == '-' && *++c == '>' ) )


/***************************************
 ***************************************/

static int
valid_c_identifier( const char * s )
{
    if ( fdopt.lax )
        return 1;

    /* Empty is considered to be valid */

    if ( ! s || ! *s || ( *s == ' ' && *( s + 1 ) == '\0' ) )
        return 1;

    if ( ! isalpha( ( unsigned char ) *s ) && *s != '_' )
        return 0;

    for ( s++; *s; s++ )
        if ( ! isalnum( ( unsigned char ) *s ) && ! OK_letter( s ) )
            return 0;

    return 1;
}


/***************************************
 ***************************************/

static void
copy_shortcut( FL_OBJECT * dest,
			   FL_OBJECT * src )
{
	if ( src->shortcut )
    {
        size_t i = 0;

        while ( src->shortcut[ i++ ] )
            /* empty */ ;

        if ( i )
        {
            dest->shortcut = malloc( i * sizeof *dest->shortcut );
            memcpy( dest->shortcut, src->shortcut, i * sizeof *dest->shortcut );
        }
    }
	else
		dest->shortcut = NULL;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
