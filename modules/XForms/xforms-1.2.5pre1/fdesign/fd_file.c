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
 * \file fd_file.c
 *
*  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This file is part of the Form Designer.
 *
 * It contains the routines to save and load forms in the internal
 * format used by the form designer. This is readable ASCII.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fd_main.h"
#include "fd_spec.h"

#include <string.h>
#include <ctype.h>

/* Writes an obj description to a file. Note externally the coordinate
 * system always starts from lower-left corner of the screen */

#if 0
#define OBJ_Y( ob )   ( ob->form->h - ob->y - ob->h )
#else
#define OBJ_Y( ob )   obj->y
#endif


static int read_dummy_box( void );
static int read_dummy_type( void );


/***************************************
 ***************************************/

static void
save_object( FILE      * fp,
             FL_OBJECT * obj )
{
    char name[ MAX_VAR_LEN ],
         cbname[ MAX_VAR_LEN ],
         argname[ MAX_VAR_LEN ];
    char *label;
    double sc = get_conversion_factor( );
    FL_OBJECT *defobj,
              fake_obj;

    if ( obj->parent )
        return;

    defobj = find_class_default( obj->objclass, obj->type );

    get_object_name( obj, name, cbname, argname );

    fprintf( fp, "\n--------------------\n" );
    fprintf( fp, "class: %s\n", class_name( obj->objclass ) );

    if ( obj->objclass != FL_BEGIN_GROUP && obj->objclass != FL_END_GROUP )
    {
        fprintf( fp, "type: FL_%s\n",
                 find_type_name( obj->objclass, obj->type ) );
        fake_obj.x = obj->x;
        fake_obj.y = obj->y;
        fake_obj.w = obj->w;
        fake_obj.h = obj->h;
        fli_scale_object( &fake_obj, sc, sc );
        fprintf( fp, "box: %d %d %d %d\n", fake_obj.x, fake_obj.y,
                 fake_obj.w, fake_obj.h );

        fprintf( fp, "boxtype: %s\n", boxtype_name( obj->boxtype ) );
        fprintf( fp, "colors: %s %s\n", fli_query_colorname( obj->col1 ),
                 fli_query_colorname( obj->col2 ) );
        fprintf( fp, "alignment: %s\n", align_name( obj->align, 0 ) );
        fprintf( fp, "style: %s\n", style_name( obj->lstyle ) );
        fprintf( fp, "size: %s\n", lsize_name( obj->lsize ) );
        fprintf( fp, "lcol: %s\n", fli_query_colorname( obj->lcol ) );
        label = get_label( obj, 0 );
        fprintf( fp, "label: %s\n", label );
        fl_free( label );
        fprintf( fp, "shortcut: %s\n", get_shortcut_string( obj ) );
        fprintf( fp, "resize: %s\n", resize_name( obj->resize ) );
        fprintf( fp, "gravity: %s %s\n",
                 gravity_name( obj->nwgravity ),
                 gravity_name( obj->segravity ) );
    }

    if (    ( obj->objclass != FL_END_GROUP && obj->objclass != FL_BEGIN_GROUP )
         || *name )
        fprintf( fp, "name: %s\n", name );

    if ( obj->objclass != FL_BEGIN_GROUP && obj->objclass != FL_END_GROUP )
    {
        fprintf( fp, "callback: %s\n", cbname );
        fprintf( fp, "argument: %s\n", argname );
        if ( ! defobj || obj->how_return != defobj->how_return )
            fprintf( fp, "return: %s\n",
                     get_how_return_name( obj->how_return, 0 ) );

        save_objclass_spec_info( fp, obj );
    }
}


/*
 * X version changed color systemtically, need to do a translation
 * from old fd files on the fly
 */

typedef struct {
    int oldval,
        newval;
} Trantable;

static Trantable tcolor[ ] =
{
    {  0, FL_BLACK },
    {  1, FL_RED },
    {  2, FL_GREEN },
    {  3, FL_YELLOW },
    {  4, FL_BLUE },
    {  5, FL_MAGENTA },
    {  6, FL_CYAN },
    {  7, FL_WHITE },
    {  8, FL_BOTTOM_BCOL }, /* approx */

    {  9, FL_INDIANRED },
    { 10, FL_PALEGREEN },
    { 11, FL_PALEGREEN },
    { 12, FL_SLATEBLUE },

    { 35, FL_RIGHT_BCOL },
    { 36, FL_RIGHT_BCOL },  /* approx */
    { 37, FL_RIGHT_BCOL },  /* approx  */
    { 40, FL_BOTTOM_BCOL },
    { 47, FL_COL1 },
    { 49, FL_MCOL },
    { 51, FL_TOP_BCOL },
    { 55, FL_LEFT_BCOL }
};

static Trantable tclass[ ] =
{
    {     1, FL_BOX },
    {     2, FL_TEXT },
    {     3, FL_BITMAP },
    {     4, FL_CHART },
    {    11, FL_BUTTON },
    {    12, FL_LIGHTBUTTON },
    {    13, FL_ROUNDBUTTON },
    {    21, FL_SLIDER },
    {    22, FL_DIAL },
    {    23, FL_POSITIONER },
    {    24, FL_VALSLIDER },
    {    25, FL_COUNTER },
    {    31, FL_INPUT },
    {    41, FL_MENU },
    {    42, FL_CHOICE },
    {    61, FL_CLOCK },
    {    62, FL_TIMER },
    {    71, FL_BROWSER },
    {   101, FL_FREE },
    { 10000, FL_BEGIN_GROUP },
    { 20000, FL_END_GROUP }
};

static Trantable talign[] =
{
    { 0, FL_ALIGN_TOP },
    { 1, FL_ALIGN_BOTTOM },
    { 2, FL_ALIGN_LEFT },
    { 3, FL_ALIGN_RIGHT },
    { 4, FL_ALIGN_CENTER }
};

static Trantable tbtype[ ] =
{
    { 0, FL_NO_BOX },
    { 1, FL_UP_BOX },
    { 2, FL_DOWN_BOX },
    { 3, FL_FLAT_BOX },
    { 4, FL_BORDER_BOX },
    { 5, FL_SHADOW_BOX },
    { 6, FL_FRAME_BOX },
    { 7, FL_ROUNDED_BOX },
    { 8, FL_RFLAT_BOX },
    { 9, FL_RSHADOW_BOX }
};


/***************************************
 ***************************************/

static int
do_trans( Trantable * tab,
          int         n,
          int         old )
{
    Trantable *p = tab, *q;

    for ( q = p + n; p < q; p++ )
        if ( p->oldval == old )
            return p->newval;
    return old;
}


#define new_class( o ) do_trans( tclass, sizeof tclass / sizeof *tclass, ( o ) )
#define new_color( o ) do_trans( tcolor, sizeof tcolor / sizeof *tcolor, ( o ) )
#define new_align( o ) do_trans( talign, sizeof talign / sizeof *talign, ( o ) )
#define new_btype( o ) do_trans( tbtype, sizeof tbtype / sizeof *tbtype, ( o ) )


/***************************************
 ***************************************/

static int
ff_read_boxtype( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%b", &obj->boxtype ) ) < 0 )
        return ff_err( "Can't read expected object boxtype" );

    if ( r == 0 )
        return ff_err( "\"boxtype\" key without value" );

    if ( fd_magic == MAGIC2 )
        obj->boxtype = new_btype( obj->boxtype );

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_colors( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%c%c", &obj->col1, &obj->col2 ) ) < 0 )
        return ff_err( "Can't read expected object colors" );

    if ( r != 2 )
        return ff_err( "\"colors\" key without two object colors" );

    if ( fd_magic == MAGIC2 )
    {
        obj->col1 = new_color( obj->col1 );
        obj->col2 = new_color( obj->col2 );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_alignment( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%a", &obj->align ) ) < 0 )
        return ff_err( "Can't read expected object alignment" );

    if ( r == 0 )
        return ff_err( "\"alignment\" key without or invalid value" );

    if ( fd_magic == MAGIC2 )
        obj->align = new_align( obj->align );

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_lstyle( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%p", &obj->lstyle ) ) < 0 )
        return ff_err( "Can't read expected object label style" );

    if ( r == 0 )
        return ff_err( "\"style\" key without or invalid value" );

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_lsize( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%q", &obj->lsize ) ) < 0 )
        return ff_err( "Can't read expected object label size" );

    if ( r == 0 )
        return ff_err( "\"size\" key without or invalid value" );

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_lcolor( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%c", &obj->lcol ) ) < 0 )
        return ff_err( "Can't read expected object label color" );

    if ( r == 0 )
        return ff_err( "\"lcol\" key without or invalid value" );

    if ( fd_magic == MAGIC2 )
        obj->lcol = new_color( obj->lcol );

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_resize( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%r", &obj->resize ) ) < 0 )
        return ff_err( "Can't read expected object resize value" );

    if ( r == 0 )
        return ff_err( "\"resize\" key without or invalid value" );

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_label( FL_OBJECT * obj )
{
    int r;
    char *label;

    if ( ( r = ff_read( "%S", &label ) ) < 0 )
        return ff_err( "Can't read expected object label" );

    if ( r == 1 )
    {
        set_label( obj, label );
        fli_safe_free( label );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_shortcut( FL_OBJECT * obj )
{
    int r;
    char *shortcut;

    if ( ( r = ff_read( "%s", &shortcut ) ) < 0 )
        return ff_err( "Can't read expected object shortcut" );

    if ( r == 1 )
    {
        set_shortcut( obj, shortcut );
        fli_safe_free( shortcut );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_callback( FL_OBJECT * obj )
{
    int r;
    char *cbname;

    if ( ( r = ff_read( "%v", &cbname ) ) < 0 )
        return ff_err( "Can't read expected object callback" );

    if ( r == 1 )
    {
        set_object_name( obj, NULL, cbname, NULL );
        fli_safe_free( cbname );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_name( FL_OBJECT * obj )
{
    int r;
    char *name;

    if ( ( r = ff_read( "%s", &name ) ) < 0 )
        return ff_err( "Can't read expected object name" );

    if ( r == 1 )
    {
        set_object_name( obj, name, NULL, NULL );
        fli_safe_free( name );
    }

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_gravity( FL_OBJECT * obj )
{
    int r;

    if ( ( r = ff_read( "%g%g", &obj->nwgravity, &obj->segravity ) ) < 0 )
        return ff_err( "Can't read expected object gravity values" );

    if ( r != 2 )
    {
        if ( r == 0 )
            ff_err( "\"gravity\" key without valid values" );
        if ( r == 1 )
            ff_err( "\"gravity\" key with only one valid value" );
        return FF_READ_FAILURE;
    }

    return 0;
}


/***************************************
 ***************************************/

static int
ff_read_argument( FL_OBJECT * obj )

{
    int r;
    char *arg;

    if ( ( r = ff_read( "%s", &arg ) ) < 0 )
        return ff_err( "Can't read expected object callback argument" );

    if ( r == 1 )
    {
        set_object_name( obj, NULL, NULL, arg );
        fli_safe_free( arg );
    }

    return 0;
}


/***************************************
 ***************************************/

static int 
ff_read_return( FL_OBJECT * obj )
{
    int r;
    char *return_name;
    int ret;

    if ( ( r = ff_read( "%s", &return_name ) ) < 0 )
        return ff_err( "Can't read expected object return" );

    if ( r == 0 )
        return ff_err( "\"return\" key with no or invalid value" );

    ret = get_how_return_val( return_name );

    fli_safe_free( return_name );

    if ( ret == -1 )
        return ff_err( "Invalid value for \"return\" key" );

    fl_set_object_return( obj, ret );

    return 0;
}


/***************************************
 ***************************************/

typedef int ( * obj_attr_func )( FL_OBJECT * );

typedef struct {
    const char    * name;
    obj_attr_func   func;
} obj_attr_handlers;


static obj_attr_handlers attr_array[ ] =
{
    { "boxtype",   ff_read_boxtype   },
    { "colors",    ff_read_colors    },
    { "alignment", ff_read_alignment },
    { "style",     ff_read_lstyle    },
    { "lstyle",    ff_read_lstyle    },
    { "size",      ff_read_lsize     },
    { "lsize",     ff_read_lsize     },
    { "lcol",      ff_read_lcolor    },
    { "resize",    ff_read_resize    },
    { "label",     ff_read_label     },
    { "shortcut",  ff_read_shortcut  },
    { "callback",  ff_read_callback  },
    { "name",      ff_read_name      },
    { "gravity",   ff_read_gravity   },
    { "argument",  ff_read_argument  },
    { "return",    ff_read_return    }
};


/***************************************
 * Reads all information from a .fd file until it's
 * detected that there's either a new form or object
 * or the last line of the file has been reached.
 * When called the first key for an object, "class:"
 * already has been read from the file.
 ***************************************/

static int
load_object( void )
{
    int objclass;
    char *type_name;
    int type = 0;
    FL_Coord x = 0,
             y = 0,
             w = 0,
             h = 0;
    char *key = NULL,
         *p;
    FL_OBJECT *obj;
    int r;
        
    /* Start with trying to read the minmal information needed. First we
       want the object class */

    if ( ! ff_read( "%o", &objclass ) < 0 )
        return ff_err( "Expected object class" );

    if ( fd_magic == MAGIC2 )
        objclass = new_class( objclass );

    /* Next we need the object type. normally this is a string except for
       pseudo-objects that start and end a group */

    if ( objclass != FL_BEGIN_GROUP && objclass != FL_END_GROUP )
    {
        if (    ff_read( "%k%t", &key, &type_name ) < 2
             || strcmp( key, "type" ) )
        {
            fl_free( key );
            return ff_err( "Expected object type" );
        }

        fl_free( key );

        if ( ( type = find_type_value( objclass, type_name ) ) < 0 )
        {
            char *tmp = fl_malloc(   strlen( "Invalid type for object class: " )
                                   + strlen( type_name ) + 1 );

            if ( tmp )
            {
                sprintf( tmp, "Invalid type for object class: %s",
                         type_name );
                ff_err( tmp );
                fl_free( tmp );

            }

            fl_free( type_name );
            return FF_READ_FAILURE;
        }

        fl_free( type_name );

        /* As the third entry the size of the object (following the "box" key)
           is required, exceptions are the pseudo-objectst that start and end
           a group, they may have less values */

        if (    ( r = ff_read( "%k%D%D%U%U", &key, &x, &y, &w, &h ) ) < 5
             || strcmp( key, "box" ) )
        {
            fl_free( key );

            if ( r == 0 )
                ff_err( "Expected object box size" );
            else
            {
                char *tmp = fl_malloc( strlen( "Expected object box sizes as "
                                               "4 values, found only" ) + 20 );

                if ( tmp )
                {
                    sprintf( tmp, "Expected object box sizes as 4 "
                             "values, found only %d", r - 1 );
                    ff_err( tmp );
                    fl_free( tmp );
                }
            }
            
            return FF_READ_FAILURE;
        }

        fl_free( key );
    }

    if ( cur_form && fd_magic < MAGIC4 )
        y = cur_form->h - y - h;

    /* Create the new object */

    if ( ! ( obj = add_an_object( objclass, type, x, y, w, h ) ) )
        return ff_err( "Failed to create an object" );

    /* Now read the optional attributes, order is irrelevant except that
       all general object attributes must come before those specific to
       the type of the object and here we only look for the general ones */

    while ( 1 )
    {
        size_t i;

        if ( ( r = ff_read( "%k", &key ) ) < 0 )
            return ff_err( "Failed to read expected key" );

        /* The pseudo-objects FL_BEGIN_GROUP and FL_END_GROUP may have a
           'type' and 'box' field we didn't check for yet - what they
           contain is actually irrelevant but we must read them if present */

        if (    r == 1
             && ( objclass == FL_BEGIN_GROUP || objclass == FL_END_GROUP ) )
        {
            if ( ! strcmp( key, "type" ) )
            {
                fli_safe_free( key );
                if ( read_dummy_type( ) == FF_READ_FAILURE )
                    return FF_READ_FAILURE;
                else
                    continue;
            }

            if ( ! strcmp( key, "box" ) )
            {
                fli_safe_free( key );
                if ( read_dummy_box( ) == FF_READ_FAILURE )
                    return FF_READ_FAILURE;
                else
                    continue;
            }
        }

        if ( r == 0 || ! strcmp( key, "Name" ) || ! strcmp( key, "class" ) )
            break;

        for ( i = 0; i < sizeof attr_array / sizeof *attr_array; i++ )
            if ( ! strcmp( key, attr_array[ i ].name ) )
            {
                fli_safe_free( key );
                if ( attr_array[ i ].func( obj ) == FF_READ_FAILURE )
                    return FF_READ_FAILURE;
                break;
            }

        if ( i == sizeof attr_array / sizeof *attr_array )
            break;

        fli_safe_free( key );
    }

    /* Some extra adjustments for spinner objects (this is an evil hack but
       avoiding it would require a complete change of how fdesign works) */

    if ( obj->objclass == FL_SPINNER )
    {
        FL_OBJECT *subobj = fl_get_spinner_input( obj );

        subobj->col1 = obj->col1;
        subobj->col2 = obj->col2;

        subobj->lstyle = obj->lstyle;
        subobj->lsize  = obj->lsize;
    }

    /* If the key read isn't "Name" or "class" (indicating the start of the
       next form or object) it must be an object specific key */

    if ( r == 1 && strcmp( key, "Name" ) && strcmp( key, "class" ) )
        r = load_objclass_spec_info( obj, key );
    else
    {
        /* If a key could be read continue, otherwise this must be (nearly)
           the end of the file and the name of the main function must be
           readable (or something is wrong) */

        if ( r == 1 )
            r = ! strcmp( key, "class" ) ?
                FF_AT_START_OF_OBJECT : FF_AT_START_OF_FORM;
        else
        {
            if ( ff_read( "%v", &p ) < 1 )
                return ff_err( "Expected main function name, not found here" );

            fli_sstrcpy( main_name, p, MAX_VAR_LEN );
            fli_safe_free( p );

            r = FF_AT_END_OF_FILE;
        }

        fli_safe_free( key );
    }

    fli_handle_object( obj, FL_ATTRIB, 0, 0, 0, NULL, 0 );

    return r;
}


/***************************************
 * Function for reading the 'type' of a FL_BEGIN_GROUP or FL_END_GROUP
 * pseudo-object (which alsways is an int with value 0)
 ***************************************/

static int
read_dummy_type( void )
{
    int type;
    
    if ( ff_read( "%d", &type ) < 0 || type != 0 )
         return ff_err( "Expected object type" );
    return 0;
}



/***************************************
 * Function for reading the box size of a FL_BEGIN_GROUP or FL_END_GROUP
 * pseudo-object, we can expect either 1 or 4 FL_COORD values
 ***************************************/

static int
read_dummy_box( void )
{
    int r;
    FL_COORD dummy;
        
    r = ff_read( "%D%D%U%U", &dummy, &dummy, &dummy, &dummy );
    if ( r != 1 &&  r != 4 )
        return ff_err( "Expected object box size with 1 or 4 valid values" );
    return 0;
}


/***************************************
 * Saves a form definition to the file
 ***************************************/

void
write_form( FILE    * fp,
            FL_FORM * form,
            char      fname[ ] )
{
    int obj_cnt;
    FL_OBJECT *obj;

    fprintf( fp, "\n=============== FORM ===============\n"
                 "Name: %s\n"
                 "Width: %d\n"
                 "Height: %d\n",
             fname, convert_u( form->w ), convert_u( form->h ) );

    /* Print the number of objects in the form (don't count those that are
       subobjects) */

    for ( obj_cnt = 0, obj = form->first->next; obj; obj = obj->next )
        if ( ! obj->parent )
            obj_cnt++;

    fprintf( fp, "Number of Objects: %d\n", obj_cnt );

    /* Print all objects */

    for ( obj = form->first->next; obj; obj = obj->next )
        save_object( fp, obj );
}


/***************************************
 * Reads all information about a form from an .fd file until
 * it's detected that a new form starts or the last line of
 * the file has been reached. When we arrive here the "Name:"
 * key as well as the name of the form itself already have been
 * read in. We return when we detect that a new form starts
 * (due to the "Mame:" key or the last line of the file should
 * have been reached.
 ***************************************/

int
read_form( void )
{
    char *key;
    float w = -1.0,
          h = -1.0;
    int num_objects = -1;
    int r;
    int i;

    /* Try to read information pertinent to the form (name already has been
       read in) until the first key for an object in the form ("class:") is
       found */

    while ( 1 )
    {
        if ( ff_read( "%k", &key ) < 1 )
            return ff_err( "Invalid format of file" );

        if ( ! strcmp( key, "class" ) )
        {
            fli_safe_free( key );
            break;
        }
        else if ( ! strcmp( key, "Width" ) )
        {
            fli_safe_free( key );

            if ( ff_read( "%f", &w ) < 1 )
                return ff_err( "Can't read expected form width" );

            if ( w < 0.0 )
                return ff_err( "Invalid negative form width" );
        }
        else if ( ! strcmp( key, "Height" ) )
        {
            fli_safe_free( key );

            if ( ff_read( "%f", &h ) < 1 )
                return ff_err( "Can't read expected form height" );

            if ( h < 0.0 )
                return ff_err( "Invalid negative form height" );
        }
        else if ( ! strcmp( key, "Number of Objects" ) )
        {
            fli_safe_free( key );

            if ( ff_read( "%d", &num_objects ) < 1 )
                return ff_err( "Can't read expected number of objects in "
                               "form" );

            if ( num_objects <= 0 )
                return ff_err( "Invalid number of objects, must be at "
                               "least 1" );
        }
    }

    /* Before continuing with reading the form's objects check that at
       least width, height and number of objects in form were found */

    if ( w < 0.0 )
        return ff_err( "Width of form not found" );

    if ( h < 0.0 )
        return ff_err( "Height of form not found" );

    if ( num_objects < 0 )
        return ff_err( "Number of objects in form not found" );

    /* Create the new form */

    cur_form = fl_bgn_form( FL_NO_BOX, ( FL_Coord ) w, ( FL_Coord ) h );
    fl_end_form( );

    /* Read all objects until next form starts or end file seems to
       have been reached */

    r = FF_AT_START_OF_OBJECT;

    for ( i = 0; i < num_objects && r == FF_AT_START_OF_OBJECT; i++ )
        r = load_object( );

    if ( r == FF_READ_FAILURE )
        return FF_READ_FAILURE;

    if ( r == FF_AT_START_OF_OBJECT )
        return ff_err( "More objects found than expected" );

    if ( i < num_objects )
        return ff_err( "Less objects found than expected" );

    return r;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
