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
 * \file fd_objects.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * This file is part of the Form Designer.
 *
 * It contains routines to keep track of all different object classes
 * and the types inside each class. To add a class of object to the
 * form designer, only this file has to be changed slightly:
 *      - in init_classes() the class and types must be added.
 *      - in add_an_object() the way of adding it should be added.
 *
 * Also to support output fully, fd_spec.c needs to be modified
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <math.h>

#include "fd_main.h"
#include "sp_freeobj.h"
#include "xpm/broken.xpm"
#include "xpm/broken.xbm"

#define VN( a )        a,#a
#define OBJNAME( a )   #a,fl_create_##a,fl_add_##a

typedef struct {
    int defined;
    char tname[ MAX_TYPE_NAME_LEN ];
} TDEF;

typedef FL_OBJECT * ( * FL_ADDPTR ) ( int, FL_Coord, FL_Coord, FL_Coord,
                                      FL_Coord, const char * );

typedef struct {
    int          cn;
    FL_OBJECT  * defobj;                              /* default */
    TDEF         types[ MAXTYPES ];
    char         cname[ MAX_CLASS_NAME_LEN ];         /* add_XXX */
    char         formal_cname[ MAX_CLASS_NAME_LEN ];
    FL_OBJECT  * defobj1;                             /* to specific type */
    FL_ADDPTR    createit,
                 addit;
    int          var_boxtype;   /* means default boxtype may depend on type */
    int          default_type;
    const char * default_label;
    int          bline;
} CDEF;

static CDEF classes[ MAXCLASSES ];
static int cnumb = 0;

typedef FL_OBJECT * ( * FL_ADDFREEPTR )( int, FL_Coord, FL_Coord, FL_Coord,
                                         FL_Coord, const char *, FL_HANDLEPTR );


/***************************************
 * Adds a class definition
 ***************************************/

static void
add_class_def( int         numb,
               char      * formal_name,
               char      * name,
               FL_ADDPTR   createit,
               FL_ADDPTR   addit,
               int         bl )
{
    int i;

    if ( cnumb == MAXCLASSES )
    {
        fprintf( stderr, "exceeding maxclass allowed\n" );
        return;
    }

    classes[ cnumb ].cn = numb;
    strcpy( classes[ cnumb ].cname, name );
    strcpy( classes[ cnumb ].formal_cname, formal_name );
    if ( createit )
        classes[ cnumb ].defobj = createit( 1, 0, 0, 1, 1, "" );
    classes[ cnumb ].createit = createit;
    classes[ cnumb ].addit = addit;
    classes[ cnumb ].bline = bl;

    for ( i = 0; i < MAXTYPES; i++ )
        classes[ cnumb ].types[ i ].defined = FL_FALSE;
    cnumb++;
}


/***************************************
 ***************************************/

static CDEF *
find_class_struct( int n )
{
    int i;

    for ( i = 0; i < cnumb; i++ )
    {
        if ( classes[ i ].cn == n )
            return classes + i;
    }

    M_err( "find_class_struct", "Can't find class %d", n );
    return NULL;
}


/***************************************
 * Adds a type definition to a class
 ***************************************/

static void
add_type_def( int  cn,
              int  tn,
              char name[ ] )
{
    int i;

    if ( tn >= MAXTYPES || tn < 0 )
    {
        M_err( "add_type_def", "Bad type: %d", tn );
        return;
    }

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cn )
        {
            classes[ i ].types[ tn ].defined = FL_TRUE;
            strcpy( classes[ i ].types[ tn ].tname, name );
        }
}


/***************************************
 * Sets a default type and label for class cn
 ***************************************/

static void
set_class_default( int    cn,
                   int    def_type,
                   char * label )
{
    int i;

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cn )
        {
            classes[ i ].default_type = def_type;
            classes[ i ].default_label = label;     /* note: no copy */
        }
}


/***************************************
 ***************************************/

static void
set_var_boxtype( int cn,
                 int yes  FL_UNUSED_ARG )
{
    int i;

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cn )
            classes[ i ].var_boxtype = 1;
}


/***************************************
 ***************************************/

static FL_OBJECT *
fd_create_free( int          type,
                FL_Coord     x,
                FL_Coord     y,
                FL_Coord     w,
                FL_Coord     h,
                const char * l )
{
    return fl_create_free( type, x, y, w, h, l, noop_handle );
}


/***************************************
 ***************************************/

static FL_OBJECT *
fd_add_free( int          type,
             FL_Coord     x,
             FL_Coord     y,
             FL_Coord     w,
             FL_Coord     h,
             const char * l )
{
    FL_OBJECT *obj = fl_add_free( type, x, y, w, h, l, noop_handle );

    obj->c_vdata = NULL;
    return obj;
}


/****
  INITIALIZING THE CLASSES
****/

int cur_class = -1;     /* class selected in the object class browser */


/****
  CALLBACK ROUTINES
****/

/***************************************
 * Handles a class change event
 ***************************************/

void
object_cb( FL_OBJECT * obj,
           long        arg  FL_UNUSED_ARG )
{
    int line = fl_get_browser( obj );

    clear_selection( );
    redraw_the_form( 0 );

    cur_class = -1;

    if ( line > 0 )
    {
        const char *name = fl_get_browser_line( obj, line );
        int i;

        for ( i = 0; *classes[ i ].cname && i < MAXCLASSES; i++ )
            if ( ! strcmp( classes[ i ].cname, name ) )
            {
                cur_class = classes[ i ].cn;
                break;
            }
    }

    select_pallette_entry( cur_class );
}


/***************************************
 ***************************************/

static void
add_button_types( int button_class )
{
    add_type_def( button_class, FL_NORMAL_BUTTON,     "NORMAL_BUTTON" );
    add_type_def( button_class, FL_PUSH_BUTTON,       "PUSH_BUTTON" );
    add_type_def( button_class, FL_RADIO_BUTTON,      "RADIO_BUTTON" );
    add_type_def( button_class, FL_TOUCH_BUTTON,      "TOUCH_BUTTON" );
    add_type_def( button_class, FL_HIDDEN_BUTTON,     "HIDDEN_BUTTON" );
    add_type_def( button_class, FL_INOUT_BUTTON,      "INOUT_BUTTON" );
    add_type_def( button_class, FL_MENU_BUTTON,       "MENU_BUTTON" );
    add_type_def( button_class, FL_RETURN_BUTTON,     "RETURN_BUTTON" );
    add_type_def( button_class, FL_HIDDEN_RET_BUTTON, "HIDDEN_RET_BUTTON" );
}


/***************************************
 ***************************************/

static void
add_frame_types( int frame_class )
{
    add_type_def( frame_class, FL_NO_FRAME,       "NO_FRAME" );
    add_type_def( frame_class, FL_UP_FRAME,       "UP_FRAME" );
    add_type_def( frame_class, FL_DOWN_FRAME,     "DOWN_FRAME" );
    add_type_def( frame_class, FL_BORDER_FRAME,   "BORDER_FRAME" );
    add_type_def( frame_class, FL_ENGRAVED_FRAME, "ENGRAVED_FRAME" );
    add_type_def( frame_class, FL_ROUNDED_FRAME,  "ROUNDED_FRAME" );
    add_type_def( frame_class, FL_EMBOSSED_FRAME, "EMBOSSED_FRAME" );
    add_type_def( frame_class, FL_SHADOW_FRAME,   "SHADOW_FRAME" );
    add_type_def( frame_class, FL_OVAL_FRAME,     "OVAL_FRAME" );
}


/***************************************
 ***************************************/

static void
add_slider_types( int sclass )
{
    add_type_def( sclass, FL_VERT_SLIDER,         "VERT_SLIDER"         );
    add_type_def( sclass, FL_HOR_SLIDER,          "HOR_SLIDER"          );
    add_type_def( sclass, FL_VERT_FILL_SLIDER,    "VERT_FILL_SLIDER"    );
    add_type_def( sclass, FL_HOR_FILL_SLIDER,     "HOR_FILL_SLIDER"     );
    add_type_def( sclass, FL_VERT_NICE_SLIDER,    "VERT_NICE_SLIDER"    );
    add_type_def( sclass, FL_HOR_NICE_SLIDER,     "HOR_NICE_SLIDER"     );
    add_type_def( sclass, FL_VERT_BROWSER_SLIDER, "VERT_BROWSER_SLIDER" );
    add_type_def( sclass, FL_HOR_BROWSER_SLIDER,  "HOR_BROWSER_SLIDER"  );
    add_type_def( sclass, FL_VERT_PROGRESS_BAR,   "VERT_PROGRESS_BAR"   );
    add_type_def( sclass, FL_HOR_PROGRESS_BAR,    "HOR_PROGRESS_BAR"    );
}

/***************************************
 ***************************************/

static void
add_scrollbar_types( int sclass )
{
    add_type_def( sclass, FL_VERT_SCROLLBAR,      "VERT_SCROLLBAR"        );
    add_type_def( sclass, FL_HOR_SCROLLBAR,       "HOR_SCROLLBAR"         );
    add_type_def( sclass, FL_VERT_THIN_SCROLLBAR, "VERT_THIN_SCROLLBAR"   );
    add_type_def( sclass, FL_HOR_THIN_SCROLLBAR,  "HOR_THIN_SCROLLBAR"    );
    add_type_def( sclass, FL_VERT_NICE_SCROLLBAR, "VERT_NICE_SCROLLBAR"   );
    add_type_def( sclass, FL_HOR_NICE_SCROLLBAR,  "HOR_NICE_SCROLLBAR"    );
    add_type_def( sclass, FL_VERT_PLAIN_SCROLLBAR, "VERT_PLAIN_SCROLLBAR" );
    add_type_def( sclass, FL_HOR_PLAIN_SCROLLBAR, "HOR_PLAIN_SCROLLBAR"   );
}


/***************************************
 ***************************************/

static void
add_chart_types( int cclass )
{
    add_type_def( cclass, FL_BAR_CHART,        "BAR_CHART"        );
    add_type_def( cclass, FL_HORBAR_CHART,     "HORBAR_CHART"     );
    add_type_def( cclass, FL_LINE_CHART,       "LINE_CHART"       );
    add_type_def( cclass, FL_FILLED_CHART,     "FILLED_CHART"     );
    add_type_def( cclass, FL_SPIKE_CHART,      "SPIKE_CHART"      );
    add_type_def( cclass, FL_PIE_CHART,        "PIE_CHART"        );
    add_type_def( cclass, FL_SPECIALPIE_CHART, "SPECIALPIE_CHART" );
}


/***************************************
 ***************************************/

static void
add_xyplot_types( int xyclass )
{
    add_type_def( xyclass, FL_NORMAL_XYPLOT,     "NORMAL_XYPLOT"     );
    add_type_def( xyclass, FL_ACTIVE_XYPLOT,     "ACTIVE_XYPLOT"     );
    add_type_def( xyclass, FL_SQUARE_XYPLOT,     "SQUARE_XYPLOT"     );
    add_type_def( xyclass, FL_CIRCLE_XYPLOT,     "CIRCLE_XYPLOT"     );
    add_type_def( xyclass, FL_POINTS_XYPLOT,     "POINTS_XYPLOT"     );
    add_type_def( xyclass, FL_LINEPOINTS_XYPLOT, "LINEPOINTS_XYPLOT" );
    add_type_def( xyclass, FL_DASHED_XYPLOT,     "DASHED_XYPLOT"     );
    add_type_def( xyclass, FL_DOTTED_XYPLOT,     "DOTTED_XYPLOT"     );
    add_type_def( xyclass, FL_DOTDASHED_XYPLOT,  "DOTDASHED_XYPLOT"  );
    add_type_def( xyclass, FL_LONGDASHED_XYPLOT, "LONGDASHED_XYPLOT" );
    add_type_def( xyclass, FL_FILL_XYPLOT,       "FILL_XYPLOT"       );
    add_type_def( xyclass, FL_IMPULSE_XYPLOT,    "IMPULSE_XYPLOT"    );
    add_type_def( xyclass, FL_EMPTY_XYPLOT,      "EMPTY_XYPLOT"      );
}


/***************************************
 * Initializes all the classes and types. Must be adapted
 * to add new classes and types.
 ***************************************/

void
init_classes( void )
{
    static int initialized;
    VN_pair *vp;
    int bl = 0;

    if ( initialized )
        return;

    initialized = 1;

    fl_set_browser_fontstyle( fd_control->objectbrowser, FL_TIMES_STYLE );

    fl_add_browser_line( fd_control->objectbrowser, "box" );
    add_class_def( VN( FL_BOX ), OBJNAME( box ), ++bl );
    for ( vp = vn_btype; vp->val >= 0; vp++ )
        add_type_def( FL_BOX, vp->val, vp->name + 3 );
    set_class_default( FL_BOX, FL_UP_BOX, "" );

    fl_add_browser_line( fd_control->objectbrowser, "frame" );
    add_class_def( VN( FL_FRAME ), OBJNAME( frame ), ++bl );
    add_frame_types( FL_FRAME );
    set_class_default( FL_FRAME, FL_ENGRAVED_FRAME, "" );

    fl_add_browser_line( fd_control->objectbrowser, "labelframe" );
    add_class_def( VN( FL_LABELFRAME ), OBJNAME( labelframe ), ++bl );
    add_frame_types( FL_LABELFRAME );
    set_class_default( FL_LABELFRAME, FL_ENGRAVED_FRAME, "frame" );

    fl_add_browser_line( fd_control->objectbrowser, "text" );
    add_class_def( VN( FL_TEXT ), OBJNAME( text ), ++bl );
    add_type_def( FL_TEXT, FL_NORMAL_TEXT, "NORMAL_TEXT" );
    set_class_default( FL_TEXT, FL_NORMAL_TEXT, "text" );

    fl_add_browser_line( fd_control->objectbrowser, "bitmap" );
    add_class_def( VN( FL_BITMAP ), OBJNAME( bitmap ), ++bl );
    add_type_def( FL_BITMAP, FL_NORMAL_BITMAP, "NORMAL_BITMAP" );

    fl_add_browser_line( fd_control->objectbrowser, "pixmap" );
    add_class_def( VN( FL_PIXMAP ), OBJNAME( pixmap ), ++bl );
    add_type_def( FL_PIXMAP, FL_NORMAL_PIXMAP, "NORMAL_PIXMAP" );

    fl_add_browser_line( fd_control->objectbrowser, "chart" );
    add_class_def( VN( FL_CHART ), OBJNAME( chart ), ++bl );
    add_chart_types( FL_CHART );

    fl_add_browser_line( fd_control->objectbrowser, "clock" );
    add_class_def( VN( FL_CLOCK ), OBJNAME( clock ), ++bl );
    add_type_def( FL_CLOCK, FL_ANALOG_CLOCK,  "ANALOG_CLOCK" );
    add_type_def( FL_CLOCK, FL_DIGITAL_CLOCK, "DIGITAL_CLOCK" );
    set_class_default( FL_CLOCK, FL_ANALOG_CLOCK, "" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "button" );
    add_class_def( VN( FL_BUTTON ), OBJNAME( button ), ++bl );
    add_button_types( FL_BUTTON );
    set_class_default( FL_BUTTON, FL_NORMAL_BUTTON, "button" );

    fl_add_browser_line( fd_control->objectbrowser, "roundbutton" );
    add_class_def( VN( FL_ROUNDBUTTON ), OBJNAME( roundbutton ), ++bl );
    add_button_types( FL_ROUNDBUTTON );
    set_class_default( FL_ROUNDBUTTON, FL_PUSH_BUTTON, "button" );

    fl_add_browser_line( fd_control->objectbrowser, "round3dbutton" );
    add_class_def( VN( FL_ROUND3DBUTTON ), OBJNAME( round3dbutton ), ++bl );
    add_button_types( FL_ROUND3DBUTTON );
    set_class_default( FL_ROUND3DBUTTON, FL_PUSH_BUTTON, "button" );

    fl_add_browser_line( fd_control->objectbrowser, "checkbutton" );
    add_class_def( VN( FL_CHECKBUTTON ), OBJNAME( checkbutton ), ++bl );
    add_button_types( FL_CHECKBUTTON );
    set_class_default( FL_CHECKBUTTON, FL_PUSH_BUTTON, "button" );

    fl_add_browser_line( fd_control->objectbrowser, "lightbutton" );
    add_class_def( VN( FL_LIGHTBUTTON ), OBJNAME( lightbutton ), ++bl );
    add_button_types( FL_LIGHTBUTTON );
    set_class_default( FL_LIGHTBUTTON, FL_PUSH_BUTTON, "button" );

    fl_add_browser_line( fd_control->objectbrowser, "scrollbutton" );
    add_class_def( VN( FL_SCROLLBUTTON ), OBJNAME( scrollbutton ), ++bl );
    add_button_types( FL_SCROLLBUTTON );
    set_class_default( FL_SCROLLBUTTON, FL_TOUCH_BUTTON, "8" );

    fl_add_browser_line( fd_control->objectbrowser, "bitmapbutton" );
    add_class_def( VN( FL_BITMAPBUTTON ), OBJNAME( bitmapbutton ), ++bl );
    add_button_types( FL_BITMAPBUTTON );

    fl_add_browser_line( fd_control->objectbrowser, "pixmapbutton" );
    add_class_def( VN( FL_PIXMAPBUTTON ), OBJNAME( pixmapbutton ), ++bl );
    add_button_types( FL_PIXMAPBUTTON );

    fl_add_browser_line( fd_control->objectbrowser, "labelbutton" );
    add_class_def( VN( FL_LABELBUTTON ), OBJNAME( labelbutton ), ++bl );
    add_button_types( FL_LABELBUTTON );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "slider" );
    add_class_def( VN( FL_SLIDER ), OBJNAME( slider ), ++bl );
    add_slider_types( FL_SLIDER );

    fl_add_browser_line( fd_control->objectbrowser, "valslider" );
    add_class_def( VN( FL_VALSLIDER ), OBJNAME( valslider ), ++bl );
    add_slider_types( FL_VALSLIDER );

    fl_add_browser_line( fd_control->objectbrowser, "scrollbar" );
    add_class_def( VN( FL_SCROLLBAR ), OBJNAME( scrollbar ), ++bl );
    add_scrollbar_types( FL_SCROLLBAR );

    fl_add_browser_line( fd_control->objectbrowser, "dial" );
    add_class_def( VN( FL_DIAL ), OBJNAME( dial ), ++bl );
    add_type_def( FL_DIAL, FL_NORMAL_DIAL, "NORMAL_DIAL" );
    add_type_def( FL_DIAL, FL_LINE_DIAL, "LINE_DIAL" );
    add_type_def( FL_DIAL, FL_FILL_DIAL, "FILL_DIAL" );
    set_var_boxtype( FL_DIAL, 1 );

    fl_add_browser_line( fd_control->objectbrowser, "positioner" );
    add_class_def( VN( FL_POSITIONER ), OBJNAME( positioner ), ++bl );
    add_type_def( FL_POSITIONER, FL_NORMAL_POSITIONER,  "NORMAL_POSITIONER" );
    add_type_def( FL_POSITIONER, FL_OVERLAY_POSITIONER, "OVERLAY_POSITIONER" );
    add_type_def( FL_POSITIONER, FL_INVISIBLE_POSITIONER,
                  "INVISIBLE_POSITIONER" );
    set_var_boxtype( FL_POSITIONER, 1 );

    fl_add_browser_line( fd_control->objectbrowser, "thumbwheel" );
    add_class_def( VN( FL_THUMBWHEEL ), OBJNAME( thumbwheel ), ++bl );
    add_type_def( FL_THUMBWHEEL, FL_HOR_THUMBWHEEL,  "HOR_THUMBWHEEL" );
    add_type_def( FL_THUMBWHEEL, FL_VERT_THUMBWHEEL, "VERT_THUMBWHEEL" );

    fl_add_browser_line( fd_control->objectbrowser, "counter" );
    add_class_def( VN( FL_COUNTER ), OBJNAME( counter ), ++bl );
    add_type_def( FL_COUNTER, FL_NORMAL_COUNTER, "NORMAL_COUNTER" );
    add_type_def( FL_COUNTER, FL_SIMPLE_COUNTER, "SIMPLE_COUNTER" );

    fl_add_browser_line( fd_control->objectbrowser, "spinner" );
    add_class_def( VN( FL_SPINNER ), OBJNAME( spinner ), ++bl );
    add_type_def( FL_SPINNER, FL_INT_SPINNER, "INT_SPINNER" );
    add_type_def( FL_SPINNER, FL_FLOAT_SPINNER, "FLOAT_SPINNER" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "input" );
    add_class_def( VN( FL_INPUT ), OBJNAME( input ), ++bl );
    add_type_def( FL_INPUT, FL_NORMAL_INPUT,    "NORMAL_INPUT" );
    add_type_def( FL_INPUT, FL_FLOAT_INPUT,     "FLOAT_INPUT" );
    add_type_def( FL_INPUT, FL_INT_INPUT,       "INT_INPUT" );
    add_type_def( FL_INPUT, FL_HIDDEN_INPUT,    "HIDDEN_INPUT" );
    add_type_def( FL_INPUT, FL_MULTILINE_INPUT, "MULTILINE_INPUT" );
    add_type_def( FL_INPUT, FL_SECRET_INPUT,    "SECRET_INPUT" );
    add_type_def( FL_INPUT, FL_DATE_INPUT,      "DATE_INPUT" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "menu" );
    add_class_def( VN( FL_MENU ), OBJNAME( menu ), ++bl );
    add_type_def( FL_MENU, FL_PUSH_MENU,     "PUSH_MENU" );
    add_type_def( FL_MENU, FL_PULLDOWN_MENU, "PULLDOWN_MENU" );
    add_type_def( FL_MENU, FL_TOUCH_MENU,    "TOUCH_MENU" );
    set_var_boxtype( FL_MENU, 1 );

    fl_add_browser_line( fd_control->objectbrowser, "choice" );
    add_class_def( VN( FL_CHOICE ), OBJNAME( choice ), ++bl );
    add_type_def( FL_CHOICE, FL_NORMAL_CHOICE,   "NORMAL_CHOICE" );
    add_type_def( FL_CHOICE, FL_NORMAL_CHOICE2,  "NORMAL_CHOICE2" );
    add_type_def( FL_CHOICE, FL_DROPLIST_CHOICE, "DROPLIST_CHOICE" );
    set_var_boxtype( FL_CHOICE, 1 );

    fl_add_browser_line( fd_control->objectbrowser, "browser" );
    add_class_def( VN( FL_BROWSER), OBJNAME( browser ), ++bl );
    add_type_def( FL_BROWSER, FL_NORMAL_BROWSER, "NORMAL_BROWSER" );
    add_type_def( FL_BROWSER, FL_SELECT_BROWSER, "SELECT_BROWSER" );
    add_type_def( FL_BROWSER, FL_HOLD_BROWSER,   "HOLD_BROWSER" );
    add_type_def( FL_BROWSER, FL_DESELECTABLE_HOLD_BROWSER,
                                                 "DESELECTABLE_HOLD_BROWSER" );
    add_type_def( FL_BROWSER, FL_MULTI_BROWSER,  "MULTI_BROWSER" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "timer" );
    add_class_def( VN( FL_TIMER ), OBJNAME( timer ), ++bl );
    add_type_def( FL_TIMER, FL_NORMAL_TIMER, "NORMAL_TIMER" );
    add_type_def( FL_TIMER, FL_VALUE_TIMER,  "VALUE_TIMER" );
    add_type_def( FL_TIMER, FL_HIDDEN_TIMER, "HIDDEN_TIMER" );
    set_class_default( FL_TIMER, FL_NORMAL_TIMER, "timer" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "xyplot" );
    add_class_def( VN( FL_XYPLOT ), OBJNAME( xyplot ), ++bl );
    add_xyplot_types( FL_XYPLOT );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "canvas" );
    add_class_def( VN( FL_CANVAS ), "canvas",
                   fl_create_simu_canvas, fl_add_simu_canvas, ++bl );
    add_type_def( FL_CANVAS, FL_NORMAL_CANVAS,   "NORMAL_CANVAS" );
    add_type_def( FL_CANVAS, FL_SCROLLED_CANVAS, "SCROLLED_CANVAS" );
    set_class_default( FL_CANVAS, FL_NORMAL_CANVAS, "" );

    fl_add_browser_line( fd_control->objectbrowser, "glcanvas" );
    add_class_def( VN( FL_GLCANVAS ), "glcanvas",
                   fl_create_simu_glcanvas, fl_add_simu_glcanvas, ++bl );
    add_type_def( FL_GLCANVAS, FL_NORMAL_CANVAS,   "NORMAL_CANVAS" );
    add_type_def( FL_GLCANVAS, FL_SCROLLED_CANVAS, "SCROLLED_CANVAS" );
    set_class_default( FL_GLCANVAS, FL_NORMAL_CANVAS, "" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "tabfolder" );
    add_class_def( FL_NTABFOLDER, "FL_TABFOLDER", "tabfolder",
                   fl_create_ntabfolder, fl_add_ntabfolder, ++bl );
    add_type_def( FL_NTABFOLDER, FL_TOP_TABFOLDER, "TOP_TABFOLDER" );
    add_type_def( FL_NTABFOLDER, FL_BOTTOM_TABFOLDER, "BOTTOM_TABFOLDER" );
    set_class_default( FL_NTABFOLDER, FL_TOP_TABFOLDER, "" );

    fl_add_browser_line( fd_control->objectbrowser, "formbrowser" );
    add_class_def( FL_FORMBROWSER, "FL_FORMBROWSER", "formbrowser",
                   fl_create_nformbrowser, fl_add_nformbrowser, ++bl );
    add_type_def( FL_FORMBROWSER, FL_NORMAL_FORMBROWSER, "NORMAL_FORMBROWSER" );

    fl_add_browser_line( fd_control->objectbrowser, "@-" );
    bl++;

    fl_add_browser_line( fd_control->objectbrowser, "freeobject" );
    add_class_def( VN( FL_FREE ), "freeobject", fd_create_free, fd_add_free,
                   ++bl );
    add_type_def( FL_FREE, FL_NORMAL_FREE,     "NORMAL_FREE" );
    add_type_def( FL_FREE, FL_INACTIVE_FREE,   "INACTIVE_FREE" );
    add_type_def( FL_FREE, FL_INPUT_FREE,      "INPUT_FREE" );
    add_type_def( FL_FREE, FL_CONTINUOUS_FREE, "CONTINUOUS_FREE" );
    add_type_def( FL_FREE, FL_ALL_FREE, "ALL_FREE" );

    /* ADD NEW CLASSES HERE */

    /* Group must be last, palette.c need this */

    add_class_def( VN( FL_BEGIN_GROUP ), "group", 0, 0, 0 );
    add_type_def( FL_BEGIN_GROUP, 0, "0" );

    add_class_def( VN( FL_END_GROUP ), "endgroup", 0, 0, 0 );
    add_type_def( FL_END_GROUP, 0, "0" );
}


/***************************************
 ***************************************/

void
select_object_by_class( int cn )
{
    int i;

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cn )
        {
            fl_select_browser_line( fd_control->objectbrowser,
                                    classes[ i ].bline );
            fl_show_browser_line( fd_control->objectbrowser,
                                  classes[ i ].bline );
            cur_class = cn;
            break;
        }
}


/****
  GETTING INFORMATION ABOUT CLASSES AND TYPES
****/

/***************************************
 * Returns a pointer to the (short) name of the class
 ***************************************/

char *
find_class_name( int cln )
{
    int i;
    static char buf[ MAX_CLASS_NAME_LEN ];

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cln )
            return classes[ i ].cname;
    sprintf( buf, "%d", cln );
    return buf;
}


/***************************************
 * Returns a pointer to the formal name of the class
 ***************************************/

char *
class_name( int cls )
{
    int i;
    static char buf[ MAX_CLASS_NAME_LEN ];

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cls )
            return classes[ i ].formal_cname;
    sprintf( buf, "%d", cls );
    return buf;
}


/***************************************
 * Returns the class value
 ***************************************/

int
class_val( const char * name )
{
    int i;

    for ( i = 0; i < cnumb; i++ )
    {
        if (    strcmp( classes[ i ].cname, name ) == 0
             || strcmp( classes[ i ].formal_cname, name ) == 0 )
            return classes[ i ].cn;
    }

    return atoi( name );
}


/***************************************
 * Returns a pointer to the default object of the class. var_boxtype
 * means different type may have different boxtypes
 ***************************************/

FL_OBJECT *
find_class_default( int cln,
                    int t )
{
    int i;
    CDEF *c = classes;

    for ( i = 0; i < cnumb; i++, c++ )
        if ( c->cn == cln )
        {
            if ( c->var_boxtype )
            {
                if ( c->defobj1 )
                    fl_free_object( c->defobj1 );
                return c->defobj1 = c->createit( t, 0, 0, 1, 1, "" );
            }
            else
                return c->defobj;
        }

    return NULL;
}


/***************************************
 * Returns the number of types in the class
 ***************************************/

int
find_class_maxtype( int cln )
{
    int i, j,
        n = 0;

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cln )
            for ( j = 0; j < MAXTYPES; j++ )
                if ( classes[ i ].types[ j ].defined )
                    n++;
    return n;
}


/***************************************
 * Returns a pointer to the name of the type in the class
 ***************************************/

const char *
find_type_name( int cln,
                int tyn )
{
    int i;
    static char buf[ MAX_TYPE_NAME_LEN ];

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cln )
            return classes[ i ].types[ tyn ].tname;
    sprintf( buf, "%d", tyn );
    return buf;
}


/***************************************
 * Returns a integer indicating the value of a type
 ***************************************/

int
find_type_value( int          cln,
                 const char * type_name )
{
    int i,
        jmax = find_class_maxtype( cln ),
        j;

    for ( i = 0; i < cnumb; i++ )
        if ( classes[ i ].cn == cln )
            for ( j = 0; j < jmax; j++ )
                if (    ! strcmp( classes[ i ].types[ j ].tname, type_name )
                     || (    ! strncmp( type_name, "FL_", 3 )
                          && ! strcmp( classes[ i ].types[ j ].tname,
                                       type_name + 3 ) ) )
                    return j;

    M_err( "TypeValue", "type %s is unknown", type_name );
    return -1;
}


/****
  ADDING OBJECTS
****/

#define pm_width  28
#define pm_height 28


/***************************************
 ***************************************/

void
set_testing_pixmap( FL_OBJECT * ob )
{
    fl_set_pixmap_data( ob, broken );
}


/***************************************
 ***************************************/

void
set_testing_bitmap( FL_OBJECT * obj )
{
    if ( obj->objclass == FL_BITMAP )
        fl_set_bitmap_data( obj, broken_width, broken_height,
                            ( unsigned char * ) broken_bits );
    else
        fl_set_bitmapbutton_data( obj, broken_width, broken_height,
                                  ( unsigned char * ) broken_bits );
}


/***************************************
 * Adds an object to the current form  type = -1 means default type
 ***************************************/

FL_OBJECT *
add_an_object( int      objclass,
               int      type,
               FL_Coord x,
               FL_Coord y,
               FL_Coord w,
               FL_Coord h )
{
    FL_OBJECT *obj = NULL;
    CDEF *cls;
    static FL_FORM *cf = NULL;

    if ( cur_form == NULL )
        return NULL;

    /* This routine is called with X coordinate system, need to translate to
       up-right coordinate system */

    if ( ! ( cls = find_class_struct( objclass ) ) )
    {
        fprintf( stderr, "unknown class %d\n", objclass );
        return 0;
    }

    if ( ! cf )
        fl_addto_form( cur_form );

    switch ( objclass )
    {
        case FL_BEGIN_GROUP:
            cf = cur_form;
            obj = fl_bgn_group( );
            break;

        case FL_END_GROUP:
            obj = fli_end_group( );
            break;

        case FL_BITMAP:
            if ( type == -1 )
                type = FL_NORMAL_BITMAP;
            obj = cls->addit( type, x, y, w, h, "" );
            if ( ! fdopt.conv_only )
                set_testing_bitmap( obj );
            break;

        case FL_PIXMAP:
            if ( type == -1 )
                type = FL_NORMAL_PIXMAP;
            obj = cls->addit( type, x, y, w, h, "" );
            if ( ! fdopt.conv_only )
                set_testing_pixmap( obj );
            break;

        case FL_CHART:
            if ( type == -1 )
                type = FL_BAR_CHART;
            obj = cls->addit( type, x, y, w, h, "" );
            fl_add_chart_value( obj, 4.0, "item 1", 2 );
            fl_add_chart_value( obj, 8.0, "item 2", 3 );
            fl_add_chart_value( obj, 2.0, "item 3", 4 );
            fl_add_chart_value( obj, 5.0, "item 4", 5 );
            break;

        case FL_BITMAPBUTTON:
            if ( type == -1 )
                type = FL_NORMAL_BUTTON;
            obj = cls->addit( type, x, y, w, h, "" );
            if ( ! fdopt.conv_only )
                set_testing_bitmap( obj );
            break;

        case FL_PIXMAPBUTTON:
            if ( type == -1 )
                type = FL_NORMAL_BUTTON;
            obj = cls->addit( type, x, y, w, h, "" );
            if ( ! fdopt.conv_only )
                set_testing_pixmap( obj );
            break;

        case FL_SLIDER:
            if ( type == -1 )
                type = h > w ? FL_VERT_BROWSER_SLIDER : FL_HOR_BROWSER_SLIDER;
            obj = cls->addit( type, x, y, w, h, "" );
            break;

        case FL_VALSLIDER:
            if ( type == -1 )
                type = h > w ? FL_VERT_BROWSER_SLIDER : FL_HOR_BROWSER_SLIDER;
            obj = cls->addit( type, x, y, w, h, "" );
            break;

        case FL_SCROLLBAR:
            if ( type == -1 )
                type = h > w ? FL_VERT_SCROLLBAR : FL_HOR_SCROLLBAR;
            obj = cls->addit( type, x, y, w, h, "" );
            break;

        case FL_THUMBWHEEL:
            if ( type == -1 )
                type = h > w ? FL_VERT_THUMBWHEEL : FL_HOR_THUMBWHEEL;
            obj = cls->addit( type, x, y, w, h, "" );
            break;

        case FL_INPUT:
            if ( type == -1 )
                type = h < 60 ? FL_NORMAL_INPUT : FL_MULTILINE_INPUT;
            obj = cls->addit( type, x, y, w, h, "Input" );
            fl_set_input_hscrollbar( obj, FL_OFF );
            fl_set_input_vscrollbar( obj, FL_OFF );
            break;

        case FL_MENU:
            if ( type == -1 )
                type = FL_PULLDOWN_MENU;
            obj = cls->addit( type, x, y, w, h, "Menu" );
            get_superspec( obj );       /* super spec must exist for testing */
            break;

        case FL_CHOICE:
            if ( type == -1 )
                type = FL_NORMAL_CHOICE2;
            obj = cls->addit( type, x, y, w, h, "" );
            get_superspec( obj );       /* super spec must exist for testing */
            break;

        case FL_BROWSER:
            if ( type == -1 )
                type = FL_NORMAL_BROWSER;
            obj = cls->addit( type, x, y, w, h, "" );
            get_superspec( obj );       /* super spec must exist for testing */
            break;

        case FL_XYPLOT:
            if ( type == -1 )
                type = FL_NORMAL_XYPLOT;
            {
                float xx[ 30 ],
                      yy[ 30 ];
                int i;

                for ( i = 0; i < 30; i++ )
                {
                    xx[ i ] = 3.1415 * ( i + 0.5 ) / 8.0;
                    yy[ i ] = FL_abs( sin( 2 * xx[ i ] ) + cos( xx[ i ] ) );
                }

                obj = cls->addit( type, x, y, w, h, "" );
                fl_set_xyplot_data( obj, xx, yy, 30, "", "", "" );
            }
            break;

        case FL_FREE:
            if ( type == -1 )
                type = FL_NORMAL_FREE;
            obj = fl_add_free( type, x, y, w, h, "", noop_handle );
            break;

        default:
            if ( type == -1 )
                type = cls->default_type;
            obj = cls->addit( type, x, y, w, h, cls->default_label );
            break;
    }

    if ( ! obj )
    {
        fprintf( stderr, "Failed to create object (class = %d type = %d)\n",
                 objclass, type );
        return NULL;
    }

    obj->fl1 = obj->x;
    obj->fr1 = cur_form->w_hr - obj->fl1;
    obj->ft1 = obj->y;
    obj->fb1 = cur_form->h_hr - obj->ft1;

    obj->fl2 = obj->x + obj->w;
    obj->fr2 = cur_form->w - obj->fl2;
    obj->ft2 = obj->y + obj->h;
    obj->fb2 = cur_form->h - obj->ft2;

    if ( ! cf || objclass == FL_END_GROUP )
    {
        fl_end_form( );
        cf = NULL;
    }

    obj->active = 1;

    return obj;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
