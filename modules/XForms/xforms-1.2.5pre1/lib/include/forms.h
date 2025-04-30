/*
 *
 *  This file is part of the XForms library package.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *  \file forms.h
 *
 *. All XForms files as distributed in this package are
 *  Copyright(c) 1996-2002 by T.C. Zhao and Mark Overmars,
 *  with part of the code Copyright (c) 1999-2002 by T.C. Zhao
 *  and Steve Lamont.
 *  ALL RIGHTS RESERVED.
 *
 * Permission to use, copy, and distribute this software in its entirety
 * without fee, is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies and their
 * documentation.
 *
 * As of April 2002, xforms is released under the GNU LGPL license.
 * You can use xforms for any purpose that's compatible with
 * LGPL with the restriction that you will need a special license
 * for distributed  binary commercial software that requires or is
 * based on xforms or its derivative.
 *
 * This software is provided "as is" without expressed or implied
 * warranty of any kind.
 *
 * The homepage for XForms is at
 * https://savannah.nongnu.org/projects/xforms/
 *
 * If you have questions about XForms or encounter problems please
 * subscribe to the mailing list at
 * http://cweblog.usuhs.mil/mailman/listinfo/xforms
 *
 * ******** This file is generated automatically. DO NOT CHANGE *********
 */

#ifndef FL_FORMS_H
#define FL_FORMS_H

#define FL_VERSION             1
#define FL_REVISION            2
#define FL_FIXLEVEL            "5pre1"
#define FL_INCLUDE_VERSION     ( FL_VERSION * 1000 + FL_REVISION )

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>

#if defined __cplusplus
extern "C"
{
#endif

#if defined _WIN32
#define FL_WIN32
#include <windows.h>
#endif

#if ! defined FL_WIN32 || ! defined SHARED_LIB
#define FL_EXPORT extern
#else
#ifdef MAKING_FORMS
#define FL_EXPORT __declspec( dllexport ) extern
#else
#define FL_EXPORT __declspec( dllimport ) extern
#endif              /* MAKING_FORMS */
#endif              /* FL_WIN32 */

/**
 * \file Basic.h
 *
 *  Basic definitions and limits.
 *  Window system independent prototypes
 *
 *  Modify with care
 */

#ifndef FL_BASIC_H
#define FL_BASIC_H

#include <math.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/Xresource.h>

#if defined __GNUC__
#define FL_UNUSED_ARG __attribute__ ((unused))
#else
#define FL_UNUSED_ARG
#endif

/* Some general constants */

enum {
    FL_ON          = 1,
    FL_OK          = 1,
    FL_VALID       = 1,
    FL_PREEMPT     = 1,
    FL_AUTO        = 2,
    FL_WHEN_NEEDED = FL_AUTO,
    FL_OFF         = 0,
    FL_CANCEL      = 0,
    FL_INVALID     = 0,

    /* WM_DELETE_WINDOW callback return */

    FL_IGNORE      = -1
};

/* Max  directory length  */

#ifndef FL_PATH_MAX
#ifndef PATH_MAX
#define FL_PATH_MAX       1024
#else
#define FL_PATH_MAX       PATH_MAX
#endif
#endif /* ! def FL_PATH_MAX */

/* The screen coordinate unit, FL_Coord, must be of signed type */

typedef int FL_Coord;
#define FL_COORD         FL_Coord

typedef unsigned long FL_COLOR;

/* Coordinates can be in pixels, milli-meters or points (1/72inch) */

typedef enum {
    FL_COORD_PIXEL,         /* default, Pixel           */
    FL_COORD_MM,            /* milli-meter              */
    FL_COORD_POINT,         /* point                    */
    FL_COORD_centiMM,       /* one hundredth of a mm    */
    FL_COORD_centiPOINT     /* one hundredth of a point */
} FL_COORD_UNIT;

/* All object classes. */

typedef enum {
    FL_INVALID_CLASS,      /*  0 */
    FL_BUTTON,             /*  1 */
    FL_LIGHTBUTTON,        /*  2 */
    FL_ROUNDBUTTON,        /*  3 */
    FL_ROUND3DBUTTON,      /*  4 */
    FL_CHECKBUTTON,        /*  5 */
    FL_BITMAPBUTTON,       /*  6 */
    FL_PIXMAPBUTTON,       /*  7 */
    FL_BITMAP,             /*  8 */
    FL_PIXMAP,             /*  9 */
    FL_BOX,                /* 10 */
    FL_TEXT,               /* 11 */
    FL_MENU,               /* 12 */
    FL_CHART,              /* 13 */
    FL_CHOICE,             /* 14 */
    FL_COUNTER,            /* 15 */
    FL_SLIDER,             /* 16 */
    FL_VALSLIDER,          /* 17 */
    FL_INPUT,              /* 18 */
    FL_BROWSER,            /* 19 */
    FL_DIAL,               /* 20 */
    FL_TIMER,              /* 21 */
    FL_CLOCK,              /* 22 */
    FL_POSITIONER,         /* 23 */
    FL_FREE,               /* 24 */
    FL_XYPLOT,             /* 25 */
    FL_FRAME,              /* 26 */
    FL_LABELFRAME,         /* 27 */
    FL_CANVAS,             /* 28 */
    FL_GLCANVAS,           /* 29 */
    FL_TABFOLDER,          /* 30 */
    FL_SCROLLBAR,          /* 31 */
    FL_SCROLLBUTTON,       /* 32 */
    FL_MENUBAR,            /* 33 */
    FL_TEXTBOX,            /* 34, for internal use only */
    FL_LABELBUTTON,        /* 35 */
    FL_COMBOBOX,           /* 36 */
    FL_IMAGECANVAS,        /* 37 */
    FL_THUMBWHEEL,         /* 38 */
    FL_COLORWHEEL,         /* 39 */
    FL_FORMBROWSER,        /* 40 */
    FL_SELECT,             /* 41 */
    FL_NMENU,              /* 42 */
    FL_SPINNER,            /* 43 */
    FL_TBOX,               /* 44 */
    FL_CLASS_END           /* sentinel */
} FL_CLASS;

#define FL_BEGIN_GROUP        10000
#define FL_END_GROUP          20000

#define FL_USER_CLASS_START   1001  /* min. user class  value */
#define FL_USER_CLASS_END     9999  /* max. user class  value */

/* Maximum border width (in pixel) */

#define FL_MAX_BW          10

/* How to display a form onto screen */

typedef enum {
    FL_PLACE_FREE       =   0,      /* size remain resizable      */
    FL_PLACE_MOUSE      =   1,      /* mouse centered on form     */
    FL_PLACE_CENTER     =   2,         /* center of the screen       */
    FL_PLACE_POSITION   =   4,         /* specific position          */
    FL_PLACE_SIZE       =   8,         /* specific size              */
    FL_PLACE_GEOMETRY   =  16,         /* specific size and position */
    FL_PLACE_ASPECT     =  32,         /* keep aspect ratio          */
    FL_PLACE_FULLSCREEN =  64,         /* scale to fit to screen     */
    FL_PLACE_HOTSPOT    = 128,         /* so mouse fall on (x,y)     */
    FL_PLACE_ICONIC     = 256,         /* start in iconified form    */

    /* Modifiers */

    FL_FREE_SIZE        = ( 1 << 14 ),
	FL_FIX_SIZE         = ( 1 << 15 )  /* seems to be useless, but some
										  programs seem to rely on it... */
} FL_PLACE;

#define FL_PLACE_FREE_CENTER ( FL_PLACE_CENTER | FL_FREE_SIZE )
#define FL_PLACE_CENTERFREE  ( FL_PLACE_CENTER | FL_FREE_SIZE )

/* Window manager decoration request and forms attributes */

enum {
    FL_FULLBORDER = 1,      /* normal                                  */
    FL_TRANSIENT,           /* set TRANSIENT_FOR property              */
    FL_NOBORDER             /* use override_redirect to supress decor. */
 };

/* All box types */

typedef enum {
    FL_NO_BOX,                /*  0 */
    FL_UP_BOX,                /*  1 */
    FL_DOWN_BOX,              /*  2 */
    FL_BORDER_BOX,            /*  3 */
    FL_SHADOW_BOX,            /*  4 */
    FL_FRAME_BOX,             /*  5 */
    FL_ROUNDED_BOX,           /*  6 */
    FL_EMBOSSED_BOX,          /*  7 */
    FL_FLAT_BOX,              /*  8 */
    FL_RFLAT_BOX,             /*  9 */
    FL_RSHADOW_BOX,           /* 10 */
    FL_OVAL_BOX,              /* 11 */
    FL_ROUNDED3D_UPBOX,       /* 12 */
    FL_ROUNDED3D_DOWNBOX,     /* 13 */
    FL_OVAL3D_UPBOX,          /* 14 */
    FL_OVAL3D_DOWNBOX,        /* 15 */
    FL_OVAL3D_FRAMEBOX,       /* 16 */
    FL_OVAL3D_EMBOSSEDBOX,    /* 17 */

    /* for internal use only */

    FL_TOPTAB_UPBOX,
    FL_SELECTED_TOPTAB_UPBOX,
    FL_BOTTOMTAB_UPBOX,
    FL_SELECTED_BOTTOMTAB_UPBOX,
 
    FL_MAX_BOX_STYLES               /* sentinel */
} FL_BOX_TYPE;

#define FL_IS_UPBOX( t )    (    ( t ) == FL_UP_BOX           \
                              || ( t ) == FL_OVAL3D_UPBOX     \
                              || ( t ) == FL_ROUNDED3D_UPBOX)

#define FL_IS_DOWNBOX( t )  (    ( t ) == FL_DOWN_BOX          \
                              || ( t ) == FL_OVAL3D_DOWNBOX    \
                              || ( t ) == FL_ROUNDED3D_DOWNBOX)

#define FL_TO_DOWNBOX( t )  ( ( t ) == FL_UP_BOX ? FL_DOWN_BOX:         \
                              ( ( t ) == FL_ROUNDED3D_UPBOX ?           \
                                FL_ROUNDED3D_DOWNBOX:                   \
                                ( ( t ) == FL_OVAL3D_UPBOX ?            \
                                  FL_OVAL3D_DOWNBOX : ( t ) ) ) )

/* How to place text relative to a box */

typedef enum {
	FL_ALIGN_CENTER,
    FL_ALIGN_TOP          = 1,
    FL_ALIGN_BOTTOM       = 2,
    FL_ALIGN_LEFT         = 4,
    FL_ALIGN_RIGHT        = 8,
    FL_ALIGN_LEFT_TOP     = ( FL_ALIGN_TOP    | FL_ALIGN_LEFT  ),
    FL_ALIGN_RIGHT_TOP    = ( FL_ALIGN_TOP    | FL_ALIGN_RIGHT ),
    FL_ALIGN_LEFT_BOTTOM  = ( FL_ALIGN_BOTTOM | FL_ALIGN_LEFT  ),
    FL_ALIGN_RIGHT_BOTTOM = ( FL_ALIGN_BOTTOM | FL_ALIGN_RIGHT ),
    FL_ALIGN_INSIDE       = ( 1 << 13 ),
    FL_ALIGN_VERT         = ( 1 << 14 ),    /* not functional yet  */

    /* the rest is for backward compatibility only, don't use! */

    FL_ALIGN_TOP_LEFT     = FL_ALIGN_LEFT_TOP,
    FL_ALIGN_TOP_RIGHT    = FL_ALIGN_RIGHT_TOP,
    FL_ALIGN_BOTTOM_LEFT  = FL_ALIGN_LEFT_BOTTOM,
    FL_ALIGN_BOTTOM_RIGHT = FL_ALIGN_RIGHT_BOTTOM
} FL_ALIGN;


FL_EXPORT int fl_is_inside_lalign( int align );

FL_EXPORT int fl_is_outside_lalign( int align );

FL_EXPORT int fl_is_center_lalign( int align );

FL_EXPORT int fl_to_inside_lalign( int align );

FL_EXPORT int fl_to_outside_lalign( int align );

/* Mouse buttons */

enum {
    FL_MBUTTON1 = 1,
    FL_MBUTTON2,
    FL_MBUTTON3,
    FL_MBUTTON4,
    FL_MBUTTON5
};

#define FL_LEFT_MOUSE        FL_MBUTTON1
#define FL_MIDDLE_MOUSE      FL_MBUTTON2
#define FL_RIGHT_MOUSE       FL_MBUTTON3
#define FL_SCROLLUP_MOUSE    FL_MBUTTON4
#define FL_SCROLLDOWN_MOUSE  FL_MBUTTON5

#define FL_LEFTMOUSE         FL_LEFT_MOUSE
#define FL_MIDDLEMOUSE       FL_MIDDLE_MOUSE
#define FL_RIGHTMOUSE        FL_RIGHT_MOUSE
#define FL_SCROLLUPMOUSE     FL_SCROLLUP_MOUSE
#define FL_SCROLLDOWNMOUSE   FL_SCROLLDOWN_MOUSE

/* Flags for when to return an object */

#define FL_RETURN_NONE            0U
#define FL_RETURN_CHANGED         1U
#define FL_RETURN_END             2U
#define FL_RETURN_END_CHANGED     4U
#define FL_RETURN_SELECTION       8U
#define FL_RETURN_DESELECTION    16U
#define FL_RETURN_TRIGGERED    1024U
#define FL_RETURN_ALWAYS       ( ~ FL_RETURN_END_CHANGED )


/*  Some special color indices for FL private colormap. It does not matter
 *  what the value of each enum is, but it must start from 0 and be
 *  consecutive. */

typedef enum {
    FL_BLACK,
	FL_RED,
	FL_GREEN,
	FL_YELLOW,
    FL_BLUE,
	FL_MAGENTA,
	FL_CYAN,
	FL_WHITE,
    FL_TOMATO,
	FL_INDIANRED,
	FL_SLATEBLUE,
    FL_COL1,
	FL_RIGHT_BCOL,
	FL_BOTTOM_BCOL,
	FL_TOP_BCOL,
	FL_LEFT_BCOL,
    FL_MCOL,
    FL_INACTIVE,
	FL_PALEGREEN,
	FL_DARKGOLD,
    FL_ORCHID,
	FL_DARKCYAN,
	FL_DARKTOMATO,
	FL_WHEAT,
	FL_DARKORANGE,
    FL_DEEPPINK,
	FL_CHARTREUSE,
	FL_DARKVIOLET,
	FL_SPRINGGREEN,
    FL_DODGERBLUE,
	FL_LIGHTER_COL1,
	FL_DARKER_COL1,
	FL_ALICEBLUE,
	FL_ANTIQUEWHITE,
	FL_AQUA,
	FL_AQUAMARINE,
	FL_AZURE,
	FL_BEIGE,
	FL_BISQUE,
	FL_BLANCHEDALMOND,
	FL_BLUEVIOLET,
	FL_BROWN,
	FL_BURLYWOOD,
	FL_CADETBLUE,
	FL_CHOCOLATE,
	FL_CORAL,
	FL_CORNFLOWERBLUE,
	FL_CORNSILK,
	FL_CRIMSON,
	FL_DARKBLUE,
	FL_DARKGOLDENROD,
	FL_DARKGRAY,
	FL_DARKGREEN,
	FL_DARKGREY,
	FL_DARKKHAKI,
	FL_DARKMAGENTA,
	FL_DARKOLIVEGREEN,
	FL_DARKORCHID,
	FL_DARKRED,
	FL_DARKSALMON,
	FL_DARKSEAGREEN,
	FL_DARKSLATEBLUE,
	FL_DARKSLATEGRAY,
	FL_DARKSLATEGREY,
	FL_DARKTURQUOISE,
	FL_DEEPSKYBLUE,
	FL_DIMGRAY,
	FL_DIMGREY,
	FL_FIREBRICK,
	FL_FLORALWHITE,
	FL_FORESTGREEN,
	FL_FUCHSIA,
	FL_GAINSBORO,
	FL_GHOSTWHITE,
	FL_GOLD,
	FL_GOLDENROD,
	FL_GRAY,
	FL_GREENYELLOW,
	FL_GREY,
	FL_HONEYDEW,
	FL_HOTPINK,
	FL_INDIGO,
	FL_IVORY,
	FL_KHAKI,
	FL_LAVENDER,
	FL_LAVENDERBLUSH,
	FL_LAWNGREEN,
	FL_LEMONCHIFFON,
	FL_LIGHTBLUE,
	FL_LIGHTCORAL,
	FL_LIGHTCYAN,
	FL_LIGHTGOLDENRODYELLOW,
	FL_LIGHTGRAY,
	FL_LIGHTGREEN,
	FL_LIGHTGREY,
	FL_LIGHTPINK,
	FL_LIGHTSALMON,
	FL_LIGHTSEAGREEN,
	FL_LIGHTSKYBLUE,
	FL_LIGHTSLATEGRAY,
	FL_LIGHTSLATEGREY,
	FL_LIGHTSTEELBLUE,
	FL_LIGHTYELLOW,
	FL_LIME,
	FL_LIMEGREEN,
	FL_LINEN,
	FL_MAROON,
	FL_MEDIUMAQUAMARINE,
	FL_MEDIUMBLUE,
	FL_MEDIUMORCHID,
	FL_MEDIUMPURPLE,
	FL_MEDIUMSEAGREEN,
	FL_MEDIUMSLATEBLUE,
	FL_MEDIUMSPRINGGREEN,
	FL_MEDIUMTURQUOISE,
	FL_MEDIUMVIOLETRED,
	FL_MIDNIGHTBLUE,
	FL_MINTCREAM,
	FL_MISTYROSE,
	FL_MOCCASIN,
	FL_NAVAJOWHITE,
	FL_NAVY,
	FL_OLDLACE,
	FL_OLIVE,
	FL_OLIVEDRAB,
	FL_ORANGE,
	FL_ORANGERED,
	FL_PALEGOLDENROD,
	FL_PALETURQUOISE,
	FL_PALEVIOLETRED,
	FL_PAPAYAWHIP,
	FL_PEACHPUFF,
	FL_PERU,
	FL_PINK,
	FL_PLUM,
	FL_POWDERBLUE,
	FL_PURPLE,
	FL_ROSYBROWN,
	FL_ROYALBLUE,
	FL_SADDLEBROWN,
	FL_SALMON,
	FL_SANDYBROWN,
	FL_SEAGREEN,
	FL_SEASHELL,
	FL_SIENNA,
	FL_SILVER,
	FL_SKYBLUE,
	FL_SLATEGRAY,
	FL_SLATEGREY,
	FL_SNOW,
	FL_STEELBLUE,
	FL_TAN,
	FL_TEAL,
	FL_THISTLE,
	FL_TURQUOISE,
	FL_VIOLET,
	FL_WHITESMOKE,
	FL_YELLOWGREEN,
    FL_COLOR_CHOOSER_COLOR,
    FL_FREE_COL1,
    FL_FREE_COL2,
    FL_FREE_COL3,
    FL_FREE_COL4,
    FL_FREE_COL5,
    FL_FREE_COL6,
    FL_FREE_COL7,
    FL_FREE_COL8,
    FL_FREE_COL9,
    FL_FREE_COL10,
    FL_FREE_COL11,
    FL_FREE_COL12,
    FL_FREE_COL13,
    FL_FREE_COL14,
    FL_FREE_COL15,
    FL_FREE_COL16,
    FL_NOCOLOR = INT_MAX
} FL_PD_COL;


#define FL_BUILT_IN_COLS  ( FL_YELLOWGREEN + 1 )
#define FL_INACTIVE_COL   FL_INACTIVE

/* Some aliases for a number of colors */

#define FL_GRAY16           FL_RIGHT_BCOL
#define FL_GRAY35           FL_BOTTOM_BCOL
#define FL_GRAY80           FL_TOP_BCOL
#define FL_GRAY90           FL_LEFT_BCOL
#define FL_GRAY63           FL_COL1
#define FL_GRAY75           FL_MCOL
#define FL_LCOL             FL_BLACK
#define FL_NoColor          FL_NOCOLOR

/* An alias probably for an earlier typo */

#define FL_DOGERBLUE        FL_DODGERBLUE

/* Events that a form reacts to  */

typedef enum {
    FL_NOEVENT,                /*  0 No event */
    FL_DRAW,                   /*  1 object is asked to redraw itself */
    FL_PUSH,                   /*  2 mouse button was pressed on the object */
    FL_RELEASE,                /*  3 mouse button was release gain */
    FL_ENTER,                  /*  4 mouse entered the object */
    FL_LEAVE,                  /*  5 mouse left the object */
    FL_MOTION,                 /*  6 mouse motion over the object happend */
    FL_FOCUS,                  /*  7 object obtained focus */
    FL_UNFOCUS,                /*  8 object lost focus */
    FL_KEYPRESS,               /*  9 key was pressed while object has focus */
    FL_UPDATE,                 /* 10 for objects that need to update something
                                     from time to time */
    FL_STEP,                   /* 11 */
    FL_SHORTCUT,               /* 12 */
    FL_FREEMEM,                /* 13 object is asked to free all its memory */
    FL_OTHER,                  /* 14 property, selection etc */
    FL_DRAWLABEL,              /* 15 */
    FL_DBLCLICK,               /* 16 double click on object */
    FL_TRPLCLICK,              /* 17 triple click on object */
    FL_ATTRIB,                 /* 18 an object attribute changed */
    FL_KEYRELEASE,             /* 19 key was released while object has focus */
    FL_PS,                     /* 20 dump a form into EPS      */
    FL_MOVEORIGIN,             /* 21 dragging the form across the screen
                                     changes its absolute x,y coords. Objects
                                     that themselves contain forms should
                                     ensure that they are up to date. */
    FL_RESIZED,                /* 22 the object has been resized by scale_form
                                     Tell it that this has happened so that
                                     it can resize any FL_FORMs that it
                                     contains. */
	FL_PASTE,                  /* 23 text was pasted into input object */
	FL_TRIGGER,                /* 24 result of fl_trigger_object() */

	/* The following are only for backward compatibility, not used anymore */

	FL_MOVE      = FL_MOTION,
    FL_KEYBOARD  = FL_KEYPRESS,
    FL_MOUSE     = FL_UPDATE
} FL_EVENTS;


/* Resize policies */

typedef enum {
    FL_RESIZE_NONE,
    FL_RESIZE_X,
    FL_RESIZE_Y,
    FL_RESIZE_ALL = ( FL_RESIZE_X | FL_RESIZE_Y )
} FL_RESIZE_T;


/* Keyboard focus control */

typedef enum {
    FL_KEY_NORMAL  = 1,     /* normal keys(0-255) - tab +left/right */
    FL_KEY_TAB     = 2,     /* normal keys + 4 direction cursor     */
    FL_KEY_SPECIAL = 4,     /* only needs special keys (>255)       */
    FL_KEY_ALL     = 7      /* all keys                             */
} FL_KEY;

#define FL_ALT_MASK      ( 1L << 25 )   /* alt + Key --> FL_ALT_MASK + key */
#define FL_CONTROL_MASK  ( 1L << 26 )
#define FL_SHIFT_MASK    ( 1L << 27 )
#define FL_ALT_VAL       FL_ALT_MASK    /* Don' use! */

#define MAX_SHORTCUTS    8

/* Pop-up menu item attributes. NOTE if more than 8, need to change
 * choice and menu class where mode is kept by a single byte */

enum {
    FL_PUP_NONE,
    FL_PUP_GREY  = 1,
    FL_PUP_BOX   = 2,
    FL_PUP_CHECK = 4,
    FL_PUP_RADIO = 8
};

#define FL_PUP_GRAY      FL_PUP_GREY
#define FL_PUP_TOGGLE    FL_PUP_BOX        /* not used anymore */
#define FL_PUP_INACTIVE  FL_PUP_GREY

/* Popup and menu entries */

typedef int ( * FL_PUP_CB )( int );        /* callback prototype  */

typedef struct {
    const char * text;           /* label of a popup/menu item   */
    FL_PUP_CB    callback;       /* the callback function        */
    const char * shortcut;       /* hotkeys                      */
    int          mode;           /* FL_PUP_GRAY, FL_PUP_CHECK etc */
} FL_PUP_ENTRY;

#define FL_MENU_ENTRY  FL_PUP_ENTRY

/*******************************************************************
 * FONTS
 ******************************************************************/

#define FL_MAXFONTS     48  /* max number of fonts */

typedef enum {
    FL_INVALID_STYLE = -1,
    FL_NORMAL_STYLE,
    FL_BOLD_STYLE,
    FL_ITALIC_STYLE,
    FL_BOLDITALIC_STYLE,

    FL_FIXED_STYLE,
    FL_FIXEDBOLD_STYLE,
    FL_FIXEDITALIC_STYLE,
    FL_FIXEDBOLDITALIC_STYLE,

    FL_TIMES_STYLE,
    FL_TIMESBOLD_STYLE,
    FL_TIMESITALIC_STYLE,
    FL_TIMESBOLDITALIC_STYLE,

    FL_MISC_STYLE,
    FL_MISCBOLD_STYLE,
    FL_MISCITALIC_STYLE,
    FL_SYMBOL_STYLE,

    /* modfier masks. Need to fit a short  */

    FL_SHADOW_STYLE   = ( 1 <<  9 ),
    FL_ENGRAVED_STYLE = ( 1 << 10 ),
    FL_EMBOSSED_STYLE = ( 1 << 11 )
} FL_TEXT_STYLE;

#define FL_FONT_STYLE FL_TEXT_STYLE

#define special_style( a )  (    ( a ) >= FL_SHADOW_STYLE                     \
                              && ( a ) <= ( FL_EMBOSSED_STYLE + FL_MAXFONTS ) )

/* Standard sizes in XForms */

#define FL_TINY_SIZE        8
#define FL_SMALL_SIZE      10
#define FL_NORMAL_SIZE     12
#define FL_MEDIUM_SIZE     14
#define FL_LARGE_SIZE      18
#define FL_HUGE_SIZE       24

#define FL_DEFAULT_SIZE   FL_SMALL_SIZE

/* Defines for compatibility */

#define FL_TINY_FONT      FL_TINY_SIZE
#define FL_SMALL_FONT     FL_SMALL_SIZE
#define FL_NORMAL_FONT    FL_NORMAL_SIZE
#define FL_MEDIUM_FONT    FL_MEDIUM_SIZE
#define FL_LARGE_FONT     FL_LARGE_SIZE
#define FL_HUGE_FONT      FL_HUGE_SIZE

#define FL_NORMAL_FONT1   FL_SMALL_FONT
#define FL_NORMAL_FONT2   FL_NORMAL_FONT
#define FL_DEFAULT_FONT   FL_SMALL_FONT

#define FL_BOUND_WIDTH  ( FL_Coord ) 1     /* Border width of boxes */

/* Definition of basic struct that holds an object */

#define  FL_CLICK_TIMEOUT  400  /* double click interval */

typedef struct FL_FORM_    FL_FORM;
typedef struct FL_OBJECT_  FL_OBJECT;
typedef struct FL_pixmap_  FL_pixmap;

struct FL_OBJECT_ {
    FL_FORM        * form;           /* the form this object belongs to */
    void           * u_vdata;        /* anything the user likes */
    char           * u_cdata;        /* anything the user likes */
    long             u_ldata;        /* anything the user likes */

    int              objclass;       /* class of object, button, slider etc */
    int              type;           /* type within the class */
    int              boxtype;        /* what kind of box type */
    FL_Coord         x,              /* current obj. location and size */
                     y,
                     w,
                     h;
    double           fl1,            /* distances of upper left hand (1) and */
                     fr1,            /* lower right hand corner (2) to left, */
                     ft1,            /* right, top and bottom of enclosing   */
                     fb1,            /* form */
                     fl2,
                     fr2,
                     ft2,
                     fb2;
    FL_Coord         bw;
    FL_COLOR         col1,           /* colors of obj */
                     col2;
    char           * label;          /* object label */
    FL_COLOR         lcol;           /* label color */
    int              align;
    int              lsize,          /* label size and style */
                     lstyle;
    long           * shortcut;
    int              ( * handle )( FL_OBJECT *,
                                   int,
                                   FL_Coord,
                                   FL_Coord,
                                   int,
                                   void * );
    void             ( * object_callback )( FL_OBJECT *,
                                            long );
    long             argument;
    void           * spec;           /* instantiation */

    int              ( * prehandle )( FL_OBJECT *,
                                      int,
                                      FL_Coord,
                                      FL_Coord,
                                      int,
                                      void * );
    int              ( * posthandle )( FL_OBJECT *,
                                       int,
                                       FL_Coord,
                                       FL_Coord,
                                       int,
                                       void * );
    void             ( * set_return )( FL_OBJECT *,
                                       unsigned int );

    /* Re-configure preference */

    unsigned int     resize;         /* what to do if WM resizes the FORM     */
    unsigned int     nwgravity;      /* how to re-position top-left corner    */
    unsigned int     segravity;      /* how to re-position lower-right corner */

    FL_OBJECT      * prev;           /* prev. obj in form */
    FL_OBJECT      * next;           /* next. obj in form */

    FL_OBJECT      * parent;
    FL_OBJECT      * child;
    FL_OBJECT      * nc;             /* next child */

    FL_pixmap      * flpixmap;       /* pixmap double buffering stateinfo */
    int              use_pixmap;     /* true to use pixmap double buffering*/

    /* Some interaction flags */

    int              returned;       /* what last interaction returned */
    unsigned int     how_return;     /* under which conditions to return */
    int              double_buffer;  /* only used by mesa/gl canvas */
    int              pushed;
    int              focus;
    int              belowmouse;
    int              active;         /* if object accepts events */
    int              input;
    int              wantkey;
    int              radio;
    int              automatic;
    int              redraw;
    int              visible;
    int              is_under;       /* if (partially) hidden by other object */
    int              clip;
    unsigned long    click_timeout;
    void           * c_vdata;        /* for class use */
    char           * c_cdata;        /* for class use */
    long             c_ldata;        /* for class use */
    FL_COLOR         dbl_background; /* double buffer background */
    char           * tooltip;
    int              tipID;
    int              group_id;
    int              want_motion;
    int              want_update;
};


/* Callback function for an entire form */

typedef void ( * FL_FORMCALLBACKPTR )( FL_OBJECT *,
                                       void * );
/* Object callback function      */

typedef void ( * FL_CALLBACKPTR )( FL_OBJECT *,
                                   long );

/* Preemptive callback function  */

typedef int ( * FL_RAW_CALLBACK )( FL_FORM *,
                                   void * );

/* At close (WM menu delete/close etc.) function */

typedef int ( * FL_FORM_ATCLOSE )( FL_FORM *,
                                   void * );
/* Deactivate/activate callback */

typedef void ( * FL_FORM_ATDEACTIVATE )( FL_FORM *,
                                         void * );
typedef void ( * FL_FORM_ATACTIVATE )( FL_FORM *,
                                       void * );

typedef int ( * FL_HANDLEPTR )( FL_OBJECT *,
                                int,
                                FL_Coord,
                                FL_Coord,
                                int,
                                void * );

/* Error callback */

typedef void ( * FL_ERROR_FUNC )( const char *,
                                  const char *,
                                  ... );

FL_EXPORT FL_OBJECT *FL_EVENT;

/*** FORM ****/

/* Form visibility state: form->visible */

enum {
  FL_BEING_HIDDEN = -1,
  FL_HIDDEN       = 0,
  FL_INVISIBLE    = FL_HIDDEN,
  FL_VISIBLE      = 1
};

struct FL_FORM_ {
    void                 * fdui;          /* for fdesign */
    void                 * u_vdata;       /* for application */
    char                 * u_cdata;       /* for application */
    long                   u_ldata;       /* for application */

    char *                 label;         /* window title */
    Window                 window;        /* X resource ID for window */
    FL_Coord               x,             /* current geometry info */
                           y,
                           w,
                           h;
    int                    handle_dec_x,
                           handle_dec_y;
    FL_Coord               hotx,          /* hot-spot of the form */
                           hoty;
    double                 w_hr,          /* high resolution width and height */
                           h_hr;          /* (needed for precise scaling) */

    FL_OBJECT            * first;
    FL_OBJECT            * last;
    FL_OBJECT            * focusobj;

    FL_FORMCALLBACKPTR     form_callback;
    FL_FORM_ATACTIVATE     activate_callback;
    FL_FORM_ATDEACTIVATE   deactivate_callback;
    void                 * form_cb_data;
    void                 * activate_data;
    void                 * deactivate_data;

    FL_RAW_CALLBACK        key_callback;
    FL_RAW_CALLBACK        push_callback;
    FL_RAW_CALLBACK        crossing_callback;
    FL_RAW_CALLBACK        motion_callback;
    FL_RAW_CALLBACK        all_callback;

    unsigned long          compress_mask;
    unsigned long          evmask;

    /* WM_DELETE_WINDOW message handler */

    FL_FORM_ATCLOSE        close_callback;
    void                 * close_data;

    FL_pixmap            * flpixmap;         /* back buffer */

    Pixmap                 icon_pixmap;
    Pixmap                 icon_mask;

    /* Interaction and other flags */

    int                    deactivated;      /* non-zero if deactivated */
    int                    use_pixmap;       /* true if dbl buffering */
    int                    frozen;           /* true if sync change */
    int                    visible;          /* true if mapped */
    int                    wm_border;        /* window manager info */
    unsigned int           prop;             /* other attributes */
    int                    num_auto_objects;
    int                    needs_full_redraw;
    int                    sort_of_modal;    /* internal use */
    FL_FORM              * parent;
    FL_FORM              * child;
    FL_OBJECT            * parent_obj;
    int                    attached;         /* not independent anymore */
    void                   ( * pre_attach )( FL_FORM * );
    void                 * attach_data;
    int                    in_redraw;
};


/* All FD_xxx structure emitted by fdesign contains at least the
 * following */

typedef struct {
    FL_FORM * form;
    void    * vdata;
    char    * cdata;
    long      ldata;
} FD_Any;

/* Async IO stuff */

enum {
    FL_READ   = 1,
    FL_WRITE  = 2,
    FL_EXCEPT = 4
};

/* IO other than XEvent Q */

typedef void ( * FL_IO_CALLBACK )( int,
                                   void * );

FL_EXPORT void fl_add_io_callback( int              fd,
                                   unsigned int     mask,
                                   FL_IO_CALLBACK   callback,
                                   void           * data );

FL_EXPORT void fl_remove_io_callback( int            fd,
                                      unsigned int   mask,
                                      FL_IO_CALLBACK cb );

/* signals */

typedef void ( * FL_SIGNAL_HANDLER )( int,
                                      void * );

FL_EXPORT void fl_add_signal_callback( int                 s,
                                       FL_SIGNAL_HANDLER   cb,
                                       void              * data );

FL_EXPORT void fl_remove_signal_callback( int s );

FL_EXPORT void fl_signal_caught( int s );

FL_EXPORT void fl_app_signal_direct( int y );


enum {
	FL_INPUT_END_EVENT_CLASSIC = 0,
	FL_INPUT_END_EVENT_ALWAYS  = 1
};

FL_EXPORT int fl_input_end_return_handling( int type );


/* Timeouts */

typedef void (* FL_TIMEOUT_CALLBACK )( int, void * );

FL_EXPORT int fl_add_timeout( long                  msec,
                              FL_TIMEOUT_CALLBACK   callback,
                              void                * data );

FL_EXPORT void fl_remove_timeout( int id );

/* Basic public routine prototypes */

FL_EXPORT int fl_library_version( int * ver,
                                  int * rev );

FL_EXPORT long fl_library_full_version( int         * version,
										int         * revision,
										int         * fix_level,
										const char ** extra );

/** Generic routines that deal with FORMS **/

FL_EXPORT FL_FORM * fl_bgn_form( int      type,
                                 FL_Coord w,
                                 FL_Coord h );

FL_EXPORT void fl_end_form( void );

FL_EXPORT FL_OBJECT * fl_do_forms( void );

FL_EXPORT FL_OBJECT * fl_check_forms( void );

FL_EXPORT FL_OBJECT * fl_do_only_forms( void );

FL_EXPORT FL_OBJECT * fl_check_only_forms( void );

FL_EXPORT void fl_freeze_form( FL_FORM * form );

FL_EXPORT void fl_set_focus_object( FL_FORM   * form,
                                    FL_OBJECT * obj );

FL_EXPORT FL_OBJECT *fl_get_focus_object( FL_FORM * form );

FL_EXPORT void fl_reset_focus_object( FL_OBJECT * ob );

#define fl_set_object_focus   fl_set_focus_object

FL_EXPORT FL_FORM_ATCLOSE fl_set_form_atclose( FL_FORM         * form,
                                               FL_FORM_ATCLOSE   fmclose,
                                               void            * data );

FL_EXPORT FL_FORM_ATCLOSE fl_set_atclose( FL_FORM_ATCLOSE   fmclose,
                                          void            * data );

FL_EXPORT FL_FORM_ATACTIVATE fl_set_form_atactivate( FL_FORM            * form,
													 FL_FORM_ATACTIVATE   cb,
													 void               * data );

FL_EXPORT FL_FORM_ATDEACTIVATE fl_set_form_atdeactivate( FL_FORM              * form,
														 FL_FORM_ATDEACTIVATE   cb,
														 void                 * data );

FL_EXPORT void fl_unfreeze_form( FL_FORM * form );

FL_EXPORT int fl_form_is_activated( FL_FORM * form );

FL_EXPORT void fl_deactivate_form( FL_FORM * form );

FL_EXPORT void fl_activate_form( FL_FORM * form );

FL_EXPORT void fl_deactivate_all_forms( void );

FL_EXPORT void fl_activate_all_forms( void );

FL_EXPORT void fl_freeze_all_forms( void );

FL_EXPORT void fl_unfreeze_all_forms( void );

FL_EXPORT void fl_scale_form( FL_FORM * form,
                              double    xsc,
                              double    ysc );

FL_EXPORT void fl_set_form_position( FL_FORM  * form,
                                     FL_Coord   x,
                                     FL_Coord   y );

FL_EXPORT void fl_set_form_title( FL_FORM    * form,
                                  const char * name );

FL_EXPORT void fl_set_form_title_f( FL_FORM *    form,
									const char * fmt,
									... );

FL_EXPORT void fl_set_app_mainform( FL_FORM * form );

FL_EXPORT FL_FORM * fl_get_app_mainform( void );

FL_EXPORT void fl_set_app_nomainform( int flag );

FL_EXPORT void fl_set_form_callback( FL_FORM            * form,
                                     FL_FORMCALLBACKPTR   callback,
                                     void               * d );

#define  fl_set_form_call_back    fl_set_form_callback

FL_EXPORT void fl_set_form_size( FL_FORM  * form,
                                 FL_Coord   w,
                                 FL_Coord   h );

FL_EXPORT void fl_set_form_background_color( FL_FORM * form,
											 FL_COLOR  color );

FL_EXPORT FL_COLOR fl_get_form_background_color( FL_FORM * form );

FL_EXPORT void fl_set_form_hotspot( FL_FORM  * form,
                                    FL_Coord   x,
                                    FL_Coord   y );

FL_EXPORT void fl_set_form_hotobject( FL_FORM   * form,
                                      FL_OBJECT * ob );

FL_EXPORT void fl_set_form_minsize( FL_FORM  * form,
                                    FL_Coord   w,
                                    FL_Coord   h );

FL_EXPORT void fl_set_form_maxsize( FL_FORM  * form,
                                    FL_Coord   w,
                                    FL_Coord   h );

FL_EXPORT void fl_set_form_event_cmask( FL_FORM       * form,
                                        unsigned long   cmask );

FL_EXPORT unsigned long fl_get_form_event_cmask( FL_FORM * form );

FL_EXPORT void fl_set_form_geometry( FL_FORM  * form,
                                     FL_Coord   x,
                                     FL_Coord   y,
                                     FL_Coord   w,
                                     FL_Coord   h );

#define fl_set_initial_placement fl_set_form_geometry

FL_EXPORT Window fl_show_form( FL_FORM    * form,
                               int          place,
                               int          border,
                               const char * name );

FL_EXPORT Window fl_show_form_f( FL_FORM    * form,
								 int          place,
								 int          border,
								 const char * fmt,
								 ... );

FL_EXPORT void fl_hide_form( FL_FORM * form );

FL_EXPORT void fl_free_form( FL_FORM * form );

FL_EXPORT void fl_redraw_form( FL_FORM * form );

FL_EXPORT void fl_set_form_dblbuffer( FL_FORM * form,
                                      int       y );

FL_EXPORT Window fl_prepare_form_window( FL_FORM    * form,
                                         int          place,
                                         int          border,
                                         const char * name );

FL_EXPORT Window fl_prepare_form_window_f( FL_FORM    * form,
										   int          place,
										   int          border,
										   const char * fmt,
										   ... );

FL_EXPORT Window fl_show_form_window( FL_FORM * form );

FL_EXPORT double fl_adjust_form_size( FL_FORM * form );

FL_EXPORT int fl_form_is_visible( FL_FORM * form );

FL_EXPORT int fl_form_is_iconified( FL_FORM * form );

FL_EXPORT FL_RAW_CALLBACK fl_register_raw_callback( FL_FORM         * form,
                                                    unsigned long     mask,
                                                    FL_RAW_CALLBACK   rcb );

#define fl_register_call_back fl_register_raw_callback

FL_EXPORT FL_OBJECT * fl_bgn_group( void );

FL_EXPORT void fl_end_group( void );

FL_EXPORT FL_OBJECT *fl_addto_group( FL_OBJECT * group );


/****** Routines that deal with FL_OBJECTS ********/

FL_EXPORT int fl_get_object_objclass( FL_OBJECT * obj );

FL_EXPORT int fl_get_object_type( FL_OBJECT * obj );

FL_EXPORT void fl_set_object_boxtype( FL_OBJECT * ob,
                                      int         boxtype );

FL_EXPORT int fl_get_object_boxtype( FL_OBJECT * obj );

FL_EXPORT void fl_set_object_bw( FL_OBJECT * ob,
                                 int         bw );

FL_EXPORT int fl_get_object_bw( FL_OBJECT * ob );

FL_EXPORT void fl_set_object_resize( FL_OBJECT    * ob,
                                     unsigned int   what );

FL_EXPORT void fl_get_object_resize( FL_OBJECT    * ob,
                                     unsigned int * what );

FL_EXPORT void fl_set_object_gravity( FL_OBJECT    * ob,
                                      unsigned int   nw,
                                      unsigned int   se );

FL_EXPORT void fl_get_object_gravity( FL_OBJECT    * ob,
                                      unsigned int * nw,
                                      unsigned int * se );

FL_EXPORT void fl_set_object_lsize( FL_OBJECT * obj,
                                    int         lsize );

FL_EXPORT int fl_get_object_lsize( FL_OBJECT * obj );


FL_EXPORT void fl_set_object_lstyle( FL_OBJECT * obj,
                                     int         lstyle );

FL_EXPORT int fl_get_object_lstyle( FL_OBJECT * obj );

FL_EXPORT void fl_set_object_lcol( FL_OBJECT * ob,
								   FL_COLOR    lcol );

FL_EXPORT FL_COLOR fl_get_object_lcol( FL_OBJECT * obj );

FL_EXPORT unsigned int fl_set_object_return( FL_OBJECT    * ob,
											 unsigned int   when );

FL_EXPORT unsigned int fl_get_object_return( FL_OBJECT * ob );

FL_EXPORT void fl_set_object_lalign( FL_OBJECT * obj,
                                     int         align );

FL_EXPORT int fl_get_object_lalign( FL_OBJECT * obj );

FL_EXPORT void fl_set_object_shortcut( FL_OBJECT  * obj,
                                       const char * sstr,
                                       int          showit );

FL_EXPORT void fl_set_object_shortcutkey( FL_OBJECT    * obj,
                                          unsigned int   keysym );

FL_EXPORT void fl_set_object_dblbuffer( FL_OBJECT * ob,
                                        int         y );

FL_EXPORT void fl_set_object_color( FL_OBJECT * ob,
                                    FL_COLOR    col1,
                                    FL_COLOR    col2 );

FL_EXPORT void fl_get_object_color( FL_OBJECT * obj,
									FL_COLOR  * col1,
									FL_COLOR  * col2 );

FL_EXPORT void fl_set_object_label( FL_OBJECT  * ob,
                                    const char * label );

FL_EXPORT void fl_set_object_label_f( FL_OBJECT  * obj,
									  const char * fmt,
									  ... );

FL_EXPORT const char * fl_get_object_label( FL_OBJECT * obj );

FL_EXPORT void fl_set_object_helper( FL_OBJECT  * ob,
                                     const char * tip );

FL_EXPORT void fl_set_object_helper_f( FL_OBJECT  * ob,
									   const char * fmt,
									   ... );

FL_EXPORT void fl_set_object_position( FL_OBJECT * obj,
                                       FL_Coord    x,
                                       FL_Coord    y );

FL_EXPORT void fl_get_object_size( FL_OBJECT * obj,
                                   FL_Coord  * w,
                                   FL_Coord  * h );

FL_EXPORT void fl_set_object_size( FL_OBJECT * obj,
                                   FL_Coord    w,
                                   FL_Coord    h );

FL_EXPORT void fl_set_object_automatic( FL_OBJECT * obj,
                                        int         flag );

FL_EXPORT int fl_object_is_automatic( FL_OBJECT * obj );

FL_EXPORT void fl_draw_object_label( FL_OBJECT * ob );

FL_EXPORT void fl_draw_object_label_outside( FL_OBJECT * ob );

FL_EXPORT FL_OBJECT * fl_get_object_component( FL_OBJECT * composite,
                                               int          objclass,
                                               int          type,
                                               int          numb );

FL_EXPORT void fl_for_all_objects( FL_FORM * form,
                                   int       ( * cb )( FL_OBJECT *, void * ),
                                   void    * v );

#define fl_draw_object_outside_label fl_draw_object_label_outside

FL_EXPORT void fl_set_object_dblclick( FL_OBJECT     * obj,
									   unsigned long   timeout );

FL_EXPORT unsigned long fl_get_object_dblclick( FL_OBJECT * obj );

FL_EXPORT void fl_set_object_geometry( FL_OBJECT * obj,
                                       FL_Coord    x,
                                       FL_Coord    y,
                                       FL_Coord    w,
                                       FL_Coord    h );

FL_EXPORT void fl_move_object( FL_OBJECT * obj,
                               FL_Coord    dx,
                               FL_Coord    dy );

#define fl_set_object_lcolor  fl_set_object_lcol
#define fl_get_object_lcolor  fl_get_object_lcol

FL_EXPORT void fl_fit_object_label( FL_OBJECT * obj,
                                    FL_Coord    xmargin,
                                    FL_Coord    ymargin );

FL_EXPORT void fl_get_object_geometry( FL_OBJECT * ob,
                                       FL_Coord  *  x,
                                       FL_Coord  *  y,
                                       FL_Coord  *  w,
                                       FL_Coord  *  h );

FL_EXPORT void fl_get_object_position( FL_OBJECT * ob,
                                       FL_Coord  * x,
                                       FL_Coord  * y );

/* This one takes into account the label */

FL_EXPORT void fl_get_object_bbox( FL_OBJECT * obj,
                                   FL_Coord  * x,
                                   FL_Coord  * y,
                                   FL_Coord  * w,
                                   FL_Coord  * h );

#define fl_compute_object_geometry   fl_get_object_bbox

FL_EXPORT void fl_call_object_callback( FL_OBJECT * ob );

FL_EXPORT FL_HANDLEPTR fl_set_object_prehandler( FL_OBJECT    * ob,
                                                 FL_HANDLEPTR   phandler );

FL_EXPORT FL_HANDLEPTR fl_set_object_posthandler( FL_OBJECT    * ob,
                                                  FL_HANDLEPTR   post );

FL_EXPORT FL_CALLBACKPTR fl_set_object_callback( FL_OBJECT      * obj,
                                                 FL_CALLBACKPTR   callback,
                                                 long             argument );

#define fl_set_object_align   fl_set_object_lalign
#define fl_set_call_back      fl_set_object_callback

FL_EXPORT void fl_redraw_object( FL_OBJECT * obj );

FL_EXPORT void fl_show_object( FL_OBJECT * ob );

FL_EXPORT void fl_hide_object( FL_OBJECT * ob );

FL_EXPORT int fl_object_is_visible( FL_OBJECT * obj );

FL_EXPORT void fl_free_object( FL_OBJECT * obj );

FL_EXPORT void fl_delete_object( FL_OBJECT * obj );

FL_EXPORT int fl_get_object_return_state( FL_OBJECT *obj );

FL_EXPORT void fl_trigger_object( FL_OBJECT * obj );

FL_EXPORT void fl_activate_object( FL_OBJECT * ob );

FL_EXPORT void fl_deactivate_object( FL_OBJECT * ob );

FL_EXPORT int fl_object_is_active( FL_OBJECT * obj );

FL_EXPORT int fl_enumerate_fonts( void ( * output )( const char * s ),
                                  int  shortform );

FL_EXPORT int fl_set_font_name( int          n,
                                const char * name );

FL_EXPORT int fl_set_font_name_f( int          n,
								  const char * fmt,
								  ... );

FL_EXPORT const char * fl_get_font_name( int n );

FL_EXPORT void fl_set_font( int numb,
                            int size );

/* Routines that facilitate free object */

FL_EXPORT int fl_get_char_height( int   style,
                                  int   size,
                                  int * asc,
                                  int * desc );

FL_EXPORT int fl_get_char_width( int style,
                                 int size );

FL_EXPORT int fl_get_string_height( int          style,
                                    int          size,
                                    const char * s,
                                    int          len,
                                    int        * asc,
                                    int        * desc );

FL_EXPORT int fl_get_string_width( int          style,
                                   int          size,
                                   const char * s,
                                   int          len );

FL_EXPORT int fl_get_string_widthTAB( int          style,
                                      int          size,
                                      const char * s,
                                      int          len );

FL_EXPORT void fl_get_string_dimension( int          fntstyle,
                                        int          fntsize,
                                        const char * s,
                                        int          len,
                                        int        * width,
                                        int        * height );

#define fl_get_string_size  fl_get_string_dimension

FL_EXPORT void fl_get_align_xy( int   align,
                                int   x,
                                int   y,
                                int   w,
                                int   h,
                                int   xsize,
                                int   ysize,
                                int   xoff,
                                int   yoff,
                                int * xx,
                                int * yy );

FL_EXPORT int fl_get_label_char_at_mouse( FL_OBJECT * obj );

#define fl_drw_text fl_draw_text
FL_EXPORT void fl_draw_text( int          align,
							 FL_Coord     x,
							 FL_Coord     y,
							 FL_Coord     w,
							 FL_Coord     h,
							 FL_COLOR     c,
							 int          style,
							 int          size,
							 const char * istr );

#define fl_drw_text_beside fl_draw_text_beside
FL_EXPORT void fl_draw_text_beside( int          align,
									FL_Coord     x,
									FL_Coord     y,
									FL_Coord     w,
									FL_Coord     h,
									FL_COLOR     c,
									int          style,
									int          size,
									const char * str );

#define fl_drw_text_cursor fl_draw_text_cursor
FL_EXPORT void fl_draw_text_cursor( int          align,
									FL_Coord     x,
									FL_Coord     y,
									FL_Coord     w,
									FL_Coord     h,
									FL_COLOR     c,
									int          style,
									int          size,
									const char * str,
									FL_COLOR     cc,
									int          pos );

#define fl_drw_box fl_draw_box
FL_EXPORT void fl_draw_box( int      style,
							FL_Coord x,
							FL_Coord y,
							FL_Coord w,
							FL_Coord h,
							FL_COLOR c,
							int      bw_in );

typedef void ( * FL_DRAWPTR )( FL_Coord,
                               FL_Coord,
                               FL_Coord,
                               FL_Coord,
                               int,
                               FL_COLOR);

FL_EXPORT int fl_add_symbol( const char * name,
                             FL_DRAWPTR   drawit,
                             int          scalable );

FL_EXPORT int fl_delete_symbol( const char * name );

FL_EXPORT int fl_draw_symbol( const char * label,
                              FL_Coord     x,
                              FL_Coord     y,
                              FL_Coord     w,
                              FL_Coord     h,
                              FL_COLOR     col );

FL_EXPORT unsigned long fl_mapcolor( FL_COLOR col,
                                     int      r,
                                     int      g,
                                     int      b );

FL_EXPORT long fl_mapcolorname( FL_COLOR     col,
                                const char * name );

#define fl_mapcolor_name  fl_mapcolorname

FL_EXPORT void fl_free_colors( FL_COLOR * c,
                               int        n );

FL_EXPORT void fl_free_pixels( unsigned long * pix,
                               int             n );

FL_EXPORT void fl_set_color_leak( int y );

FL_EXPORT unsigned long fl_getmcolor( FL_COLOR   i,
                                      int      * r,
                                      int      * g,
                                      int      * b );

FL_EXPORT unsigned long fl_get_pixel( FL_COLOR col );

#define fl_get_flcolor   fl_get_pixel

FL_EXPORT void fl_get_icm_color( FL_COLOR   col,
                                 int      * r,
                                 int      * g,
                                 int      * b );

FL_EXPORT void fl_set_icm_color( FL_COLOR col,
                                 int      r,
                                 int      g,
                                 int      b );

FL_EXPORT void fl_color( FL_COLOR col );

FL_EXPORT void fl_bk_color( FL_COLOR col );

FL_EXPORT void fl_set_gamma( double r,
                             double g,
                             double b );

FL_EXPORT void fl_show_errors( int y );

/* Some macros */

#define FL_max( a, b )            ( ( a ) > ( b ) ? ( a ) : ( b ) )
#define FL_min( a, b )            ( ( a ) < ( b ) ? ( a ) : ( b ) )
#define FL_abs( a )               ( ( a ) > 0 ? ( a ) : ( - ( a ) ) )
#define FL_nint( a )              ( ( int ) ( ( a ) > 0 ?               \
                                              ( ( a ) + 0.5 ) :         \
                                              ( ( a ) - 0.5 ) ) )
#define FL_nlong( a )             ( ( long ) ( ( a ) > 0 ?              \
                                               ( ( a ) + 0.5 ) :        \
                                               ( ( a ) - 0.5 ) ) )
#define FL_clamp( a, amin, amax ) ( ( a ) < ( amin ) ?                  \
                                    ( amin ) : ( ( a ) > ( amax ) ?     \
                                                 ( amax ) : ( a ) ) )
#define FL_crnd( a )              ( ( FL_Coord ) ( ( a ) > 0 ?          \
                                                   ( ( a ) + 0.5 ) :    \
                                                   ( ( a ) - 0.5 ) ) )

typedef int ( * FL_FSCB )( const char *,
                           void * );

/* Utilities for new objects */

FL_EXPORT FL_FORM *fl_current_form;

FL_EXPORT void fl_add_object( FL_FORM   * form,
                              FL_OBJECT * obj );

FL_EXPORT FL_FORM *fl_addto_form( FL_FORM * form );

FL_EXPORT FL_OBJECT * fl_make_object( int            objclass,
                                      int            type,
                                      FL_Coord       x,
                                      FL_Coord       y,
                                      FL_Coord       w,
                                      FL_Coord       h,
                                      const char   * label,
                                      FL_HANDLEPTR   handle );

FL_EXPORT void fl_add_child( FL_OBJECT *,
                             FL_OBJECT * );

FL_EXPORT void fl_set_coordunit( int u );

FL_EXPORT void fl_set_border_width( int bw );

FL_EXPORT void fl_set_scrollbar_type( int t );

#define fl_set_thinscrollbar( t )                                        \
    fl_set_scrollbar_type( t ? FL_THIN_SCROLLBAR : FL_NORMAL_SCROLLBAR )

FL_EXPORT void fl_flip_yorigin( void );

FL_EXPORT int fl_get_coordunit( void );

FL_EXPORT int fl_get_border_width( void );

/* Misc. routines */

FL_EXPORT void fl_ringbell( int percent );

FL_EXPORT void fl_gettime( long * sec,
                           long * usec );

FL_EXPORT const char * fl_now( void );

FL_EXPORT const char * fl_whoami( void );

FL_EXPORT long fl_mouse_button( void );

FL_EXPORT int fl_current_event( void );

FL_EXPORT char * fl_strdup( const char * s );

FL_EXPORT void fl_set_err_logfp( FILE * fp );

FL_EXPORT void fl_set_error_handler( FL_ERROR_FUNC user_func );

FL_EXPORT char ** fl_get_cmdline_args( int * );

/* This function was called 'fl_set_error_logfp/' in XForms 0.89. */

#define fl_set_error_logfp fl_set_err_logfp

#define fl_mousebutton fl_mouse_button

/* These give more flexibility for future changes. Also application
 * can re-assign these pointers to whatever function it wants, e.g.,
 * to a shared memory pool allocator. */

FL_EXPORT void ( * fl_free )( void * );

FL_EXPORT void * ( * fl_malloc )( size_t );

FL_EXPORT void * ( * fl_calloc )( size_t,
                                  size_t );

FL_EXPORT void * ( * fl_realloc )( void *,
                                   size_t );

FL_EXPORT int fl_msleep( unsigned long msec );

#define FL_MAX_MENU_CHOICE_ITEMS   128

typedef const char * ( * FL_VAL_FILTER )( FL_OBJECT *,
                                          double,
                                          int );

FL_EXPORT int fl_is_same_object( FL_OBJECT * obj1,
								 FL_OBJECT * obj2 );

#endif /* ! defined FL_BASIC_H */


/**
 * \file XBasic.h
 *
 *  X Window dependent stuff
 *
 */

#ifndef FL_XBASIC_H
#define FL_XBASIC_H

/* Draw mode */

enum {
    FL_XOR  = GXxor,
    FL_COPY = GXcopy,
    FL_AND  = GXand
};

#define FL_MINDEPTH  1


/* FL_xxx does not do anything anymore, but kept for compatibility */

enum {
    FL_IllegalVisual = -1,
    FL_StaticGray    = StaticGray,
    FL_GrayScale     = GrayScale,
    FL_StaticColor   = StaticColor,
    FL_PseudoColor   = PseudoColor,
    FL_TrueColor     = TrueColor,
    FL_DirectColor   = DirectColor,
    FL_DefaultVisual = 10         /* special request */
};


enum {
    FL_North         = NorthGravity,
    FL_NorthEast     = NorthEastGravity,
    FL_NorthWest     = NorthWestGravity,
    FL_South         = SouthGravity,
    FL_SouthEast     = SouthEastGravity,
    FL_SouthWest     = SouthWestGravity,
    FL_East          = EastGravity,
    FL_West          = WestGravity,
    FL_NoGravity     = ForgetGravity,
    FL_ForgetGravity = ForgetGravity
};

#ifndef GreyScale
#define GreyScale   GrayScale
#define StaticGrey  StaticGray
#endif

#define FL_is_gray( v )  ( ( v ) == GrayScale || ( v ) == StaticGray )
#define FL_is_rgb( v )   ( ( v ) == TrueColor || ( v ) == DirectColor )


/* Internal colormap size. Not really very meaningful as fl_mapcolor
 * and company allow color "leakage", that is, although only FL_MAX_COLS
 * are kept in the internal colormap, the server might have substantially
 * more colors allocated */

#define FL_MAX_COLORS   1024
#define FL_MAX_COLS     FL_MAX_COLORS


/* FL graphics state information. Some are redundant. */

typedef struct {
    XVisualInfo   * xvinfo;
    XFontStruct   * cur_fnt;            /* current font in default GC */
    Colormap        colormap;           /* colormap valid for xvinfo */
    Window          trailblazer;        /* a valid window for xvinfo */
    int             vclass,             /* visual class and color depth */
                    depth;
    int             rgb_bits;           /* primary color resolution */
    int             dithered;           /* true if dithered color */
    int             pcm;                /* true if colormap is not shared */
    GC              gc[ 16 ];           /* working GC */
    GC              textgc[ 16 ];       /* GC used exclusively for text */
    GC              dimmedGC;           /* A GC having a checkboard stipple */
    unsigned long   lut[ FL_MAX_COLS ]; /* secondary lookup table */
    unsigned int    rshift,
                    rmask,
                    rbits;
    unsigned int    gshift,
                    gmask,
                    gbits;
    unsigned int    bshift,
                    bmask,
                    bbits;
} FL_State;

#define FL_STATE FL_State    /* for compatibility */


/***** Global variables ******/

FL_EXPORT Display *fl_display;

FL_EXPORT int fl_screen;

FL_EXPORT Window fl_root;   /* root window */
FL_EXPORT Window fl_vroot;  /* virtual root window */
FL_EXPORT int fl_scrh,      /* screen dimension in pixels */
              fl_scrw;
FL_EXPORT int fl_vmode;

#define fl_visual    ( fl_state[ fl_vmode ].xvinfo->visual )
#define fl_colormap  ( fl_state[ fl_vmode ].colormap )

#define fl_get_visual( )    ( fl_state[ fl_vmode ].xvinfo->visual )
#define fl_get_colormap( )  ( fl_state[ fl_vmode ].colormap )


/* Current version only runs in single visual mode */

#define  fl_get_vclass( )          fl_vmode
#define  fl_get_form_vclass( a )   fl_vmode
#define  fl_get_gc( )              fl_state[ fl_vmode ].gc[ 0 ]

FL_EXPORT FL_State fl_state[ ];

FL_EXPORT char *fl_ul_magic_char;

FL_EXPORT double fl_dpi;
#define fl_get_dpi( ) ( fl_dpi )

FL_EXPORT int fl_mode_capable( int mode,
                               int warn );


#define fl_default_win( )       ( fl_state[ fl_vmode ].trailblazer )
#define fl_default_window( )    ( fl_state[ fl_vmode ].trailblazer )


/* All pixmaps used by FL_OBJECT to simulate double buffering have the
 * following entries in the structure. FL_Coord x,y are used to shift
 * the origin of the drawing routines */

struct FL_pixmap_ {
    Pixmap         pixmap;
    Window         win;
    Visual       * visual;
    FL_Coord       x,
                   y,
                   w,
                   h;
    int            depth;
    FL_COLOR       dbl_background;
    FL_COLOR       pixel;
};


/* Fonts related */

#define FL_MAX_FONTSIZES         10
#define FL_MAX_FONTNAME_LENGTH   80

typedef struct {
    XFontStruct * fs[ FL_MAX_FONTSIZES ];               /* cached fontstruct */
    short         size[ FL_MAX_FONTSIZES ];             /* cached sizes */
    short         nsize;                                /* cached so far */
    char          fname[ FL_MAX_FONTNAME_LENGTH + 1 ];  /* without size info */
} FL_FONT;

/* Some basic drawing routines */

typedef XPoint      FL_POINT;
typedef XRectangle  FL_RECT;

/* Rectangles */

FL_EXPORT void fl_rectangle( int      fill,
                             FL_Coord x,
                             FL_Coord y,
                             FL_Coord w,
                             FL_Coord h,
                             FL_COLOR col );

FL_EXPORT void fl_rectbound( FL_Coord x,
                             FL_Coord y,
                             FL_Coord w,
                             FL_Coord h,
                             FL_COLOR col );

#define fl_rectf( x, y, w, h, c)   fl_rectangle( 1, x, y, w, h, c )
#define fl_rect( x, y, w, h, c )   fl_rectangle( 0, x, y, w, h, c )

/* Rectangle with rounded-corners */

FL_EXPORT void fl_roundrectangle( int      fill,
                                  FL_Coord x,
                                  FL_Coord y,
                                  FL_Coord w,
                                  FL_Coord h,
                                  FL_COLOR col );

#define fl_roundrectf( x, y, w, h, c )  fl_roundrectangle( 1, x, y, w, h, c )
#define fl_roundrect( x, y, w, h, c )   fl_roundrectangle( 0, x, y, w, h, c )

/* General polygon and polylines */

FL_EXPORT void fl_polygon( int        fill,
                           FL_POINT * xp,
                           int        n,
                           FL_COLOR   col );

#define fl_polyf( p, n, c )       fl_polygon( 1, p, n, c )
#define fl_polyl( p, n, c )       fl_polygon( 0, p, n, c )

#define fl_polybound( p, n, c )               \
    do { fl_polygon( 1, p, n, c );            \
         fl_polygon( 0, p, n, FL_BLACK );     \
       } while( 0 )

FL_EXPORT void fl_lines( FL_POINT * xp,
                         int        n,
                         FL_COLOR   col );

FL_EXPORT void fl_line( FL_Coord xi,
                        FL_Coord yi,
                        FL_Coord xf,
                        FL_Coord yf,
                        FL_COLOR c );

FL_EXPORT void fl_point( FL_Coord x,
                         FL_Coord y,
                         FL_COLOR c );

FL_EXPORT void fl_points( FL_POINT * p,
                          int        np,
                          FL_COLOR   c );

#define fl_simple_line fl_line

FL_EXPORT void fl_dashedlinestyle( const char * dash,
                                   int          ndash );

FL_EXPORT void fl_update_display( int block );


#define fl_diagline( x, y, w, h, c )                                          \
    do                                                                        \
    {                                                                         \
        FL_COORD fli_x = ( x ), fli_y = ( y );                                \
        fl_line( fli_x, fli_y, fli_x + ( w ) - 1, fli_y + ( h ) - 1, ( c ) ); \
    } while ( 0 )

/* Line attributes */

enum {
    FL_SOLID          = LineSolid,
    FL_USERDASH       = LineOnOffDash,
    FL_USERDOUBLEDASH = LineDoubleDash,
    FL_DOT,
    FL_DOTDASH,
    FL_DASH,
    FL_LONGDASH
};

FL_EXPORT void fl_linewidth( int n );

FL_EXPORT void fl_linestyle( int n );

FL_EXPORT void fl_drawmode( int request );

FL_EXPORT int fl_get_linewidth( void );

FL_EXPORT int fl_get_linestyle( void );

FL_EXPORT int fl_get_drawmode( void );

#define fl_set_linewidth    fl_linewidth
#define fl_set_linestyle    fl_linestyle
#define fl_set_drawmode     fl_drawmode

/** Ellipses **/

FL_EXPORT void fl_circ( FL_COORD x,
                        FL_COORD y,
                        FL_COORD r,
                        FL_COLOR col );

FL_EXPORT void fl_circf( FL_COORD x,
                         FL_COORD y,
                         FL_COORD r,
                         FL_COLOR col );

FL_EXPORT void fl_circbound( FL_COORD x,
                             FL_COORD y,
                             FL_COORD r,
                             FL_COLOR col );

FL_EXPORT void fl_oval( int      fill,
                        FL_Coord x,
                        FL_Coord y,
                        FL_Coord w,
                        FL_Coord h,
                        FL_COLOR col );

FL_EXPORT void fl_ovalbound( FL_Coord x,
                             FL_Coord y,
                             FL_Coord w,
                             FL_Coord h,
                             FL_COLOR col );

FL_EXPORT void fl_ovalarc( int      fill,
                           FL_Coord x,
                           FL_Coord y,
                           FL_Coord w,
                           FL_Coord h,
                           int      t0,
                           int      dt,
                           FL_COLOR col );

#define fl_ovalf( x, y, w, h, c )     fl_oval( 1, x, y, w, h, c )
#define fl_ovall( x, y, w, h, c )     fl_oval( 0, x, y, w, h, c )
#define fl_oval_bound                 fl_ovalbound

/* Arcs */

FL_EXPORT void fl_arcf( FL_COORD x,
                        FL_Coord y,
                        FL_COORD r,
                        int      a1,
                        int      a2,
                        FL_COLOR col );

FL_EXPORT void fl_arc( FL_COORD x,
                       FL_Coord y,
                       FL_COORD r,
                       int      a1,
                       int      a2,
                       FL_COLOR col );

FL_EXPORT void fl_pieslice( int      fill,
                            FL_Coord x,
                            FL_Coord y,
                            FL_Coord w,
                            FL_Coord h,
                            int      a1,
                            int      a2,
                            FL_COLOR col );

/* High level drawing routines */

#define fl_drw_frame fl_draw_frame
FL_EXPORT void fl_draw_frame( int      style,
                              FL_Coord x,
                              FL_Coord y,
                              FL_Coord w,
                              FL_Coord h,
                              FL_COLOR c,
                              int      bw );

/*
 * Interfaces
 */

FL_EXPORT XFontStruct *fl_get_fontstruct( int style,
                                          int size );

#define fl_get_font_struct    fl_get_fontstruct
#define fl_get_fntstruct      fl_get_font_struct

FL_EXPORT Window fl_get_mouse( FL_Coord  * x,
                               FL_Coord  * y,
                               unsigned int * keymask );

FL_EXPORT void fl_set_mouse( FL_Coord mx,
                             FL_Coord my );

FL_EXPORT Window fl_get_win_mouse( Window         win,
                                   FL_Coord     * x,
                                   FL_Coord     * y,
                                   unsigned int * keymask );

FL_EXPORT Window fl_get_form_mouse( FL_FORM      * fm,
                                    FL_Coord     * x,
                                    FL_Coord     * y,
                                    unsigned int * keymask );

FL_EXPORT FL_FORM * fl_win_to_form( Window win );

FL_EXPORT void fl_set_form_icon( FL_FORM * form,
                                 Pixmap   p,
                                 Pixmap   m );

FL_EXPORT int fl_get_decoration_sizes( FL_FORM * form,
                                       int     * top,
                                       int     * right,
                                       int     * bottom,
                                       int     * left );

FL_EXPORT void fl_raise_form( FL_FORM * form );

FL_EXPORT void fl_lower_form( FL_FORM * form );

FL_EXPORT void fl_set_foreground( GC       gc,
                                  FL_COLOR color );
FL_EXPORT void fl_set_background( GC       gc,
                                  FL_COLOR color );

/* General windowing support */

FL_EXPORT Window fl_wincreate( const char * label );

FL_EXPORT Window fl_winshow( Window win );

FL_EXPORT Window fl_winopen( const char * label );

FL_EXPORT void fl_winhide( Window win );

FL_EXPORT void fl_winclose( Window win );

FL_EXPORT void fl_winset( Window win );

FL_EXPORT int fl_winreparent( Window win,
                              Window new_parent );

FL_EXPORT void fl_winfocus( Window win );

FL_EXPORT Window fl_winget( void );

FL_EXPORT int fl_iconify( Window win );

FL_EXPORT void fl_winresize( Window   win,
                             FL_Coord neww,
                             FL_Coord newh );

FL_EXPORT void fl_winmove( Window   win,
                           FL_Coord dx,
                           FL_Coord dy );

FL_EXPORT void fl_winreshape( Window   win,
                              FL_Coord dx,
                              FL_Coord dy,
                              FL_Coord w,
                              FL_Coord h );

FL_EXPORT void fl_winicon( Window win,
                           Pixmap p,
                           Pixmap m );

FL_EXPORT void fl_winbackground( Window        win,
                                 unsigned long bk );

FL_EXPORT void fl_winstepsize( Window   win,
                               FL_Coord dx,
                               FL_Coord dy );

FL_EXPORT int fl_winisvalid( Window win );

FL_EXPORT void fl_wintitle( Window       win,
                            const char * title );

FL_EXPORT void fl_wintitle_f( Window       win,
                              const char * fmt,
                              ... );

FL_EXPORT void fl_winicontitle( Window       win,
                                const char * title );

FL_EXPORT void fl_winicontitle_f( Window       win,
                                  const char * fmt,
                                  ... );

FL_EXPORT void fl_winposition( FL_Coord x,
                               FL_Coord y );

#define fl_pref_winposition   fl_winposition
#define fl_win_background     fl_winbackground
#define fl_winstepunit        fl_winstepsize
#define fl_set_winstepunit    fl_winstepsize

FL_EXPORT void fl_winminsize( Window   win,
                              FL_Coord w,
                              FL_Coord h );

FL_EXPORT void fl_winmaxsize( Window   win,
                              FL_Coord w,
                              FL_Coord h );

FL_EXPORT void fl_winaspect( Window   win,
                             FL_Coord x,
                             FL_Coord y );

FL_EXPORT void fl_reset_winconstraints( Window win );


FL_EXPORT void fl_winsize( FL_Coord w,
                           FL_Coord h );

FL_EXPORT void fl_initial_winsize( FL_Coord w,
                                   FL_Coord h );

#define fl_pref_winsize  fl_winsize

FL_EXPORT void fl_initial_winstate( int state );

FL_EXPORT Colormap fl_create_colormap( XVisualInfo * xv,
                                       int           nfill );



FL_EXPORT void fl_wingeometry( FL_Coord x,
                               FL_Coord y,
                               FL_Coord w,
                               FL_Coord h );

#define fl_pref_wingeometry  fl_wingeometry

FL_EXPORT void fl_initial_wingeometry( FL_Coord x,
                                       FL_Coord y,
                                       FL_Coord w,
                                       FL_Coord h );

FL_EXPORT void fl_noborder( void );

FL_EXPORT void fl_transient( void );

FL_EXPORT void fl_get_winsize( Window     win,
                               FL_Coord * w,
                               FL_Coord * h );

FL_EXPORT void fl_get_winorigin( Window     win,
                                 FL_Coord * x,
                                 FL_Coord * y );

FL_EXPORT void fl_get_wingeometry( Window     win,
                                   FL_Coord * x,
                                   FL_Coord * y,
                                   FL_Coord * w,
                                   FL_Coord * h );

/* For compatibility */

#define fl_get_win_size          fl_get_winsize
#define fl_get_win_origin        fl_get_winorigin
#define fl_get_win_geometry      fl_get_wingeometry
#define fl_initial_winposition   fl_pref_winposition

#define fl_get_display( )            fl_display
#define FL_FormDisplay( form )       fl_display
#define FL_ObjectDisplay( object )   fl_display
#define FL_IS_CANVAS( o )   \
    ( ( o )->objclass == FL_CANVAS || ( o )->objclass == FL_GLCANVAS )

/* The window an object belongs to - for drawing */

#define FL_ObjWin( o )   \
    ( FL_IS_CANVAS( o ) ? fl_get_canvas_id( o ) : ( o )->form->window )


FL_EXPORT Window fl_get_real_object_window( FL_OBJECT * ob );

#define FL_OBJECT_WID  FL_ObjWin

/*  All registerable events, including Client Message */

#define FL_ALL_EVENT  (   KeyPressMask       \
                        | KeyReleaseMask     \
                        | ButtonPressMask    \
                        | ButtonReleaseMask  \
                        | EnterWindowMask    \
                        | LeaveWindowMask    \
                        | ButtonMotionMask   \
                        | PointerMotionMask )


/* Replacements for X functions that access the event queue */

FL_EXPORT int fl_XNextEvent( XEvent * xev );

FL_EXPORT int fl_XPeekEvent( XEvent * xev );

FL_EXPORT int fl_XEventsQueued( int mode );

FL_EXPORT void fl_XPutBackEvent( XEvent * xev );

FL_EXPORT const XEvent *fl_last_event( void );

typedef int ( * FL_APPEVENT_CB )( XEvent *, void * );

FL_EXPORT FL_APPEVENT_CB fl_set_event_callback( FL_APPEVENT_CB   callback,
                                                void           * user_data );

FL_EXPORT FL_APPEVENT_CB fl_set_idle_callback( FL_APPEVENT_CB   callback,
                                               void           * user_data );

FL_EXPORT long fl_addto_selected_xevent( Window win,
                                         long   mask );

FL_EXPORT long fl_remove_selected_xevent( Window win,
                                          long   mask );

#define fl_add_selected_xevent  fl_addto_selected_xevent

FL_EXPORT void fl_set_idle_delta( long delta );

FL_EXPORT FL_APPEVENT_CB fl_add_event_callback( Window           win,
                                                int              ev,
                                                FL_APPEVENT_CB   wincb,
                                                void           * user_data );

FL_EXPORT void fl_remove_event_callback( Window win,
                                         int    ev );

FL_EXPORT void fl_activate_event_callbacks( Window win );

FL_EXPORT XEvent *fl_print_xevent_name( const char   * where,
                                        const XEvent * xev );

FL_EXPORT void fl_XFlush( void );

#define metakey_down( mask )     ( ( mask ) & Mod1Mask )
#define shiftkey_down( mask )    ( ( mask ) & ShiftMask )
#define controlkey_down( mask )  ( ( mask ) & ControlMask )
#define button_down( mask )      (    ( ( mask ) & Button1Mask )  \
                                   || ( ( mask ) & Button2Mask )  \
                                   || ( ( mask ) & Button3Mask )  \
                                   || ( ( mask ) & Button4Mask )  \
                                   || ( ( mask ) & Button5Mask ) )

#define fl_keypressed            fl_keysym_pressed

/****************** Resources ***************/

typedef enum {
    FL_NONE,
    FL_SHORT = 10,
    FL_BOOL,
    FL_INT,
    FL_LONG,
    FL_FLOAT,
    FL_STRING
} FL_RTYPE;

typedef struct {
    const char * res_name;      /* resource name                        */
    const char * res_class;     /* resource class                       */
    FL_RTYPE     type;          /* FL_INT, FL_FLOAT, FL_BOOL, FL_STRING */
    void       * var;           /* address for the variable             */
    const char * defval;        /* default setting in string form       */
    int          nbytes;        /* used only for strings                */
} FL_RESOURCE;

#define FL_resource FL_RESOURCE

#define FL_CMD_OPT   XrmOptionDescRec

FL_EXPORT Display * fl_initialize( int        * na,
                                   char       * arg[ ],
                                   const char * appclass,
                                   FL_CMD_OPT * appopt,
                                   int          nappopt );

FL_EXPORT void fl_finish( void );

FL_EXPORT const char * fl_get_resource( const char * rname,
                                        const char * cname,
                                        FL_RTYPE     dtype,
                                        const char * defval,
                                        void       * val,
                                        int          size );

FL_EXPORT void fl_set_resource( const char * str,
                                const char * val );

FL_EXPORT void fl_get_app_resources( FL_RESOURCE * appresource,
                                     int           n );

FL_EXPORT void fl_set_visualID( long id );

FL_EXPORT int fl_keysym_pressed( KeySym k );

#define buttonLabelSize  buttonFontSize
#define sliderLabelSize  sliderFontSize
#define inputLabelSize   inputFontSize

/* All Form control variables. Named closely as its resource name */

typedef struct {
    float  rgamma,
           ggamma,
           bgamma;
    int    debug,
           sync;
    int    depth,
           vclass,
           doubleBuffer;
    int    ulPropWidth,         /* underline stuff       */
           ulThickness;
    int    buttonFontSize;
    int    sliderFontSize;
    int    inputFontSize;
    int    browserFontSize;
    int    menuFontSize;
    int    choiceFontSize;
    int    labelFontSize;       /* all other labels fonts */
    int    pupFontSize,         /* font for pop-up menus  */
           pupFontStyle;
    int    privateColormap;
    int    sharedColormap;
    int    standardColormap;
    int    scrollbarType;
    int    backingStore;
    int    coordUnit;
    int    borderWidth;
    int    safe;
    char * rgbfile;             /* where RGB file is, not used */
    char   vname[ 24 ];
} FL_IOPT;

#define FL_PDButtonLabelSize  FL_PDButtonFontSize
#define FL_PDSliderLabelSize  FL_PDSliderFontSize
#define FL_PDInputLabelSize   FL_PDInputFontSize

/* Program default masks */

enum {
    FL_PDDepth           = ( 1 <<  1 ),
    FL_PDClass           = ( 1 <<  2 ),
    FL_PDDouble          = ( 1 <<  3 ),
    FL_PDSync            = ( 1 <<  4 ),
    FL_PDPrivateMap      = ( 1 <<  5 ),
    FL_PDScrollbarType   = ( 1 <<  6 ),
    FL_PDPupFontSize     = ( 1 <<  7 ),
    FL_PDButtonFontSize  = ( 1 <<  8 ),
    FL_PDInputFontSize   = ( 1 <<  9 ),
    FL_PDSliderFontSize  = ( 1 << 10 ),
    FL_PDVisual          = ( 1 << 11 ),
    FL_PDULThickness     = ( 1 << 12 ),
    FL_PDULPropWidth     = ( 1 << 13 ),
    FL_PDBS              = ( 1 << 14 ),
    FL_PDCoordUnit       = ( 1 << 15 ),
    FL_PDDebug           = ( 1 << 16 ),
    FL_PDSharedMap       = ( 1 << 17 ),
    FL_PDStandardMap     = ( 1 << 18 ),
    FL_PDBorderWidth     = ( 1 << 19 ),
    FL_PDSafe            = ( 1 << 20 ),
    FL_PDMenuFontSize    = ( 1 << 21 ),
    FL_PDBrowserFontSize = ( 1 << 22 ),
    FL_PDChoiceFontSize  = ( 1 << 23 ),
    FL_PDLabelFontSize   = ( 1 << 24 )
};

#define FL_PDButtonLabel   FL_PDButtonLabelSize

FL_EXPORT void fl_set_defaults( unsigned   long mask,
                                FL_IOPT  * cntl );

FL_EXPORT void fl_set_tabstop( const char * s );

FL_EXPORT int fl_get_visual_depth( void );

FL_EXPORT int fl_is_global_clipped( void );

FL_EXPORT int fl_is_clipped( int include_global );

FL_EXPORT int fl_is_text_clipped( int include_global );

FL_EXPORT void fl_set_clipping( FL_Coord x,
                                FL_Coord y,
                                FL_Coord w,
                                FL_Coord h );

FL_EXPORT void fl_unset_clipping( void );

FL_EXPORT void fl_set_text_clipping( FL_Coord x,
                                     FL_Coord y,
                                     FL_Coord w,
                                     FL_Coord h );

FL_EXPORT void fl_unset_text_clipping( void );

FL_EXPORT int fl_get_global_clipping( FL_COORD * x,
                                      FL_COORD * y,
                                      FL_COORD * w,
                                      FL_COORD * h );

FL_EXPORT int fl_get_clipping( int        include_global,
                               FL_COORD * x,
                               FL_COORD * y,
                               FL_COORD * w,
                               FL_COORD * h );

FL_EXPORT int fl_get_text_clipping( int        include_global,
                                    FL_COORD * x,
                                    FL_COORD * y,
                                    FL_COORD * w,
                                    FL_COORD * h );

FL_EXPORT void fl_set_gc_clipping( GC       gc,
                                   FL_Coord x,
                                   FL_Coord y,
                                   FL_Coord w,
                                   FL_Coord h );

FL_EXPORT void fl_unset_gc_clipping( GC gc );


/* How we pack and unpack colors */

#ifndef FL_PCBITS
typedef unsigned char     FL_PCTYPE;          /* primary color type */
#define FL_PCBITS         8                   /* primary color bits */
#define FL_PCMAX          ( ( 1 << FL_PCBITS ) - 1 )
#define FL_PCCLAMP( a )   \
    ( ( a ) > ( FL_PCMAX ) ? ( FL_PCMAX ) : ( ( a ) < 0 ? 0 : ( a ) ) )
typedef unsigned int       FL_PACKED4;
#define FL_PACKED          FL_PACKED4

#define FL_RMASK           0x000000ff
#define FL_RSHIFT          0
#define FL_GMASK           0x0000ff00
#define FL_GSHIFT          8
#define FL_BMASK           0x00ff0000
#define FL_BSHIFT          16
#define FL_AMASK           0xff000000
#define FL_ASHIFT          24

/* If PCBITS is not 8, we need to apply the RGBmask */

#define FL_GETR( packed )  ( ( ( packed ) >> FL_RSHIFT ) & FL_RMASK )
#define FL_GETG( packed )  ( ( ( packed ) >> FL_GSHIFT ) & FL_PCMAX )
#define FL_GETB( packed )  ( ( ( packed ) >> FL_BSHIFT ) & FL_PCMAX )
#define FL_GETA( packed )  ( ( ( packed ) >> FL_ASHIFT ) & FL_PCMAX )

#define FL_PACK3( r, g, b )   \
    ( ( ( r ) << FL_RSHIFT ) | ( ( g ) << FL_GSHIFT ) | ( ( b ) << FL_BSHIFT ) )

#define FL_PACK            FL_PACK3

#define FL_PACK4( r, g, b, a ) ( FL_PACK3( r, g, b ) | ( ( a ) << FL_ASHIFT ) )

#define FL_UNPACK( p, r, g, b )   \
    do { r = FL_GETR( p );        \
         g = FL_GETG( p );        \
         b = FL_GETB( p );        \
    } while( 0 )

#define FL_UNPACK3 FL_UNPACK

#define FL_UNPACK4( p, r, g, b, a )   \
    do { FL_UNPACK3( p, r, g, b );    \
         a = FL_GETA( p );            \
    } while( 0 )

#endif

typedef struct {
   unsigned int rshift,
                rmask,
                rbits;
   unsigned int gshift,
                gmask,
                gbits;
   unsigned int bshift,
                bmask,
                bbits;
   int          bits_per_rgb;
   int          colormap_size;
} FL_RGB2PIXEL_;

#define FL_RGB2PIXEL  FL_RGB2PIXEL_

#endif /* ! defined FL_XBASIC_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */


#ifndef FL_POPUP_H
#define FL_POPUP_H

typedef struct FL_POPUP_ FL_POPUP;
typedef struct FL_POPUP_ENTRY_ FL_POPUP_ENTRY;
typedef struct FL_POPUP_RETURN_ FL_POPUP_RETURN;

typedef int ( * FL_POPUP_CB )( FL_POPUP_RETURN * );

struct FL_POPUP_RETURN_ {
    long int               val;          /* value assigned to popup entry */
    void                 * user_data;    /* pointer to user data */
    const char           * text;         /* text of the selected popup entry */
    const char           * label;        /* left-flushed label part */
    const char           * accel;        /* right-flushed label part */
    const FL_POPUP_ENTRY * entry;        /* pointer to selected popup entry */
    const FL_POPUP       * popup;        /* popup we're called for */
};

struct FL_POPUP_ {
    FL_POPUP         * next;             /* next in linked list */
    FL_POPUP         * prev;             /* previous in linked list */
    FL_POPUP         * parent;           /* for sub-popups: direct parent */
    FL_POPUP         * top_parent;       /* and top-most parent */
    FL_POPUP_ENTRY   * entries;          /* pointer to list of entries */
    char             * title;
    Window             win;              /* popup window */
    Window             parent_win;       /* parent window of popup window */
    Cursor             cursor;           /* cursor for the popup */
    FL_POPUP_CB        callback;
    int                use_req_pos;      /* if set use req_x, req_y */
    int                req_x,
                       req_y;
    int                x,                /* position of popup window */
                       y;
    unsigned int       w,                /* dimensions of popup window */
                       h;
    int                min_width;        /* minimum width of popup */
    int                title_box_x,      /* position of title box */
                       title_box_y;
    unsigned int       title_box_w,      /* dimensions of title box */
                       title_box_h;
    int                has_subs,
                       has_boxes;
    int                counter;
    int                title_font_style;
    int                title_font_size;
    int                entry_font_style;
    int                entry_font_size;
    unsigned long      event_mask;
    int                bw;               /* border width */
    FL_COLOR           bg_color;         /* background color of popup*/
    FL_COLOR           on_color;         /* color of entry under mouse */
    FL_COLOR           title_color;      /* color of title text */
    FL_COLOR           text_color;       /* normal text color of entry */
    FL_COLOR           text_on_color;    /* text color when mouse on entry */
    FL_COLOR           text_off_color;   /* text color of disabled entry */
    FL_COLOR           radio_color;      /* color of radio buttons */
    int                policy;
    int                need_recalc;      /* do we need to recalc position? */
    FL_POPUP_RETURN    ret;              /* structure passed to calbacks
                                            and returned on selection */
};

struct FL_POPUP_ENTRY_ {
    FL_POPUP_ENTRY * prev;               /* next in linked list */
    FL_POPUP_ENTRY * next;               /* previous in linked list */
    FL_POPUP       * popup;              /* popup it belongs to */
    int              is_act;             /* set while mouse is over it */
    char           * text;               /* complete text of entry */
    char           * label;              /* cleaned-up label text */
    char           * accel;              /* cleaned-up accelerator key text */
    long int         val;                /* value associated with entry */
    void           * user_data;          /* pointer to user data */
    int              type;               /* normal, toggle, radio, sub-popup */
    unsigned int     state;              /* disabled, hidden, checked */
    int              group;              /* group (for radio entries only) */
    FL_POPUP       * sub;                /* sub-popup bound to entry */
    long int       * shortcut;           /* keyboard shortcuts */
    int              ulpos;              /* underline position in text */
    FL_POPUP_CB      callback;           /* callback for entry */
    FL_POPUP_CB      enter_callback;     /* callback for entering entry */
    FL_POPUP_CB      leave_callback;     /* callback for leaving entry */
    int              x,                  /* position of entry text */
                     y;
    unsigned int     w,
                     h;                  /* height of entry text */
    int              box_x,
                     box_y;
    unsigned int     box_w,
                     box_h;
    unsigned int     sl_h;
    int              ul_x,
                     ul_y;
    unsigned int     ul_w,
                     ul_h;
};

typedef struct {
    const char     * text;               /* text of entry */
    FL_POPUP_CB      callback;           /* (selection) callback */
    const char     * shortcut;           /* keyboard shortcut description */
    int              type;               /* type of entry */
    int              state;              /* disabled, hidden, checked */
} FL_POPUP_ITEM;

/* Popup policies */

enum {
    FL_POPUP_NORMAL_SELECT,
    FL_POPUP_DRAG_SELECT
};

/* Popup states */

enum {
    FL_POPUP_NONE     = 0,
    FL_POPUP_DISABLED = 1,               /* entry is disabled */
    FL_POPUP_HIDDEN   = 2,               /* entry is temporarily hidden */
    FL_POPUP_CHECKED  = 4                /* tooogle/radio item is in on state */
};

/* Popup entry types */

enum {
    FL_POPUP_NORMAL,                     /* normal popup entry */
    FL_POPUP_TOGGLE,                     /* toggle ("binary") popup entry */
    FL_POPUP_RADIO,                      /* radio popup entry */
    FL_POPUP_SUB,                        /* sub-popup popup entry */
    FL_POPUP_LINE                        /* line popup entry */
};

/* Popup color types */

enum {
    FL_POPUP_BACKGROUND_COLOR,
    FL_POPUP_HIGHLIGHT_COLOR,
    FL_POPUP_TITLE_COLOR,
    FL_POPUP_TEXT_COLOR,
    FL_POPUP_HIGHLIGHT_TEXT_COLOR,
    FL_POPUP_DISABLED_TEXT_COLOR,
    FL_POPUP_RADIO_COLOR
};

FL_EXPORT FL_POPUP *fl_popup_add( Window,
                                  const char * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_add_entries( FL_POPUP *,
                                                const char *,
                                                ... );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_insert_entries( FL_POPUP *,
                                                   FL_POPUP_ENTRY *,
                                                   const char *,
                                                   ... );

FL_EXPORT FL_POPUP *fl_popup_create( Window,
                                     const char *,
                                     FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_add_items( FL_POPUP      *,
											  FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_insert_items( FL_POPUP       *,
												 FL_POPUP_ENTRY *,
												 FL_POPUP_ITEM  * );

FL_EXPORT int fl_popup_delete( FL_POPUP * );

FL_EXPORT int fl_popup_entry_delete( FL_POPUP_ENTRY * );

FL_EXPORT FL_POPUP_RETURN *fl_popup_do( FL_POPUP * );

FL_EXPORT void fl_popup_set_position( FL_POPUP *,
                                      int,
                                      int );

FL_EXPORT int fl_popup_get_policy( FL_POPUP * );

FL_EXPORT int fl_popup_set_policy( FL_POPUP *,
                                   int );

FL_EXPORT FL_POPUP_CB fl_popup_set_callback( FL_POPUP *,
                                             FL_POPUP_CB );

FL_EXPORT void fl_popup_get_title_font( FL_POPUP *,
                                        int *,
                                        int * );

FL_EXPORT void fl_popup_set_title_font( FL_POPUP *,
                                        int,
                                        int );

FL_EXPORT void fl_popup_entry_get_font( FL_POPUP *,
                                        int *,
                                        int * );

FL_EXPORT void fl_popup_entry_set_font( FL_POPUP *,
                                        int,
                                        int );

FL_EXPORT int fl_popup_get_bw( FL_POPUP * );

FL_EXPORT int fl_popup_set_bw( FL_POPUP *,
                               int );

FL_EXPORT FL_COLOR fl_popup_get_color( FL_POPUP *,
                                       int );

FL_EXPORT FL_COLOR fl_popup_set_color( FL_POPUP *,
                                       int,
                                       FL_COLOR );

FL_EXPORT void fl_popup_set_cursor( FL_POPUP *,
                                    int );

FL_EXPORT const char *fl_popup_get_title( FL_POPUP   * );

FL_EXPORT FL_POPUP *fl_popup_set_title( FL_POPUP *,
                                        const char * );

FL_EXPORT FL_POPUP * fl_popup_set_title_f( FL_POPUP   * popup,
										   const char * fmt,
										   ... );

FL_EXPORT FL_POPUP_CB fl_popup_entry_set_callback( FL_POPUP_ENTRY *,
                                                   FL_POPUP_CB );

FL_EXPORT FL_POPUP_CB fl_popup_entry_set_enter_callback( FL_POPUP_ENTRY *,
                                                         FL_POPUP_CB );

FL_EXPORT FL_POPUP_CB fl_popup_entry_set_leave_callback( FL_POPUP_ENTRY *,
                                                         FL_POPUP_CB );

FL_EXPORT unsigned int fl_popup_entry_get_state( FL_POPUP_ENTRY * );

FL_EXPORT unsigned int fl_popup_entry_set_state( FL_POPUP_ENTRY *,
                                                 unsigned int );

FL_EXPORT unsigned int fl_popup_entry_clear_state( FL_POPUP_ENTRY *,
                                                   unsigned int );

FL_EXPORT unsigned int fl_popup_entry_raise_state( FL_POPUP_ENTRY *,
                                                   unsigned int );

FL_EXPORT unsigned int fl_popup_entry_toggle_state( FL_POPUP_ENTRY *,
                                                    unsigned int );

FL_EXPORT int fl_popup_entry_set_text( FL_POPUP_ENTRY *,
                                       const char * );

FL_EXPORT void fl_popup_entry_set_shortcut( FL_POPUP_ENTRY *,
                                            const char * );

FL_EXPORT long int fl_popup_entry_set_value( FL_POPUP_ENTRY *,
                                             long int );

FL_EXPORT void *fl_popup_entry_set_user_data( FL_POPUP_ENTRY *,
                                              void * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_position( FL_POPUP *,
                                                          int );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_value( FL_POPUP *,
                                                       long );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_user_data( FL_POPUP *,
                                                           void * );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_text( FL_POPUP *,
                                                      const char * );

FL_EXPORT FL_POPUP_ENTRY * fl_popup_entry_get_by_text_f( FL_POPUP *,
														 const char *,
														 ... );

FL_EXPORT FL_POPUP_ENTRY *fl_popup_entry_get_by_label( FL_POPUP *,
                                                       const char * );

FL_EXPORT FL_POPUP_ENTRY * fl_popup_entry_get_by_label_f( FL_POPUP *,
														  const char *,
														  ... );

FL_EXPORT int fl_popup_entry_get_group( FL_POPUP_ENTRY * );

FL_EXPORT int fl_popup_entry_set_group( FL_POPUP_ENTRY *,
                                        int );

FL_EXPORT FL_POPUP *fl_popup_entry_get_subpopup( FL_POPUP_ENTRY * );

FL_EXPORT FL_POPUP *fl_popup_entry_set_subpopup( FL_POPUP_ENTRY *,
                                                 FL_POPUP * );

FL_EXPORT int fl_popup_get_size( FL_POPUP *,
                                 unsigned int *,
                                 unsigned int * );

FL_EXPORT int fl_popup_get_min_width( FL_POPUP * );

FL_EXPORT int fl_popup_set_min_width( FL_POPUP *,
                                      int );

#endif /* ! defined FL_POPUP_H */

/**
 * \file bitmap.h
 *
 *   Object Class: Bitmap
 */

#ifndef FL_BITMAP_H
#define FL_BITMAP_H

#define    FL_NORMAL_BITMAP      0

/***** Defaults *****/

#define FL_BITMAP_BOXTYPE   FL_NO_BOX
#define FL_BITMAP_COL1      FL_COL1     /* background of bitmap */
#define FL_BITMAP_COL2      FL_COL1     /* not used currently   */
#define FL_BITMAP_LCOL      FL_LCOL     /* foreground of bitmap */
#define FL_BITMAP_ALIGN     FL_ALIGN_BOTTOM

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_bitmap( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_bitmap( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_set_bitmap_data( FL_OBJECT     * ob,
                                   int             w,
                                   int             h,
                                   unsigned char * data );

FL_EXPORT void fl_set_bitmap_file( FL_OBJECT  * ob,
                                   const char * fname );

FL_EXPORT Pixmap fl_read_bitmapfile( Window         win,
                                     const char   * file,
                                     unsigned int * w,
                                     unsigned int * h,
                                     int          * hotx,
                                     int          * hoty );

FL_EXPORT Pixmap fl_create_from_bitmapdata( Window       win,
											const char * data,
											int          width,
											int          height );

/* for compatibility */

#define fl_set_bitmap_datafile    fl_set_bitmap_file

/* PIXMAP stuff */

#define FL_NORMAL_PIXMAP   0

FL_EXPORT FL_OBJECT * fl_create_pixmap( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_pixmap( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_set_pixmap_data( FL_OBJECT   * ob,
                                   char       ** bits );

FL_EXPORT void fl_set_pixmap_file( FL_OBJECT  * ob,
                                   const char * fname );

FL_EXPORT void fl_set_pixmap_align( FL_OBJECT * ob,
                                    int         align,
                                    int         xmargin,
                                    int         ymargin );

FL_EXPORT void fl_set_pixmap_pixmap( FL_OBJECT * ob,
                                     Pixmap      id,
                                     Pixmap      mask );

FL_EXPORT void fl_set_pixmap_colorcloseness( int red,
                                             int green,
                                             int blue );

FL_EXPORT void fl_free_pixmap_pixmap( FL_OBJECT * ob );

FL_EXPORT void fl_free_pixmap_focus_pixmap( FL_OBJECT * obj );

FL_EXPORT Pixmap fl_get_pixmap_pixmap( FL_OBJECT * ob,
                                       Pixmap    * p,
                                       Pixmap    * m );

FL_EXPORT Pixmap fl_read_pixmapfile( Window         win,
                                     const char   * file,
                                     unsigned int * w,
                                     unsigned int * h,
                                     Pixmap       * shape_mask,
                                     int          * hotx,
                                     int          * hoty,
                                     FL_COLOR       tran );

FL_EXPORT Pixmap fl_create_from_pixmapdata( Window          win,
                                            char         ** data,
                                            unsigned int  * w,
                                            unsigned int  * h,
                                            Pixmap        * sm,
                                            int           * hotx,
                                            int           * hoty,
                                            FL_COLOR        tran );

FL_EXPORT void fl_free_pixmap( Pixmap id );


#endif /* ! defined FL_BITMAP_H */

/**
 * \file box.h
 *
 */

#ifndef FL_BOX_H
#define FL_BOX_H

/* Type is already defined in Basic.h */

FL_EXPORT FL_OBJECT * fl_create_box( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_add_box( int          type,
                                  FL_Coord     x,
                                  FL_Coord     y,
                                  FL_Coord     w,
                                  FL_Coord     h,
                                  const char * label );

#endif /* ! defined FL_BOX_H */

/*
 * \file browser.h
 *
 *  Object class Browser
 */

#ifndef FL_BROWSER_H
#define FL_BROWSER_H


/***** Types    *****/

typedef enum {
    FL_NORMAL_BROWSER,
    FL_SELECT_BROWSER,
    FL_HOLD_BROWSER,
    FL_MULTI_BROWSER,
	FL_DESELECTABLE_HOLD_BROWSER
} FL_BROWSER_TYPE;

/***** Defaults *****/

#define FL_BROWSER_BOXTYPE  FL_DOWN_BOX
#define FL_BROWSER_COL1     FL_COL1
#define FL_BROWSER_COL2     FL_YELLOW
#define FL_BROWSER_LCOL     FL_LCOL
#define FL_BROWSER_ALIGN    FL_ALIGN_BOTTOM


/***** Others   *****/

#define FL_BROWSER_SLCOL        FL_COL1
#define FL_BROWSER_FONTSIZE     FL_SMALL_SIZE


/* This exists only for backward compatibility and isn't used anymore! */

#define FL_BROWSER_LINELENGTH   2048


/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_browser( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_browser( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT void fl_clear_browser( FL_OBJECT * ob );

FL_EXPORT void fl_add_browser_line( FL_OBJECT  * ob,
                                    const char * newtext );

FL_EXPORT void fl_add_browser_line_f( FL_OBJECT  * ob,
									  const char * fmt,
									  ... );


FL_EXPORT void fl_addto_browser( FL_OBJECT  * obj,
                                 const char * text );

FL_EXPORT void fl_addto_browser_f( FL_OBJECT  * obj,
								   const char * fmt,
								   ...);

#define fl_append_browser  fl_addto_browser_chars
FL_EXPORT void fl_addto_browser_chars( FL_OBJECT  * ob,
                                       const char * str );

FL_EXPORT void fl_addto_browser_chars_f( FL_OBJECT  * ob,
										 const char * fmt,
										 ... );

#define fl_append_browser_f  fl_addto_browser_chars_f
FL_EXPORT void fl_insert_browser_line( FL_OBJECT  * ob,
                                       int          linenumb,
                                       const char * newtext );

FL_EXPORT void fl_insert_browser_line_f( FL_OBJECT  * ob,
										 int          linenumb,
										 const char * fmt,
										 ... );

FL_EXPORT void fl_delete_browser_line( FL_OBJECT * ob,
                                       int         linenumb );

FL_EXPORT void fl_replace_browser_line( FL_OBJECT  * ob,
                                        int          linenumb,
                                        const char * newtext );

FL_EXPORT void fl_replace_browser_line_f( FL_OBJECT  * ob,
										  int          linenumb,
										  const char * fmt,
										  ... );

FL_EXPORT const char *fl_get_browser_line( FL_OBJECT * ob,
                                           int         linenumb );

FL_EXPORT int fl_load_browser( FL_OBJECT  * ob,
                               const char * filename );

FL_EXPORT void fl_select_browser_line( FL_OBJECT * ob, 
                                       int         line );

FL_EXPORT void fl_deselect_browser_line( FL_OBJECT * ob,
                                         int         line );

FL_EXPORT void fl_deselect_browser( FL_OBJECT * ob );

FL_EXPORT int fl_isselected_browser_line( FL_OBJECT * ob,
                                          int         line );

FL_EXPORT int fl_get_browser_topline( FL_OBJECT * ob );

FL_EXPORT int fl_get_browser( FL_OBJECT * ob );

FL_EXPORT int fl_get_browser_maxline( FL_OBJECT * ob );

FL_EXPORT int fl_get_browser_screenlines( FL_OBJECT * ob );

FL_EXPORT void fl_set_browser_topline( FL_OBJECT * ob,
                                       int         line );

FL_EXPORT void fl_set_browser_bottomline( FL_OBJECT * ob,
										  int         line );

FL_EXPORT void fl_set_browser_fontsize( FL_OBJECT * ob,
                                        int         size );

FL_EXPORT void fl_set_browser_fontstyle( FL_OBJECT * ob,
                                         int         style );

FL_EXPORT void fl_set_browser_specialkey( FL_OBJECT * ob,
                                          int         specialkey );

FL_EXPORT void fl_set_browser_vscrollbar( FL_OBJECT * ob,
                                          int         on );

FL_EXPORT void fl_set_browser_hscrollbar( FL_OBJECT * ob,
                                          int         on );

FL_EXPORT void fl_set_browser_line_selectable( FL_OBJECT * ob,
                                               int         line,
                                               int         flag );

FL_EXPORT void fl_get_browser_dimension( FL_OBJECT * ob,
                                         FL_Coord  * x,
                                         FL_Coord  * y,
                                         FL_Coord  * w,
                                         FL_Coord  * h );

FL_EXPORT void fl_set_browser_dblclick_callback( FL_OBJECT      * ob,
                                                 FL_CALLBACKPTR   cb,
                                                 long             a );

FL_EXPORT FL_Coord fl_get_browser_xoffset( FL_OBJECT * ob );

FL_EXPORT double fl_get_browser_rel_xoffset( FL_OBJECT * ob );

FL_EXPORT void fl_set_browser_xoffset( FL_OBJECT * ob,
                                       FL_Coord    npixels );

FL_EXPORT void fl_set_browser_rel_xoffset( FL_OBJECT * ob,
                                           double      val );

FL_EXPORT FL_Coord fl_get_browser_yoffset( FL_OBJECT * ob );

FL_EXPORT double fl_get_browser_rel_yoffset( FL_OBJECT * ob );

FL_EXPORT void fl_set_browser_yoffset( FL_OBJECT * ob,
                                       FL_Coord    npixels );

FL_EXPORT void fl_set_browser_rel_yoffset( FL_OBJECT * ob,
                                           double      val );

FL_EXPORT void fl_set_browser_scrollbarsize( FL_OBJECT * ob,
                                             int         hh,
                                             int         vw );

FL_EXPORT void fl_show_browser_line( FL_OBJECT * ob,
                                     int         j );

FL_EXPORT int fl_set_default_browser_maxlinelength( int n );

#ifndef FL_BROWSER_SCROLL_CALLBACKt
#define FL_BROWSER_SCROLL_CALLBACKt
typedef void ( * FL_BROWSER_SCROLL_CALLBACK )( FL_OBJECT *,
                                               int,
                                               void * );
#endif

FL_EXPORT void
    fl_set_browser_hscroll_callback( FL_OBJECT *,
                                     FL_BROWSER_SCROLL_CALLBACK,
                                     void * );

FL_EXPORT void
    fl_set_browser_vscroll_callback( FL_OBJECT *,
                                     FL_BROWSER_SCROLL_CALLBACK,
                                     void * );

FL_EXPORT int fl_get_browser_line_yoffset( FL_OBJECT *,
										   int  );

FL_EXPORT FL_BROWSER_SCROLL_CALLBACK
    fl_get_browser_hscroll_callback( FL_OBJECT * );

FL_EXPORT FL_BROWSER_SCROLL_CALLBACK
    fl_get_browser_vscroll_callback( FL_OBJECT * );

FL_EXPORT int fl_get_browser_scrollbar_repeat( FL_OBJECT * );

FL_EXPORT void fl_set_browser_scrollbar_repeat( FL_OBJECT *,
												int  );

#endif /* ! defined FL_BROWSER_H */

/**
 * \file button.h
 *
 * All Buttons: regular button, light button and round button
 *
 */

#ifndef FL_BUTTON_H
#define FL_BUTTON_H


typedef enum {
    FL_NORMAL_BUTTON,
    FL_PUSH_BUTTON,
    FL_RADIO_BUTTON,
    FL_HIDDEN_BUTTON,
    FL_TOUCH_BUTTON,
    FL_INOUT_BUTTON,
    FL_RETURN_BUTTON,
    FL_HIDDEN_RET_BUTTON,
    FL_MENU_BUTTON
} FL_BUTTON_TYPE;

#define FL_TOGGLE_BUTTON    FL_PUSH_BUTTON

typedef struct {
    Pixmap         pixmap,
                   mask;
    unsigned int   bits_w,
                   bits_h;
    int            val;             /* state of button (on/off) */
    int            mousebut;        /* mouse button that caused the push     */
    int            timdel;          /* time since last touch (TOUCH buttons) */
    int            event;           /* what event triggers redraw            */
    int            is_pushed;       /* set while drawn as pushed down        */
    int            react_to[ 5 ];   /* mouse buttons button reacts to        */
    long           cspecl;          /* reserved for class specfic stuff      */
    void         * cspecv;          /* misc. things                          */
    char         * filename;
    Pixmap         focus_pixmap,
                   focus_mask;
    char         * focus_filename;
} FL_BUTTON_SPEC;

#define FL_BUTTON_STRUCT FL_BUTTON_SPEC

typedef void ( * FL_DrawButton )( FL_OBJECT * );
typedef void ( * FL_CleanupButton )( FL_BUTTON_STRUCT * );

#define FL_DRAWBUTTON      FL_DrawButton
#define FL_CLEANUPBUTTON   FL_CleanupButton

/* normal button default */

#define FL_BUTTON_BOXTYPE           FL_UP_BOX
#define FL_BUTTON_COL1              FL_COL1
#define FL_BUTTON_COL2              FL_COL1
#define FL_BUTTON_LCOL              FL_LCOL
#define FL_BUTTON_ALIGN             FL_ALIGN_CENTER
#define FL_BUTTON_MCOL1             FL_MCOL
#define FL_BUTTON_MCOL2             FL_MCOL
#define FL_BUTTON_BW                FL_BOUND_WIDTH

/* light button defaults */

#define FL_LIGHTBUTTON_BOXTYPE      FL_UP_BOX
#define FL_LIGHTBUTTON_COL1         FL_COL1
#define FL_LIGHTBUTTON_COL2         FL_YELLOW
#define FL_LIGHTBUTTON_LCOL         FL_LCOL
#define FL_LIGHTBUTTON_ALIGN        ( FL_ALIGN_CENTER | FL_ALIGN_INSIDE )
#define FL_LIGHTBUTTON_TOPCOL       FL_COL1
#define FL_LIGHTBUTTON_MCOL         FL_MCOL
#define FL_LIGHTBUTTON_MINSIZE      ( ( FL_Coord ) 12 )

/* round button defaults */

#define FL_ROUNDBUTTON_BOXTYPE      FL_NO_BOX
#define FL_ROUNDBUTTON_COL1         FL_MCOL
#define FL_ROUNDBUTTON_COL2         FL_YELLOW
#define FL_ROUNDBUTTON_LCOL         FL_LCOL
#define FL_ROUNDBUTTON_ALIGN        FL_ALIGN_CENTER
#define FL_ROUNDBUTTON_TOPCOL       FL_COL1
#define FL_ROUNDBUTTON_MCOL         FL_MCOL

/* round3d button defaults */

#define FL_ROUND3DBUTTON_BOXTYPE    FL_NO_BOX
#define FL_ROUND3DBUTTON_COL1       FL_COL1
#define FL_ROUND3DBUTTON_COL2       FL_BLACK
#define FL_ROUND3DBUTTON_LCOL       FL_LCOL
#define FL_ROUND3DBUTTON_ALIGN      FL_ALIGN_CENTER
#define FL_ROUND3DBUTTON_TOPCOL     FL_COL1
#define FL_ROUND3DBUTTON_MCOL       FL_MCOL

/* check button defaults */

#define FL_CHECKBUTTON_BOXTYPE      FL_NO_BOX
#define FL_CHECKBUTTON_COL1         FL_COL1
#define FL_CHECKBUTTON_COL2         FL_YELLOW
#define FL_CHECKBUTTON_LCOL         FL_LCOL
#define FL_CHECKBUTTON_ALIGN        FL_ALIGN_CENTER

#define FL_CHECKBUTTON_TOPCOL       FL_COL1
#define FL_CHECKBUTTON_MCOL         FL_MCOL

/* bitmap button defaults */

#define FL_BITMAPBUTTON_BOXTYPE     FL_UP_BOX
#define FL_BITMAPBUTTON_COL1        FL_COL1         /* bitmap background  */
#define FL_BITMAPBUTTON_COL2        FL_BLUE         /* "focus" color       */
#define FL_BITMAPBUTTON_LCOL        FL_LCOL         /* bitmap foreground   */
#define FL_BITMAPBUTTON_ALIGN       FL_ALIGN_BOTTOM

/* bitmap button defaults */

#define FL_PIXMAPBUTTON_BOXTYPE     FL_UP_BOX
#define FL_PIXMAPBUTTON_COL1        FL_BUTTON_COL1
#define FL_PIXMAPBUTTON_COL2        FL_BUTTON_COL2
#define FL_PIXMAPBUTTON_LCOL        FL_BUTTON_LCOL
#define FL_PIXMAPBUTTON_MCOL1       FL_BUTTON_MCOL1
#define FL_PIXMAPBUTTON_MCOL2       FL_BUTTON_MCOL2
#define FL_PIXMAPBUTTON_ALIGN       FL_ALIGN_BOTTOM

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_button( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_create_roundbutton( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT FL_OBJECT * fl_create_round3dbutton( int        type,
                                               FL_Coord   x,
                                               FL_Coord   y,
                                               FL_Coord   w,
                                               FL_Coord   h,
                                               const char * label );

FL_EXPORT FL_OBJECT * fl_create_lightbutton( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT FL_OBJECT * fl_create_checkbutton( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT FL_OBJECT * fl_create_bitmapbutton( int          type,
                                              FL_Coord     x,
                                              FL_Coord     y,
                                              FL_Coord     w,
                                              FL_Coord     h,
                                              const char * label );

FL_EXPORT FL_OBJECT * fl_create_pixmapbutton( int          type,
                                              FL_Coord     x,
                                              FL_Coord     y,
                                              FL_Coord     w,
                                              FL_Coord     h,
                                              const char * label );

FL_EXPORT FL_OBJECT * fl_create_scrollbutton( int          type,
                                              FL_Coord     x,
                                              FL_Coord     y,
                                              FL_Coord     w,
                                              FL_Coord     h,
                                              const char * label );

FL_EXPORT FL_OBJECT * fl_create_labelbutton( int           type,
                                             FL_Coord      x,
                                             FL_Coord      y,
                                             FL_Coord      w,
                                             FL_Coord      h,
                                             const char * label );

FL_EXPORT FL_OBJECT *fl_add_roundbutton( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_round3dbutton( int          type,
                                            FL_Coord     x,
                                            FL_Coord     y,
                                            FL_Coord     w,
                                            FL_Coord     h,
                                            const char * label );

FL_EXPORT FL_OBJECT * fl_add_lightbutton( int         type,
                                          FL_Coord    x,
                                          FL_Coord    y,
                                          FL_Coord    w,
                                          FL_Coord    h,
                                          const char * label );

FL_EXPORT FL_OBJECT * fl_add_checkbutton( int          type,
                                          FL_Coord     x,
                                          FL_Coord     y,
                                          FL_Coord     w,
                                          FL_Coord     h,
                                          const char * label );

FL_EXPORT FL_OBJECT * fl_add_button( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_add_bitmapbutton( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_scrollbutton( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_labelbutton( int          type,
                                          FL_Coord     x,
                                          FL_Coord     y,
                                          FL_Coord     w,
                                          FL_Coord     h,
                                          const char * label );

#define fl_set_bitmapbutton_file  fl_set_bitmap_file

FL_EXPORT void fl_set_bitmapbutton_data( FL_OBJECT     * ob,
                                         int             w,
                                         int             h,
                                         unsigned char * bits );

#define fl_set_bitmapbutton_datafile  fl_set_bitmapbutton_file

FL_EXPORT FL_OBJECT * fl_add_pixmapbutton( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

#define fl_set_pixmapbutton_data       fl_set_pixmap_data
#define fl_set_pixmapbutton_file       fl_set_pixmap_file
#define fl_set_pixmapbutton_pixmap     fl_set_pixmap_pixmap
#define fl_get_pixmapbutton_pixmap     fl_get_pixmap_pixmap
#define fl_set_pixmapbutton_align      fl_set_pixmap_align
#define fl_free_pixmapbutton_pixmap    fl_free_pixmap_pixmap
#define fl_set_pixmapbutton_datafile   fl_set_pixmapbutton_file
#define fl_set_pixmapbutton_show_focus fl_set_pixmapbutton_focus_outline


FL_EXPORT void fl_set_pixmapbutton_focus_outline( FL_OBJECT * ob,
                                                  int         yes );

FL_EXPORT void fl_set_pixmapbutton_focus_data( FL_OBJECT  * ob,
                                               char      ** bits );

FL_EXPORT void fl_set_pixmapbutton_focus_file( FL_OBJECT  * ob,
                                               const char * fname );

FL_EXPORT void fl_set_pixmapbutton_focus_pixmap( FL_OBJECT * ob,
                                                 Pixmap      id,
                                                 Pixmap      mask );

FL_EXPORT int fl_get_button( FL_OBJECT * ob );

FL_EXPORT void fl_set_button( FL_OBJECT * ob,
                              int         pushed );

FL_EXPORT int fl_get_button_numb( FL_OBJECT * ob );

#define fl_set_button_shortcut  fl_set_object_shortcut

FL_EXPORT FL_OBJECT * fl_create_generic_button( int          objclass,
                                                int          type,
                                                FL_Coord     x,
                                                FL_Coord     y,
                                                FL_Coord     w,
                                                FL_Coord     h,
                                                const char * label );

FL_EXPORT void fl_add_button_class( int              bclass,
                                    FL_DrawButton    drawit,
                                    FL_CleanupButton cleanup );

FL_EXPORT void fl_set_button_mouse_buttons( FL_OBJECT    * ob,
                                            unsigned int   buttons );

FL_EXPORT void fl_get_button_mouse_buttons( FL_OBJECT    * ob,
                                            unsigned int * buttons );

#endif /* ! defined FL_BUTTON_H */

/**
 * \file canvas.h
 *
 * Header for FL_CANVAS
 *
 */

#ifndef FL_CANVAS_H_
#define FL_CANVAS_H_

typedef enum {
    FL_NORMAL_CANVAS,
    FL_SCROLLED_CANVAS
} FL_CANVAS_TYPE;

typedef int ( * FL_HANDLE_CANVAS )( FL_OBJECT *,
                                    Window,
                                    int,
                                    int,
                                    XEvent *,
                                    void * );

typedef int ( * FL_MODIFY_CANVAS_PROP )( FL_OBJECT * );

/******************** Default *********************/

#define FL_CANVAS_BOXTYPE   FL_DOWN_BOX     /* really the decoration frame */
#define FL_CANVAS_ALIGN     FL_ALIGN_TOP

/************ Interfaces    ************************/

FL_EXPORT FL_OBJECT * fl_create_generic_canvas( int          canvas_class,
                                                int          type,
                                                FL_Coord     x,
                                                FL_Coord     y,
                                                FL_Coord     w,
                                                FL_Coord     h,
                                                const char * label );

FL_EXPORT FL_OBJECT * fl_add_canvas( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_create_canvas( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

/* backward compatibility */

#define fl_set_canvas_decoration fl_set_object_boxtype

FL_EXPORT void fl_set_canvas_colormap( FL_OBJECT * ob,
                                       Colormap    colormap );

FL_EXPORT void fl_set_canvas_visual( FL_OBJECT * obj,
                                     Visual    * vi );

FL_EXPORT void fl_set_canvas_depth( FL_OBJECT * obj,
                                    int         depth );

FL_EXPORT void fl_set_canvas_attributes( FL_OBJECT            * ob,
                                         unsigned int           mask,
                                         XSetWindowAttributes * xswa );

FL_EXPORT FL_HANDLE_CANVAS fl_add_canvas_handler( FL_OBJECT        * ob,
                                                  int                ev,
                                                  FL_HANDLE_CANVAS   h,
                                                  void             * udata );

FL_EXPORT Window fl_get_canvas_id( FL_OBJECT * ob );

FL_EXPORT Colormap fl_get_canvas_colormap( FL_OBJECT * ob );

FL_EXPORT int fl_get_canvas_depth( FL_OBJECT * obj );

FL_EXPORT void fl_remove_canvas_handler( FL_OBJECT        * ob,
                                         int                ev,
                                         FL_HANDLE_CANVAS   h );

FL_EXPORT void fl_share_canvas_colormap( FL_OBJECT * ob,
                                         Colormap    colormap );

FL_EXPORT void fl_clear_canvas( FL_OBJECT * ob );

FL_EXPORT void fl_modify_canvas_prop( FL_OBJECT             * obj,
                                      FL_MODIFY_CANVAS_PROP   init,
                                      FL_MODIFY_CANVAS_PROP   activate,
                                      FL_MODIFY_CANVAS_PROP   cleanup );

FL_EXPORT void fl_canvas_yield_to_shortcut( FL_OBJECT * ob,
                                            int         yes );

/* This is an attempt to maintain some sort of backwards compatibility
 * with old code whilst also getting rid of the old, system-specific
 * hack. */

#ifdef AUTOINCLUDE_GLCANVAS_H
#include <glcanvas.h>
#endif

#endif /* ! defined FL_CANVAS_H */

/**
 * \file chart.h
 *
 * Object Class: Chart
 *
 */

#ifndef FL_CHART_H
#define FL_CHART_H

typedef enum {
    FL_BAR_CHART,
    FL_HORBAR_CHART,
    FL_LINE_CHART,
    FL_FILL_CHART,
    FL_SPIKE_CHART,
    FL_PIE_CHART,
    FL_SPECIALPIE_CHART
} FL_CHART_TYPE;

#define FL_FILLED_CHART  FL_FILL_CHART  /* for backward compatibility */

/***** Defaults *****/

#define FL_CHART_BOXTYPE    FL_BORDER_BOX
#define FL_CHART_COL1       FL_COL1
#define FL_CHART_LCOL       FL_LCOL
#define FL_CHART_ALIGN      FL_ALIGN_BOTTOM

/***** Others   *****/

#define FL_CHART_MAX        2048

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_chart( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_chart( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

FL_EXPORT void fl_clear_chart( FL_OBJECT * ob );

FL_EXPORT void fl_add_chart_value( FL_OBJECT  * ob,
                                   double       val,
                                   const char * str,
                                   FL_COLOR     col );

FL_EXPORT void fl_insert_chart_value( FL_OBJECT  * ob,
                                      int          indx,
                                      double       val,
                                      const char * str,
                                      FL_COLOR     col );

FL_EXPORT void fl_replace_chart_value( FL_OBJECT  * ob,
                                       int          indx,
                                       double       val,
                                       const char * str,
                                       FL_COLOR     col );

FL_EXPORT void fl_set_chart_bounds( FL_OBJECT * ob,
                                    double      min,
                                    double      max );

FL_EXPORT void fl_get_chart_bounds( FL_OBJECT * ob,
                                    double    * min,
                                    double    * max );

FL_EXPORT void fl_set_chart_maxnumb( FL_OBJECT * ob,
									 int         maxnumb );

FL_EXPORT void fl_set_chart_autosize( FL_OBJECT * ob,
                                      int         autosize );

FL_EXPORT void fl_set_chart_lstyle( FL_OBJECT * ob,
                                    int         lstyle );

FL_EXPORT void fl_set_chart_lsize( FL_OBJECT * ob,
                                   int         lsize );

FL_EXPORT void fl_set_chart_lcolor( FL_OBJECT * ob,
                                    FL_COLOR    lcol );

FL_EXPORT void fl_set_chart_baseline( FL_OBJECT * ob,
                                      int         iYesNo );

#define fl_set_chart_lcol   fl_set_chart_lcolor

#endif /* ! defined FL_CHART_H */

/**
 * \file choice.h
 *
 */

#ifndef FL_CHOICE_H
#define FL_CHOICE_H


typedef enum {
    FL_NORMAL_CHOICE,
    FL_NORMAL_CHOICE2,
    FL_DROPLIST_CHOICE,
    FL_BROWSER_CHOICE
} FL_CHOICE_TYPE;

#define  FL_SIMPLE_CHOICE  FL_NORMAL_CHOICE

/***** Defaults *****/

#define FL_CHOICE_BOXTYPE   FL_ROUNDED_BOX
#define FL_CHOICE_COL1      FL_COL1
#define FL_CHOICE_COL2      FL_LCOL
#define FL_CHOICE_LCOL      FL_LCOL
#define FL_CHOICE_ALIGN     FL_ALIGN_LEFT

/***** Others   *****/

#define FL_CHOICE_MCOL      FL_MCOL
#define FL_CHOICE_MAXITEMS  128

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_choice( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_choice( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_clear_choice( FL_OBJECT * ob );

FL_EXPORT int fl_addto_choice( FL_OBJECT  * ob,
                               const char * str );

FL_EXPORT int fl_addto_choice_f( FL_OBJECT *  ob,
								 const char * fmt,
								 ... );

FL_EXPORT void fl_replace_choice( FL_OBJECT  * ob,
                                  int          numb,
                                  const char * str );

FL_EXPORT void fl_replace_choice_f( FL_OBJECT *  ob,
									int          numb,
									const char * fmt,
									... );

FL_EXPORT void fl_delete_choice( FL_OBJECT * ob,
                                 int         numb );

FL_EXPORT void fl_set_choice( FL_OBJECT * ob,
                              int         choice );

FL_EXPORT void fl_set_choice_text( FL_OBJECT  * ob,
                                   const char * txt );

FL_EXPORT void fl_set_choice_text_f( FL_OBJECT *  ob,
									 const char * fmt,
									 ... );

FL_EXPORT int fl_get_choice( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_choice_item_text( FL_OBJECT * ob,
                                                int         n );

FL_EXPORT int fl_get_choice_maxitems( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_choice_text( FL_OBJECT * ob );

FL_EXPORT void fl_set_choice_fontsize( FL_OBJECT * ob,
                                       int         size );

FL_EXPORT void fl_set_choice_fontstyle( FL_OBJECT * ob,
                                        int         style );

FL_EXPORT void fl_set_choice_align( FL_OBJECT * ob,
                                    int         align );

FL_EXPORT int fl_get_choice_item_mode( FL_OBJECT *  ob,
                                       int          item );

FL_EXPORT void fl_set_choice_item_mode( FL_OBJECT    * ob,
                                        int            item,
                                        unsigned int   mode );

FL_EXPORT void fl_set_choice_item_shortcut( FL_OBJECT  * ob,
                                            int          item,
                                            const char * sc );

FL_EXPORT int fl_set_choice_entries( FL_OBJECT    * ob,
                                     FL_PUP_ENTRY * ent );

FL_EXPORT int fl_set_choice_notitle( FL_OBJECT * ob,
                                     int         n );

FL_EXPORT int fl_set_choice_align_bottom( FL_OBJECT * ob,
										  int         n );

#endif /* ! defined FL_CHOICE_H */

/**
 * \file clipbd.h
 *
 * prototypes for clipboard stuff
 */

#ifndef FL_CLIPBD_H
#define FL_CLIPBD_H

typedef Atom FL_CPTYPE;

typedef int ( * FL_LOSE_SELECTION_CB )( FL_OBJECT *, long );
typedef int ( * FL_SELECTION_CB )( FL_OBJECT *, long, const void *, long );

#define FL_SELECTION_CALLBACK        FL_SELECTION_CB
#define FL_LOSE_SELECTION_CALLBACK   FL_LOSE_SELECTION_CB

FL_EXPORT int fl_stuff_clipboard( FL_OBJECT            * ob,
                                  long                   type,
                                  const void           * data,
                                  long                   size,
                                  FL_LOSE_SELECTION_CB   lose_callback );

FL_EXPORT int fl_request_clipboard( FL_OBJECT       * ob,
                                    long              type,
                                    FL_SELECTION_CB   got_it_callback );

#endif /* ! defined FL_CLIPBD_H */

/**
 * \file clock.h
 */

#ifndef FL_CLOCK_H
#define FL_CLOCK_H

enum {
    FL_ANALOG_CLOCK,
    FL_DIGITAL_CLOCK
};

#define FL_CLOCK_BOXTYPE   FL_UP_BOX
#define FL_CLOCK_COL1      FL_INACTIVE_COL
#define FL_CLOCK_COL2      FL_BOTTOM_BCOL
#define FL_CLOCK_LCOL      FL_BLACK
#define FL_CLOCK_ALIGN     FL_ALIGN_BOTTOM

#define FL_CLOCK_TOPCOL  FL_COL1

FL_EXPORT FL_OBJECT * fl_create_clock( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * s );

FL_EXPORT FL_OBJECT * fl_add_clock( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * s );

FL_EXPORT void fl_get_clock( FL_OBJECT * ob,
                             int       * h,
                             int       * m,
                             int       * s );

FL_EXPORT long fl_set_clock_adjustment( FL_OBJECT * ob,
                                        long        offset );

FL_EXPORT void fl_set_clock_ampm( FL_OBJECT * ob,
                                  int         y );

#endif /* ! defined FL_CLOCK_H */

/**
 * \file counter.h
 */

#ifndef FL_COUNTER_H
#define FL_COUNTER_H

typedef enum {
    FL_NORMAL_COUNTER,
    FL_SIMPLE_COUNTER
} FL_COUNTER_TYPE;

/***** Defaults *****/

#define FL_COUNTER_BOXTYPE  FL_UP_BOX
#define FL_COUNTER_COL1     FL_COL1
#define FL_COUNTER_COL2     FL_BLUE           /* ct label     */
#define FL_COUNTER_LCOL     FL_LCOL           /* ct reporting */
#define FL_COUNTER_ALIGN    FL_ALIGN_BOTTOM

/***** Others *****/

#define FL_COUNTER_BW       FL_BOUND_WIDTH

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_counter( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_counter( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT void fl_set_counter_value( FL_OBJECT * ob,
                                     double      val );

FL_EXPORT void fl_set_counter_bounds( FL_OBJECT * ob,
                                      double      min,
                                      double      max );

FL_EXPORT void fl_set_counter_step( FL_OBJECT * ob,
                                    double      s,
                                    double      l );

FL_EXPORT void fl_set_counter_precision( FL_OBJECT * ob,
                                         int         prec );

FL_EXPORT int fl_get_counter_precision( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_return( FL_OBJECT    * ob,
                                      unsigned int   how );

FL_EXPORT double fl_get_counter_value( FL_OBJECT * ob );

FL_EXPORT void fl_get_counter_bounds( FL_OBJECT * ob,
                                      double    * min,
                                      double    * max );

FL_EXPORT void fl_get_counter_step( FL_OBJECT * ob,
                                    double    * s,
                                    double    * l );

FL_EXPORT void fl_set_counter_filter( FL_OBJECT     * ob,
                                      FL_VAL_FILTER   filter );

/* Functions to set and get the timeout value used by the
 * counter code to control modification of the counter value. */

FL_EXPORT int fl_get_counter_repeat( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_repeat( FL_OBJECT * ob,
                                      int         millisec );

FL_EXPORT int fl_get_counter_min_repeat( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_min_repeat( FL_OBJECT * ob,
                                          int         millisec );

FL_EXPORT int fl_get_counter_speedjump( FL_OBJECT * ob );

FL_EXPORT void fl_set_counter_speedjump( FL_OBJECT * ob,
                                         int         yes_no );

#endif /* ! defined FL_COUNTER_H */

/**
 * \file cursor.h
 *
 * Cursor defs and prototypes
 */

#ifndef FL_CURSOR_H
#define FL_CURSOR_H

#include <X11/cursorfont.h>

enum {
    FL_INVISIBLE_CURSOR = -2,
    FL_DEFAULT_CURSOR   = -1,
    FL_BUSY_CURSOR      = XC_watch,
    FL_CROSSHAIR_CURSOR = XC_tcross,
    FL_KILL_CURSOR      = XC_pirate,
    FL_NWARROW_CURSOR   = XC_top_left_arrow,
    FL_NEARROW_CURSOR   = XC_arrow
};

#ifndef XC_invisible
#define XC_invisible   FL_INVISIBLE_CURSOR
#endif

FL_EXPORT void fl_set_cursor( Window win,
                              int    name );

FL_EXPORT void fl_set_cursor_color( int      name,
                                    FL_COLOR fg,
                                    FL_COLOR bg );

FL_EXPORT int fl_create_bitmap_cursor( const char * source,
                                       const char * mask,
                                       int          w,
                                       int          h,
                                       int          hotx,
                                       int          hoty );

FL_EXPORT int fl_create_animated_cursor( int * cur_names,
                                         int   timeout );

#define fl_reset_cursor( win )   fl_set_cursor( win, FL_DEFAULT_CURSOR );

#endif /* ! defined FL_CURSOR_H */

/**
 * \file dial.h
 */

#ifndef FL_DIAL_H
#define FL_DIAL_H

typedef enum {
    FL_NORMAL_DIAL,
    FL_LINE_DIAL,
    FL_FILL_DIAL
} FL_DIAL_TYPE;

enum {
    FL_DIAL_CW,
    FL_DIAL_CCW
};

/***** Defaults *****/

#define FL_DIAL_BOXTYPE     FL_FLAT_BOX
#define FL_DIAL_COL1        FL_COL1
#define FL_DIAL_COL2        FL_RIGHT_BCOL
#define FL_DIAL_LCOL        FL_LCOL
#define FL_DIAL_ALIGN       FL_ALIGN_BOTTOM

/***** Others   *****/

#define FL_DIAL_TOPCOL      FL_COL1

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_dial( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT FL_OBJECT * fl_add_dial( int          type,
                                   FL_Coord     x,
                                   FL_Coord     y,
                                   FL_Coord     w,
                                   FL_Coord     h,
                                   const char * label );

FL_EXPORT void fl_set_dial_value( FL_OBJECT * obj,
                                  double      val );

FL_EXPORT double fl_get_dial_value( FL_OBJECT * obj );

FL_EXPORT void fl_set_dial_bounds( FL_OBJECT * obj,
                                   double      min,
                                   double      max );

FL_EXPORT void fl_get_dial_bounds( FL_OBJECT * obj,
                                   double    * min,
                                   double    * max );

FL_EXPORT void fl_set_dial_step( FL_OBJECT * obj,
                                 double      value );

FL_EXPORT double fl_get_dial_step( FL_OBJECT * obj );

FL_EXPORT void fl_set_dial_return( FL_OBJECT    * obj,
                                   unsigned int   value );

FL_EXPORT void fl_set_dial_angles( FL_OBJECT * obj,
                                   double      amin,
                                   double      amax );

FL_EXPORT void fl_get_dial_angles( FL_OBJECT * obj,
                                   double    * amin,
                                   double    * amax );

FL_EXPORT void fl_set_dial_cross( FL_OBJECT * obj,
                                  int         flag );

#define fl_set_dial_crossover  fl_set_dial_cross

FL_EXPORT void fl_set_dial_direction( FL_OBJECT * obj,
                                      int         dir );

FL_EXPORT int fl_get_dial_direction( FL_OBJECT * obj );


#endif /* ! defined FL_DIAL_H */

/**
 * \file filesys.h
 *
 *  Convenience functions to read a directory
 */

#ifndef FL_FILESYS_H
#define FL_FILESYS_H

/*  File types */

enum {
    FT_FILE,
    FT_DIR,
    FT_LINK,
    FT_SOCK,
    FT_FIFO,
    FT_BLK,
    FT_CHR,
    FT_OTHER
};

typedef struct {
    char          * name;           /* entry name             */
    int             type;           /* FILE_TYPE              */
    long            dl_mtime;       /* file modification time */
    unsigned long   dl_size;        /* file size in bytes     */
} FL_Dirlist;

enum {
    FL_ALPHASORT = 1,       /* sort in alphabetic order           */
    FL_RALPHASORT,          /* sort in reverse alphabetic order   */
    FL_MTIMESORT,           /* sort according to modifcation time */
    FL_RMTIMESORT,          /* sort in reverse modificaiton time  */
    FL_SIZESORT,            /* sort in increasing size order      */
    FL_RSIZESORT,           /* sort in decreasing size order      */
    FL_CASEALPHASORT,       /* sort case insensitive              */
    FL_RCASEALPHASORT       /* sort case insensitive              */
};

typedef int ( * FL_DIRLIST_FILTER )( const char *, int );

/* read dir with pattern filtering. All dirs read might be cached.
 * Must not change dirlist in anyway. */

FL_EXPORT const FL_Dirlist * fl_get_dirlist( const char * dir,
                                             const char * pattern,
                                             int        * n,
                                             int          rescan );

FL_EXPORT FL_DIRLIST_FILTER fl_set_dirlist_filter( FL_DIRLIST_FILTER filter );

FL_EXPORT int fl_set_dirlist_sort( int method );

FL_EXPORT int fl_set_dirlist_filterdir( int yes );

FL_EXPORT void fl_free_dirlist( const FL_Dirlist * dl );

#endif /* ! defined FL_FILESYS_H */

/**
 * \file flps.h
 */

#ifndef FLPS_H
#define FLPS_H

/* postscript stuff */

enum {
   FLPS_AUTO,                  /* switch to landscale if does not fit */
   FLPS_LANDSCAPE,             /* landscape always                    */
   FLPS_PORTRAIT,              /* portrait always                     */
   FLPS_BESTFIT                /* even margins/best fit               */
};

enum {
  FLPS_BW = -1,
  FLPS_GRAYSCALE,
  FLPS_COLOR
};

typedef struct {
    int          ps_color;
    int          orientation;
    int          auto_fit;
    int          drawbox;
    int          eps;
    float        xdpi,
                 ydpi;
    float        paper_w,
                 paper_h;
    float        gamma;
    const char * tmpdir;
    int          printer_dpi;
    float        hm,
                 vm;
    float        xscale,
                 yscale;
    int          scale_text;
    int          first_page_only;
    int          clip;
} FLPS_CONTROL;

FL_EXPORT FLPS_CONTROL * flps_init( void );

FL_EXPORT int fl_object_ps_dump( FL_OBJECT  * ob,
                                 const char * fname );

#endif /* ! defined FLPS_H */

/**
 * \file formbrowser.h
 *
 */

#ifndef FL_FORMBROWSER_H
#define FL_FORMBROWSER_H

enum {
    FL_NORMAL_FORMBROWSER
};

enum {
   FL_SMOOTH_SCROLL,
   FL_JUMP_SCROLL
};

#define   FL_FORMBROWSER_BOXTYPE  FL_DOWN_BOX
#define   FL_FORMBROWSER_COL1     FL_COL1
#define   FL_FORMBROWSER_ALIGN    FL_ALIGN_TOP

FL_EXPORT int fl_addto_formbrowser( FL_OBJECT * ob,
                                    FL_FORM   * form );

FL_EXPORT FL_FORM * fl_delete_formbrowser_bynumber( FL_OBJECT * ob,
                                                    int         num );

FL_EXPORT int fl_delete_formbrowser( FL_OBJECT * ob,
                                     FL_FORM   * form );

FL_EXPORT FL_FORM * fl_replace_formbrowser( FL_OBJECT * ob,
                                            int         num,
                                            FL_FORM   * form );

FL_EXPORT int fl_insert_formbrowser( FL_OBJECT * ob,
                                     int         line,
                                     FL_FORM   * new_form );

FL_EXPORT int fl_get_formbrowser_area( FL_OBJECT * ob,
                                       int       * x,
                                       int       * y,
                                       int       * w,
                                       int       * h );

FL_EXPORT void fl_set_formbrowser_scroll( FL_OBJECT * ob,
                                          int         how );

FL_EXPORT void fl_set_formbrowser_hscrollbar( FL_OBJECT * ob,
                                              int         how );

FL_EXPORT void fl_set_formbrowser_vscrollbar( FL_OBJECT * ob,
                                              int         how );

FL_EXPORT FL_FORM *fl_get_formbrowser_topform( FL_OBJECT * ob );

FL_EXPORT int fl_set_formbrowser_topform( FL_OBJECT * ob,
                                          FL_FORM   * form );

FL_EXPORT FL_FORM * fl_set_formbrowser_topform_bynumber( FL_OBJECT * ob,
                                                         int         n );

FL_EXPORT int fl_set_formbrowser_xoffset( FL_OBJECT * ob,
                                          int         offset );

FL_EXPORT int fl_set_formbrowser_yoffset( FL_OBJECT * ob,
                                          int         offset );

FL_EXPORT int fl_get_formbrowser_xoffset( FL_OBJECT * ob );

FL_EXPORT int fl_get_formbrowser_yoffset( FL_OBJECT * ob );

FL_EXPORT int fl_find_formbrowser_form_number( FL_OBJECT * ob,
                                               FL_FORM   * form );

FL_EXPORT FL_OBJECT * fl_add_formbrowser( int          type,
                                          FL_Coord     x,
                                          FL_Coord     y,
                                          FL_Coord     w,
                                          FL_Coord     h,
                                          const char * label );

FL_EXPORT FL_OBJECT * fl_create_formbrowser( int          type,
                                             FL_Coord     x,
                                             FL_Coord     y,
                                             FL_Coord     w,
                                             FL_Coord     h,
                                             const char * label );

FL_EXPORT int fl_get_formbrowser_numforms( FL_OBJECT * ob );

#define fl_get_formbrowser_forms  fl_get_formbrowser_numforms

FL_EXPORT FL_FORM * fl_get_formbrowser_form( FL_OBJECT * ob,
                                             int         n );

#endif /* ! defined FL_FORMBROWSER_H */

/**
 * \file frame.h
 */

#ifndef FL_FRAME_H
#define FL_FRAME_H

/* types of frames */

enum {
    FL_NO_FRAME,
    FL_UP_FRAME,
    FL_DOWN_FRAME,
    FL_BORDER_FRAME,
    FL_SHADOW_FRAME,
    FL_ENGRAVED_FRAME,
    FL_ROUNDED_FRAME,
    FL_EMBOSSED_FRAME,
    FL_OVAL_FRAME
};

#define FL_FRAME_COL1   FL_BLACK   /* border color     */
#define FL_FRAME_COL2   FL_COL1    /* label background */
#define FL_FRAME_LCOL   FL_BLACK   /* label color      */

FL_EXPORT FL_OBJECT * fl_create_frame( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_frame( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

/* labeld frame */

FL_EXPORT FL_OBJECT * fl_create_labelframe( int          type,
                                            FL_Coord     x,
                                            FL_Coord     y,
                                            FL_Coord     w,
                                            FL_Coord     h,
                                            const char * label );

FL_EXPORT FL_OBJECT * fl_add_labelframe( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

#endif /* ! defined FL_FRAME_H */

/**
 * \file free.h
 *
 *  Object Class: Free
 */

#ifndef FL_FREE_H
#define FL_FREE_H


typedef enum {
    FL_NORMAL_FREE,
    FL_INACTIVE_FREE,
    FL_INPUT_FREE,
    FL_CONTINUOUS_FREE,
    FL_ALL_FREE
} FL_FREE_TYPE;

#define FL_SLEEPING_FREE  FL_INACTIVE_FREE

FL_EXPORT FL_OBJECT * fl_create_free( int            type,
                                      FL_Coord       x,
                                      FL_Coord       y,
                                      FL_Coord       w,
                                      FL_Coord       h,
                                      const char   * label,
                                      FL_HANDLEPTR   handle );

FL_EXPORT FL_OBJECT * fl_add_free( int            type,
                                   FL_Coord       x,
                                   FL_Coord       y,
                                   FL_Coord       w,
                                   FL_Coord       h,
                                   const char   * label,
                                   FL_HANDLEPTR   handle );

#endif /* ! defined FL_FREE_H */

/**
 * \file goodies.h
 */

#ifndef FL_GOODIES_H
#define FL_GOODIES_H

/***** Resources and misc. goodie routines ******/

#define FLAlertDismissLabel     "flAlert.dismiss.label"
#define FLAlertTitle            "flAlert.title"

#define FLQuestionYesLabel      "flQuestion.yes.label"
#define FLQuestionNoLabel       "flQuestion.no.label"
#define FLQuestionTitle         "flQuestion.title"

#define FLOKLabel               "flInput.ok.label"
#define FLInputClearLabel       "flInput.clear.label"
#define FLInputCancelLabel      "flInput.cancel.label"
#define FLInputTitle            "flInput.title"

#define FLChoiceTitle           "flChoice.title"

FL_EXPORT void fl_set_goodies_font(
        int style,
        int size
        );

/*********** messages and questions **************/

FL_EXPORT void fl_show_message( const char *,
                                const char *,
                                const char * );

FL_EXPORT void fl_show_messages( const char * );

#define fl_show_msg fl_show_messages_f
FL_EXPORT void fl_show_messages_f( const char *,
								   ... );

FL_EXPORT void fl_hide_message( void );

#define fl_hide_msg       fl_hide_message
#define fl_hide_messages  fl_hide_message

FL_EXPORT int fl_show_question( const char *,
                                int );

FL_EXPORT void fl_hide_question( void );

FL_EXPORT void fl_show_alert( const char *,
                              const char *,
                              const char *,
                              int );


#define fl_show_alert2  fl_show_alert_f
FL_EXPORT void fl_show_alert_f( int          c,
								const char * fmt,
                               ... );

FL_EXPORT void fl_hide_alert( void );

FL_EXPORT const char * fl_show_input( const char *,
                                      const char * );

FL_EXPORT void fl_hide_input( void );

FL_EXPORT const char * fl_show_simple_input( const char *,
                                             const char * );

FL_EXPORT int fl_show_colormap( int );

/********* choices *****************/

FL_EXPORT int fl_show_choices( const char *,
                               int,
                               const char *,
                               const char *,
                               const char *,
                               int );

FL_EXPORT int fl_show_choice( const char *,
                              const char *,
                              const char *,
                              int,
                              const char *,
                              const char *,
                              const char *,
                              int );

FL_EXPORT void fl_hide_choice( void );

FL_EXPORT void fl_set_choices_shortcut( const char *,
                                       const char *,
                                       const char * );

#define fl_set_choice_shortcut fl_set_choices_shortcut

/************ one liner ***************/

FL_EXPORT void fl_show_oneliner( const char *,
                                 FL_Coord,
                                 FL_Coord );

FL_EXPORT void fl_hide_oneliner( void );

FL_EXPORT void fl_set_oneliner_font( int,
                                     int );

FL_EXPORT void fl_set_oneliner_color( FL_COLOR,
                                      FL_COLOR );

FL_EXPORT void fl_set_tooltip_font( int,
                                    int );

FL_EXPORT void fl_set_tooltip_color( FL_COLOR,
                                     FL_COLOR );

FL_EXPORT void fl_set_tooltip_boxtype( int );

FL_EXPORT void fl_set_tooltip_lalign( int );

/************* command log **************/

typedef struct {
    FL_FORM   * form;
    void      * vdata;                  /* UNUSED, remove in later version */
    char      * cdata;                  /* UNUSED, remove in later version */
    long        ldata;                  /* UNUSED, remove in later version */
    FL_OBJECT * browser;
    FL_OBJECT * close_browser;
    FL_OBJECT * clear_browser;
} FD_CMDLOG;

#ifdef FL_WIN32
#define FL_PID_T HANDLE
#else
#define FL_PID_T long
#endif

FL_EXPORT FL_PID_T fl_exe_command( const char *,
                                   int );

FL_EXPORT int fl_end_command( FL_PID_T );

FL_EXPORT int fl_check_command( FL_PID_T );

FL_EXPORT FILE * fl_popen( const char *,
                           const char * );

FL_EXPORT int fl_pclose( FILE * );

FL_EXPORT int fl_end_all_command( void );

FL_EXPORT void fl_show_command_log( int );

FL_EXPORT void fl_hide_command_log( void );

FL_EXPORT void fl_clear_command_log( void );

FL_EXPORT void fl_addto_command_log( const char * );

FL_EXPORT void fl_addto_command_log_f( const char *,
									   ...);

FL_EXPORT void fl_set_command_log_position( int,
                                            int );

FL_EXPORT FD_CMDLOG * fl_get_command_log_fdstruct( void );

/* Aliases */

#define fl_open_command    fl_exe_command
#define fl_close_command   fl_end_command

/******* File selector *****************/

#define FL_MAX_FSELECTOR  6

typedef struct {
    FL_FORM   * fselect;
    void      * vdata;
    void      * cdata;
    long        ldata;
    FL_OBJECT * browser,
              * input,
              * prompt,
              * resbutt;
    FL_OBJECT * patbutt,
              * dirbutt,
              * cancel,
              * ready;
    FL_OBJECT * dirlabel,
              * patlabel;
    FL_OBJECT * appbutt[ 3 ];
} FD_FSELECTOR;

FL_EXPORT int fl_use_fselector( int );

FL_EXPORT const char * fl_show_fselector( const char *,
                                          const char *,
                                          const char *,
                                          const char * );

FL_EXPORT void fl_hide_fselector( void );

FL_EXPORT void fl_set_fselector_fontsize( int );

FL_EXPORT void fl_set_fselector_fontstyle( int );

FL_EXPORT void fl_set_fselector_placement( int );

FL_EXPORT void fl_set_fselector_border( int );

#define fl_set_fselector_transient( b )   \
            fl_set_fselector_border( ( b ) ? FL_TRANSIENT : FL_FULLBORDER )

FL_EXPORT void fl_set_fselector_callback( FL_FSCB,
                                          void * );

FL_EXPORT const char * fl_get_filename( void );

FL_EXPORT const char * fl_get_directory( void );

FL_EXPORT const char * fl_get_pattern( void );

FL_EXPORT int fl_set_directory( const char * );

FL_EXPORT void fl_set_pattern( const char * );

FL_EXPORT void fl_refresh_fselector( void );

FL_EXPORT void fl_add_fselector_appbutton( const char *,
                                           void ( * )( void * ),
                                           void * );

FL_EXPORT void fl_remove_fselector_appbutton( const char * );

FL_EXPORT void fl_disable_fselector_cache( int );

FL_EXPORT void fl_invalidate_fselector_cache( void );

FL_EXPORT FL_FORM * fl_get_fselector_form( void );

FL_EXPORT FD_FSELECTOR * fl_get_fselector_fdstruct( void );

FL_EXPORT void fl_hide_fselector( void );

FL_EXPORT void fl_set_fselector_filetype_marker( int,
                                                 int,
                                                 int,
                                                 int,
                                                 int );

#define fl_show_file_selector     fl_show_fselector
#define fl_set_fselector_cb       fl_set_fselector_callback

#define fl_set_fselector_title( s )   \
        fl_set_form_title( fl_get_fselector_form( ), s )

FL_EXPORT int fl_goodies_atclose( FL_FORM *,
                                  void * );

FL_EXPORT int fl_show_color_chooser( const int * rgb_in,
									 int       * rgb_out );

#endif /* ! defined FL_GOODIES_H */

/**
 * \file input.h
 */

#ifndef FL_INPUT_H
#define FL_INPUT_H


/***** Types    *****/

typedef enum {
    FL_NORMAL_INPUT,
    FL_FLOAT_INPUT,
    FL_INT_INPUT,
    FL_DATE_INPUT,
    FL_MULTILINE_INPUT,
    FL_HIDDEN_INPUT,
    FL_SECRET_INPUT
} FL_INPUT_TYPE;

/* for date input */

enum {
    FL_INPUT_MMDD,
    FL_INPUT_DDMM
};

enum {
    FL_NORMAL_INPUT_MODE,
    FL_DOS_INPUT_MODE
};

/***** Defaults *****/

#define FL_INPUT_BOXTYPE    FL_DOWN_BOX
#define FL_INPUT_COL1       FL_COL1
#define FL_INPUT_COL2       FL_MCOL
#define FL_INPUT_LCOL       FL_LCOL
#define FL_INPUT_ALIGN      FL_ALIGN_LEFT

/***** Others   *****/

#define FL_INPUT_TCOL       FL_LCOL
#define FL_INPUT_CCOL       FL_BLUE

#define FL_RINGBELL         ( 1 << 4 )

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_input( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_input( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

FL_EXPORT void fl_set_input( FL_OBJECT  * ob,
                             const char * str );

FL_EXPORT void fl_set_input_f( FL_OBJECT  * obj,
							   const char * fmt,
							   ... );

FL_EXPORT void fl_set_input_return( FL_OBJECT    * ob,
                                    unsigned int   when );

FL_EXPORT void fl_set_input_color( FL_OBJECT * ob,
                                   FL_COLOR    textcol,
                                   FL_COLOR    curscol );

FL_EXPORT void fl_get_input_color( FL_OBJECT * ob,
                                   FL_COLOR  * textcol,
                                   FL_COLOR  * curscol );

FL_EXPORT void fl_set_input_scroll( FL_OBJECT * ob,
                                    int         yes );

FL_EXPORT void fl_set_input_cursorpos( FL_OBJECT * ob,
                                       int         xpos,
                                       int         ypos );

FL_EXPORT void fl_set_input_selected( FL_OBJECT * ob,
                                      int         yes );

FL_EXPORT void fl_set_input_selected_range( FL_OBJECT * ob,
                                            int         begin,
                                            int         end );

FL_EXPORT const char *fl_get_input_selected_range( FL_OBJECT * ob,
                                                   int       * begin,
                                                   int       * end );

FL_EXPORT void fl_set_input_maxchars( FL_OBJECT * ob,
                                      int         maxchars );

FL_EXPORT void fl_set_input_format( FL_OBJECT * ob,
                                    int         fmt,
                                    int         sep );

FL_EXPORT void fl_set_input_hscrollbar( FL_OBJECT * ob,
                                        int         pref );

FL_EXPORT void fl_set_input_vscrollbar( FL_OBJECT * ob,
                                        int         pref );

FL_EXPORT void fl_set_input_topline( FL_OBJECT * ob,
                                     int         top );

FL_EXPORT void fl_set_input_scrollbarsize( FL_OBJECT * ob,
                                           int         hh,
                                           int         vw );

FL_EXPORT void fl_get_input_scrollbarsize( FL_OBJECT * ob,
                                           int       * hh,
                                           int       * vw );

FL_EXPORT void fl_set_input_xoffset( FL_OBJECT * ob,
                                     int         xoff );

FL_EXPORT int fl_get_input_xoffset( FL_OBJECT * ob );

FL_EXPORT int fl_set_input_fieldchar( FL_OBJECT * ob,
                                      int         fchar );

FL_EXPORT int fl_get_input_topline( FL_OBJECT * ob );

FL_EXPORT int fl_get_input_screenlines( FL_OBJECT * ob );

FL_EXPORT int fl_get_input_cursorpos( FL_OBJECT * ob,
                                      int       * x,
                                      int       * y );

FL_EXPORT void fl_set_input_cursor_visible( FL_OBJECT * ob,
                                            int         visible );

FL_EXPORT int fl_get_input_numberoflines( FL_OBJECT * ob );

FL_EXPORT void fl_get_input_format( FL_OBJECT * ob,
                                    int       * fmt,
                                    int       * sep );

FL_EXPORT const char * fl_get_input( FL_OBJECT * ob );

typedef int ( * FL_INPUT_VALIDATOR )(FL_OBJECT  *,
									 const char *,
									 const char *,
									 int );

#define FL_INPUTVALIDATOR FL_INPUT_VALIDATOR

FL_EXPORT FL_INPUT_VALIDATOR
fl_set_input_filter( FL_OBJECT          * ob,
					 FL_INPUT_VALIDATOR   validate );

FL_EXPORT int fl_validate_input( FL_OBJECT *obj );

#define fl_set_input_shortcut   fl_set_object_shortcut

/* edit keys. */

typedef struct {
    /* basic editing */

    long del_prev_char;     /* delete previous char    */
    long del_next_char;     /* delete next char        */
    long del_prev_word;     /* delete previous word    */
    long del_next_word;     /* delete next word        */

    /* movement */

    long moveto_prev_line;  /* one line  up             */
    long moveto_next_line;  /* one line down            */
    long moveto_prev_char;  /* one char left            */
    long moveto_next_char;  /* one char right           */
    long moveto_prev_word;  /* one word left            */
    long moveto_next_word;  /* one word right           */
    long moveto_prev_page;  /* one page up              */
    long moveto_next_page;  /* one page down            */
    long moveto_bol;        /* move to begining of line */
    long moveto_eol;        /* move to end of line      */
    long moveto_bof;        /* move to begin of file    */
    long moveto_eof;        /* move to end of file      */

    /* misc. stuff */

    long transpose;         /* switch two char positions */
    long paste;             /* paste the edit buffer    */
    long backspace;         /* another  del_prev_char   */
    long del_to_bol;        /* cut to begining of line  */
    long del_to_eol;        /* cut to end of line       */
    long clear_field;       /* delete everything        */
    long del_to_eos;        /* not implemented          */
} FL_EditKeymap;

FL_EXPORT void fl_set_input_editkeymap( const FL_EditKeymap * keymap );

FL_EXPORT void fl_get_input_editkeymap( FL_EditKeymap * keymap );

FL_EXPORT void fl_set_default_editkeymap( void );

FL_EXPORT int fl_set_input_mode( int mode );

#endif /* ! defined FL_INPUT_H */

/**
 * \file menu.h
 */

#ifndef FL_MENU_H
#define FL_MENU_H


/************   Object Class: Menu         ************/

typedef enum {
    FL_TOUCH_MENU,
    FL_PUSH_MENU,
    FL_PULLDOWN_MENU
} FL_MENU_TYPE;

/***** Defaults *****/

#define FL_MENU_BOXTYPE     FL_BORDER_BOX
#define FL_MENU_COL1        FL_COL1
#define FL_MENU_COL2        FL_MCOL
#define FL_MENU_LCOL        FL_LCOL
#define FL_MENU_ALIGN       FL_ALIGN_CENTER

/***** Others   *****/

#define FL_MENU_MAXITEMS    128
#define FL_MENU_MAXSTR      64        /* not used anymore! JTT */

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_menu( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT FL_OBJECT * fl_add_menu( int          type,
                                   FL_Coord     x,
                                   FL_Coord     y,
                                   FL_Coord     w,
                                   FL_Coord     h,
                                   const char * label );

FL_EXPORT void fl_clear_menu( FL_OBJECT * ob );

FL_EXPORT void fl_set_menu( FL_OBJECT  * ob,
                            const char * menustr ,
                            ... );

FL_EXPORT int fl_addto_menu( FL_OBJECT  * ob,
                             const char * menustr,
                             ... );

FL_EXPORT void fl_replace_menu_item( FL_OBJECT  * ob,
                                     int          numb,
                                     const char * str,
                                     ... );

FL_EXPORT void fl_delete_menu_item( FL_OBJECT * ob,
                                    int         numb );

FL_EXPORT FL_PUP_CB fl_set_menu_item_callback( FL_OBJECT *  ob,
                                               int          numb,
                                               FL_PUP_CB    cb );

FL_EXPORT void fl_set_menu_item_shortcut( FL_OBJECT  * ob,
                                          int          numb,
                                          const char * str );

FL_EXPORT void fl_set_menu_item_mode( FL_OBJECT    * ob,
                                      int            numb,
                                      unsigned int   mode );

FL_EXPORT void fl_show_menu_symbol( FL_OBJECT * ob,
                                    int         show );

FL_EXPORT void fl_set_menu_popup( FL_OBJECT * ob,
                                  int         pup );

FL_EXPORT int fl_get_menu_popup( FL_OBJECT * ob );

FL_EXPORT int fl_get_menu( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_menu_item_text( FL_OBJECT * ob,
                                              int         numb );

FL_EXPORT int fl_get_menu_maxitems( FL_OBJECT * ob );

FL_EXPORT unsigned int fl_get_menu_item_mode( FL_OBJECT * ob,
                                              int         numb );

FL_EXPORT const char *fl_get_menu_text( FL_OBJECT * ob );

FL_EXPORT int fl_set_menu_entries( FL_OBJECT    * ob,
                                   FL_PUP_ENTRY * ent );

FL_EXPORT int fl_set_menu_notitle( FL_OBJECT * ob,
                                   int         off );

FL_EXPORT int fl_set_menu_item_id( FL_OBJECT * ob,
                                   int         item,
                                   int         id );

#endif /* ! defined FL_MENU_H */


#ifndef FL_NMENU_H
#define FL_NMENU_H


/* Nmenu object types */

enum {
    FL_NORMAL_NMENU,
    FL_NORMAL_TOUCH_NMENU,
    FL_BUTTON_NMENU,
    FL_BUTTON_TOUCH_NMENU
};

FL_EXPORT FL_OBJECT *fl_create_nmenu(
        int,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        const char *
        );

FL_EXPORT FL_OBJECT *fl_add_nmenu(
        int,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        FL_Coord,
        const char *
        );

FL_EXPORT int fl_clear_nmenu(
        FL_OBJECT *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_add_nmenu_items(
        FL_OBJECT  *,
        const char *,
        ...
        );

FL_EXPORT FL_POPUP_ENTRY *fl_insert_nmenu_items(
        FL_OBJECT *,
        FL_POPUP_ENTRY *,
        const char     *,
        ...
        );

FL_EXPORT FL_POPUP_ENTRY *fl_replace_nmenu_item(
        FL_OBJECT *,
        FL_POPUP_ENTRY *,
        const char *,
        ...
        );

FL_EXPORT int fl_delete_nmenu_item(
        FL_OBJECT *,
        FL_POPUP_ENTRY *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_set_nmenu_items(
        FL_OBJECT *,
        FL_POPUP_ITEM *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_add_nmenu_items2(
		FL_OBJECT *,
		FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP_ENTRY *fl_insert_nmenu_items2(
		FL_OBJECT *,
		FL_POPUP_ENTRY *,
		FL_POPUP_ITEM  * );

FL_EXPORT FL_POPUP_ENTRY *fl_replace_nmenu_items2(
		FL_OBJECT *,
		FL_POPUP_ENTRY *,
		FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP *fl_get_nmenu_popup(
        FL_OBJECT *
        );

FL_EXPORT int fl_set_nmenu_popup(
        FL_OBJECT *,
        FL_POPUP  *
        );

FL_EXPORT FL_POPUP_RETURN *fl_get_nmenu_item(
        FL_OBJECT *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_get_nmenu_item_by_value(
        FL_OBJECT *,
        long int
        );

FL_EXPORT FL_POPUP_ENTRY *fl_get_nmenu_item_by_label(
        FL_OBJECT *,
        const char *
        );

FL_EXPORT FL_POPUP_ENTRY *fl_get_nmenu_item_by_text(
        FL_OBJECT *,
        const char *
        );

FL_EXPORT int fl_set_nmenu_policy(
        FL_OBJECT *,
        int
        );

FL_EXPORT FL_COLOR fl_set_nmenu_hl_text_color(
        FL_OBJECT *,
        FL_COLOR
        );

#endif /* ! defined FL_NMENU_H */

/**
 * \file positioner.h
 */

#ifndef FL_POSITIONER_H
#define FL_POSITIONER_H


#define FL_NORMAL_POSITIONER      0
#define FL_OVERLAY_POSITIONER     1
#define FL_INVISIBLE_POSITIONER   2

/***** Defaults *****/

#define FL_POSITIONER_BOXTYPE   FL_DOWN_BOX
#define FL_POSITIONER_COL1      FL_COL1
#define FL_POSITIONER_COL2      FL_RED
#define FL_POSITIONER_LCOL      FL_LCOL
#define FL_POSITIONER_ALIGN     FL_ALIGN_BOTTOM

typedef int ( * FL_POSITIONER_VALIDATOR )( FL_OBJECT * obj,
										   double      x,
										   double      y,
										   double    * x_repl,
										   double    * y_repl );

#define FL_POSITIONER_INVALID  0
#define FL_POSITIONER_VALID    1
#define FL_POSITIONER_REPLACED 2

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_positioner( int          type,
                                            FL_Coord     x,
                                            FL_Coord     y,
                                            FL_Coord     w,
                                            FL_Coord     h,
                                            const char * label );

FL_EXPORT FL_OBJECT * fl_add_positioner( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

FL_EXPORT int fl_set_positioner_values( FL_OBJECT * obj,
										double      new_x,
										double      new_y );

FL_EXPORT int fl_set_positioner_xvalue( FL_OBJECT * ob,
										double      val );

FL_EXPORT double fl_get_positioner_xvalue( FL_OBJECT * ob );

FL_EXPORT void fl_set_positioner_xbounds( FL_OBJECT * ob,
                                          double      min,
                                          double      max );

FL_EXPORT void fl_get_positioner_xbounds( FL_OBJECT * ob,
                                          double    * min,
                                          double    * max );

FL_EXPORT int fl_set_positioner_yvalue( FL_OBJECT * ob,
										double      val );

FL_EXPORT double fl_get_positioner_yvalue( FL_OBJECT * ob );

FL_EXPORT void fl_set_positioner_ybounds( FL_OBJECT * ob,
                                          double      min,
                                          double      max );

FL_EXPORT void fl_get_positioner_ybounds( FL_OBJECT * ob,
                                          double    * min,
                                          double    * max );

FL_EXPORT void fl_set_positioner_xstep( FL_OBJECT * ob,
                                        double      value );

FL_EXPORT double fl_get_positioner_xstep( FL_OBJECT * ob );

FL_EXPORT void fl_set_positioner_ystep( FL_OBJECT * ob,
                                        double      value );

FL_EXPORT double fl_get_positioner_ystep( FL_OBJECT * ob );

FL_EXPORT void fl_set_positioner_return( FL_OBJECT    * ob,
                                         unsigned int   when );

FL_EXPORT void fl_set_positioner_mouse_buttons( FL_OBJECT    * obj,
												unsigned int   mouse_buttons );

FL_EXPORT void fl_get_positioner_mouse_buttons( FL_OBJECT    * obj,
												unsigned int * mouse_buttons );

FL_EXPORT int fl_get_positioner_numb( FL_OBJECT * obj );

FL_EXPORT FL_POSITIONER_VALIDATOR
fl_set_positioner_validator( FL_OBJECT               * obj,
							 FL_POSITIONER_VALIDATOR   validator );

FL_EXPORT void fl_reset_positioner( FL_OBJECT * obj );


#endif /* ! defined FL_POSITIONER_H */


#ifndef FL_SCROLLBAR_H
#define FL_SCROLLBAR_H

enum {
    FL_VERT_SCROLLBAR,
    FL_HOR_SCROLLBAR,

    FL_VERT_THIN_SCROLLBAR,
    FL_HOR_THIN_SCROLLBAR,

    FL_VERT_NICE_SCROLLBAR,
    FL_HOR_NICE_SCROLLBAR,

    FL_VERT_PLAIN_SCROLLBAR,
    FL_HOR_PLAIN_SCROLLBAR,

    FL_HOR_BASIC_SCROLLBAR  = FL_HOR_PLAIN_SCROLLBAR,
    FL_VERT_BASIC_SCROLLBAR = FL_VERT_PLAIN_SCROLLBAR
};

enum {
	FL_NORMAL_SCROLLBAR,
	FL_THIN_SCROLLBAR,
	FL_NICE_SCROLLBAR,
	FL_PLAIN_SCROLLBAR
};

#define FL_SCROLLBAR_ALIGN   FL_ALIGN_BOTTOM


FL_EXPORT FL_OBJECT * fl_create_scrollbar( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_scrollbar( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT double fl_get_scrollbar_value( FL_OBJECT * ob );

FL_EXPORT void fl_set_scrollbar_value( FL_OBJECT * ob,
                                       double      val );

FL_EXPORT void fl_set_scrollbar_size( FL_OBJECT * ob,
                                      double      val );

FL_EXPORT double fl_get_scrollbar_size( FL_OBJECT * obj );

FL_EXPORT void fl_set_scrollbar_increment( FL_OBJECT * ob,
                                           double      l,
                                           double      r );

FL_EXPORT void fl_get_scrollbar_increment( FL_OBJECT * ob,
                                           double    * a,
                                           double    * b );

FL_EXPORT void fl_set_scrollbar_bounds( FL_OBJECT * ob,
                                        double      b1,
                                        double      b2 );

FL_EXPORT void fl_get_scrollbar_bounds( FL_OBJECT * ob,
                                        double    * b1,
                                        double    * b2 );

FL_EXPORT void fl_set_scrollbar_return( FL_OBJECT    * ob,
                                        unsigned int   when );

FL_EXPORT void fl_set_scrollbar_step( FL_OBJECT * ob,
                                      double      step );

FL_EXPORT int fl_get_scrollbar_repeat( FL_OBJECT * obj );

FL_EXPORT void fl_set_scrollbar_repeat( FL_OBJECT * obj,
										int         millisec );

#endif /* ! defined FL_SCROLLBAR_H */

/**
 * \file select.h
 */

#ifndef FL_SELECT_H
#define FL_SELECT_H


/* Select object types */

enum {
    FL_NORMAL_SELECT,
    FL_MENU_SELECT,
    FL_DROPLIST_SELECT
};

/* Defaults */

#define FL_SELECT_COL1          FL_COL1
#define FL_SELECT_COL2          FL_MCOL
#define FL_SELECT_LCOL          FL_LCOL
#define FL_SELECT_ALIGN         FL_ALIGN_LEFT

FL_EXPORT FL_OBJECT *fl_create_select( int,
                                       FL_Coord,
                                       FL_Coord,
                                       FL_Coord,
                                       FL_Coord,
                                       const char * );

FL_EXPORT FL_OBJECT *fl_add_select( int,
                                    FL_Coord,
                                    FL_Coord,
                                    FL_Coord,
                                    FL_Coord,
                                    const char * );

FL_EXPORT int fl_clear_select( FL_OBJECT * );

FL_EXPORT FL_POPUP_ENTRY *fl_add_select_items( FL_OBJECT  *,
                                               const char *,
                                               ... );

FL_EXPORT FL_POPUP_ENTRY *fl_insert_select_items( FL_OBJECT *,
                                                  FL_POPUP_ENTRY *,
                                                  const char     *,
                                                  ... );

FL_EXPORT FL_POPUP_ENTRY *fl_replace_select_item( FL_OBJECT *,
                                                  FL_POPUP_ENTRY *,
                                                  const char *,
                                                  ... );

FL_EXPORT int fl_delete_select_item( FL_OBJECT *,
                                     FL_POPUP_ENTRY * );

FL_EXPORT long fl_set_select_items( FL_OBJECT *,
                                    FL_POPUP_ITEM * );

FL_EXPORT FL_POPUP *fl_get_select_popup( FL_OBJECT * );

FL_EXPORT int fl_set_select_popup( FL_OBJECT *,
                                   FL_POPUP  * );

FL_EXPORT FL_POPUP_RETURN *fl_get_select_item( FL_OBJECT * );

FL_EXPORT FL_POPUP_RETURN *fl_set_select_item( FL_OBJECT *,
                                               FL_POPUP_ENTRY * );

FL_EXPORT FL_POPUP_ENTRY *fl_get_select_item_by_value( FL_OBJECT *,
                                                       long );

FL_EXPORT FL_POPUP_ENTRY *fl_get_select_item_by_label( FL_OBJECT *,
                                                       const char * );

FL_EXPORT FL_POPUP_ENTRY * fl_get_select_item_by_label_f( FL_OBJECT  *,
														  const char *,
														  ... );

FL_EXPORT FL_POPUP_ENTRY * fl_get_select_item_by_text_f( FL_OBJECT  * obj,
														 const char * fmt,
														 ... );

FL_EXPORT FL_POPUP_ENTRY *fl_get_select_item_by_text( FL_OBJECT *,
                                                      const char * );

FL_EXPORT FL_COLOR fl_get_select_text_color( FL_OBJECT * );

FL_EXPORT FL_COLOR fl_set_select_text_color( FL_OBJECT *,
                                             FL_COLOR );

FL_EXPORT int fl_get_select_text_font( FL_OBJECT *,
                                       int *,
                                       int * );

FL_EXPORT int fl_set_select_text_font( FL_OBJECT *,
                                       int,
                                       int );

FL_EXPORT int fl_get_select_text_align( FL_OBJECT * );

FL_EXPORT int fl_set_select_text_align( FL_OBJECT *,
                                        int );

FL_EXPORT int fl_set_select_policy( FL_OBJECT *,
                                    int );

#endif /* ! defined FL_SELECT_H */

/**
 * \file slider.h
 *
 * Object Class: Slider
 */

#ifndef FL_SLIDER_H
#define FL_SLIDER_H


#define FL_HOR_FLAG     1
#define FL_SCROLL_FLAG  16

typedef enum {
    FL_VERT_SLIDER           = 0,
    FL_HOR_SLIDER            = FL_VERT_SLIDER          | FL_HOR_FLAG,

    FL_VERT_FILL_SLIDER      = 2,
    FL_HOR_FILL_SLIDER       = FL_VERT_FILL_SLIDER     | FL_HOR_FLAG,

    FL_VERT_NICE_SLIDER      = 4,
    FL_HOR_NICE_SLIDER       = FL_VERT_NICE_SLIDER     | FL_HOR_FLAG,

    FL_VERT_BROWSER_SLIDER   = 6,
    FL_HOR_BROWSER_SLIDER    = FL_VERT_BROWSER_SLIDER  | FL_HOR_FLAG,

	FL_VERT_PROGRESS_BAR     = 8,
	FL_HOR_PROGRESS_BAR      = FL_VERT_PROGRESS_BAR    | FL_HOR_FLAG,

    /* The following are for use with scrollbars only! */

    /* For FL_VERT_SCROLLBAR and FL_HOR_SCROLLBAR */

    FL_VERT_BROWSER_SLIDER2   = FL_VERT_SLIDER         | FL_SCROLL_FLAG,
    FL_HOR_BROWSER_SLIDER2    = FL_HOR_SLIDER          | FL_SCROLL_FLAG,

    /* for FL_VERT_THIN_SCROLLBAR and FL_VERT_THIN_SCROLLBAR */

    FL_VERT_THIN_SLIDER       = FL_VERT_FILL_SLIDER    | FL_SCROLL_FLAG,
    FL_HOR_THIN_SLIDER        = FL_HOR_FILL_SLIDER     | FL_SCROLL_FLAG,

    /* For FL_VERT_NICE_SCROLLBAR and FL_HOR_NICE_SCROLLBAR */

    FL_VERT_NICE_SLIDER2      = FL_VERT_NICE_SLIDER    | FL_SCROLL_FLAG,
    FL_HOR_NICE_SLIDER2       = FL_HOR_NICE_SLIDER     | FL_SCROLL_FLAG,

    /* for use as FL_VERT_PLAIN_SCROLLBAR and FL_VERT_PLAIN_SCROLLBAR */

    FL_VERT_BASIC_SLIDER      = FL_VERT_BROWSER_SLIDER | FL_SCROLL_FLAG,
    FL_HOR_BASIC_SLIDER       = FL_HOR_BROWSER_SLIDER  | FL_SCROLL_FLAG
} FL_SLIDER_TYPE;

/***** Defaults *****/

#define FL_SLIDER_BW1       FL_BOUND_WIDTH
#define FL_SLIDER_BW2       FL_abs( FL_BOUND_WIDTH )
#define FL_SLIDER_BOXTYPE   FL_DOWN_BOX
#define FL_SLIDER_COL1      FL_COL1
#define FL_SLIDER_COL2      FL_COL1
#define FL_SLIDER_LCOL      FL_LCOL
#define FL_SLIDER_ALIGN     FL_ALIGN_BOTTOM

/***** Others   *****/

#define FL_SLIDER_FINE      0.25
#define FL_SLIDER_WIDTH     0.10

#define FL_SLIDER_MAX_PREC  10

/***** Routines *****/

FL_EXPORT FL_OBJECT * fl_create_slider( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_slider( int          type,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT FL_OBJECT * fl_create_valslider( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_valslider( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT void fl_set_slider_value( FL_OBJECT * ob,
                                    double      val );

FL_EXPORT double fl_get_slider_value( FL_OBJECT * ob );

FL_EXPORT void fl_set_slider_bounds( FL_OBJECT * ob,
                                     double      min,
                                     double      max );

FL_EXPORT void fl_get_slider_bounds( FL_OBJECT * ob,
                                     double    * min,
                                     double    * max );

FL_EXPORT void fl_set_slider_return( FL_OBJECT    * ob,
                                     unsigned int   value );

FL_EXPORT void fl_set_slider_step( FL_OBJECT * ob,
                                   double      value );

FL_EXPORT void fl_set_slider_increment( FL_OBJECT * ob,
                                        double      l,
                                        double      r );

FL_EXPORT void fl_get_slider_increment( FL_OBJECT * ob,
                                        double    * l,
                                        double    * r );

FL_EXPORT void fl_set_slider_size( FL_OBJECT * ob,
                                   double      size );

FL_EXPORT double fl_get_slider_size( FL_OBJECT * obj );

FL_EXPORT void fl_set_slider_precision( FL_OBJECT * ob,
                                        int         prec );

FL_EXPORT void fl_set_slider_filter( FL_OBJECT     * ob,
                                     FL_VAL_FILTER   filter );

FL_EXPORT int fl_get_slider_repeat( FL_OBJECT * obj );

FL_EXPORT void fl_set_slider_repeat( FL_OBJECT * obj,
									 int         millisec );

FL_EXPORT void fl_set_slider_mouse_buttons( FL_OBJECT    * obj,
											unsigned int   mouse_buttons );
FL_EXPORT void fl_get_slider_mouse_buttons( FL_OBJECT    * obj,
											unsigned int * mouse_buttons );


#endif /* ! defined FL_SLIDER_H */

#ifndef FL_SPINNER_H
#define FL_SPINNER_H

typedef enum {
    FL_INT_SPINNER,
    FL_FLOAT_SPINNER
} FL_SPINNER_TYPE;

FL_EXPORT FL_OBJECT * fl_create_spinner( int            type,
                                         FL_Coord       x,
                                         FL_Coord       y,
                                         FL_Coord       w,
                                         FL_Coord       h,
                                         const char * label );

FL_EXPORT FL_OBJECT * fl_add_spinner( int            type,
                                      FL_Coord   x,
                                      FL_Coord   y,
                                      FL_Coord   w,
                                      FL_Coord   h,
                                      const char * label );

FL_EXPORT double fl_get_spinner_value( FL_OBJECT * obj );

FL_EXPORT double fl_set_spinner_value( FL_OBJECT * obj,
                                       double      val );

FL_EXPORT void fl_set_spinner_bounds( FL_OBJECT * obj,
                                      double      min,
                                      double      max );

FL_EXPORT void fl_get_spinner_bounds( FL_OBJECT * obj,
                                      double    * min,
                                      double    * max );

FL_EXPORT void fl_set_spinner_step( FL_OBJECT * obj,
                                    double      step );

FL_EXPORT double fl_get_spinner_step( FL_OBJECT * obj );

FL_EXPORT void fl_set_spinner_precision( FL_OBJECT * obj,
                                         int         prec );

FL_EXPORT int fl_get_spinner_precision( FL_OBJECT * obj );

FL_EXPORT FL_OBJECT * fl_get_spinner_input( FL_OBJECT * obj );

FL_EXPORT FL_OBJECT * fl_get_spinner_up_button( FL_OBJECT * obj );

FL_EXPORT FL_OBJECT * fl_get_spinner_down_button( FL_OBJECT * obj );


#endif /* ! defined FL_SPINNER_H */

/**
 * \file tabfolder.h
 */

#ifndef FL_FOLDER_H
#define FL_FOLDER_H

enum {
    FL_TOP_TABFOLDER,       /* tab on top */
    FL_BOTTOM_TABFOLDER,
    FL_LEFT_TABFOLDER,
    FL_RIGHT_TABFOLDER,
    FL_NORMAL_TABFOLDER = FL_TOP_TABFOLDER
};

enum {
    FL_NO,
    FL_FIT,
    FL_ENLARGE_ONLY
};

FL_EXPORT FL_OBJECT * fl_create_tabfolder( int          type,
                                           FL_Coord     x,
                                           FL_Coord     y,
                                           FL_Coord     w,
                                           FL_Coord     h,
                                           const char * label );

FL_EXPORT FL_OBJECT * fl_add_tabfolder( int          type,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_addto_tabfolder( FL_OBJECT  * ob,
                                          const char * title,
                                          FL_FORM    * form );

FL_EXPORT FL_FORM * fl_get_tabfolder_folder_bynumber( FL_OBJECT * ob,
                                                      int         num );

FL_EXPORT FL_FORM * fl_get_tabfolder_folder_byname( FL_OBJECT  * ob,
                                                    const char * name );

FL_EXPORT FL_FORM * fl_get_tabfolder_folder_byname_f( FL_OBJECT  * ob,
													  const char * fmt,
													  ...);

FL_EXPORT void fl_delete_folder( FL_OBJECT * ob,
                                 FL_FORM   * form );

FL_EXPORT void fl_delete_folder_bynumber( FL_OBJECT * ob,
                                          int         num );

FL_EXPORT void fl_delete_folder_byname( FL_OBJECT  * ob,
                                        const char * name );

FL_EXPORT void fl_delete_folder_byname_f( FL_OBJECT  * ob,
										  const char * fmt,
										  ... );

FL_EXPORT void fl_set_folder( FL_OBJECT * ob,
                              FL_FORM   * form );

FL_EXPORT void fl_set_folder_byname( FL_OBJECT  * ob,
                                     const char * name );

FL_EXPORT void fl_set_folder_byname_f( FL_OBJECT  * ob,
									   const char * fmt,
									   ... );

FL_EXPORT void fl_set_folder_bynumber( FL_OBJECT * ob,
                                       int         num );

FL_EXPORT FL_FORM * fl_get_folder( FL_OBJECT * ob );

FL_EXPORT int fl_get_folder_number( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_folder_name( FL_OBJECT * ob );

FL_EXPORT int fl_get_tabfolder_numfolders( FL_OBJECT * ob );

FL_EXPORT FL_FORM * fl_get_active_folder( FL_OBJECT * ob );

FL_EXPORT int fl_get_active_folder_number( FL_OBJECT * ob );

FL_EXPORT const char * fl_get_active_folder_name( FL_OBJECT * ob );


FL_EXPORT void fl_get_folder_area( FL_OBJECT * ob,
                                   FL_Coord  * x,
                                   FL_Coord  * y,
                                   FL_Coord  * w,
                                   FL_Coord  * h );

FL_EXPORT void fl_replace_folder_bynumber( FL_OBJECT * ob,
                                           int         num,
                                           FL_FORM   * form );

FL_EXPORT int fl_set_tabfolder_autofit( FL_OBJECT * ob,
                                        int         y );

FL_EXPORT int fl_set_default_tabfolder_corner( int n );

FL_EXPORT int fl_set_tabfolder_offset( FL_OBJECT * obj,
                                       int         offset );

FL_EXPORT int fl_get_tabfolder_offset( FL_OBJECT * obj );

#endif /* ! defined FL_FOLDER_H */

/**
 * \file text.h
 */

#ifndef FL_TEXT_H
#define FL_TEXT_H

enum {
    FL_NORMAL_TEXT
};

#define FL_TEXT_BOXTYPE    FL_FLAT_BOX
#define FL_TEXT_COL1       FL_COL1
#define FL_TEXT_COL2       FL_MCOL
#define FL_TEXT_LCOL       FL_LCOL
#define FL_TEXT_ALIGN      ( FL_ALIGN_LEFT | FL_ALIGN_INSIDE )

FL_EXPORT FL_OBJECT * fl_create_text( int          type,
                                      FL_Coord     x,
                                      FL_Coord     y,
                                      FL_Coord     w,
                                      FL_Coord     h,
                                      const char * label );

FL_EXPORT FL_OBJECT * fl_add_text( int          type,
                                   FL_Coord     x,
                                   FL_Coord     y,
                                   FL_Coord     w,
                                   FL_Coord     h,
                                   const char * label );

#endif /* ! defined FL_TEXT_H */

/**
 * \file thumbwheel.h
 */

#ifndef FL_THUMBWHEEL_H
#define FL_THUMBWHEEL_H


enum {
    FL_VERT_THUMBWHEEL,
    FL_HOR_THUMBWHEEL
};

/* defaults */

#define FL_THUMBWHEEL_COL1      FL_COL1
#define FL_THUMBWHEEL_COL2      FL_COL1
#define FL_THUMBWHEEL_LCOL      FL_BLACK
#define FL_THUMBWHEEL_BOXTYPE   FL_BORDER_BOX
#define FL_THUMBWHEEL_ALIGN     FL_ALIGN_BOTTOM

FL_EXPORT double fl_get_thumbwheel_value( FL_OBJECT * ob );

FL_EXPORT double fl_set_thumbwheel_value( FL_OBJECT * ob,
                                          double      value );

FL_EXPORT double fl_get_thumbwheel_step( FL_OBJECT * ob );

FL_EXPORT double fl_set_thumbwheel_step( FL_OBJECT * ob,
                                         double      step );

FL_EXPORT int fl_set_thumbwheel_return( FL_OBJECT    * ob,
                                        unsigned int   when );

FL_EXPORT int fl_set_thumbwheel_crossover( FL_OBJECT * ob,
                                           int         flag );

FL_EXPORT void fl_set_thumbwheel_bounds( FL_OBJECT * ob,
                                         double      min,
                                         double      max );

FL_EXPORT void fl_get_thumbwheel_bounds( FL_OBJECT * ob,
                                         double    * min,
                                         double    * max );

FL_EXPORT FL_OBJECT * fl_create_thumbwheel( int          type,
                                            FL_Coord     x,
                                            FL_Coord     y,
                                            FL_Coord     w,
                                            FL_Coord     h,
                                            const char * label );

FL_EXPORT FL_OBJECT * fl_add_thumbwheel( int          type,
                                         FL_Coord     x,
                                         FL_Coord     y,
                                         FL_Coord     w,
                                         FL_Coord     h,
                                         const char * label );

#endif /* ! defined FL_THUMBWHEEL_H */

/**
 * \file timer.h
 *
 *  Object Class: Timer
 */

#ifndef FL_TIMER_H
#define FL_TIMER_H


typedef enum {
    FL_NORMAL_TIMER,
    FL_VALUE_TIMER,
    FL_HIDDEN_TIMER
} FL_TIMER_TYPE;

/***** Defaults *****/

#define FL_TIMER_BOXTYPE    FL_DOWN_BOX
#define FL_TIMER_COL1       FL_COL1
#define FL_TIMER_COL2       FL_RED
#define FL_TIMER_LCOL       FL_LCOL
#define FL_TIMER_ALIGN      FL_ALIGN_CENTER

/***** Others   *****/

#define FL_TIMER_BLINKRATE  0.2

/***** Routines *****/

typedef char * ( * FL_TIMER_FILTER )( FL_OBJECT *, double );

FL_EXPORT FL_OBJECT * fl_create_timer( int          type,
                                       FL_Coord     x,
                                       FL_Coord     y,
                                       FL_Coord     w,
                                       FL_Coord     h,
                                       const char * label );

FL_EXPORT FL_OBJECT * fl_add_timer( int          type,
                                    FL_Coord     x,
                                    FL_Coord     y,
                                    FL_Coord     w,
                                    FL_Coord     h,
                                    const char * label );

FL_EXPORT void fl_set_timer( FL_OBJECT * ob,
                             double      total );

FL_EXPORT double fl_get_timer( FL_OBJECT * ob );

FL_EXPORT void fl_set_timer_countup( FL_OBJECT * ob,
                                     int         yes );

FL_EXPORT FL_TIMER_FILTER fl_set_timer_filter( FL_OBJECT       * ob,
                                               FL_TIMER_FILTER   filter );

FL_EXPORT void fl_suspend_timer( FL_OBJECT * ob );

FL_EXPORT void fl_resume_timer( FL_OBJECT * ob );

#endif /* ! defined FL_TIMER_H */

/**
 * \file xpopup.h
 *
 *  Prototypes for xpop-up menus
 */

#ifndef FL_XPOPUP_H
#define FL_XPOPUP_H


#define FL_MAXPUPI     128  /* max item each pup        */
#define FL_PUP_PADH    4    /* space between each items */

typedef void ( * FL_PUP_ENTERCB )( int, void * );   /* call back prototype  */
typedef void ( * FL_PUP_LEAVECB )( int, void * );   /* call back prototype  */

FL_EXPORT int fl_setpup_entries( int            nm,
                                 FL_PUP_ENTRY * entries );

FL_EXPORT int fl_newpup( Window win );

FL_EXPORT int fl_defpup( Window       win,
                         const char * str,
                         ... );

FL_EXPORT int fl_addtopup( int          n,
                           const char * str,
                           ... );

FL_EXPORT int fl_setpup_mode( int          nm,
                              int          ni,
                              unsigned int mode );

FL_EXPORT void fl_freepup( int n );

FL_EXPORT int fl_dopup( int n );


FL_EXPORT Cursor fl_setpup_default_cursor( int cursor );

FL_EXPORT void fl_setpup_default_color( FL_COLOR fg,
										FL_COLOR bg );

FL_EXPORT void fl_setpup_default_pup_checked_color( FL_COLOR col );

FL_EXPORT int fl_setpup_default_fontsize( int size );

FL_EXPORT int fl_setpup_default_fontstyle( int style );

#define fl_setpup_fontsize            fl_setpup_default_fontsize    
#define fl_setpup_fontstyle           fl_setpup_default_fontstyle   
#define fl_setpup_color               fl_setpup_default_color       
#define fl_setpup_default_checkcolor  fl_setpup_default_pup_checked_color
#define fl_setpup_checkcolor          fl_setpup_default_pup_checked_color

FL_EXPORT int fl_setpup_default_bw( int bw );

FL_EXPORT void fl_setpup_shortcut( int          nm,
                                   int          ni,
                                   const char * sc );

FL_EXPORT void fl_setpup_position( int x,
                                   int y );

FL_EXPORT void fl_setpup_align_bottom( void );

FL_EXPORT void fl_setpup_selection( int nm,
                                    int ni );

FL_EXPORT void fl_setpup_shadow( int n,
                                 int y );

FL_EXPORT void fl_setpup_softedge( int n,
                                   int y );

FL_EXPORT void fl_setpup_bw( int n,
                             int bw );

FL_EXPORT void fl_setpup_title( int          nm,
                                const char * title );

FL_EXPORT void fl_setpup_title_f( int          nm,
								  const char * fmt,
								  ... );

FL_EXPORT FL_PUP_ENTERCB fl_setpup_entercb( int              nm,
                                            FL_PUP_ENTERCB   cb,
                                            void           * data );

FL_EXPORT FL_PUP_LEAVECB fl_setpup_leavecb( int              nm,
                                            FL_PUP_LEAVECB   cb,
                                            void           * data );

FL_EXPORT void fl_setpup_pad( int n,
                              int padw,
                              int padh );

FL_EXPORT Cursor fl_setpup_cursor( int nm,
                                   int cursor );

FL_EXPORT int fl_setpup_maxpup( int n );

FL_EXPORT unsigned int fl_getpup_mode( int nm,
                                       int ni );

FL_EXPORT const char * fl_getpup_text( int nm,
                                       int ni );

FL_EXPORT void fl_showpup( int n );

FL_EXPORT void fl_hidepup( int n );

FL_EXPORT int fl_getpup_items( int n );

FL_EXPORT int fl_current_pup( void );

#define fl_setpup_hotkey    fl_setpup_shortcut

FL_EXPORT FL_PUP_CB fl_setpup_itemcb( int        nm,
                                      int       ni,
                                      FL_PUP_CB cb );

FL_EXPORT FL_PUP_CB fl_setpup_menucb( int       nm,
                                      FL_PUP_CB cb );

FL_EXPORT void fl_setpup_submenu( int m,
                                  int i,
                                  int subm );

#define fl_setpup    fl_setpup_mode

#endif /* ! defined FL_XPOPUP_H */

/**
 * \file xyplot.h
 */

#ifndef FL_XYPLOT_H
#define FL_XYPLOT_H

/*  Class FL_XYPLOT */

typedef enum {
    FL_NORMAL_XYPLOT,       /* solid line                        */
    FL_SQUARE_XYPLOT,       /* with added square                 */
    FL_CIRCLE_XYPLOT,       /* with added circle                 */
    FL_FILL_XYPLOT,         /* fill completely                   */
    FL_POINTS_XYPLOT,       /* only data points                  */
    FL_DASHED_XYPLOT,       /* dashed line                       */
    FL_IMPULSE_XYPLOT,
    FL_ACTIVE_XYPLOT,       /* accepts interactive manipulations */
    FL_EMPTY_XYPLOT,
    FL_DOTTED_XYPLOT,
    FL_DOTDASHED_XYPLOT,
    FL_LONGDASHED_XYPLOT,
    FL_LINEPOINTS_XYPLOT    /* line & points                     */
} FL_XYPLOT_TYPE;

enum {
    FL_LINEAR,
    FL_LOG
};

enum {
    FL_GRID_NONE  = 0,
    FL_GRID_MAJOR = 1,
    FL_GRID_MINOR = 2
};

/***** Defaults *****/

#define FL_XYPLOT_BOXTYPE       FL_FLAT_BOX
#define FL_XYPLOT_COL1          FL_COL1
#define FL_XYPLOT_LCOL          FL_LCOL
#define FL_XYPLOT_ALIGN         FL_ALIGN_BOTTOM
#define FL_MAX_XYPLOTOVERLAY    32

/***** Others   *****/

FL_EXPORT FL_OBJECT * fl_create_xyplot( int          t,
                                        FL_Coord     x,
                                        FL_Coord     y,
                                        FL_Coord     w,
                                        FL_Coord     h,
                                        const char * label );

FL_EXPORT FL_OBJECT * fl_add_xyplot( int          t,
                                     FL_Coord     x,
                                     FL_Coord     y,
                                     FL_Coord     w,
                                     FL_Coord     h,
                                     const char * label );

FL_EXPORT void fl_set_xyplot_data( FL_OBJECT  * ob,
                                   float      * x,
                                   float      * y,
                                   int          n,
                                   const char * title,
                                   const char * xlabel,
                                   const char * ylabel );

FL_EXPORT void fl_set_xyplot_data_double( FL_OBJECT  * ob,
                                          double     * x,
                                          double     * y,
                                          int          n,
                                          const char * title,
                                          const char * xlabel,
                                          const char * ylabel );

FL_EXPORT int fl_set_xyplot_file( FL_OBJECT  * ob,
                                  const char * f,
                                  const char * title,
                                  const char * xl,
                                  const char * yl );

FL_EXPORT void fl_insert_xyplot_data( FL_OBJECT * ob,
                                      int         id,
                                      int         n,
                                      double      x,
                                      double      y );

#define fl_set_xyplot_datafile   fl_set_xyplot_file

FL_EXPORT void fl_add_xyplot_text( FL_OBJECT  * ob,
                                   double       x,
                                   double       y,
                                   const char * text,
                                   int          al,
                                   FL_COLOR     col );

FL_EXPORT void fl_delete_xyplot_text( FL_OBJECT  * ob,
                                      const char * text );

FL_EXPORT int fl_set_xyplot_maxoverlays( FL_OBJECT * ob,
                                         int         maxover );

FL_EXPORT void fl_add_xyplot_overlay( FL_OBJECT * ob,
                                      int         id,
                                      float     * x,
                                      float     * y,
                                      int         n,
                                      FL_COLOR    col );

FL_EXPORT int fl_add_xyplot_overlay_file( FL_OBJECT  * ob,
                                          int          id,
                                          const char * f,
                                          FL_COLOR     c );

FL_EXPORT void fl_set_xyplot_return( FL_OBJECT    * ob,
                                     unsigned int   when );

FL_EXPORT void fl_set_xyplot_xtics( FL_OBJECT * ob,
                                    int         major,
                                    int         minor );

FL_EXPORT void fl_set_xyplot_ytics( FL_OBJECT * ob,
                                    int         major,
                                    int         minor );

FL_EXPORT void fl_set_xyplot_xbounds( FL_OBJECT * ob,
                                      double      xmin,
                                      double      xmax );

FL_EXPORT void fl_set_xyplot_ybounds( FL_OBJECT * ob,
                                      double      ymin,
                                      double      ymax );

FL_EXPORT void fl_get_xyplot_xbounds( FL_OBJECT * ob,
                                      float     * xmin,
                                      float     * xmax );

FL_EXPORT void fl_get_xyplot_ybounds( FL_OBJECT * ob,
                                      float     * ymin,
                                      float     * ymax );

FL_EXPORT void fl_get_xyplot( FL_OBJECT * ob,
                              float     * x,
                              float     * y,
                              int       * i );

FL_EXPORT int fl_get_xyplot_data_size( FL_OBJECT * obj );

FL_EXPORT void fl_get_xyplot_data( FL_OBJECT * ob,
                                   float     * x,
                                   float     * y,
                                   int       * n );

FL_EXPORT void fl_get_xyplot_data_pointer( FL_OBJECT  * ob,
                                           int          id,
                                           float     ** x,
                                           float     ** y,
                                           int        *n );

FL_EXPORT void fl_get_xyplot_overlay_data( FL_OBJECT * ob,
                                           int         id,
                                           float     * x,
                                           float     * y,
                                           int       * n );

FL_EXPORT void fl_set_xyplot_overlay_type( FL_OBJECT * ob,
                                           int         id,
                                           int         type );

FL_EXPORT void fl_delete_xyplot_overlay( FL_OBJECT * ob,
                                         int         id );

FL_EXPORT void fl_set_xyplot_interpolate( FL_OBJECT * ob,
                                          int         id,
                                          int         deg,
                                          double      grid );

FL_EXPORT void fl_set_xyplot_inspect( FL_OBJECT * ob,
                                      int         yes );

FL_EXPORT void fl_set_xyplot_symbolsize( FL_OBJECT * ob,
                                         int         n );

FL_EXPORT void fl_replace_xyplot_point( FL_OBJECT * ob,
                                        int         i,
                                        double      x,
                                        double      y );

/* Replace the value of a particular point in dataset setID,
 * where setID=0 is the first data set.
 * This routine is an extension of fl_replace_xyplot_point
 * which acts on the first dataset only. */

FL_EXPORT void fl_replace_xyplot_point_in_overlay( FL_OBJECT * ob,
                                                   int         i,
                                                   int         setID,
                                                   double      x,
                                                   double      y );

FL_EXPORT void fl_get_xyplot_xmapping( FL_OBJECT * ob,
                                       float     * a,
                                       float     * b );

FL_EXPORT void fl_get_xyplot_ymapping( FL_OBJECT * ob,
                                       float     * a,
                                       float     * b );

FL_EXPORT void fl_set_xyplot_keys( FL_OBJECT  * ob,
                                   char      ** keys,
                                   float         x,
                                   float         y,
                                   int           align );

FL_EXPORT void fl_set_xyplot_key( FL_OBJECT  * ob,
                                  int          id,
                                  const char * key );

FL_EXPORT void fl_set_xyplot_key_position( FL_OBJECT * ob,
                                           float       x,
                                           float       y,
                                           int         align );

FL_EXPORT void fl_set_xyplot_key_font( FL_OBJECT * ob,
                                       int         style,
                                       int         size );

FL_EXPORT int fl_get_xyplot_numdata( FL_OBJECT * ob,
                                     int         id );

/* The following two functions will be removed.
 * Use fl_set_object_l[size|style] for the functionalities */

FL_EXPORT void fl_set_xyplot_fontsize( FL_OBJECT * ob,
                                       int         size );

FL_EXPORT void fl_set_xyplot_fontstyle( FL_OBJECT * ob,
                                        int         style );

FL_EXPORT void fl_xyplot_s2w( FL_OBJECT * ob,
                              double      sx,
                              double      sy,
                              float     * wx,
                              float     * wy );

FL_EXPORT void fl_xyplot_w2s( FL_OBJECT * ob,
                              double      wx,
                              double      wy,
                              float     * sx,
                              float     * sy );

FL_EXPORT void fl_set_xyplot_xscale( FL_OBJECT * ob,
                                     int         scale,
                                     double      base );

FL_EXPORT void fl_set_xyplot_yscale( FL_OBJECT * ob,
                                     int         scale,
                                     double      base );

FL_EXPORT void fl_clear_xyplot( FL_OBJECT * ob );

FL_EXPORT void fl_set_xyplot_linewidth( FL_OBJECT * ob,
                                        int         id,
                                        int         lw );

FL_EXPORT void fl_set_xyplot_xgrid( FL_OBJECT * ob,
                                    int         xgrid );

FL_EXPORT void fl_set_xyplot_ygrid( FL_OBJECT * ob,
                                    int         ygrid );

FL_EXPORT int fl_set_xyplot_grid_linestyle( FL_OBJECT * ob,
                                            int         style );

FL_EXPORT void fl_set_xyplot_alphaxtics( FL_OBJECT  * ob,
                                         const char * m,
                                         const char * s );

FL_EXPORT void fl_set_xyplot_alphaytics( FL_OBJECT  * ob,
                                         const char * m,
                                         const char * s );

FL_EXPORT void fl_set_xyplot_fixed_xaxis( FL_OBJECT  * ob,
                                          const char * lm,
                                          const char * rm );

FL_EXPORT void fl_set_xyplot_fixed_yaxis( FL_OBJECT  * ob,
                                          const char * bm,
                                          const char * tm );

FL_EXPORT int fl_interpolate( const float * wx,
                              const float * wy,
                              int           nin,
                              float       * x,
                              float       * y,
                              double        grid,
                              int           ndeg );

typedef void ( * FL_XYPLOT_SYMBOL )( FL_OBJECT *,
                                     int,
                                     FL_POINT *,
                                     int,
                                     int,
                                     int );

FL_EXPORT FL_XYPLOT_SYMBOL fl_set_xyplot_symbol( FL_OBJECT        * ob,
                                                 int                id,
                                                 FL_XYPLOT_SYMBOL   symbol );

FL_EXPORT int fl_set_xyplot_mark_active( FL_OBJECT * ob,
                                         int         y );

FL_EXPORT void fl_get_xyplot_screen_area( FL_OBJECT * obj,
										  FL_COORD  * llx,
										  FL_COORD  * lly,
										  FL_COORD  * urx,
										  FL_COORD  * ury );

FL_EXPORT void fl_get_xyplot_world_area( FL_OBJECT * obj,
										 float     * llx,
										 float     * lly,
										 float     * urx,
										 float     * ury );

FL_EXPORT int fl_set_xyplot_log_minor_xtics( FL_OBJECT * obj,
											 int         yesno );

FL_EXPORT int fl_set_xyplot_log_minor_ytics( FL_OBJECT * obj,
											 int         yesno );

FL_EXPORT void fl_set_xyplot_mouse_buttons( FL_OBJECT    * obj,
											unsigned int   mouse_buttons );

FL_EXPORT void fl_get_xyplot_mouse_buttons( FL_OBJECT    * obj,
											unsigned int * mouse_buttons );

#endif  /* ! defined FL_XYPLOT_H */

/* the following (fl_fheight) etc. were never documented and were
   removed from V0.89, but apparently this broke some applications that
   were using them. Put them back in 10/22/00 */

#define fl_textgc      fl_textgc_( )
#define fl_gc          fl_gc_( )
#define fl_cur_win     fl_cur_win_( )
#define fl_fheight     fl_fheight_( )
#define fl_fdesc       fl_fdesc_( )
#define fl_cur_fs      fl_cur_fs_( )

FL_EXPORT GC fl_gc_( void );
FL_EXPORT GC fl_textgc_( void );
FL_EXPORT int fl_fheight_( void );
FL_EXPORT int fl_fdesc_( void );
FL_EXPORT Window fl_cur_win_( void );
FL_EXPORT XFontStruct * fl_cur_fs_( void );
FL_EXPORT Display * fl_display_( void );

#if ! defined FL_TRUE && ! defined FL_FALSE
#define FL_FALSE        0
#define FL_TRUE         ( ! FL_FALSE )
#endif

#if defined __cplusplus
}
#endif

#endif /* FL_FORMS_H */
