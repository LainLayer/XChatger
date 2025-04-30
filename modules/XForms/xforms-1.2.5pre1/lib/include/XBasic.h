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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.     See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/********************** crop here for forms.h **********************/

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
