/*
 * This file is part of XForms.
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
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file fd2ps.h
 */

#ifndef FD2PS_H
#define FD2PS_H

#include "include/forms.h"

/* configuration infomation */

typedef struct {
    FILE       * fp;
    float        xdpi,          /* screen resolution         */
                 ydpi;
    int          colorps;       /* false if grayscale        */
    int          eps;           /* true for EPS              */
    float        paper_w,       /* default paper size        */
                 paper_h;
    const char * paper_name;
    int          bw;            /* current border width      */
    int          user_bw;       /* bw specified on cmdline   */
    int          verbose;
    int          inverted;      /* take care of coord switch */
    int          landscape;     /* print version             */
    int          unit;          /* unit of measure           */
    int          pages;         /* how many pages            */
    int          page;          /* current page              */
    int          epsf_import;   /* true if importing EPS     */
    float        xscale,
                 yscale;
    float        gamma;         /* color adjustment          */
    int          pack,
                 len,
                 lastc,
                 literal;
    char       * rgbfile;
    int          xpmtops_direct;

    /* internal stuff */

    const char * poly_name; /* PS poly name               */
} PSInfo;

typedef struct {
    float x,
          y;
} Point;


#define MAX_CONTENT      64 /* max browser initialization lines */
#define rgb2gray( r, g, b )   \
     ( 0.299 * ( r ) + 0.587 * ( g ) + 0.114 * ( b ) + 0.4 )

/* since we never take interactions with PS device, we can use a
 * common SPEC to hold all attributes of all types of objects
 * that have effect on the drawings.  */

typedef struct {
    float    ax,            /* mapping factor */
             bx,
             ay,
             by;
    float    xval,
             yval;
    float    xmin,
             ymin;
    float    xmax,
             ymax;
    float    xstep,         /* positioner          */
             ystep;
    float    lstep,         /* counter             */
             sstep;
    float    slsize;        /* sliders             */
    float    val;           /* */
    float    max,
             min;
    int      prec;
    int      int_val;

    float    thetai,
             thetaf;

    float    origin;
    int      direction;

    /* pixmap/bitmap stuff */

    char   * file;
    int      dx,            /* alignment margin */
             dy;
    int      align;
    int      show_focus;

    /* slider spec */

    int      right;
    float    xsl,
             ysl,
             wsl,
             hsl,
             sbw;
    int      has_sb;
    int      lines,
             screenlines;
    char  ** content;       /* for input & browser */
    short  * mode;
    int      fontstyle,
             fontsize;
    int      v_pref,
             h_pref;
} ALLSPEC;

#define SPEC ALLSPEC

extern PSInfo psinfo, *flps;

extern void ps_color(long);

/* basic drawing of simple geomtric figures */

extern void ps_draw_init( void );
extern void ps_rectangle( int, float, float, float, float, long );
extern void ps_roundrectangle( int, float, float, float, float, long );
extern void ps_lines( Point *, int, long );
extern void ps_line( float, float, float, float, long );
extern void ps_poly( int, Point *, int, long );
extern int ps_draw_symbol( const char *, float, float, float, float, long );
extern void ps_oval( int, float, float, float, float, long );
extern void ps_pieslice( int fill, float x, float y, float w, float h,
                         int t1, int t2, long col );
extern void ps_circ( int, float, float, float, long );
extern void ps_arc( int fill, float x, float y, float r,
                    int t1, int t2, long col );
extern void ps_set_clipping( int, int, int, int );
extern void ps_unset_clipping( void );

#define ps_rectf( x, y, w, h, c )   ps_rectangle( 1, x, y, w, h, c )
#define ps_rect( x, y, w, h, c )    ps_rectangle( 0, x, y, w, h, c )


extern void ps_draw_box( int, float, float, float, float, long, float );
extern void ps_draw_tbox( int, float, float, float, float, long, float );
extern void ps_draw_frame( int, float, float, float, float, long, int );
extern void ps_draw_checkbox( int, float, float, float, float, long, int );

/* basic text drawing routines */

extern void ps_draw_text( int, float, float, float, float,
                          long, int, int, const char * );
extern void ps_draw_text_beside( int, float, float, float, float,
                                 long, int, int, const char * );
extern void ps_text_init( void );

/* FL Object drawing routine */

extern void ps_show_form( FL_FORM * );
extern int load_form_definiation( const char * );

extern char *ul_magic_char;

extern char *fl_strdup( const char * );

extern int find_type_val( int, const char * );
extern void ps_invalidate_color_cache( void );
extern void ps_set_linewidth( float, float );
extern void ps_get_linewidth( float *, float * );
extern void ps_reset_linewidth( void );

#define ps_start_lw   ps_set_linewidth
#define ps_end_lw     ps_reset_linewidth

extern void set_object_modifier( void ( * )( FL_OBJECT * ) );

extern int fl_get_namedcolor( const char *s );
extern void flps_set_object_shortcut( FL_OBJECT *, const char *, int );
extern void print_version( int );
extern const char *get_version( void );
extern int unit_val(const char *);
extern const char *unit_name( int );
extern void ps_log( const char *s );
extern void apply_gamma( float );
extern const char *ascii_date( void );
extern const char *whoami( void );
extern const char *find_class_name( int );
extern int find_class_val( const char * );
extern void ps_set_font( int, int );
extern int load_form_definition( const char * );
int
fl_is_inside_lalign( int align );
extern int fl_is_outside_lalign( int align );
extern int fl_is_center_lalign( int align );
extern int fl_to_inside_lalign( int align );
extern int fl_to_outside_lalign( int align );
extern void fl_get_outside_align( int align, int x, int y, int w, int h,
                                  int *new_align, int *newx, int *newy );
extern void fl_get_hv_align( int, int *, int * );
extern void draw_bitmap( const char *, float, float, float, float,
                         long, long );
extern int get_gray255( long );
extern void get_scale_unit( int, float *, float * );
extern void draw_xpm( FL_OBJECT * );
extern void fl_query_imap( long col, int *r, int *g, int *b );
extern void get_paper_size( const char *, float *, float * );
extern void list_papers( const char * );
extern void ps_invalidate_font_cache( void );
extern void emit_epsf_import_command( void );
extern FL_OBJECT *flps_make_object( int, int, int, int, int, int,
                                    const char *, void * );

#define PS_SPECIAL( c ) (    c == '(' || c == ')'    \
                          || c == '[' || c == ']'    \
                          || c == ' ' || c == '<'    \
                          || c == '>' || c == '%'    \
                          || c == '#' || c == '/' )


extern void ps_output( const char *, ... );
extern void ps_verbatim( const char *, ... );

#define ISBUTTON( cls )  \
   (    cls == FL_BUTTON        || cls == FL_LIGHTBUTTON       \
     || cls == FL_CHECKBUTTON   || cls == FL_ROUNDBUTTON       \
     || cls == FL_ROUND3DBUTTON || cls == FL_PIXMAPBUTTON      \
     || cls == FL_BITMAPBUTTON  || cls == FL_SCROLLBUTTON      \
     || cls == FL_LABELBUTTON )

#define ISCHOICE( cls )   \
    ( cls == FL_CHOICE || cls == FL_MENU || cls == FL_BROWSER )

extern int xpmtops_direct( const char *, int, int, long );

typedef struct {
    int  red,
         green,
         blue,
         alpha;
    char key[ 4 ];
    char name[ 32 ];
} fd2psCMAP;

extern int image2colorps( short *, int, int, fd2psCMAP *, int, const char * );
extern int image2grayps( short *, int, int, fd2psCMAP *, int, const char * );
extern char *ps_literal( const char * );


#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
