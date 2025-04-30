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
 * \file fd_main.h
 *
 * This file is the header file used in the Form Designer
 */

#ifndef FD_MAIN_H_
#define FD_MAIN_H_

#include <stdio.h>
#include "include/forms.h"
#include "flinternal.h"

#ifndef FALSE
#define FALSE    0
#define TRUE    ( ! FALSE )
#endif

/* since MAGIC4 all coordinates are relative to the top-left */

#define MAGIC2   12321
#define MAGIC3   12322
#define MAGIC4   13000
#define MAGIC5   14000     /* since XForms 1.0.92 */
#define MAGIC6   15000     /* since XForms 1.0.94pre4 */


/* general limits */

#define MAX_CLASS_NAME_LEN  64  /* FL_BUTTON etc.                     */
#define MAX_TYPE_NAME_LEN   64  /* FL_RADIO_BUTTON etc                */
#define MAX_VAR_LEN        128  /* max. length of a variable/function */

/* various options  of the program */

typedef struct {
    int    language;
    int    emit_code;       /* if emit UI code */
    int    emit_main;
    int    emit_cb;
    int    lax;
    int    altformat;
    int    conv_only;
    int    show_pallete;
    int    compensate;      /* if emit font size compensation code */
    int    unit;
    char * output_dir;
} FD_Opt;

enum {
    FD_C         = 1,
    FD_ADA95,
    FD_PERL,
    FD_PASCAL,
    FD_PYTHON,
    FD_FORTRAN,
    FD_PS,
    FD_SCM,
    FD_EXP
};

/* We use different file selector for different tasks */

enum {
    SAVE_FSELECTOR,
    LOAD_FSELECTOR,
    XPM_FSELECTOR
};

#define MAX_CONVERTOR  ( FD_EXP + 1 )

/* Structure that will hole all forms created */

typedef struct {
    FL_FORM * form;                 /* The form */
    char      fname[ MAX_VAR_LEN ]; /* Its name */
} FRM;

typedef struct {
    const char * lang_name;
    int          ( * convert )( const char *,
                                FRM        *,
                                int );      /* built-in convertor */
    const char * extern_convertor;    /* the converter itself         */
    const char * contact_info;        /* who to contact in case of error      */
    int          need_c_code;         /* if translator works on C or .fd file */
    void         ( * init )( void );  /* additional initialization */
} Conv;

extern Conv convertor[ ];
extern FD_Opt fdopt;

#define ShiftIsDown( mask )    ( mask & ShiftMask )

/******** in fd_main.c    *********/

extern long main_window;    /* The identifier of the main window */
extern FL_Coord winw,
                winh;
extern int changed;         /* Whether the file has changed. */
extern char main_name[ ];   /* Main creation routine name */

/******** in fd_rubber.c  *********/

/* Contains routines for drawing rubberband boxes. */

void set_step_size( double );    /* sets the stepsize */

double get_step_size( void );    /* returns the stepsize */

/* Sets the bounding box in which the drawing occurs */

void set_bounding_box( double,
                       double,
                       double,
                       double );

/* returns the position of the mouse in world coordinates */

void get_mouse_pos( double *,
                    double * );

/* drag a box around until the user releases a mouse button */

void move_box( double *,
               double *,
               double *,
               double *,
               int );

/* scales a box until the user releases a left mouse button */

void scale_box( double *,
                double *,
                double *,
                double * );

/******** in fd_select.c *********/

/* Contains the routines that deal with the maintenance of the
   current selection of objects */

int is_selected( FL_OBJECT * );      /* Returns whether the object is
                                        selected. */

void addto_selection( FL_OBJECT * ); /* Adds an object to a
                                        selection */

void addgroupto_selection( FL_OBJECT * );    /* Adds a group of objects
                                                to a selection */

void deletefrom_selection( FL_OBJECT * );    /* Deletes an object from a
                                                selection */

void clear_selection( void );    /* Clears the current selection */

void resize_selection( FL_Coord,
                       FL_Coord );

void move_selection( FL_Coord,
                     FL_Coord );

void deletegroupfrom_selection( FL_OBJECT * );   /* Deletes a group of objects
                                                    from a selection */

void draw_selbox( void );       /* Draws the box around the selected objects */

void handle_select( const XEvent * );   /* Change the selection when
                                           user puhed mouse. */

void handle_move( const XEvent * );     /* Moves or scales the
                                           selection. */
void select_all( void );                /* Selects all objectsin the form */

void change_selection( void );          /* Changes the atributes of the
                                           selection */

void align_selection( int );            /* Aligns the objects in the
                                           selection */
void show_selection( void );            /* Makes the selection visible. */

void hide_selection( void );            /* Makes the selection invisible. */

void raise_selection( void );           /* Raises the selection */

void lower_selection( void );           /* Lower the selection */

void cut_selection( void );             /* Deletes all objects in the
                                           selection */
void paste_selection( void );           /* Puts elements from buffer into
                                           form */
void copy_selection( void );            /* Copies objects in selection to
                                           buffer */
FL_OBJECT **dup_selection( void );

void set_selection( FL_OBJECT ** );

void free_dupped_selection( FL_OBJECT ** );

void next_selection( void );

void prev_selection( void );

void group_selection( void );           /* Turns objects in the selection
                                           into a group. */

void flatten_selection( void );         /* Removes begin and end groups from
                                           the selection. */

/******** in fd_attribs.c **********/

/* Contains routines to set and change attributes of objects. */

int change_object( FL_OBJECT *,         /* changes the settings for object */
                   int );

void change_type( FL_OBJECT *,  /* Changes the type of a particular object. */
                  int);

void set_label( FL_OBJECT *,   /* Sets the object label (interpreting \n's). */
                const char * ); 
                                               
void set_shortcut( FL_OBJECT *,
                   const char * );
char *get_label( const FL_OBJECT *, /* Returns object label */
                 int);              /*  (turning NL's into \n's). */
char *get_shortcut_string( const FL_OBJECT * );


/******** in fl_file_fun.c    ********/

#define FF_READ_FAILURE        -1
#define FF_AT_END_OF_FILE       0
#define FF_AT_START_OF_FORM     1
#define FF_AT_START_OF_OBJECT   2


int ff_get_fd_file( const char *,
                    int  );
char *ff_get_filename_copy( void );
int ff_read( const char *,
             ... );
void ff_close( void );
int ff_err( const char * );


/******** in fl_file.c    ********/

/* Contains all routines that deal with saving and loading forms. */

int read_form( void );
void write_form( FILE *,
                 FL_FORM *,
                 char[ ] );

/******** in fl_print.c   ********/

/* Contains all routines that deal with printing forms in C format. */

void print_form( FILE *,
                 FL_FORM *,
                 const char * );
void print_callbacks_and_globals( FILE *,
                                  FL_FORM *,
                                  int );

/* For making the header file */

void print_header( FILE *,
                   FL_FORM *,
                   const char * );
void output_main( FILE *,
                  FRM *,
                  int );
void output_callbacks( FILE *,
                       FRM *,
                       int );

/******** in fd_forms.c   *********/

/* Contains the routines that maintain the collection of forms. */

extern FL_FORM *cur_form;

const char * get_form_name( FL_FORM * form );

/* The current form under construction */

void redraw_the_form( int );

/* Redraws the current form. The argument indicates whether the background
   should be redrawn. */

void reshape_form_background( FL_Coord,
                              FL_Coord );

/* loads the forms from a file */

int load_forms( int,
                const char * );

int save_forms( const char * );

/* saves the forms to a file, returns whether actually saved */

/******** fd_groups.c *********/

/* Contains the routines that deal with groups. */

/* Fills in the groups in the current form. */

void fillin_groups( void );


/******** fd_names.c  **********/

/* Routines that keep track of the object names */

void get_object_name( const FL_OBJECT *,
                      char *,
                      char *,
                      char * );

void set_object_name( FL_OBJECT *,
                      const char *,
                      const char *,
                      const char * );

const char * get_object_c_name( FL_OBJECT * obj );

/******** fd_objects.c *********/

/* Contains the different object classes and types. */

#define MAXCLASSES  60  /* Max. number of object classes handled */
#define MAXTYPES    24  /* Max. number of types per class.     */

/* Maximal number of object classes. */

/* The current class of object to be added */

extern int cur_class;

/* Initializes all the classes and types. */

void init_classes( void );

/* adds an object to the current form */

FL_OBJECT * add_an_object( int,
                           int,
                           FL_Coord,
                           FL_Coord,
                           FL_Coord,
                           FL_Coord );

/* Returns a pointer to the name of the class */

char *find_class_name( int );

char * find_class_name( int );

/* Returns the number of types in the class */

int find_class_maxtype( int );

/* Returns the default object in the class */

FL_OBJECT * find_class_default( int,
                                int );

/* Returns a pointer to the name of the type in the class */

const char *find_type_name( int,
                            int );

int find_type_value( int,
                     const char * );

extern unsigned long fd_red,
                     fd_black,
                     fd_white,
                     fd_col;

extern int fd_magic;
extern int fd_border;
extern int fd_trackgeometry,
           fd_buttonLabelSize,
           fd_testborder;

void color( unsigned long );

int getbutton( int );

void fd_clear( int,
               int,
               int,
               int );

void rect( FL_Coord,
           FL_Coord,
           FL_Coord,
           FL_Coord );

void rectf( FL_Coord,
            FL_Coord,
            FL_Coord,
            FL_Coord );

int fl_qtest( void );

/* attribute query routines */

char * class_name( int );
int class_val( const char * );

char * gravity_name( int );
int gravity_val( const char * );

char * resize_name( int );
int resize_val( const char * );

char * style_name( int );
int style_val( const char * );

const char * align_name( int,
                         int );
int align_val( const char * );

char * lsize_name( int );
int lsize_val( const char * );

char * boxtype_name( int );
int boxtype_val( const char * );

extern char * loadedfile;
extern char *loadedfile_fullpath;

typedef struct {
    int    val;         /* value       */
    char * name;        /* formal name */
    char * shown;       /* name shown  */
    char * hotkey;      /* hotkeys     */
} VN_pair;

char * get_vn_name( VN_pair *,
                    int );
int get_vn_val( VN_pair *,
                const char * );

extern VN_pair vn_btype[ ];
extern VN_pair vn_gravity[ ];
extern VN_pair vn_align[ ];
extern VN_pair vn_resize[ ];

extern int fd_align_fontsize,
           fd_type_fontsize;
extern int fd_convert,
           fd_show_palette;

const char * get_fd_name( const char * );

extern int fd_bwidth;

char * unit_name( int );

int unit_val( const char * );

int convert_u( int );

double get_conversion_factor( void );

extern char xform_header[ ];
extern char glcanvas_header[ ];

void show_geometry( int,
                    int,
                    int,
                    int );

void show_selmessage( FL_OBJECT *[ ],
                      int );

enum {
    FD_LEFT    = 1,
    FD_HCENTER = 2,
    FD_RIGHT   = 3,
    FD_HEQUAL  = 4,
    FD_BOTTOM  = 5,
    FD_VCENTER = 6,
    FD_TOP     = 7,
    FD_VEQUAL  = 8
};

enum {
    HELP_VERSION,
    HELP_GENERAL,
    HELP_MOUSE,
    HELP_KEYBOARD,
    HELP_GROUP,
    HELP_TEST,
    HELP_SAVE
};

extern FL_FORM * thetestform;

FL_OBJECT * fl_create_simu_canvas( int,
                                   FL_Coord,
                                   FL_Coord,
                                   FL_Coord,
                                   FL_Coord,
                                  const char * );

FL_OBJECT * fl_add_simu_canvas( int,
                                FL_Coord,
                                FL_Coord,
                                FL_Coord,
                                FL_Coord,
                                const char * );

FL_OBJECT * fl_create_simu_glcanvas( int,
                                     FL_Coord,
                                     FL_Coord,
                                     FL_Coord,
                                     FL_Coord,
                                     const char * );

FL_OBJECT * fl_add_simu_glcanvas( int,
                                  FL_Coord,
                                  FL_Coord,
                                  FL_Coord,
                                  FL_Coord,
                                  const char * );

/* Object class specific info handler */

void save_objclass_spec_info( FILE *,
                              FL_OBJECT * );

int load_objclass_spec_info( FL_OBJECT *,
                             char *);

void emit_objclass_spec_info( FILE *,
                              FL_OBJECT * );

void emit_objclass_spec_header( FILE *,
                                FL_OBJECT * );

void emit_objclass_spec_global( FILE *,
                                FL_OBJECT * );

void set_objclass_spec_attributes( FL_OBJECT *,
                                   long );

void obj_spec_reread( FL_OBJECT * obj );

void obj_spec_apply( FL_OBJECT * obj );

void obj_spec_restore( FL_OBJECT * obj );

int has_class_spec_info( FL_OBJECT * );

void modify_attrib_basic_color( FL_COLOR,
                                FL_COLOR );

/* Control panel etc */

#include "fd/ui_theforms.h"
#include "fd/ui_attrib.h"

extern FD_control *fd_control;

extern FD_attrib *fd_attrib;

extern FD_generic_attrib *fd_generic_attrib;

extern FD_test * fd_test;

extern FD_align * fd_align;

extern FD_resize * fd_resize;

extern FD_helpform * fd_help;

void loadforms_cb( FL_OBJECT *,
                   long );

void saveforms_cb( FL_OBJECT *,
                   long );

void saveforms_as_cb( FL_OBJECT *,
                      long );

void mergeforms_cb( FL_OBJECT *,
                    long );

void exit_cb( FL_OBJECT *,
              long );

void changegroupname_cb( FL_OBJECT *,
                         long );

void mainname_cb( FL_OBJECT *,
                  long );

void create_the_forms( void );

void control_init( FD_control * );

extern FL_FORM *thetestform;

int within_selection( double,
                      double );

extern int no_selection;

int C_output( const char *,
              FRM *,
              int );

extern int is_pasting;

void init_align( void );

void cleanup_spec( FL_OBJECT * );

/* fake stuff */

#define FL_NTABFOLDER  50

FL_OBJECT *fl_add_ntabfolder( int,
                              FL_Coord,
                              FL_Coord,
                              FL_Coord,
                              FL_Coord,
                              const char *);

FL_OBJECT *fl_create_ntabfolder( int,
                                 FL_Coord,
                                 FL_Coord,
                                 FL_Coord,
                                 FL_Coord,
                                 const char * );

FL_OBJECT *fl_add_nformbrowser( int,
                                FL_Coord,
                                FL_Coord,
                                FL_Coord,
                                FL_Coord,
                                const char * );

FL_OBJECT *fl_create_nformbrowser( int,
                                   FL_Coord,
                                   FL_Coord,
                                   FL_Coord,
                                   FL_Coord,
                                   const char * );

void make_backup( const char * );

int is_var_boxtype( int cn );

void set_testing_pixmap( FL_OBJECT * );

void set_testing_bitmap( FL_OBJECT * ob );

void set_snap_size( int,
                    int );

int get_snap_size( void );

void show_pallette( void );

void hide_pallette( void );

void reset_pallette_menu_status( void );

void select_pallette_entry( int );

void reset_pallette( void );

typedef struct {
    double           min,
                     max,
                     xmin,
                     xmax,
                     ymin,
                     ymax;
    double           val,
                     xval,
                     yval;
    double           step,
                     sstep,
                     lstep,
                     xstep,
                     ystep;
    double           slsize;
    double           thetai,
                     thetaf;
    double           ldelta,
                     rdelta;
    double           dval,
                     dmin,
                     dmax,
                     dstep;
    int              prec;
    int              direction;
    int              mbuttons;
    int              int_val;
    int              align;
    int              dx,
                     dy;
    int              show_focus;
    int              h_pref,
                     v_pref;
    int              nlines;
    int              xmajor,
                     xminor;
    int              ymajor,
                     yminor;
    int              xscale,
                     yscale;
    float            xbase,
                     ybase;
    int              xgrid,
                     ygrid;
    char          ** content;
    char          ** shortcut;
    char          ** callback;
    unsigned char  * mode;
    int              new_menuapi;
    int              global_scope;
    int              showsymbol;
    char           * misc_char;
    int              grid_linestyle;
    int              no_title;
    int              mark_active;
    int            * mval;
    int              orient;
} SuperSPEC;

SuperSPEC * get_superspec( FL_OBJECT * );

SuperSPEC * spec_to_superspec( FL_OBJECT * );

void * superspec_to_spec( FL_OBJECT * );

void copy_superspec( FL_OBJECT * dest,
                     FL_OBJECT * src );

void free_superspec( FL_OBJECT * obj );

#define ISBUTTON( cls )  (    ( cls ) == FL_BUTTON             \
                           || ( cls ) == FL_LIGHTBUTTON        \
                           || ( cls ) == FL_CHECKBUTTON        \
                           || ( cls ) == FL_ROUNDBUTTON        \
                           || ( cls ) == FL_ROUND3DBUTTON      \
                           || ( cls ) == FL_PIXMAPBUTTON       \
                           || ( cls ) == FL_BITMAPBUTTON       \
                           || ( cls ) == FL_SCROLLBUTTON       \
                           || ( cls ) == FL_LABELBUTTON )

#define ISCHOICE( cls )  (    ( cls ) == FL_CHOICE             \
                           || ( cls ) == FL_MENU               \
                           || ( cls ) == FL_BROWSER )

void select_object_by_class( int );

char * append_fd_suffix( const char * );

const char * get_placement( FL_FORM * );

unsigned int
check_resize( unsigned int what,
              int          nw,
              int          se );

void reset_dupinfo_cache( void );

int is_duplicate_info( const char * );

char * rel2abs( const char * rel_path );

int is_valid_c_name( const char * str );

void setup_how_return_menu( FL_OBJECT * );

void reset_how_return_menu( FL_OBJECT *,
                            unsigned int );

void handle_how_return_changes( FL_OBJECT *,
                                FL_OBJECT * );

int get_how_return_val( const char * );

const char * get_how_return_name( unsigned int,
                                  int );

const char * file_tail( const char * );

void reset_object_list( void );


void addform_cb( FL_OBJECT *,
                 long );

void deleteform_cb( FL_OBJECT *,
                    long );

void changename_cb( FL_OBJECT *,
                    long );

void changesize_cb( FL_OBJECT *,
                    long );

#endif /* FD_MAIN_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
