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


/*
 * Test browser/slider and color handling. Select a colorname,
 * the program will show the color. Change the sliders, the
 * program will pick a colorname that has the closest color.
 *
 *  This file is part of xforms package.
 *  T.C. Zhao and M. Overmars  (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>
#include <limits.h>

#define MAX_RGB 3000

static FL_FORM *cl;
static FL_OBJECT *rescol,
                 *dbobj,
                 *colbr,
                 *rs,
                 *gs,
                 *bs;
char dbname[ FL_PATH_MAX ] ;
static void create_form_cl( void );
static int load_browser( const char * );

/* the RGB data file does not have a standard location on unix. */

#ifdef __VMS
    static char *rgbfile = "SYS$MANAGER:DECW$RGB.DAT";
#else
#ifdef __EMX__   /* OS2 */
    static char *rgbfile = "/XFree86/lib/X11/rgb.txt";
#else
	#include <sys/stat.h>

    static char *rgbfile = "/usr/lib/X11/rgb.txt";
    static char *rgbfile_2 = "/usr/share/X11/rgb.txt";
#endif
#endif

typedef struct { int r,
                     g,
                     b;
} RGBdb;

static RGBdb rgbdb[ MAX_RGB ];


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    create_form_cl( );
    strcpy( dbname, rgbfile );

#if ! defined __EMX__ && ! defined __VMS
    {
        struct stat buf;

        if ( stat( rgbfile, &buf ) == -1 )
            strcpy( dbname, rgbfile_2 );
    }
#endif

    if ( load_browser( dbname ) )
        fl_set_object_label( dbobj, dbname );
    else
        fl_set_object_label( dbobj, "None" );

    fl_set_form_minsize( cl, cl->w , cl->h );
    fl_set_form_maxsize( cl, 2 * cl->w , 2 * cl->h );
    fl_show_form( cl, FL_PLACE_FREE, FL_TRANSIENT, "RGB Browser" );

    fl_do_forms( );

    return 0;
}


/***************************************
 ***************************************/

static void
set_entry( int i )
{
    RGBdb *db = rgbdb + i;

    fl_freeze_form( cl );
    fl_mapcolor( FL_FREE_COL4 + i, db->r, db->g, db->b );
    fl_mapcolor( FL_FREE_COL4, db->r, db->g, db->b );
    fl_redraw_object( rescol );
    fl_set_slider_value( rs, db->r );
    fl_set_slider_value( gs, db->g );
    fl_set_slider_value( bs, db->b );
    fl_unfreeze_form( cl );
}


/***************************************
 ***************************************/

static void
br_cb( FL_OBJECT * ob,
       long        q   FL_UNUSED_ARG )
{
    int r = fl_get_browser( ob );

    if ( r > 0 )
        set_entry( r - 1 );
}


/***************************************
 ***************************************/

static int
read_entry( FILE * fp,
            int  * r,
            int  * g,
            int  * b,
            char * name )
{
    int  n;
    char buf[ 512 ],
         *p;

    if ( ! fgets( buf, sizeof buf, fp ) )
        return 0;

    if ( *buf == '!' )
        if ( ! fgets( buf, sizeof buf, fp ) )
             return 0;

    if ( sscanf( buf, " %d %d %d %n", r, g, b, &n ) != 3 )
        return 0;

    p = buf + n;

    /* Remove all spaces */

    while ( *p )
    {
        if ( * p != ' ' && *p != '\n' )
            *name++ = *p;
        p++;
    }
    *name = '\0';

    return ! ( feof( fp ) || ferror( fp ) );
}


/***************************************
 ***************************************/

static int
load_browser( const char * fname )
{
    FILE *fp;
    RGBdb *db = rgbdb,
          *dbs = db + MAX_RGB;
    int r,
        g,
        b,
        lr = -1,
        lg = -1,
        lb = -1;
    char name[ 256 ],
         buf[ 256 ];

#ifdef __EMX__
    extern char *__XOS2RedirRoot( const char * );
    if ( ! ( fp = fopen( __XOS2RedirRoot( fname ), "r" ) ) )
#else
    if ( ! ( fp = fopen( fname, "r" ) ) )
#endif
    {
        fl_show_alert( "Load", fname, "Can't open database file", 0 );
        return 0;
    }

    /* read the items */

    fl_freeze_form( cl );

    while ( db < dbs && read_entry( fp, &r, &g, &b, name ) )
    {
        db->r = r;
        db->g = g;
        db->b = b;

        /* unique the entries on the fly */

        if ( lr != r || lg != g || lb != b )
        {
            db++;
            lr = r;
            lg = g;
            lb = b;
            sprintf( buf, "(%3d %3d %3d) %s", r, g, b, name );
            fl_addto_browser( colbr, buf );
        }
    }

    fclose( fp );

    if ( db < dbs )
        db->r = 1000;       /* sentinel */
    else
    {
        db--;
        db->r = 1000;
    }

    fl_set_browser_topline( colbr, 1 );
    fl_select_browser_line( colbr, 1 );
    set_entry( 0 );
    fl_unfreeze_form( cl );

    return 1;
}


/***************************************
 ***************************************/

static int
search_entry( int r,
              int g,
              int b )
{
    RGBdb *db = rgbdb;
    int i,
        j;
    unsigned int mindiff = UINT_MAX;

    for ( i = j = 0; db->r < 256; db++, i++ )
    {
        int diffr = r - db->r;
        int diffg = g - db->g;
        int diffb = b - db->b;

#ifdef FL_LINEAR
        unsigned int diff = ( int ) ( 3.0 * FL_abs( diffr ) +
                                      5.9 * FL_abs( diffg ) +
                                      1.1 * FL_abs( diffb ) );
#else
        unsigned int diff = ( int ) ( 3.0 * ( diffr * diffr ) +
                                      5.9 * ( diffg * diffg ) +
                                      1.1 * ( diffb * diffb ) );
#endif

        if ( mindiff > diff )
        {
            mindiff = diff;
            j = i;
        }
    }

    return j;
}


/***************************************
 ***************************************/

static void
search_rgb( FL_OBJECT * ob  FL_UNUSED_ARG,
            long        q   FL_UNUSED_ARG )
{
    int r,
        g,
        b,
        i;
    int top  = fl_get_browser_topline( colbr );

    r = ( int ) fl_get_slider_value( rs );
    g = ( int ) fl_get_slider_value( gs );
    b = ( int ) fl_get_slider_value( bs );

    fl_freeze_form( cl );
    fl_mapcolor( FL_FREE_COL4, r, g, b );
    fl_redraw_object( rescol );
    i = search_entry( r, g, b );

    /* Change topline only if necessary */

    if ( i < top || i > top + 15 )
        fl_set_browser_topline( colbr, i - 8 );
    fl_select_browser_line( colbr, i + 1 );
    fl_unfreeze_form( cl );
}


/***************************************
 * change database
 ***************************************/

static void
db_cb( FL_OBJECT * ob,
       long        q   FL_UNUSED_ARG )
{
    const char *p = fl_show_input( "Enter new database name", dbname );
    char buf[ 512 ];

    if ( ! p || ! strcmp( p, dbname ) )
        return;

    strcpy( buf, p );
    if ( load_browser( buf ) )
    {
        strcpy( dbname, buf );
        fl_set_object_label( ob, dbname );
    }
}


/***************************************
 ***************************************/

static void
done_cb( FL_OBJECT * ob  FL_UNUSED_ARG,
         long        q   FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

static void
create_form_cl( void )
{
    FL_OBJECT *obj;

    cl = fl_bgn_form( FL_NO_BOX, 330, 385 );

    obj = fl_add_box( FL_UP_BOX, 0, 0, 330, 385, "" );
    fl_set_object_color( obj, FL_COL1, FL_COL1 );

    obj = fl_add_box( FL_NO_BOX, 40, 10, 250, 30, "Color Browser" );
    fl_set_object_lcolor( obj, FL_RED );
    fl_set_object_lsize( obj, FL_HUGE_SIZE );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE + FL_SHADOW_STYLE );
    fl_set_object_gravity( obj, FL_North, FL_North );
    fl_set_object_resize( obj, FL_RESIZE_NONE );

    dbobj = obj = fl_add_button( FL_NORMAL_BUTTON, 40, 50, 250, 25, "" );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_color( obj,
                         fl_get_visual_depth( )==1 ? FL_WHITE:  FL_COL1,
                          FL_COL1 );
    fl_set_object_callback( obj, db_cb, 0 );
    fl_set_object_gravity( obj, FL_North, FL_North );
    fl_set_object_resize( obj, FL_RESIZE_X );

    rescol = obj = fl_add_box( FL_FLAT_BOX, 225, 90, 90, 35, "" );
    fl_set_object_color( obj, FL_FREE_COL4, FL_FREE_COL4 );
    fl_set_object_boxtype( obj, FL_BORDER_BOX );
    fl_set_object_resize( obj, FL_RESIZE_NONE );
    fl_set_object_gravity( obj, FL_NorthEast, FL_East );

    rs = obj = fl_add_valslider( FL_VERT_FILL_SLIDER, 225, 130, 30, 200, "" );
    fl_set_object_color( obj,  FL_COL1, FL_RED );
    fl_set_slider_bounds( obj, 0, 255 );
    fl_set_slider_precision( obj, 0 );
    fl_set_object_callback( obj, search_rgb, 0 );
    fl_set_slider_return( obj, 0 );
    fl_set_object_resize( obj, FL_RESIZE_Y );
    fl_set_object_gravity( obj, FL_NorthEast, FL_SouthEast );
    fl_set_object_return( obj, FL_RETURN_CHANGED );

    gs = obj = fl_add_valslider( FL_VERT_FILL_SLIDER, 255, 130, 30, 200, "" );
    fl_set_object_color( obj,  FL_COL1, FL_GREEN );
    fl_set_slider_bounds( obj, 0, 255 );
    fl_set_slider_precision( obj, 0 );
    fl_set_object_callback( obj, search_rgb, 1 );
    fl_set_slider_return( obj, 0 );
    fl_set_object_resize( obj, FL_RESIZE_Y );
    fl_set_object_gravity( obj, FL_NorthEast, FL_SouthEast );
    fl_set_object_return( obj, FL_RETURN_CHANGED );

    bs = obj = fl_add_valslider( FL_VERT_FILL_SLIDER, 285, 130, 30, 200, "" );
    fl_set_object_color( obj,  FL_COL1, FL_BLUE );
    fl_set_slider_bounds( obj, 0, 255 );
    fl_set_slider_precision( obj, 0 );
    fl_set_object_callback( obj, search_rgb, 2 );
    fl_set_slider_return( obj, 0 );
    fl_set_object_resize( obj, FL_RESIZE_Y );
    fl_set_object_gravity( obj, FL_NorthEast, FL_SouthEast );
    fl_set_object_return( obj, FL_RETURN_CHANGED );

    colbr = obj = fl_add_browser( FL_HOLD_BROWSER, 10, 90, 205, 240, "" );
    fl_set_browser_fontstyle( obj, FL_FIXED_STYLE );
    fl_set_object_callback( obj, br_cb, 0 );
    fl_set_object_gravity( obj, FL_NorthWest, FL_SouthEast );

    obj = fl_add_button( FL_NORMAL_BUTTON, 135, 345, 80, 30, "Done" );
    fl_set_object_callback( obj, done_cb, 0 );
    fl_set_object_gravity( obj, FL_South, FL_South );
    fl_set_object_resize( obj, FL_RESIZE_NONE );

    fl_end_form( );

    fl_scale_form( cl, 1.1, 1.0 );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
