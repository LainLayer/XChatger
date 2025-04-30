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
 * image support test program
 *
 *  This file is part of xforms package
 *  T.C. Zhao (Nov., 1999)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "include/forms.h"
#include "image/flimage.h"
#include "fd/is_gui.h"

typedef struct
{
    FL_IMAGE       * image;
    FD_is_mainform * fd_mainform;
    FD_viewform    * fd_viewform;
    FD_processform * fd_processform;
    FD_saveAs_form * fd_saveAs_form;
    const char     * outformat;
    int              double_buffer;
    int              rgb[ 4 ];           /* current fill color */
} App;

static App app;
static int testicon = 1;


/***************************************
 ***************************************/

int
visual_cue( FL_IMAGE   * im,
            const char * s )
{
    fl_set_object_label( app.fd_mainform->status, s );

    if ( im->completed < 0 )
        fl_set_slider_value( app.fd_mainform->progressbar, 0 );
    else
        fl_set_slider_value( app.fd_mainform->progressbar,
                             ( double ) im->completed / im->total );
    return 0;
}


/***************************************
 * only show image file in file selector
 ***************************************/

static int
image_file_filter( const char * name,
                   int          type )
{
     return type == FT_FILE && flimage_is_supported( name );
}


/***************************************
 * application initialization. Enable all formats and setup visual_cue
 * and error reporting functions.
 ***************************************/

static void
app_init( void )
{
    FLIMAGE_SETUP setup;

    memset( &setup, 0, sizeof setup );

    flimage_enable_bmp( );
    flimage_enable_gif( );
    flimage_enable_ps( );
    flimage_enable_fits( );
    flimage_enable_xpm( );
    flimage_enable_xbm( );
    flimage_enable_jpeg( );
    flimage_enable_tiff( );

    /* Setup visual cue and status reporting */

    setup.visual_cue = visual_cue;
    setup.header_info = 1;
    setup.app_data = &app;
    flimage_setup( &setup );

    fl_set_dirlist_filter( image_file_filter );
}


/***************************************
 ***************************************/

void
doublebuffer_callback( FL_OBJECT * ob,
                       long        data  FL_UNUSED_ARG )
{
    app.double_buffer = fl_get_button( ob );
    if ( app.image )
        app.image->double_buffer = app.double_buffer;
}


/***************************************
 ***************************************/

void
windowlevel_callback( FL_OBJECT * ob    FL_UNUSED_ARG,
                      long        data  FL_UNUSED_ARG )
{
    if ( ! app.image )
        return;

    flimage_windowlevel( app.image,
                         fl_get_slider_value( app.fd_viewform->level ),
                         fl_get_slider_value( app.fd_viewform->window ) );
    app.image->display( app.image, app.image->win );
}


/*** callbacks and freeobj handles for form is_mainform ***/

/***************************************
 ***************************************/

void
vscroll_callback( FL_OBJECT * ob,
                  long        data  FL_UNUSED_ARG )
{
    if ( app.image )
    {
        app.image->wy = ( 0.5 - fl_get_scrollbar_value( ob ) ) * app.image->h;
        app.image->display( app.image, app.image->win );
    }
}


/***************************************
 ***************************************/

void
hscroll_callback( FL_OBJECT * ob,
                  long        data  FL_UNUSED_ARG )
{
    if ( app.image )
    {
        app.image->wx = ( 0.5 - fl_get_scrollbar_value( ob ) ) * app.image->w;
        app.image->display( app.image, app.image->win );
    }
}


/***************************************
 ***************************************/

void
outformat_callback( FL_OBJECT * ob,
                    long        data  FL_UNUSED_ARG )
{
    app.outformat = fl_get_choice_text( ob );
}


/*** Image Processing callbacks ***/

/***************************************
 ***************************************/

void
colorchange_callback( FL_OBJECT * ob,
                      long        data )
{
    app.rgb[ data ] = fl_get_slider_value( ob ) + 0.1;
    fl_mapcolor( FL_FREE_COL1, app.rgb[ 0 ], app.rgb[ 1 ], app.rgb[ 2 ] );
    fl_redraw_object( app.fd_processform->colorobj );
}


/***************************************
 ***************************************/

void
autocrop_callback( FL_OBJECT * ob    FL_UNUSED_ARG,
                   long        data  FL_UNUSED_ARG )
{
    if ( ! app.image )
        return;

    flimage_autocrop( app.image, FLIMAGE_AUTOCOLOR );
    app.image->display( app.image, app.image->win );
}


/***************************************
 ***************************************/

void
convolve_callback( FL_OBJECT * ob  FL_UNUSED_ARG,
                   long        data)
{
#if 1
    if ( app.image )
    {
        flimage_convolve( app.image, ( int ** ) data, 0, 0 );
        app.image->display( app.image, app.image->win );
    }
#else
    /* pixtran test */
    
    int red[ 256 ],
        green[ 256 ],
        blue[ 256 ],
        i;

    for ( i = 0; i < 256; i++ )
    {
        red[ i ]   = i * ( log10( 1.0 + 5 * i / 255.0 ) / log10( 1.0 + 5 ) );
        green[ i ] = i * ( log10( 1.0 + 5 * i / 255.0 ) / log10( 1.0 + 5 ) );
        blue[ i ]  = i * ( log10( 1.0 + 5 * i / 255.0 ) / log10( 1.0 + 5 ) );
    }

    flimage_transform_pixel( app.image, red, green, blue );
    app.image->display( app.image, app.image->win );
#endif
}


/***************************************
 ***************************************/

void
scaling_callback( FL_OBJECT * ob    FL_UNUSED_ARG,
                  long        data  FL_UNUSED_ARG )
{
    FD_processform *processform = app.fd_processform;
    int neww,
        newh,
        options;
    float sw,
          sh;

    if ( ! app.image )
        return;

    sw = fl_get_counter_value( processform->width );
    sh = fl_get_counter_value( processform->height );

    if ( fl_get_button( processform->pixel ) )
    {
        neww = sw + 0.1;
        newh = sh + 0.1;
    }
    else
    {
        neww = sw * app.image->w + 0.1;
        newh = sh * app.image->h + 0.1;
    }

    if ( ! strcmp( fl_get_choice_text( processform->subpixel ), "subpixel" ) )
        options = FLIMAGE_SUBPIXEL;
    else
        options = FLIMAGE_NOSUBPIXEL;

    if ( ! strcmp( fl_get_choice_text( processform->aspect ), "aspect" ) )
        options |= FLIMAGE_ASPECT;

    if ( ! strcmp( fl_get_choice_text( processform->align ), "center" ) )
        options |= FLIMAGE_CENTER;
    else
        options |= FLIMAGE_NOCENTER;

    app.image->fill_color = FL_PACK(app.rgb[ 0 ], app.rgb[ 1 ], app.rgb[ 2 ] );
    if ( flimage_scale( app.image, neww, newh, options) < 0 )
        fprintf( stderr, "scaling failed\n" );

    app.image->display( app.image, app.image->win );
}


/***************************************
 ***************************************/

void
switchtopixel_callback( FL_OBJECT * ob,
                        long        data  FL_UNUSED_ARG )
{
    FD_processform *processform = app.fd_processform;
    float w,
        h;
    FL_IMAGE *im = app.image;

    if ( ! app.image )
        return;

    /* this function may be called in two ways: real callback when switch to
       pixel button is pressed or when called directly by the application
       when a new image is loaded */

    if ( fl_get_button( processform->pixel ) )
    {
        w = ob == 0 ? 1.0 : fl_get_counter_value( processform->width );
        h = ob == 0 ? 1.0 : fl_get_counter_value( processform->height );
    }
    else
    {
        w = ob == 0 ? im->w : fl_get_counter_value( processform->width );
        h = ob == 0 ? im->h : fl_get_counter_value( processform->height );
    }

    fl_freeze_form( processform->processform );

    if ( fl_get_button( processform->pixel ) )
    {
        fl_set_counter_bounds( processform->width, 0.1 * im->w, 10.0 * im->w );
        fl_set_counter_bounds( processform->height, 0.1 * im->h, 10.0 * im->h );
        fl_set_counter_value( processform->width, w * im->w );
        fl_set_counter_value( processform->height, h * im->h );
        fl_set_counter_precision( processform->width, 0 );
        fl_set_counter_precision( processform->height, 0 );
        fl_set_counter_step( processform->width, 1, 10 );
        fl_set_counter_step( processform->height, 1, 10 );
    }
    else
    {
        fl_set_counter_bounds( processform->width, 0.1, 10.0 );
        fl_set_counter_bounds( processform->height, 0.1, 10.0 );
        fl_set_counter_value( processform->width, w / im->w );
        fl_set_counter_value( processform->height, h / im->h );
        fl_set_counter_precision( processform->width, 1 );
        fl_set_counter_precision( processform->height, 1 );
        fl_set_counter_step( processform->width, 0.1, 1 );
        fl_set_counter_step( processform->height, 0.1, 1 );
    }

    fl_unfreeze_form( processform->processform );
}


/***************************************
 * when a new image is loaded, update the GUI
 ***************************************/

void
update_process_form( void )
{
    switchtopixel_callback( 0, 0 );
}


/******************** END OF PROCESS CALLBACKS ****************************/

/***************************************
 ***************************************/

void
reset_scrollbar( FL_IMAGE * im )
{
    FD_is_mainform *fdui = im->u_vdata;

    fl_set_scrollbar_value( fdui->hscroll, 0.5 );
    fl_set_scrollbar_value( fdui->vscroll, 0.5 );
}


/***************************************
 ***************************************/

static void
test_icon( void )
{
    Pixmap pixmap;
    FL_IMAGE *im;

    if( ! testicon || app.image == 0 )
         return;

    im = flimage_dup( app.image );
    if( app.image->w > 64 || app.image->h > 64 )
        flimage_scale( im, 64, 64, FLIMAGE_ASPECT );

    pixmap = flimage_to_pixmap( im, FL_ObjWin( app.fd_viewform->pixmap ) );
    fl_free_pixmap_pixmap( app.fd_viewform->pixmap );
    fl_set_pixmap_pixmap( app.fd_viewform->pixmap, pixmap, 0 );

    flimage_free( im );
}


/***************************************
 ***************************************/

static int
load_and_show( const char * file,
               void       * data )
{
    FD_is_mainform *fdui = data;
    FL_IMAGE *image;
    FD_viewform *fd_viewform = app.fd_viewform;
    struct stat buff;

    if ( ! file || ! *file )
    {
        fprintf( stderr, "Missing file name\n" );
        return 0;
    }

    if ( ! stat( file, &buff ) && S_ISDIR( buff.st_mode ) )
    {
        fl_set_directory( file );
        return 0;
    }

    if ( ! ( image = flimage_load( file ) ) )
        return 0;

    image->u_vdata = data;
    reset_scrollbar( image );
    image->display( image, FL_ObjWin( fdui->canvas ) );
    if ( app.image )
        flimage_free( app.image );
    app.image = image;
    app.image->double_buffer = app.double_buffer;
    app.outformat = image->fmt_name;


    /* update image info */

    fl_freeze_form( fd_viewform->viewform );

    fl_set_choice_text( app.fd_saveAs_form->outformat, app.outformat );
    fl_clear_browser( fd_viewform->headerinfo );

    if ( app.image->info )
        fl_addto_browser( fd_viewform->headerinfo, app.image->info );

    if ( app.image->type == FL_IMAGE_GRAY16 )
    {
        fl_activate_object( fd_viewform->level );
        fl_activate_object( fd_viewform->window );
        fl_set_slider_bounds( fd_viewform->level, 0, image->gray_maxval );
        fl_set_slider_bounds( fd_viewform->window, 0, image->gray_maxval );
    }
    else
    {
        fl_deactivate_object( fd_viewform->level );
        fl_deactivate_object( fd_viewform->window );
    }

    test_icon( );
    fl_unfreeze_form( fd_viewform->viewform );

    update_process_form( );

    return 0;
}


static int save_file( const char *,
                      void * );


/***************************************
 ***************************************/

void
filemenu_callback( FL_OBJECT * ob,
                   long        data  FL_UNUSED_ARG )
{
    int n = fl_get_menu( ob );

    switch ( n )
    {
        case 2:            /* Open    */
            fl_use_fselector( 0 );
            fl_set_fselector_placement( FL_PLACE_MOUSE );
            fl_set_fselector_callback( load_and_show, ob->form->fdui );
            fl_show_fselector( "Load an Image", 0, "*", 0 );
            break;

        case 3:           /* Save    */
            if( app.image )
            {
                const char *f;

                fl_use_fselector( 1 );
                if ( ( f = fl_show_fselector( "OutputName", 0, "*",
                                              app.image->infile ) ) )
                    save_file( f, 0 );
            }
            break;

        case 4:           /* Save As */
            if( app.image )
                fl_show_form( app.fd_saveAs_form->saveAs_form,
                              FL_PLACE_CENTERFREE, FL_TRANSIENT,
                              "OutputForm");
            break;

        case 5:
            fl_finish( );
            exit( 0 );
    }
}


/***************************************
 ***************************************/

void
progressbar( FL_OBJECT * ob    FL_UNUSED_ARG,
             long        data  FL_UNUSED_ARG )
{
}


/***************************************
 ***************************************/

static int
expose_handle( FL_OBJECT * ob    FL_UNUSED_ARG,
               Window      win,
               int         w     FL_UNUSED_ARG,
               int         h     FL_UNUSED_ARG,
               XEvent    * xev   FL_UNUSED_ARG,
               void      * data  FL_UNUSED_ARG)
{
    if ( app.image )
        app.image->display( app.image, win );
    return 0;
}


/**********************************************************************
 * The Save As dialog
 *********************************************************************/

/***************************************
 * SaveAs file selector callback
 ***************************************/

static int save_file( const char * file,
                      void       * data  FL_UNUSED_ARG )
{
     if ( ! file || ! *file )
         return -1;
     return flimage_dump( app.image, file, app.outformat );
}


/***************************************
 ***************************************/

static void hide_it( FL_OBJECT * ob    FL_UNUSED_ARG,
                     long        data  FL_UNUSED_ARG )
{
    char file[ 256 ];
    const char *d,
               *f;

    /* get the selected file */

    fl_use_fselector( 2 );
    if  ( ( d = fl_get_directory( ) ) && ( f = fl_get_filename( ) ) )
    {
        sprintf( file,"%s/%s", d, f );
        save_file( f, 0 );
    }

    fl_hide_form( app.fd_saveAs_form->saveAs_form );
}


/***************************************
 ***************************************/

static void
init_save_as_form( void )
{
    static FD_saveAs_form *fd_saveAs_form;
    const FLIMAGE_FORMAT_INFO *fmtinfo;
    int i,
        n;
    FD_FSELECTOR *fd_fselect;

    fd_saveAs_form = create_form_saveAs_form( );
    app.fd_saveAs_form = fd_saveAs_form;

    fl_use_fselector( 2 );
    fd_fselect = fl_get_fselector_fdstruct( );
/*    fl_set_fselector_callback( save_file, 0 ); */
    fl_set_object_callback( fd_fselect->ready, hide_it, 0 );
    fl_show_object( fd_fselect->ready );
    fl_set_form_atclose( app.fd_saveAs_form->saveAs_form,
                         fl_goodies_atclose, fd_fselect->ready );

    /* Put fselector into the formbrowser as a way of reparenting */

    fl_addto_formbrowser( app.fd_saveAs_form->formcontainer,
                          fd_fselect->fselect );

    /* Fill the output format choice */

    for ( n = flimage_get_number_of_formats( ), i = 1; i <= n; i++ )
    {
        fmtinfo = flimage_get_format_info( i );

        if ( fmtinfo->read_write & FLIMAGE_WRITABLE )
            fl_addto_choice( app.fd_saveAs_form->outformat,
                             fmtinfo->short_name );
    }

    app.outformat = fl_get_choice_text( app.fd_saveAs_form->outformat );
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_is_mainform *fd_is_mainform;
    FD_viewform *fd_viewform;
    FD_processform *fd_processform;
    FD_annotationform *fd_annotationform;

    fl_set_border_width( -2 );
    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_is_mainform = create_form_is_mainform( );
    fd_viewform = create_form_viewform( );
    fd_processform = create_form_processform( );
    fd_annotationform = create_form_annotationform( );

    /* initialize app GUI */

    app.fd_mainform = fd_is_mainform;
    app.fd_viewform = fd_viewform;
    app.fd_processform = fd_processform;

    /* image related initializations */

    app_init( );

    /* fill-in form initialization code */

    fl_set_browser_fontstyle( fd_viewform->headerinfo, FL_FIXED_STYLE );

    fl_addto_tabfolder( fd_is_mainform->tabfolder, " View ",
                        fd_viewform->viewform);
    fl_addto_tabfolder( fd_is_mainform->tabfolder, "Processing",
                        fd_processform->processform );
    fl_addto_tabfolder( fd_is_mainform->tabfolder, "Annotation",
                        fd_annotationform->annotationform);

    fl_add_canvas_handler( fd_is_mainform->canvas,
                           Expose, expose_handle, 0 );

    app.rgb[ 0 ] = fl_get_slider_value( fd_processform->red )   + 0.1;
    app.rgb[ 1 ] = fl_get_slider_value( fd_processform->green ) + 0.1;
    colorchange_callback( fd_processform->blue, 2 );

    init_save_as_form( );

    /* show the main form */

    fl_show_form( fd_is_mainform->is_mainform, FL_PLACE_CENTERFREE,
                  FL_FULLBORDER, "is_mainform" );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}

#include "fd/is_gui.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
