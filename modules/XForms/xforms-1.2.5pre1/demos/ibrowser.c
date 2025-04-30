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
 * image support test. See also iconvert program
 *
 *  T.C. Zhao  (1999.03.01)
 *
 *   The GUI (fdui) is placed in image->app_data;
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "include/forms.h"
#include "image/flimage.h"
#include "fd/ibrowser_gui.h"   /* from fd/ directory */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static FL_IMAGE *curr_image;


/***************************************
 ***************************************/

static void
show_image_info( FL_IMAGE * im )
{
    FD_ibcanvas *fdui;
    char buf[ 128 ],
         wl[ 128 ];

    if ( ! im )
        return;

     if ( im->type == FL_IMAGE_GRAY16 )
         sprintf( wl, "(l=%d w=%d)", im->level, im->wwidth );
     else
         wl[ 0 ] = '\0';

     sprintf( buf, "%s(%s): (%dX%d) t=%s ot=%s dt=%s cols=%d used=%d %s",
              im->infile,im->fmt_name, im->w,im->h,
              flimage_type_name( im->type ) + 9,
              flimage_type_name( im->original_type ) + 9,
              flimage_type_name( im->display_type ) + 9,
              im->map_len, im->colors, wl );

     fdui = im->app_data;
     fl_set_object_label( fdui->text, buf );

     if ( im->comments )
     {
         fl_activate_object( fdui->comments );
         fl_set_object_lcolor( fdui->comments, FL_BLACK );
     }
     else
     {
         fl_deactivate_object( fdui->comments );
         fl_set_object_lcolor( fdui->comments, FL_INACTIVE_COL );
     }
}


/***************************************
 ***************************************/

void
show_comments( FL_OBJECT * ob    FL_UNUSED_ARG,
               long        data  FL_UNUSED_ARG )
{
    if ( curr_image && curr_image->comments )
        fprintf( stderr,"%s\n", curr_image->comments );
}


/***************************************
 ***************************************/

static int
load_and_show( const char * filename,
               void       * data )
{
    FD_ibcanvas *fdui = data;
    FL_IMAGE *image;
    int r,
        g,
        b;
    struct stat sbuf;

    if ( stat( filename, &sbuf ) < 0 || S_ISDIR( sbuf.st_mode ) )
        return 1;

    image = flimage_load( filename );

    if ( image )
    {
        show_image_info( image );
        fl_get_icm_color( fdui->canvas->col1, &r, &g, &b );
        image->app_background = FL_PACK3( r, g, b );
#if 0
        image->sh = image->h / 2;
        image->sw = image->w / 2;
#endif
        flimage_display( image, FL_ObjWin( fdui->canvas ) );
        show_image_info( image );
        flimage_free( curr_image );
        curr_image = image;
#if 0
        fl_update_display( 1 );
        sleep( 5 );
        image->wx = image->wy = 90;
        image->sx = image->sy = 80;
        image->sh = image->h - 90;
        image->sw = image->w - 90;
        flimage_display( image, FL_ObjWin( fdui->canvas ) );
#endif

        /* Re-adjust the window level stuff */

        if ( image->type == FL_IMAGE_GRAY16)
        {
            fl_set_slider_bounds( fdui->level, 0, image->gray_maxval );
            fl_set_slider_bounds( fdui->width, 0, image->gray_maxval );
        }
    }
    else
        fprintf( stderr, "can't load %s\n", filename );

    return 0;
}


/***************************************
 ***************************************/

void
scale_image( FL_OBJECT * ob,
             long        data  FL_UNUSED_ARG )
{
    FD_ibcanvas *fdui = ob->form->fdui;
    float xs = fl_get_slider_value( fdui->xfloat );
    float ys = fl_get_slider_value( fdui->yfloat );
    int aa = fl_get_button( fdui->anti_aliasing );

    if ( ! curr_image )
        return;

    flimage_scale( curr_image,
                   xs * curr_image->w, ys * curr_image->h,
                   aa ? FLIMAGE_SUBPIXEL : FLIMAGE_NOSUBPIXEL );
    flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
    show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
annotate_cb( FL_OBJECT * ob,
             long        data  FL_UNUSED_ARG )
{
    FD_ibcanvas *fdui = ob->form->fdui;
    char buf[ 128 ];
    static int cnt;
    static int tx = -1, ty;
    static int r, g, b;
    int mw = 35, mh = 35,  delta = 450, i, j;
    FLIMAGE_TEXT text;

    if ( ! curr_image )
        return;

    if ( tx < 0 )
    {
        tx = curr_image->w / 2;
        ty = curr_image->h / 2;
    }

    sprintf( buf, "Text at[%d %d]\nWith Centered display", tx, ty );

    if ( ++cnt % 3 == 0 )
    {
        r = 255;
        g = 0;
        b = 0;
    }
    else if ( cnt % 3 == 1 )
    {
        r = 0;
        g = 255;
        b = 0;
    }
    else if ( cnt % 3 == 2 )
    {
        r = 0;
        g = 0;
        b = 255;
    }

    /* positioning check */

    flimage_add_text( curr_image, "@arrow", 6, 0, 20,
                      FL_PACK(r,g,b), 0, 1, 30, 30, 0 );

    flimage_add_text( curr_image, "X", 1, 0, 20,
                      FL_PACK(r,g,b), 0, 1, 30, 30, 0 );

    flimage_add_marker( curr_image, "oval",
                        30,30,
                        mw - 15, mh - 15, FL_SOLID,
                        0, 0, FL_PACK( r, g, b ), 0 );

    flimage_add_text( curr_image, buf, strlen( buf ),
                      FL_TIMESBOLD_STYLE, 20,
                      FL_PACK( r, g, b ), FL_PACK( 255, 0, 255 ),
                      0, tx, ty, 0 );

    memset( &text, 0, sizeof text );
    text.align = FL_ALIGN_LEFT;
    text.str = ( char * ) "qXXd\nqXXd";
    text.len = strlen( text.str );
    text.style = FL_TIMESBOLD_STYLE;
    text.size = 12;
    text.x = curr_image->w;
    text.y = curr_image->h;
    text.color = FL_PACK( r, g, b );
    text.bcolor = FL_PACK( r, 0, b );
    text.nobk   = 1;

    flimage_add_text_struct( curr_image, &text );

    tx += 5;
    ty += 5;

    for ( j = 0; j < 8; j++ )
    {
        const char *ss[ ] = { "oval", "delta", "rect", "cross",
                              "arrow", "thinarrow", "line", "star" };
        for ( i = 0; i < 9; i++ )
        {
            flimage_add_marker( curr_image, ss[ j ],
                                curr_image->w - i * mw, curr_image->h- j * mh,
                                mw - 15, mh - 15, FL_SOLID,
                                i % 2, i * delta, FL_PACK( r, g, b ), 0 );
        }
    }

    flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
}


/***************************************
 ***************************************/

void
render_cb( FL_OBJECT * ob,
           long        data  FL_UNUSED_ARG )
{
    FD_ibcanvas *fdui = ob->form->fdui;

    if ( curr_image )
    {
        flimage_render_annotation( curr_image, FL_ObjWin( fdui->canvas ) );
        show_image_info( curr_image );
    }
}


/***************************************
 ***************************************/

void
flip_image( FL_OBJECT * ob,
            long        data )
{
     FD_ibcanvas *fdui = ob->form->fdui;

     if ( ! curr_image )
         return;

     flimage_flip( curr_image, data );
     flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
}


/***************************************
 ***************************************/

void
rotate_image( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
    FD_ibcanvas *fdui = ob->form->fdui;
    int angle = fl_get_counter_value( fdui->angle );
    int subpix = fl_get_button( fdui->anti_aliasing );
    unsigned int fill =  0;

    if ( ! curr_image )
        return;

    curr_image->fill_color = fill;
    flimage_rotate( curr_image, angle * 10, subpix ? FLIMAGE_SUBPIXEL : 0 );
    flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
    show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
write_image( FL_OBJECT * ob,
             long        data  FL_UNUSED_ARG )
{
    FD_ibcanvas *fdui = ob->form->fdui;
    const char *f;

    if ( ! curr_image )
        return;

    fl_use_fselector( 1 );
    fl_set_fselector_placement( FL_PLACE_MOUSE );
    if ( ! ( f = fl_show_fselector( "Save Image", NULL, "*", NULL ) ) )
        return;
    flimage_dump( curr_image, f, fl_get_choice_text( fdui->format ) );
}


/***************************************
 ***************************************/

static int
expose_handle( FL_OBJECT * ob   FL_UNUSED_ARG,
               Window      win,
               int         w    FL_UNUSED_ARG,
               int         h    FL_UNUSED_ARG,
               XEvent    * xev  FL_UNUSED_ARG,
               void      * data  FL_UNUSED_ARG )
{
    if ( curr_image )
        flimage_display( curr_image, win );
    return 0;
}


/***************************************
 ***************************************/

static int
motion_handle( FL_OBJECT * ob    FL_UNUSED_ARG,
               Window      win   FL_UNUSED_ARG,
               int         w     FL_UNUSED_ARG,
               int         h     FL_UNUSED_ARG,
               XEvent    * xev   FL_UNUSED_ARG,
               void      * data  FL_UNUSED_ARG)
{
    if ( ! curr_image )
        return 0;

    if ( 1 )
    {
/*      fprintf( stderr, "X=%d Y=%d\n", xev->xmotion.x, xev->xmotion.y ); */
    }

    return 0;
}


/***************************************
 ***************************************/

void
convolve_it( FL_OBJECT * ob,
             long        data )
{
     FD_ibcanvas *fdui = ob->form->fdui;
     int subimage = fl_get_button( fdui->subimage );

     if ( ! curr_image )
         return;

     if ( subimage )
     {
         curr_image->subw = curr_image->w / 2;
         curr_image->subh = curr_image->h / 2;
         curr_image->subx = curr_image->w / 4;
         curr_image->suby = curr_image->h / 4;
     }
     else
         curr_image->subw = 0;

     flimage_convolve( curr_image, ( int ** )data, 0, 0 );
     flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
     show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
tint_it( FL_OBJECT * ob,
         long        data  FL_UNUSED_ARG )
{
     FD_ibcanvas *fdui = ob->form->fdui;
     int subimage = fl_get_button( fdui->subimage );

     if ( ! curr_image )
         return;

     if ( subimage )
     {
         curr_image->subw = curr_image->w / 2;
         curr_image->subh = curr_image->h / 2;
         curr_image->subx = curr_image->w / 4;
         curr_image->suby = curr_image->h / 4;
     }
     else
         curr_image->subw = 0;

     flimage_tint( curr_image, FL_PACK( 0, 0, 200 ), 0.3 );
     flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
     show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
window_level( FL_OBJECT * ob,
              long        data  FL_UNUSED_ARG )
{
     FD_ibcanvas *fdui = ob->form->fdui;

     if ( ! curr_image || curr_image->type != FL_IMAGE_GRAY16 )
         return;

     flimage_windowlevel( curr_image, fl_get_slider_value( fdui->level ),
                          fl_get_slider_value( fdui->width ) );
     flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
     show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
warp_it( FL_OBJECT * ob,
         long        data  FL_UNUSED_ARG )
{
    static float m[ 2 ][ 2 ] = { { 0.5, 0.5 }, { -1, 0.7 } };
    FD_ibcanvas *fdui = ob->form->fdui;
    int aa = fl_get_button( fdui->anti_aliasing );

    if ( ! curr_image )
        return ;

    curr_image->fill_color = FL_PACK(255,255,0);
#if 0
    flimage_warp( curr_image, border, curr_image->w + 2, curr_image->h + 2,
                  ( aa ? FLIMAGE_SUBPIXEL : FLIMAGE_NOSUBPIXEL )
                  | FLIMAGE_CENTER );
#else
    flimage_warp( curr_image, m, 0,0,
                  aa ? FLIMAGE_SUBPIXEL : FLIMAGE_NOSUBPIXEL );
#endif
    flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
    show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
enhance_it( FL_OBJECT * ob,
            long        data  FL_UNUSED_ARG )
{
    FD_ibcanvas *fdui = ob->form->fdui;

    if ( curr_image )
    {
        flimage_enhance( curr_image, 0 );
        flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
        show_image_info( curr_image );
    }
}


/***************************************
 ***************************************/

void
crop_it( FL_OBJECT * ob,
         long        data )
{
    FD_ibcanvas *fdui = ob->form->fdui;

    if ( ! curr_image )
        return;

    if ( data == 0 )
        flimage_autocrop( curr_image, FLIMAGE_AUTOCOLOR );
    else
    {
        curr_image->fill_color = FL_PACK( 255, 255, 0 );
        flimage_crop( curr_image, -1, -1, -1, -1 );
    }

    flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
    show_image_info( curr_image );
}


/***************************************
 ***************************************/

void
convert_type( FL_OBJECT * ob,
              long        type )
{
     FD_ibcanvas *fdui = ob->form->fdui;

     if ( curr_image )
     {
         flimage_convert( curr_image, type, 0 );
         flimage_display( curr_image, FL_ObjWin( fdui->canvas ) );
         show_image_info( curr_image );
     }
}


/***************************************
 ***************************************/

void
browse_file( FL_OBJECT * ob,
             long        data  FL_UNUSED_ARG )
{
    fl_use_fselector( 0 );
    fl_set_fselector_placement( FL_PLACE_MOUSE );
    fl_set_fselector_callback( load_and_show, ob->form->fdui );
    fl_show_fselector( "Load an Image",  0, "*", 0 );
}


/***************************************
 ***************************************/

void
quit_callback( FL_OBJECT * ob    FL_UNUSED_ARG,
               long        data  FL_UNUSED_ARG )
{
    flimage_free( curr_image );
	fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

static int
supported_image_filter( const char * name,
                        int          type )
{
    return    type == FT_DIR
           || ( type == FT_FILE && flimage_is_supported( name ) > 0 );
}


/***************************************
 ***************************************/

static void
error_report( FL_IMAGE   * im,
              const char * s )
{
    FD_ibcanvas *fdui = im->app_data;

     if ( ! s )
         s = " ";
     fl_set_object_label( fdui->error, s );
}


/***************************************
 ***************************************/

static int
status_report( FL_IMAGE   * im,
               const char * s )
{
    FD_ibcanvas *fdui = im->app_data;
    char buf[ 512 ];

    if ( im->completed < 0 )
        strcpy( buf, s );
    else if ( im->completed >= 0 && im->completed < im->total )
    {
        sprintf( buf,"%s %3.0f%% (%4d of %4d)", s,
                 ( im->completed * 100.0 ) / im->total,
                im->completed, im->h );
    }
    else
         strcpy( buf, s );

    fl_set_object_label( fdui->status, buf );
    fl_update_display( 0 );

    return 0;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_ibcanvas *fd_ibcanvas;
    int  n;
    static FLIMAGE_SETUP setup;

    fl_set_border_width( -2 );
    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_ibcanvas = create_form_ibcanvas( );
    fl_set_object_color( fd_ibcanvas->canvas, FL_COL1, FL_COL1 );

    setup.visual_cue = status_report;
    setup.error_message = error_report;
    setup.app_data = fd_ibcanvas;
    setup.delay = 70;
    flimage_setup( &setup );

    flimage_enable_png( );
    flimage_enable_xwd( );
    flimage_enable_bmp( );
    flimage_enable_xbm( );
    flimage_enable_gif( );
    flimage_enable_sgi( );
    flimage_enable_fits( );
    flimage_enable_xpm( );
    flimage_enable_tiff( );
    flimage_enable_ps( );
#ifndef NO_JPEG
    flimage_enable_jpeg( );
#endif

    for ( n = flimage_get_number_of_formats(); n; n-- )
        fl_addto_choice( fd_ibcanvas->format,
                         ( flimage_get_format_info( n ) )->short_name );

    fl_set_dirlist_filter( supported_image_filter );

    fl_add_canvas_handler( fd_ibcanvas->canvas,
                           Expose, expose_handle, 0 );

    fl_add_canvas_handler( fd_ibcanvas->canvas,
                           MotionNotify, motion_handle, 0 );

   /* Show the first form */

    fl_show_form( fd_ibcanvas->ibcanvas, FL_PLACE_CENTERFREE, FL_FULLBORDER,
                  "ibcanvas" );

    while ( fl_do_forms( ) )
        /* empty */ ;

    return 0;
}


#include "fd/ibrowser_gui.c"


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
