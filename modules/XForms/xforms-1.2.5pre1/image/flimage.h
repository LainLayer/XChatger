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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/********************** crop here for forms.h **********************/

/* Image related routines */

#ifndef FL_IMAGE_H
#define FL_IMAGE_H

#if defined(__cplusplus)
extern "C"
{
#endif

#ifndef FL_EXPORT
#define FL_EXPORT extern
#endif

#define FL_RGB2GRAY( r, g, b )  \
    ( ( unsigned int )( ( 78 * ( r ) + 150 * ( g ) + 28 * ( b ) ) >> 8 ) )

enum {
    FL_IMAGE_NONE,
    FL_IMAGE_MONO   =    1,     /* b&w. 1bit. 0=white 1=black */
    FL_IMAGE_GRAY   =    2,     /* 8 bit gray image           */
    FL_IMAGE_CI     =    4,     /* colormmaped image          */
    FL_IMAGE_RGB    =    8,     /* RGBA image. 8bit each      */
    FL_IMAGE_PACKED =   16,     /* RGBA packed into an int    */
    FL_IMAGE_GRAY16 =   32,     /* 12bit gray scale image     */
    FL_IMAGE_RGB16  =   64,     /* 36bits color image         */
    FL_IMAGE_FLEX   = 1023,     /* all formats                */
    /* aliases */
    FLIMAGE_NONE    = FL_IMAGE_NONE,
    FLIMAGE_MONO    = FL_IMAGE_MONO,
    FLIMAGE_GRAY    = FL_IMAGE_GRAY,
    FLIMAGE_CI      = FL_IMAGE_CI,
    FLIMAGE_RGB     = FL_IMAGE_RGB,
    FLIMAGE_PACKED  = FL_IMAGE_PACKED,
    FLIMAGE_GRAY16  = FL_IMAGE_GRAY16,
    FLIMAGE_RGB16   = FL_IMAGE_RGB16,
    FLIMAGE_FLEX    = FL_IMAGE_FLEX
};

#ifndef FL_PCBITS
typedef unsigned char FL_PCTYPE;    /* primary color type */
#define FL_PCBITS         8 /* primary color bits */
#define FL_PCMAX          ( ( 1 << FL_PCBITS ) - 1 )
#define FL_PCCLAMP( a )   ( ( a ) > ( FL_PCMAX ) ?    \
                            ( FL_PCMAX ) : ( ( a ) < 0 ? 0 : ( a ) ) )

typedef unsigned int      FL_PACKED4;
#define FL_PACKED         FL_PACKED4

#define FL_RMASK          0x000000ff
#define FL_RSHIFT         0
#define FL_GMASK          0x0000ff00
#define FL_GSHIFT         8
#define FL_BMASK          0x00ff0000
#define FL_BSHIFT         16
#define FL_AMASK          0xff000000
#define FL_ASHIFT         24

/* If PCBITS is not 8, we need to apply the RGBmask */

#define FL_GETR( packed ) (   ( packed )                & FL_RMASK )
#define FL_GETG( packed ) ( ( ( packed ) >> FL_GSHIFT ) & FL_PCMAX )
#define FL_GETB( packed ) ( ( ( packed ) >> FL_BSHIFT ) & FL_PCMAX )
#define FL_GETA( packed ) ( ( ( packed ) >> FL_ASHIFT ) & FL_PCMAX )

#define FL_PACK3( r, g, b )   \
    ( ( ( r ) << FL_RSHIFT ) | ( ( g ) << FL_GSHIFT ) | ( ( b ) << FL_BSHIFT ) )

#define FL_PACK           FL_PACK3

#define FL_PACK4( r, g, b, a)  \
    ( FL_PACK3( r, g, b ) | ( ( a ) << FL_ASHIFT ) )

#define FL_UNPACK( p, r, g, b )  \
    do { r = FL_GETR( p );       \
         g = FL_GETG( p );       \
         b = FL_GETB( p );       \
    } while ( 0 )

#define FL_UNPACK3        FL_UNPACK

#define FL_UNPACK4( p, r, g, b, a )  \
    do { FL_UNPACK3( p, r, g, b );   \
         a = FL_GETA( p );           \
    } while ( 0 )

#endif

#define FL_LUTBITS        12    /* max colormap bits. 4096 entries */

#define FL_IsRGB( im )    ( ( im )->type == FL_IMAGE_RGB )
#define FL_IsPacked( im ) ( ( im )->type == FL_IMAGE_PACKED )

enum
{
    FLIMAGE_AUTOCOLOR = 0x7fffffff,
    FLIMAGE_BADCOLOR  = FLIMAGE_AUTOCOLOR
};


typedef Window FL_WINDOW;   /* unsigned long */

typedef struct flimage_text_ {
    char         * str;       /* the string itself             */
    int            len;       /* string length                 */
    int            x,         /* starting location of text (wrt image) */
                   y;
    unsigned int   color;     /* color of the text             */
    unsigned int   bcolor;    /* background color of the text  */
    int            nobk;      /* no background                 */
    int            size,      /* font size & style             */
                   style;
    int            angle;     /* in 1/10th of a degrees        */
    int            align;     /* alignment wrt to (x,y)        */
} FLIMAGE_TEXT;

typedef struct flimage_marker_ {
    const char   * name;      /* marker name                  */
    int            w,         /* size                         */
                   h ;
    int            x,         /* location                     */
                   y;
    unsigned int   color;     /* color of the marker          */
    unsigned int   bcolor;    /* aux. color of the marker     */
    int            angle;     /* in 1/10th of a degree        */
    int            fill;
    int            thickness; /* line thickness               */
    int            style;     /* line style                   */

    /* the following is filled by the library */

    void       * display;
    void       * gc;
    FL_WINDOW    win;
    const char * psdraw;
} FLIMAGE_MARKER;

#define FLIMAGE_REPFREQ  0x1f   /* report every 32 lines */

#ifndef FL_RGB2PIXEL

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
#endif

typedef struct flimage_setup_ *FLIMAGESETUP;

typedef struct flimage_ {
    int               type;         /* image type                    */
    int               w,
                      h;            /* image size                    */
    void *            app_data;     /* for application at setup time */
    void *            u_vdata;      /* for application               */
    long              u_ldata;      /* for application               */
    unsigned char  ** red;
    unsigned char  ** green;
    unsigned char  ** blue;
    unsigned char  ** alpha;
    unsigned char  ** rgba[ 4 ];    /* alias                         */
    unsigned short ** ci;
    unsigned short ** gray;
    FL_PACKED4 **     packed;
    unsigned short ** red16;          /* not currently supported */
    unsigned short ** green16;        /* not currently supported */
    unsigned short ** blue16;         /* not currently supported */
    unsigned short ** alpha16;        /* not currently supported */
    unsigned char  ** ci8;            /* not currently supported */
    int             * red_lut;        /* red lookup tables                */
    int             * green_lut;      /* green lookup tables              */
    int             * blue_lut;       /* blue lookup tables               */
    int             * alpha_lut;      /* alpha lookup tables              */
    int             * lut[ 4 ];       /* alias                            */
    int               map_len;        /* lut length                       */
    int               colors;         /* actual colors used in displaying */
    int               gray_maxval;    /* indicate the range of gray16     */
    int               ci_maxval;      /* max value of ci. not used,
                                         use map_len */
    int               rgb_maxval;     /* max value for rgb16 image       */
    int               level,
                      wwidth;
    unsigned short  * wlut;           /* lut for window levelling         */
    int               wlut_len;
    int               app_background; /* transparent color: in RGB        */
    char            * comments;
    int               comments_len;
    int               available_type;
    struct flimage_ * next;
    int               sx,             /* display subimage origin          */
                      sy;
    int               sw,             /* display subimage width           */
                      sh;
    int               wx,             /* display location relative to win */
                      wy;
    int modified;
    int               ( * display )( struct flimage_ *, FL_WINDOW );
    int               double_buffer;
    int               sxd,
                      syd,
                      swd,
                      shd;
    int               wxd,
                      wyd;
    const char      * fmt_name;       /* format name (ppm,jpg etc)     */

    /* annotation stuff */

    FLIMAGE_TEXT    * text;
    int               ntext,
                      max_text;
    int               dont_display_text;
    void              ( * display_text )( struct flimage_ * );
    void              ( * free_text )( struct flimage_ * );
    FLIMAGE_MARKER  * marker;
    int               nmarkers,
                      max_markers;
    int               dont_display_marker;
    void              ( * display_markers )( struct flimage_ * );
    void              ( * free_markers )( struct flimage_ * );

    /* physicalValue = poffset + pixelValue * pscale  */

    double            pmin,           /* physical data range             */
                      pmax;
    double            poffset;
    double            pscale;

    /* pixel grid distance */

    double            xdist_offset;
    double            xdist_scale;
    double            ydist_offset;
    double            ydist_scale;

    char            * infile;
    char            * outfile;
    long              foffset;
    int               original_type;

    /* hooks for application to have a chance to set some options.
       if pre_write returns -1, the output will be canceled */

    int               ( * pre_write )( struct flimage_ * );
    int               ( * post_write )( struct flimage_ * );

    /* image processing stuff */

    int               subx,           /* subimage origin       */
                      suby;
    int               subw,           /* subimage size         */
                      subh;
    int               sub_shape;      /* shape of the subimage */
    unsigned int      fill_color;     /* fill color            */
    int               force_convert;
    int             * llut[ 3 ];      /* linear lut            */
    int               llut_len;
    unsigned int    * hist[ 4 ];

    /* application handlers */

    int               total,
                      completed;
    int               ( * visual_cue )( struct flimage_*,
                                        const char * );
    void              ( * error_message )( struct flimage_*,
                                           const char * );
    int               error_code;     /* not currently used */

    int               display_type;   /* just before handing it to X      */
    unsigned short ** pixels;
    void            * image_spec;     /* additional image info            */
    void            * xdisplay;       /* the X connection                 */
    int               tran_rgb;       /* RGB color that should be transparent */
    int               tran_index;     /* index that should be transparent     */
    int               matr,
                      matc;

    /* multi-frame images */

    int               more;
    int               current_frame;
    int               total_frames;
    int               ( * next_frame )( struct flimage_ * );
    int               ( * prev_frame )( struct flimage_ * );
    int               ( * random_frame )( struct flimage_ *, int );
    int               ( * rewind_frame )( struct flimage_ * );
    void              ( * cleanup )( struct flimage_ * );
    int               stop_looping;

    /* the following are for internal use */

    FILE            * fpin;
    FILE            * fpout;
    void            * image_io;
    void            * io_spec;        /* io operation helper       */
    int               spec_size;
    int               depth;          /* the depth we actually use */
    int               vclass;
    void            * visual;
    unsigned long     xcolormap;
    FL_RGB2PIXEL      rgb2p;
    void            * ximage;
    FL_WINDOW         win;
    void            * gc;
    int               sdepth;         /* depth the server says     */
    void            * textgc;
    void            * markergc;
    void            * extra_io_info;
    unsigned long     pixmap;
    int               pixmap_w,
                      pixmap_h,
                      pixmap_depth;
    int               isPixmap;
    FLIMAGESETUP      setup;
    char            * info;
} FL_IMAGE;

/* some configuration stuff */

typedef struct flimage_setup_ {
    void          * app_data;
    int             ( * visual_cue )( FL_IMAGE *,
                                      const char *);
    void            ( * error_message )( FL_IMAGE *,
                                         const char *);
    int             ( * display )( FL_IMAGE *,
                                   unsigned long );

    const char    * rgbfile;
    int             do_not_clear;
    void          * xdisplay;
    int             max_frames;
    int             delay;
    int             no_auto_extension;
    int             report_frequency;
    int             double_buffer;

    /* internal use */

    unsigned long   trailblazer;
    int             header_info;
} FLIMAGE_SETUP;

FL_EXPORT void flimage_setup( FLIMAGE_SETUP * );

/* Possible errors from the library. Not currently (v0.89) used */

enum {
   FLIMAGE_ERR_NONE = 0,
   FLIMAGE_ERR_ALLOC = -50,     /* allocation error     */
   FLIMAGE_ERR_INVALID,         /* invalid image        */
   FLIMAGE_ERR_ARGUMENT,        /* bad argument/request */
   FLIMAGE_ERR_FILE,            /* io error             */
   FLIMAGE_ERR_INTERNAL,        /* bugs                 */
   FLIMAGE_ERR_UNKNOWN
};

typedef int ( * FLIMAGE_Identify )( FILE * );
typedef int ( * FLIMAGE_Description )( FL_IMAGE * );
typedef int ( * FLIMAGE_Read_Pixels )( FL_IMAGE * );
typedef int ( * FLIMAGE_Write_Image )( FL_IMAGE * );

/* Basic IO routines */

FL_EXPORT FL_IMAGE * flimage_load( const char * file );

FL_EXPORT FL_IMAGE * flimage_read( FL_IMAGE * im );

FL_EXPORT int flimage_dump( FL_IMAGE *,
							const char *,
							const char * );

FL_EXPORT int flimage_close( FL_IMAGE * );

FL_EXPORT FL_IMAGE * flimage_alloc( void );

FL_EXPORT int flimage_getmem( FL_IMAGE * );

FL_EXPORT int flimage_is_supported( const char * );

FL_EXPORT int flimage_description_via_filter( FL_IMAGE *,
											  char *const *,
											  const char *,
											  int );

FL_EXPORT int flimage_write_via_filter( FL_IMAGE *,
										char * const *,
										char * const *,
										int );

FL_EXPORT FL_IMAGE * flimage_alloc( void );

FL_EXPORT void flimage_free( FL_IMAGE * );

FL_EXPORT int flimage_display( FL_IMAGE *,
							   Window );

FL_EXPORT int flimage_sdisplay( FL_IMAGE *,
								Window );

FL_EXPORT int flimage_convert( FL_IMAGE *,
							   int,
							   int );

FL_EXPORT const char * flimage_type_name( int type );

FL_EXPORT int flimage_add_text( FL_IMAGE *,
								const char *,
								int,
								int,
								int,
								unsigned int,
								unsigned int,
								int,
								double,
								double,
								int );

FL_EXPORT int flimage_add_text_struct( FL_IMAGE *,
									   const FLIMAGE_TEXT * );

FL_EXPORT void flimage_delete_all_text( FL_IMAGE * );

FL_EXPORT int flimage_add_marker( FL_IMAGE *,
								  const char *,
								  double,
								  double,
								  double,
								  double,
								  int,
								  int,
								  int,
								  unsigned int,
								  unsigned int );

FL_EXPORT int flimage_add_marker_struct( FL_IMAGE *,
										 const FLIMAGE_MARKER * );

FL_EXPORT int flimage_define_marker( const char *,
									 void ( * )( FLIMAGE_MARKER * ),
									 const char * );

FL_EXPORT void flimage_delete_all_markers( FL_IMAGE * );

FL_EXPORT int flimage_render_annotation( FL_IMAGE *,
										 FL_WINDOW );

FL_EXPORT void flimage_error( FL_IMAGE *,
							  const char *,
							  ... );

/* Built-in format supports */

FL_EXPORT void flimage_enable_pnm( void );

FL_EXPORT int flimage_set_fits_bits( int );

/* Output options */

typedef struct
{
    int quality;
    int smoothing;
} FLIMAGE_JPEG_OPTION;

FL_EXPORT void flimage_jpeg_output_options( FLIMAGE_JPEG_OPTION * );

FL_EXPORT void flimage_pnm_output_options( int );

FL_EXPORT void flimage_gif_output_options( int );

FL_EXPORT FLPS_CONTROL * flimage_ps_options( void );

#define flimage_jpeg_options  flimage_jpeg_output_options
#define flimage_pnm_options   flimage_pnm_output_options    
#define flimage_gif_options   flimage_gif_output_options    

enum
{
    FLIMAGE_WRITABLE = FL_WRITE,
    FLIMAGE_READABLE = FL_READ
};

typedef struct {
    const char * formal_name;
    const char * short_name;
    const char * extension;
    int          type;
    int          read_write;
    int          annotation;
} FLIMAGE_FORMAT_INFO;

FL_EXPORT int flimage_get_number_of_formats( void );

FL_EXPORT const FLIMAGE_FORMAT_INFO * flimage_get_format_info( int );

FL_EXPORT void * fl_get_matrix( int,
								int,
								unsigned int );

FL_EXPORT void * fl_make_matrix( int,
								 int,
								 unsigned int,
								 void * );

FL_EXPORT void fl_free_matrix( void * );

/* This function is retained for compatibility reasons only.
   It returns 1 always. */

FL_EXPORT int fl_init_RGBdatabase( const char * );

FL_EXPORT int fl_lookup_RGBcolor( const char *,
								  int *,
								  int *,
								  int * );

FL_EXPORT int flimage_add_format( const char *,
								  const char *,
								  const char *,
								  int,
								  FLIMAGE_Identify,
								  FLIMAGE_Description,
								  FLIMAGE_Read_Pixels,
								  FLIMAGE_Write_Image );

FL_EXPORT void flimage_set_annotation_support( int,
											   int );

FL_EXPORT int flimage_getcolormap( FL_IMAGE * );

FL_EXPORT void fl_select_mediancut_quantizer( void );

/* Simple image processing routines */

#define FLIMAGE_SHARPEN        ( ( int** )( -1 ) )
#define FLIMAGE_SMOOTH         ( ( int** )( -2 ) )
#define FL_SMOOTH              FLIMAGE_SMOOTH
#define FL_SHARPEN             FLIMAGE_SHARPEN

enum {
   FLIMAGE_NOSUBPIXEL =  0,     /* scale with no subpixel sampling */
   FLIMAGE_SUBPIXEL   =  1,     /* scale with  subpixel sampling */
   FLIMAGE_CENTER     =  2,     /* center warped image. default  */
   FLIMAGE_RIGHT      =  8,     /* flush right the warped image  */
   FLIMAGE_ASPECT     = 32,     /* fit the size */
   FLIMAGE_NOCENTER   = FL_ALIGN_LEFT_TOP
};

FL_EXPORT int flimage_convolve( FL_IMAGE *,
								int **,
								int,
								int );

FL_EXPORT int flimage_convolvea( FL_IMAGE *,
								 int *,
								 int,
								 int );

FL_EXPORT int flimage_tint( FL_IMAGE *,
							unsigned int,
							double
        );

FL_EXPORT int flimage_rotate( FL_IMAGE *,
							  int,
							  int );

FL_EXPORT int flimage_flip( FL_IMAGE *,
							int );

FL_EXPORT int flimage_scale( FL_IMAGE *,
							 int,
							 int,
							 int );

FL_EXPORT int flimage_warp( FL_IMAGE *,
							float [ ][ 2 ],
							int,
							int,
							int );

FL_EXPORT int flimage_autocrop( FL_IMAGE *,
								unsigned int );

FL_EXPORT int flimage_get_autocrop( FL_IMAGE *,
									unsigned int,
									int *,
									int *,
									int *,
									int * );

FL_EXPORT int flimage_crop( FL_IMAGE *,
							int,
							int,
							int,
							int );

FL_EXPORT int flimage_replace_pixel( FL_IMAGE *,
									 unsigned int,
									 unsigned int );

FL_EXPORT int flimage_transform_pixels( FL_IMAGE *,
										int *,
										int *,
										int * );

FL_EXPORT int flimage_windowlevel( FL_IMAGE *,
								   int,
								   int );

FL_EXPORT int flimage_enhance( FL_IMAGE *,
							   int );

FL_EXPORT int flimage_from_pixmap( FL_IMAGE *,
								   Pixmap );

FL_EXPORT Pixmap flimage_to_pixmap( FL_IMAGE *, 
									FL_WINDOW );

FL_EXPORT FL_IMAGE * flimage_dup( FL_IMAGE * );

/* Miscellaneous prototypes */

FL_EXPORT int fl_object_ps_dump( FL_OBJECT *,
								 const char * );

FL_EXPORT void flimage_add_comments( FL_IMAGE *,
									 const char *,
									 int );

FL_EXPORT unsigned long flimage_color_to_pixel( FL_IMAGE *,
												int,
												int,
												int,
												int * );

FL_EXPORT FL_IMAGE * flimage_combine( FL_IMAGE *,
									  FL_IMAGE *,
									  double );

FL_EXPORT int flimage_define_marker( const char *,
									 void ( * )( FLIMAGE_MARKER * ),
									 const char * );

FL_EXPORT void flimage_display_markers( FL_IMAGE * );

FL_EXPORT FL_IMAGE *flimage_dup_( FL_IMAGE *, 
								  int );

FL_EXPORT void flimage_enable_bmp( void );

FL_EXPORT void flimage_enable_fits( void );

FL_EXPORT void flimage_enable_genesis( void );

FL_EXPORT void flimage_enable_gif( void );

FL_EXPORT void flimage_enable_gzip( void );

FL_EXPORT void flimage_enable_jpeg( void );

FL_EXPORT void flimage_enable_png( void );

FL_EXPORT void flimage_enable_ps( void );

FL_EXPORT void flimage_enable_sgi( void );

FL_EXPORT void flimage_enable_tiff( void );

FL_EXPORT void flimage_enable_xbm( void );

FL_EXPORT void flimage_enable_xpm( void );

FL_EXPORT void flimage_enable_xwd( void );

FL_EXPORT void flimage_free_ci( FL_IMAGE * );

FL_EXPORT void flimage_free_gray( FL_IMAGE * );

FL_EXPORT void flimage_free_linearlut( FL_IMAGE * );

FL_EXPORT void flimage_free_rgb( FL_IMAGE * );

FL_EXPORT void flimage_freemem( FL_IMAGE * );

FL_EXPORT int flimage_get_closest_color_from_map( FL_IMAGE *,
												  unsigned int );

FL_EXPORT int flimage_get_linearlut( FL_IMAGE * );

FL_EXPORT void flimage_invalidate_pixels( FL_IMAGE * );

FL_EXPORT FL_IMAGE *flimage_open( const char * );

FL_EXPORT int flimage_read_annotation( FL_IMAGE * );

FL_EXPORT void flimage_replace_image( FL_IMAGE *,
									  int,
									  int,
									  void *,
									  void *,
									  void * );

FL_EXPORT int flimage_swapbuffer( FL_IMAGE * );

FL_EXPORT int flimage_to_ximage( FL_IMAGE *,
								 FL_WINDOW,
								 XWindowAttributes * );

FL_EXPORT int flimage_write_annotation( FL_IMAGE * );

FL_EXPORT void flps_apply_gamma( float );

FL_EXPORT void flps_arc( int,
						 int,
						 int,
						 int,
						 int,
						 int,
						 FL_COLOR );

FL_EXPORT void flps_circ( int,
						  int,
						  int,
						  int,
						  FL_COLOR );

FL_EXPORT void flps_color( FL_COLOR col );

FL_EXPORT void flps_draw_box( int,
							  int,
							  int,
							  int,
							  int,
							  FL_COLOR,
							  int );

FL_EXPORT void flps_draw_checkbox( int,
								   int,
								   int,
								   int,
								   int,
								   FL_COLOR,
								   int );

FL_EXPORT void flps_draw_frame( int,
								int,
								int,
								int,
								int,
								FL_COLOR,
								int );

FL_EXPORT int flps_draw_symbol( const char *,
								int,
								int,
								int,
								int,
								FL_COLOR );

FL_EXPORT void flps_draw_tbox( int,
							   int,
							   int,
							   int,
							   int,
							   FL_COLOR,
							   int );

FL_EXPORT void flps_draw_text( int,
							   int,
							   int,
							   int,
							   int,
							   FL_COLOR,
							   int,
							   int,
							   const char * );

FL_EXPORT void flps_draw_text_beside( int,
									  int,
									  int,
									  int,
									  int,
									  FL_COLOR,
									  int,
									  int,
									  const char * );

FL_EXPORT void flps_emit_header( const char *,
								 int,
								 int,
								 int,
								 int,
								 int );

FL_EXPORT void flps_emit_prolog( void );

FL_EXPORT int flps_get_gray255( FL_COLOR );

FL_EXPORT int flps_get_linestyle( void );

FL_EXPORT int flps_get_linewidth( void );

FL_EXPORT FL_COLOR flps_get_namedcolor( const char * );

FL_EXPORT FLPS_CONTROL * flps_init( void );

FL_EXPORT void flps_invalidate_color_cache( void );

FL_EXPORT void flps_invalidate_font_cache( void );

FL_EXPORT void flps_invalidate_linewidth_cache( void );

FL_EXPORT void flps_invalidate_symbol_cache( void );

FL_EXPORT void flps_line( int,
						  int,
						  int,
						  int,
						  FL_COLOR );

FL_EXPORT void flps_lines( FL_POINT *,
						   int,
						   FL_COLOR );

FL_EXPORT void flps_linestyle( int );

FL_EXPORT void flps_linewidth( int );

FL_EXPORT void flps_log( const char * );

FL_EXPORT void flps_output( const char *,
							... );

FL_EXPORT void flps_oval( int,
						  int,
						  int,
						  int,
						  int,
						  FL_COLOR );

FL_EXPORT void flps_pieslice( int,
							  int,
							  int,
							  int,
							  int,
							  int,
							  int,
							  FL_COLOR );

FL_EXPORT void flps_poly( int,
						  FL_POINT *,
						  int,
						  FL_COLOR );

FL_EXPORT void flps_rectangle( int,
							   int,
							   int,
							   int,
							   int,
							   FL_COLOR );

FL_EXPORT void flps_reset_cache( void );

FL_EXPORT void flps_reset_linewidth( void );

FL_EXPORT void flps_restore_flps( void );

FL_EXPORT void flps_rgbcolor( int,
							  int,
							  int );

FL_EXPORT void flps_roundrectangle( int,
									int,
									int,
									int,
									int,
									FL_COLOR );

FL_EXPORT void flps_set_clipping( int,
								  int,
								  int,
								  int );

FL_EXPORT void flps_set_font( int,
							  int );

FL_EXPORT void flps_unset_clipping( void );

#ifdef MAKING_FORMS
#include "flimage_int.h"
#endif

#if defined(__cplusplus)
}
#endif

#endif /* ! defined FL_IMAGE_H */
