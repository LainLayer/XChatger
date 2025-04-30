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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>
#include "flinternal.h"
#include "bitmaps/colorwheel.xpm"

typedef struct
{
    FL_FORM *   form;
    FL_OBJECT * pm;            /* pixmap with colorwheel */
    FL_OBJECT * pos;           /* positioner to select hue and saturation */
    FL_OBJECT * sl;            /* slider for HSV value */
    FL_OBJECT * hsv_inp[ 3 ];  /* HSV input fields */
    FL_OBJECT * rgb_inp[ 3 ];  /* RGB input fields */
    FL_OBJECT * area;          /* area for showing selected color */
    FL_OBJECT * hex;           /* label showing selected RGB color in hex */
    FL_OBJECT * ok;            /* "OK" button */
    FL_OBJECT * quit;          /* "Quit" button */
    int         hsv[ 3 ];      /* arrays for current HSV and RGB values */
    int         rgb[ 3 ];
} COLOR_CHOOSER;



#define RED        0
#define GREEN      1
#define BLUE       2
#define HUE        0
#define SATURATION 1
#define VALUE      2


/****************************************
 * Note that there isn't a 1-to-1 mapping between HSV and RGB color spaces,
 * already since there are many more possible HSV than RGB values and also
 * some colors can't be uniquely described in HSV (e.g. all greyscale values
 * including white or black).
 ***************************************/


/***************************************
 * Conversion from RGB to HSV values
 ***************************************/

static int
rgb2hsv( const int rgb[ 3 ],
         int       hsv[ 3 ] )
{
    int min = 255,
        max = 0,
        delta,
        i,
        mi = 0;

    for ( i = RED; i <= BLUE; i++ )
    {
        /* Check that value is within the interval [0, 255], otherwise
           return -1. */

        if ( rgb[ i ] < 0 || rgb[ i ] > 255 )
            return -1;

        /* Calculate minimum and maximum and index of the maximum */

        min = rgb[ i ] < min ? rgb[ i ] : min;
        if ( rgb[ i ] > max )
        {
            max = rgb[ i ];
            mi = i;
        }
    }

    /* If all three values are identical there's no unique mapping to a
       HSV triple, set saturation and value, arbitrarily set hue to 0 and
       return 1 to indicate that there's no unique value for hue. */

    delta = max - min;

    if ( delta == 0 )
    {
        hsv[ HUE        ] = 0;
        hsv[ SATURATION ] = 0;
        hsv[ VALUE      ] = FL_nint( max / 2.55 );
        return 1;
    }

    /* Calculate hue, saturation and value - hue must be with [0, 359] */

    hsv[ SATURATION ] = FL_nint( ( 100.0 * delta ) / max );
    hsv[ VALUE      ] = FL_nint( max / 2.55 );
    hsv[ HUE ] =
        FL_nint( 60 * (   2 * mi
                        + ( rgb[ ( mi + 1 ) % 3 ] - rgb[ ( mi + 2 ) % 3 ] )
                        / (double ) delta ) );

    if ( hsv[ HUE ] < 0 )
        hsv[ HUE ] += 360;

    return 0;
}


/***************************************
 * Conversion from RGB to HSV values.
 ***************************************/

static int
hsv2rgb( const int hsv[ 3 ],
         int       rgb[ 3 ] )
{
    int i, v, p, q, t;
    double h, f;

    /* Check the input and return -1 if a value is out of bounds */

    if ( hsv[ HUE ] < 0 || hsv[ HUE ] > 359 )
        return -1;
    for ( i = SATURATION; i <= VALUE; i++ )
        if ( hsv[ i ] < 0 || hsv[ i ] > 100 )
            return -1;

    if ( hsv[ SATURATION ] == 0 )        /* achromatic (grey) */
    {
        rgb[ RED ] = rgb[ GREEN ] = rgb[ BLUE ] =
                                                FL_nint( 2.55 * hsv[ VALUE ] );
        return 0;
    }

    f = modf( hsv[ HUE ] / 60.0, &h );;
    p = FL_nint( 0.0255 * hsv[ VALUE ] * ( 100 - hsv[ SATURATION ] ) );
    q = FL_nint( 0.0255 * hsv[ VALUE ] * ( 100 - hsv[ SATURATION ] * f ) );
    t = FL_nint(   0.0255 * hsv[ VALUE ]
                 * ( 100 - hsv[ SATURATION ] * ( 1 - f ) ) );
    v = FL_nint( 2.55 * hsv[ VALUE ] );

    switch( ( int ) h )
    {
        case 0:
            rgb[ RED   ] = v;
            rgb[ GREEN ] = t;
            rgb[ BLUE  ] = p;
            break;

        case 1:
            rgb[ RED   ] = q;
            rgb[ GREEN ] = v;
            rgb[ BLUE  ] = p;
            break;

        case 2:
            rgb[ RED   ] = p;
            rgb[ GREEN ] = v;
            rgb[ BLUE  ] = t;
            break;

        case 3:
            rgb[ RED   ] = p;
            rgb[ GREEN ] = q;
            rgb[ BLUE  ] = v;
            break;

        case 4:
            rgb[ RED   ] = t;
            rgb[ GREEN ] = p;
            rgb[ BLUE  ] = v;
            break;

        case 5:
            rgb[ RED   ] = v;
            rgb[ GREEN ] = p;
            rgb[ BLUE  ] = q;
            break;
    }

    return 0;
}


/***************************************
 * Validator for the positioner, keeps the position within the
 * circle of the underlying colorwheel pixmap. Boundaries for the
 * x- and y-values have been set up so that a set of value with
 * a radius of 1 is exactly on the edge of the colorwheel.
 ***************************************/

static int
validator( FL_OBJECT * obj  FL_UNUSED_ARG,
           double      x,
           double      y,
           double    * x_repl,
           double    * y_repl )
{
    double angle;

    /* If the new position is within the circle (with radius 1) it's fine,
       tell the positioner to use it as is */

    if ( x * x + y * y <= 1 )
        return FL_POSITIONER_VALID;

    /* Otherwise replace the new position by one at the circle's border
       in the direction from the center to the new coordinates */

    angle = atan2( y, x );
    *x_repl = cos( angle );
    *y_repl = sin( angle );

    /* Tell the positioner to use the values in x_repl and y_repl */

    return FL_POSITIONER_REPLACED;
}


/***************************************
 * Sets the colorfor the box sowing the currently selected color
 * and the label with its hexadecimal value.
 ***************************************/

static void
update_color_area( COLOR_CHOOSER * cc )
{
    fl_mapcolor( FL_COLOR_CHOOSER_COLOR,
                 cc->rgb[ RED ], cc->rgb[ GREEN ], cc->rgb[ BLUE ] );
    fl_redraw_object( cc->area );

    fl_set_object_label_f( cc->hex, "#%02X%02X%02X",
                           cc->rgb[ RED ], cc->rgb[ GREEN ], cc->rgb[ BLUE ] );
}


/***************************************
 * Sets all HSV input field values at once
 ***************************************/

static void
set_hsv_inputs( COLOR_CHOOSER * cc )
{
    int i;

    for ( i = HUE; i <= VALUE; i++ )
        fl_set_input_f( cc->hsv_inp[ i ], "%d", cc->hsv[ i ] );
}


/***************************************
 * Sets all RGB input field values at once
 ***************************************/

static void
set_rgb_inputs( COLOR_CHOOSER * cc )
{
    int i;

    for ( i = RED; i <= BLUE; ++i )
        fl_set_input_f( cc->rgb_inp[ i ],   "%d", cc->rgb[ i ] );
}


/***************************************
 * Sets the HSV positioner for thw hue and saturation value
 ***************************************/

static void
set_hsv_positioner( COLOR_CHOOSER * cc )
{
    double angle  = ( atan( 1 ) * cc->hsv[ HUE ] ) / 45;
    double radius = 0.01 * cc->hsv[ SATURATION ];

    fl_set_positioner_values( cc->pos, radius * cos( angle ),
                                       radius * sin( angle ) );
}


/***************************************
 * Sets the HSV slider
 ***************************************/

static void
set_hsv_slider( COLOR_CHOOSER * cc )
{
    fl_set_slider_value( cc->sl, cc->hsv[ VALUE ] );
}


/***************************************
 * Sets both the HSV hue and saturation positioner and the HSV value slider
 ***************************************/

static void
set_hsv_elements( COLOR_CHOOSER * cc )
{
    set_hsv_positioner( cc );
    set_hsv_slider( cc );
}


/***************************************
 * Callback for the HSV hue and saturation positioner
 ***************************************/

static void
positioner_cb( FL_OBJECT * obj,
               long        data   FL_UNUSED_ARG )
{
    COLOR_CHOOSER *cc = obj->u_vdata;
    double x = fl_get_positioner_xvalue( obj ),
           y = fl_get_positioner_yvalue( obj );


    cc->hsv[ HUE ]        = FL_nint( 45 * atan2( y, x ) / atan( 1 ) );
    cc->hsv[ SATURATION ] = FL_nint( 100 * sqrt( x * x + y * y ) );

    if ( cc->hsv[ HUE ] < 0 )
        cc->hsv[ HUE ] += 360;

    set_hsv_inputs( cc );
    hsv2rgb( cc->hsv, cc->rgb );
    set_rgb_inputs( cc );
    update_color_area( cc );
}


/***************************************
 * Callback for the HSV value slider
 ***************************************/

static void
slider_cb( FL_OBJECT * obj,
           long        data   FL_UNUSED_ARG )
{
    COLOR_CHOOSER *cc = obj->u_vdata;

    cc->hsv[ VALUE ] = fl_get_slider_value( obj );

    fl_set_input_f( cc->hsv_inp[ VALUE ], "%d", cc->hsv[ VALUE ] );
    hsv2rgb( cc->hsv, cc->rgb );
    set_rgb_inputs( cc );
    update_color_area( cc );
}


/***************************************
 * Callback for the HSV input fields
 ***************************************/

static void
hsv_input_cb( FL_OBJECT * obj,
              long        data )
{
    COLOR_CHOOSER *cc = obj->u_vdata;
    int value = strtol( fl_get_input( obj ), NULL, 10 );

    if ( data == HUE )
    {
        value %= 360;
        if ( value < 0 )
            value += 360;
    }
    else
        value = FL_clamp( value, 0, 100 );
        
    cc->hsv[ data ] = value;
    fl_set_input_f( obj, "%d", value );

    hsv2rgb( cc->hsv, cc->rgb );
    set_rgb_inputs( cc );

    if ( data == VALUE )
        set_hsv_slider( cc );
    else
        set_hsv_positioner( cc );

    update_color_area( cc );
}


/***************************************
 * Callback for the RGB input fields
 ***************************************/

static void
rgb_input_cb( FL_OBJECT * obj,
              long        data )
{
    COLOR_CHOOSER *cc = obj->u_vdata;
    int value = strtol( fl_get_input( obj ), NULL, 10 );

    cc->rgb[ data ] = FL_clamp( value, 0, 100 );
    fl_set_input_f( obj, "%d", cc->rgb[ data ] );

    rgb2hsv( cc->rgb, cc->hsv );
    set_hsv_inputs( cc );

    set_hsv_elements( cc );
    update_color_area( cc );
}


/***************************************
 * Creates the color chooser form
 ***************************************/

static void
create_color_chooser_form( COLOR_CHOOSER * cc )
{
    int pos = 20,                         /* position and size of colorwheel */
        size = 221;                       /* pixmap */
    double fact = size / ( size - 20.0 ); /* factor due to white margin */
    int i;
    const char *hsv_txts[ ] = { "Hue:", "Saturation:", "Value:" };
    const char *rgb_txts[ ] = { "Red:", "Green:", "Blue:" };

    /* Start the form */

    cc->form = fl_bgn_form( FL_UP_BOX, 615, 275 );

    /* Add the colorwheel pixmap */

    cc->pm = fl_add_pixmap( FL_NORMAL_PIXMAP, pos, pos, size, size, "" );
    fl_set_object_boxtype( cc->pm, FL_DOWN_BOX );
    fl_set_pixmap_data( cc->pm, colorwheel );

    /* Overlay it with a positioner. Account fot the 10 pixel wide margins of
       the colorwheel pixmap by setting the boundary values of the positioner
       to something larger than 1 so that the exact edge of the colorwheel is
       mapped to a radius of 1 and set center to have value of 0 for both
       directions. Set up a callback and a validator that is used to keep
       the positions always within the circle. */

    cc->pos = fl_add_positioner( FL_OVERLAY_POSITIONER, pos - 1, pos - 1,
                                 size + 2, size + 2,
                                 "Hue and Saturation" );
    fl_set_positioner_xbounds( cc->pos, -fact, fact );
    fl_set_object_lsize( cc->pos, FL_DEFAULT_SIZE );
    fl_set_positioner_ybounds( cc->pos, -fact, fact );
    fl_set_positioner_xvalue( cc->pos, cc->hsv[ HUE ] );
    fl_set_positioner_yvalue( cc->pos, cc->hsv[ SATURATION ] );
    fl_set_object_callback( cc->pos, positioner_cb, 0 );
    fl_set_positioner_validator( cc->pos, validator );
    fl_set_object_color( cc->pos, FL_COL1, FL_BLACK );
    cc->pos->u_vdata = cc;

    /* Add the slider for the HSV value, with a range of [0, 100]. */

    cc->sl = fl_add_slider( FL_VERT_BROWSER_SLIDER, 255, 20, 15, 223, "Value" );
    fl_set_object_lsize( cc->sl, FL_DEFAULT_SIZE );
    fl_set_object_return( cc->sl, FL_RETURN_CHANGED );
    fl_set_slider_bounds( cc->sl, 100, 0 );
    fl_set_slider_value( cc->sl, cc->hsv[ VALUE ] );
    fl_set_slider_increment( cc->sl, 1, 1 );
    fl_set_object_callback( cc->sl, slider_cb, 0 );
    cc->sl->u_vdata = cc;
    
    /* Add input fields (and labels) for the HSV and RGB values. We do that
       in sepearte loops to jump within the input fields with <Tab> first
       through the HSV and then through the RGB input fileds. */

    for ( i = HUE; i <= VALUE; i++ )
    {
        fl_add_text( FL_NORMAL_TEXT, 290, 20 + i * 55, 80, 30, hsv_txts[ i ] );
        cc->hsv_inp[ i ] = fl_add_input( FL_INT_INPUT, 370, 20 + i * 55,
                                         80, 30, "" );
    }

    for ( i = RED; i <= BLUE; i++ )
    {
        fl_set_object_callback( cc->hsv_inp[ i ], hsv_input_cb, i );
        cc->hsv_inp[ i ]->u_vdata = cc;

        fl_add_text( FL_NORMAL_TEXT, 460, 20 + i * 55, 55, 30, rgb_txts[ i ] );
        cc->rgb_inp[ i ] = fl_add_input( FL_INT_INPUT, 515, 20 + i * 55,
                                         80, 30, "" );
        fl_set_object_callback( cc->rgb_inp[ i ], rgb_input_cb, i );
        cc->rgb_inp[ i ]->u_vdata = cc;
    }

    /* Get a color slot for the area showing the selected color. Then
       create that area and a label for showing hexadecimal color value. */

    fl_mapcolor( FL_COLOR_CHOOSER_COLOR, 255, 255, 255 );

    cc->area = fl_add_box( FL_DOWN_BOX, 290, 180, 135, 63, "" );
    fl_set_object_color( cc->area, FL_COLOR_CHOOSER_COLOR, FL_WHITE );

    cc->hex = fl_add_text( FL_NORMAL_TEXT, 480, 180, 100, 20, "#FFFFFF" );
    fl_set_object_lstyle( cc->hex, FL_FIXEDBOLD_STYLE );

    /* Finally add the "Ok" and "Cancel" buttons. */

    cc->ok = fl_add_button( FL_NORMAL_BUTTON, 455, 213, 60, 30, "Ok" );
    cc->quit = fl_add_button( FL_NORMAL_BUTTON, 535, 213, 60, 30, "Cancel" );

    fl_end_form( );
}


/***************************************
 * Function to be called by the users to have the color chooser displayed.
 * The first argument is a (const) array of RGB values to the used at
 * the start and can be a NULL pointer (in which case white is used
 * as the initial color). The second is an array of three ints used for
 * returning RFB values of the selected color. The function returns 1
 * on success and 0 when the user aborts selecting a color.
 ***************************************/

int
fl_show_color_chooser( const int * rgb_in,
                       int       * rgb_out )
{
    static COLOR_CHOOSER cc;
    FL_OBJECT *obj;
    int irgb[ ] = { 255, 255, 255 };
    int i;

    /* Check that we have a non-NULL pointer for returning the selected
       color */

    if ( rgb_out == NULL )
    {
        M_err( "fl_show_color_chooser",
               "Argument for returning selected color is a NULL pointer" );
        return 0;
    }

    /* Create the color chooser form if it doesn't exist yet. */

    if ( ! cc.form )
        create_color_chooser_form( &cc );

    /* Put it into the start configuration, either with the user supplied
       color (after making sure it's within bounds) or white. */

    if ( rgb_in )
        for ( i = RED; i <= BLUE; i++ )
            cc.rgb[ i ] = FL_clamp( rgb_in[ i ], 0, 255 );
    else
        memcpy( cc.rgb, irgb, 3 * sizeof *irgb );

    set_rgb_inputs( &cc );
    rgb2hsv( cc.rgb, cc.hsv );
    set_hsv_inputs( &cc );
    set_hsv_elements( &cc );
    update_color_area( &cc );

    /* Show form and then wait for the user to press the "Ok" or "Cancel"
       button. */

    fl_show_form( cc.form, FL_PLACE_CENTER, FL_FULLBORDER, "Color Chooser" );

    while ( ( obj = fl_do_only_forms( ) ) != cc.ok && obj != cc.quit )
        /* empty */ ;

    /* Hide the form and, if the user pressed "Ok" copy the selected
       color's RGB values into the user supplied array. */

    fl_hide_form( cc.form );

    if ( obj == cc.quit )
        return 0;

    memcpy( rgb_out, cc.rgb, 3 * sizeof *rgb_out );
    return 1;
}   


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
