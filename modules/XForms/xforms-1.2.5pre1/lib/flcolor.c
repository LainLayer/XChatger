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


/**
 * \file flcolor.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 * Colormap management.
 *
 *  XForm will by default use the visual that has the most depth
 *  and share colormap if possible. The default behavior can be
 *  overridden by resource class Visual and Depth.
 *
 *  Pixel is addressed via two indirections. First all colors
 *  are addressed using the FL defined symbolic names, FL_RED, etc
 *  which are then translated via a secondary lookup table to
 *  get the true pixel values as known by the server.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"

/******************* Local variables ************************/

static unsigned long *lut;
static unsigned long max_server_cols;   /* max cols in current visual       */
static long cols_in_default_visual;
static long predefined_cols;    /* min(max_server_col, built_in_col) */
static int allow_leakage;
static FL_COLOR lastmapped;     /* so fli_textcolor can refresh its cache */


static void fli_free_newpixel( unsigned long );
static FL_COLOR rgb2pixel( unsigned int, unsigned int, unsigned int );

/* this needs to be changed to a lookup table */

#ifndef FL_RGB2GRAY
#define FL_RGB2GRAY( r, g, b )  \
    ( ( 78 * ( r ) + 150 * ( g ) + 28 * ( b ) ) >> 8 )
#endif
#define NV( a )  #a,a


/* Default colormap entry for FORMS, subject to gamma corrections.
 *
 * The map entries are listed in the order of importance based
 * on which color we need most in case the Xserver does not have
 * enough depths to get them all. */

static FLI_IMAP fli_imap[ FL_MAX_COLS ] =
{
	{ NV( FL_BLACK                ),   0,   0,   0, 0, 0 },
	{ NV( FL_WHITE                ), 255, 255, 255, 0, 0 },
	{ NV( FL_COL1                 ), 173, 173, 173, 0, 0 },
	{ NV( FL_BOTTOM_BCOL          ),  89,  89,  89, 0, 0 },
	{ NV( FL_RIGHT_BCOL           ),  41,  41,  41, 0, 0 },
	{ NV( FL_MCOL                 ), 191, 191, 191, 0, 0 },
	{ NV( FL_LEFT_BCOL            ), 222, 222, 222, 0, 0 },
	{ NV( FL_SLATEBLUE            ), 113, 113, 198, 0, 0 },
	{ NV( FL_INDIANRED            ), 198, 113, 113, 0, 0 },
	{ NV( FL_RED                  ), 255,   0,   0, 0, 0 },
	{ NV( FL_BLUE                 ),   0,   0, 255, 0, 0 },
	{ NV( FL_GREEN                ),   0, 255,   0, 0, 0 },
	{ NV( FL_YELLOW               ), 255, 255,   0, 0, 0 },
	{ NV( FL_MAGENTA              ), 255,   0, 255, 0, 0 },
	{ NV( FL_CYAN                 ),   0, 255, 255, 0, 0 },
	{ NV( FL_TOMATO               ), 255,  99,  71, 0, 0 },
	{ NV( FL_INACTIVE             ), 110, 110, 110, 0, 0 },
	{ NV( FL_TOP_BCOL             ), 204, 204, 204, 0, 0 },
	{ NV( FL_PALEGREEN            ), 113, 198, 113, 0, 0 },
	{ NV( FL_DARKGOLD             ), 205, 149,  10, 0, 0 },
	{ NV( FL_ORCHID               ), 205, 105, 201, 0, 0 },
	{ NV( FL_DARKCYAN             ),  40, 170, 175, 0, 0 },
	{ NV( FL_DARKTOMATO           ), 139,  54,  38, 0, 0 },
	{ NV( FL_WHEAT                ), 255, 231, 155, 0, 0 },
	{ NV( FL_DARKORANGE           ), 255, 128,   0, 0, 0 },
	{ NV( FL_DEEPPINK             ), 255,   0, 128, 0, 0 },
	{ NV( FL_CHARTREUSE           ), 128, 255,   0, 0, 0 },
	{ NV( FL_DARKVIOLET           ), 128,   0, 255, 0, 0 },
	{ NV( FL_SPRINGGREEN          ),   0, 255, 128, 0, 0 },
	{ NV( FL_DODGERBLUE           ),   0, 128, 255, 0, 0 },
	{ NV( FL_DOGERBLUE            ),   0, 128, 255, 0, 0 },
	{ NV( FL_LIGHTER_COL1         ), 204, 204, 204, 0, 0 },
	{ NV( FL_DARKER_COL1          ), 161, 161, 161, 0, 0 },
	{ NV( FL_ALICEBLUE            ), 240, 248, 255, 0, 0 },
	{ NV( FL_ANTIQUEWHITE         ), 250, 235, 215, 0, 0 },
	{ NV( FL_AQUA                 ),   0, 255, 255, 0, 0 },
	{ NV( FL_AQUAMARINE           ), 127, 255, 212, 0, 0 },
	{ NV( FL_AZURE                ), 240, 255, 255, 0, 0 },
	{ NV( FL_BEIGE                ), 245, 245, 220, 0, 0 },
	{ NV( FL_BISQUE               ), 255, 228, 196, 0, 0 },
	{ NV( FL_BLANCHEDALMOND       ), 255, 235, 205, 0, 0 },
	{ NV( FL_BLUEVIOLET           ), 138,  43, 226, 0, 0 },
	{ NV( FL_BROWN                ), 165,  42,  42, 0, 0 },
	{ NV( FL_BURLYWOOD            ), 222, 184, 135, 0, 0 },
	{ NV( FL_CADETBLUE            ),  95, 158, 160, 0, 0 },
	{ NV( FL_CHOCOLATE            ), 210, 105,  30, 0, 0 },
	{ NV( FL_CORAL                ), 255, 127,  80, 0, 0 },
	{ NV( FL_CORNFLOWERBLUE       ), 100, 149, 237, 0, 0 },
	{ NV( FL_CORNSILK             ), 255, 248, 220, 0, 0 },
	{ NV( FL_CRIMSON              ), 220,  20,  60, 0, 0 },
	{ NV( FL_DARKBLUE             ),   0,   0, 139, 0, 0 },
	{ NV( FL_DARKGOLDENROD        ), 184, 134,  11, 0, 0 },
	{ NV( FL_DARKGRAY             ), 169, 169, 169, 0, 0 },
	{ NV( FL_DARKGREEN            ),   0, 100,   0, 0, 0 },
	{ NV( FL_DARKGREY             ), 169, 169, 169, 0, 0 },
	{ NV( FL_DARKKHAKI            ), 189, 183, 107, 0, 0 },
	{ NV( FL_DARKMAGENTA          ), 139,   0, 139, 0, 0 },
	{ NV( FL_DARKOLIVEGREEN       ),  85, 107,  47, 0, 0 },
	{ NV( FL_DARKORCHID           ), 153,  50, 204, 0, 0 },
	{ NV( FL_DARKRED              ), 139,   0,   0, 0, 0 },
	{ NV( FL_DARKSALMON           ), 233, 150, 122, 0, 0 },
	{ NV( FL_DARKSEAGREEN         ), 143, 188, 143, 0, 0 },
	{ NV( FL_DARKSLATEBLUE        ),  72,  61, 139, 0, 0 },
	{ NV( FL_DARKSLATEGRAY        ),  47,  79,  79, 0, 0 },
	{ NV( FL_DARKSLATEGREY        ),  47,  79,  79, 0, 0 },
	{ NV( FL_DARKTURQUOISE        ),   0, 206, 209, 0, 0 },
	{ NV( FL_DEEPSKYBLUE          ),   0, 191, 255, 0, 0 },
	{ NV( FL_DIMGRAY              ), 105, 105, 105, 0, 0 },
	{ NV( FL_DIMGREY              ), 105, 105, 105, 0, 0 },
	{ NV( FL_FIREBRICK            ), 178,  34,  34, 0, 0 },
	{ NV( FL_FLORALWHITE          ), 255, 250, 240, 0, 0 },
	{ NV( FL_FORESTGREEN          ),  34, 139,  34, 0, 0 },
	{ NV( FL_FUCHSIA              ), 255,   0, 255, 0, 0 },
	{ NV( FL_GAINSBORO            ), 220, 220, 220, 0, 0 },
	{ NV( FL_GHOSTWHITE           ), 248, 248, 255, 0, 0 },
	{ NV( FL_GOLD                 ), 255, 215,   0, 0, 0 },
	{ NV( FL_GOLDENROD            ), 218, 165,  32, 0, 0 },
	{ NV( FL_GRAY                 ), 128, 128, 128, 0, 0 },
	{ NV( FL_GREENYELLOW          ), 173, 255,  47, 0, 0 },
	{ NV( FL_GREY                 ), 128, 128, 128, 0, 0 },
	{ NV( FL_HONEYDEW             ), 240, 255, 240, 0, 0 },
	{ NV( FL_HOTPINK              ), 255, 105, 180, 0, 0 },
	{ NV( FL_INDIGO               ),  75,   0, 130, 0, 0 },
	{ NV( FL_IVORY                ), 255, 255, 240, 0, 0 },
	{ NV( FL_KHAKI                ), 240, 230, 140, 0, 0 },
	{ NV( FL_LAVENDER             ), 230, 230, 250, 0, 0 },
	{ NV( FL_LAVENDERBLUSH        ), 255, 240, 245, 0, 0 },
	{ NV( FL_LAWNGREEN            ), 124, 252,   0, 0, 0 },
	{ NV( FL_LEMONCHIFFON         ), 255, 250, 205, 0, 0 },
	{ NV( FL_LIGHTBLUE            ), 173, 216, 230, 0, 0 },
	{ NV( FL_LIGHTCORAL           ), 240, 128, 128, 0, 0 },
	{ NV( FL_LIGHTCYAN            ), 224, 255, 255, 0, 0 },
	{ NV( FL_LIGHTGOLDENRODYELLOW ), 250, 250, 210, 0, 0 },
	{ NV( FL_LIGHTGRAY            ), 211, 211, 211, 0, 0 },
	{ NV( FL_LIGHTGREEN           ), 144, 238, 144, 0, 0 },
	{ NV( FL_LIGHTGREY            ), 211, 211, 211, 0, 0 },
	{ NV( FL_LIGHTPINK            ), 255, 182, 193, 0, 0 },
	{ NV( FL_LIGHTSALMON          ), 255, 160, 122, 0, 0 },
	{ NV( FL_LIGHTSEAGREEN        ),  32, 178, 170, 0, 0 },
	{ NV( FL_LIGHTSKYBLUE         ), 135, 206, 250, 0, 0 },
	{ NV( FL_LIGHTSLATEGRAY       ), 119, 136, 153, 0, 0 },
	{ NV( FL_LIGHTSLATEGREY       ), 119, 136, 153, 0, 0 },
	{ NV( FL_LIGHTSTEELBLUE       ), 176, 196, 222, 0, 0 },
	{ NV( FL_LIGHTYELLOW          ), 255, 255, 224, 0, 0 },
	{ NV( FL_LIME                 ),   0, 255,   0, 0, 0 },
	{ NV( FL_LIMEGREEN            ),  50, 205,  50, 0, 0 },
	{ NV( FL_LINEN                ), 250, 240, 230, 0, 0 },
	{ NV( FL_MAROON               ), 128,   0,   0, 0, 0 },
	{ NV( FL_MEDIUMAQUAMARINE     ), 102, 205, 170, 0, 0 },
	{ NV( FL_MEDIUMBLUE           ),   0,   0, 205, 0, 0 },
	{ NV( FL_MEDIUMORCHID         ), 186,  85, 211, 0, 0 },
	{ NV( FL_MEDIUMPURPLE         ), 147, 112, 219, 0, 0 },
	{ NV( FL_MEDIUMSEAGREEN       ),  60, 179, 113, 0, 0 },
	{ NV( FL_MEDIUMSLATEBLUE      ), 123, 104, 238, 0, 0 },
	{ NV( FL_MEDIUMSPRINGGREEN    ),   0, 250, 154, 0, 0 },
	{ NV( FL_MEDIUMTURQUOISE      ),  72, 209, 204, 0, 0 },
	{ NV( FL_MEDIUMVIOLETRED      ), 199,  21, 133, 0, 0 },
	{ NV( FL_MIDNIGHTBLUE         ),  25,  25, 112, 0, 0 },
	{ NV( FL_MINTCREAM            ), 245, 255, 250, 0, 0 },
	{ NV( FL_MISTYROSE            ), 255, 228, 225, 0, 0 },
	{ NV( FL_MOCCASIN             ), 255, 228, 181, 0, 0 },
	{ NV( FL_NAVAJOWHITE          ), 255, 222, 173, 0, 0 },
	{ NV( FL_NAVY                 ),   0,   0, 128, 0, 0 },
	{ NV( FL_OLDLACE              ), 253, 245, 230, 0, 0 },
	{ NV( FL_OLIVE                ), 128, 128,   0, 0, 0 },
	{ NV( FL_OLIVEDRAB            ), 107, 142,  35, 0, 0 },
	{ NV( FL_ORANGE               ), 255, 165,   0, 0, 0 },
	{ NV( FL_ORANGERED            ), 255,  69,   0, 0, 0 },
	{ NV( FL_PALEGOLDENROD        ), 238, 232, 170, 0, 0 },
	{ NV( FL_PALETURQUOISE        ), 175, 238, 238, 0, 0 },
	{ NV( FL_PALEVIOLETRED        ), 219, 112, 147, 0, 0 },
	{ NV( FL_PAPAYAWHIP           ), 255, 239, 213, 0, 0 },
	{ NV( FL_PEACHPUFF            ), 255, 218, 185, 0, 0 },
	{ NV( FL_PERU                 ), 205, 133,  63, 0, 0 },
	{ NV( FL_PINK                 ), 255, 192, 203, 0, 0 },
	{ NV( FL_PLUM                 ), 221, 160, 221, 0, 0 },
	{ NV( FL_POWDERBLUE           ), 176, 224, 230, 0, 0 },
	{ NV( FL_PURPLE               ), 128,   0, 128, 0, 0 },
	{ NV( FL_ROSYBROWN            ), 188, 143, 143, 0, 0 },
	{ NV( FL_ROYALBLUE            ),  65, 105, 225, 0, 0 },
	{ NV( FL_SADDLEBROWN          ), 139,  69,  19, 0, 0 },
	{ NV( FL_SALMON               ), 250, 128, 114, 0, 0 },
	{ NV( FL_SANDYBROWN           ), 244, 164,  96, 0, 0 },
	{ NV( FL_SEAGREEN             ),  46, 139,  87, 0, 0 },
	{ NV( FL_SEASHELL             ), 255, 245, 238, 0, 0 },
	{ NV( FL_SIENNA               ), 160,  82,  45, 0, 0 },
	{ NV( FL_SILVER               ), 192, 192, 192, 0, 0 },
	{ NV( FL_SKYBLUE              ), 135, 206, 235, 0, 0 },
	{ NV( FL_SLATEGRAY            ), 112, 128, 144, 0, 0 },
	{ NV( FL_SLATEGREY            ), 112, 128, 144, 0, 0 },
	{ NV( FL_SNOW                 ), 255, 250, 250, 0, 0 },
	{ NV( FL_STEELBLUE            ),  70, 130, 180, 0, 0 },
	{ NV( FL_TAN                  ), 210, 180, 140, 0, 0 },
	{ NV( FL_TEAL                 ),   0, 128, 128, 0, 0 },
	{ NV( FL_THISTLE              ), 216, 191, 216, 0, 0 },
	{ NV( FL_TURQUOISE            ),  64, 224, 208, 0, 0 },
	{ NV( FL_VIOLET               ), 238, 130, 238, 0, 0 },
	{ NV( FL_WHITESMOKE           ), 245, 245, 245, 0, 0 },
	{ NV( FL_YELLOWGREEN          ), 154, 205,  50, 0, 0 },
    { NV( FL_COLOR_CHOOSER_COLOR  ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL1            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL2            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL3            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL4            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL5            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL6            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL7            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL8            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL9            ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL10           ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL11           ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL12           ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL13           ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL14           ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL15           ),   0,   0,   0, 0, 0 },
	{ NV( FL_FREE_COL16           ),   0,   0,   0, 0, 0 },
};

#define flmapsize ( ( int ) ( sizeof fli_imap / sizeof *fli_imap ) )


/***************************************
 ***************************************/

const char *
fli_query_colorname( FL_COLOR col )
{
    FLI_IMAP *flmap;
    static char buf[ 32 ];

    for ( flmap = fli_imap; flmap < fli_imap + FL_BUILT_IN_COLS + 1; flmap++ )
        if ( col == flmap->index )
            return flmap->name;

    /* Not a built-in */

    if ( col == FL_NoColor )
        return "FL_NoColor";

    if ( col >= FL_FREE_COL1 && col <= FL_FREE_COL16 )
        sprintf( buf,"FL_FREE_COL%ld",1+col-FL_FREE_COL1 );
    else
        sprintf( buf, "%ld", col );

    return buf;
}


/***************************************
 ***************************************/

long
fli_query_namedcolor( const char *s )
{
    FLI_IMAP *flmap;

    if ( ! s )
    {
        M_err( "fli_query_namedcolor", "Null pointer for color name" );
        return FL_MAX_COLORS + 1;
    }

    for ( flmap = fli_imap; flmap < fli_imap + FL_BUILT_IN_COLS + 1; flmap++ )
        if ( ! strcmp( s, flmap->name ) )
            return flmap->index;

    if ( strstr( s, "FL_FREE_COL" ) )
        return FL_FREE_COL1 + atoi( s + 11 ) - 1;

    if ( ! strcmp( "FL_NoColor", s ) )
        return FL_NoColor;

    /* A wild shot */

    return atoi( s );
}


/***************************************
 ***************************************/

#ifdef DO_GAMMA_CORRECTION

#include <math.h>


void
fl_set_gamma( double r,
              double g,
              double b )
{
    FLI_IMAP *fm;
    static double rgamma = 1.0,
                  ggamma = 1.0,
                  bgamma = 1.0;

    if ( fli_imap[ 4 ].grayval )
    {
        /* Too lazy to shuffle colormap around */

        M_err( "fl_set_gamma",
               "Ignored. Please call fl_set_gamma before fl_initialize()" );
        return;
    }

    if ( r <= 1.e-3 || g <= 1.e-3 || b <= 1.e-3 )
    {
        M_warn( "fl_set_gamma", "BadValue %4.2f %4.2f %4.2f. Ignored",
                r, g, b );
        return;
    }

    for ( fm = fli_imap; fm < fli_imap + FL_BUILT_IN_COLS + 1; fm++ )
    {
        fm->r = 0.5 + 255 * pow( fm->r / 255.0, rgamma / r );
        fm->g = 0.5 + 255 * pow( fm->g / 255.0, ggamma / g );
        fm->b = 0.5 + 255 * pow( fm->b / 255.0, bgamma / b );
    }

    rgamma = r;
    ggamma = g;
    bgamma = b;
}

#endif /* DO_GAMMA_CORRECTION */


static XColor *defaultc = NULL;


/***************************************
 * Copy the first several entries in the default colormap to avoid
 * flashing in case we are using a private colormap or non-default
 * visual (can't do anyting about TrueColor/DirectColor though)
 ***************************************/

#define DEFAULT_SAVE   35

static int save_index[ ] = { 2, 3, 4, 5, 6, 7, 34 };

#define NSAVE ( sizeof save_index / sizeof *save_index )

static void
be_nice( void )
{
    int i,
        save = FL_min( cols_in_default_visual - 210, DEFAULT_SAVE );
    XColor *dc;
    unsigned long newpixels[ DEFAULT_SAVE ],
                  frees[ DEFAULT_SAVE ];
    int npixels,
        found,
        j,
        k,
        saved;
    FL_COLOR black = BlackPixel( flx->display, fl_screen );
    FL_COLOR white = WhitePixel( flx->display, fl_screen );

    for ( saved = 0, dc = defaultc, i = 0; i < save; i++, dc++ )
    {
        dc->flags = DoRed | DoGreen | DoBlue;
        if ( XAllocColor( flx->display, fli_colormap( fl_vmode ), dc ) )
            newpixels[ saved++ ] = dc->pixel;
    }

    /* Only keep the pixels in the save_index. 0 and 1 are always saved */

    for ( npixels = 0, i = 2; fli_depth( fl_vmode ) > 4 && i < saved; i++ )
    {
        k = newpixels[ i ];
        for ( j = found = 0; ! found && j < ( int ) NSAVE; j++ )
            found =     k == save_index[ j ]
                     || k == ( int ) white
                     || k == ( int ) black;

        if ( ! found )
            frees[ npixels++ ] = k;
    }

    if ( npixels )
        XFreeColors( flx->display, fli_colormap( fl_vmode ),
                     frees, npixels, 0 );

    if ( save <= 0 )
    {
        XColor xc;

        M_warn( "be_nice", "Black = %ld White = %ld", black, white );

        /* As a minimum, we should preserve black & white */

        xc.flags = DoRed | DoGreen | DoBlue;
        if ( black == 0 )
        {
            xc.red = xc.green = xc.blue = 0;
            xc.pixel = 0;
            XAllocColor( flx->display, fli_colormap( fl_vmode ), &xc );
            M_warn( "be_nice", "Get Black = %ld", xc.pixel );

            if ( white == 1 )
            {
                xc.pixel = white;
                xc.red = xc.green = xc.blue = 0xffff;
                XAllocColor( flx->display, fli_colormap( fl_vmode ), &xc );
                M_warn( "be_nice", "Get White = %ld", xc.pixel );
            }
        }
        else if ( white == 0 )
        {
            xc.red = xc.green = xc.blue = 0xffff;
            XAllocColor( flx->display, fli_colormap( fl_vmode ), &xc );
            M_warn( "be_nice", "Get White = %ld", xc.pixel );

            if ( black == 1 )
            {
                xc.red = xc.green = xc.blue = black;
                xc.pixel = 0;
                XAllocColor( flx->display, fli_colormap( fl_vmode ), &xc );
                M_warn( "be_nice", "Get Black = %ld", xc.pixel );
            }
        }
    }

    M_warn( "be_nice", "Total %d colors copied", save > 0 ? save : 2 );
}


/***************************************
 ***************************************/

static int
alloc_direct_color( void )
{
    XColor xxc[ FL_BUILT_IN_COLS ],
           *xc;
    FLI_IMAP *fm;
    long pred = predefined_cols;

    for ( xc = xxc, fm = fli_imap; fm < fli_imap + pred; fm++, xc++ )
    {
        xc->red   = ( fm->r << 8 ) | 0xff;
        xc->green = ( fm->g << 8 ) | 0xff;
        xc->blue  = ( fm->b << 8 ) | 0xff;

        xc->flags = DoRed | DoGreen | DoBlue;
        xc->pixel = lut[ fm->index ] = rgb2pixel( fm->r, fm->g, fm->b );
    }

    XStoreColors( flx->display, fli_map( fl_vmode ), xxc, pred );

    return 1;
}


/***************************************
 * Do colormap allocation. DirectColor is handled seperately
 ***************************************/

static int
fill_map( void )
{
    XColor xc;
    int ok;
    long pred = predefined_cols;
    unsigned int r,
                 g,
                 b;
    FLI_IMAP *fm,
             *fs;

    lut = fl_state[ fl_vmode ].lut;
    fli_dithered( fl_vmode ) = fli_depth( fl_vmode ) <= 2;

    M_warn( "fill_map", "Trying to get %d colors", pred );

    xc.flags = DoRed | DoGreen | DoBlue;

    for ( ok = 1, fm = fli_imap, fs = fm + pred; ok && fm < fs; fm++ )
    {
        /* If Xserver is grayscale, we are really walking the "gray" area as
           the server can drive the the display with any of the r, g or b,
           need to force a correct value */

        r = FL_is_gray( fl_vmode ) ? fm->grayval : fm->r;
        g = FL_is_gray( fl_vmode ) ? fm->grayval : fm->g;
        b = FL_is_gray( fl_vmode ) ? fm->grayval : fm->b;

        xc.red   = ( r << 8 ) | 0xff;
        xc.green = ( g << 8 ) | 0xff;
        xc.blue  = ( b << 8 ) | 0xff;

        ok = XAllocColor( flx->display, fli_map( fl_vmode ), &xc );
        if ( ok )
            lut[ fm->index ] = xc.pixel;
    }

    if (    fl_state[ fl_vmode ].pcm
         || fli_cntl.sharedColormap
         || fli_dithered( fl_vmode ) )
    {
        if ( ! ok && fm > fli_imap )
            fm--;
        ok = 1;
    }

    /* Get approx. for the rest of needed colors */

    for ( fs = fli_imap + FL_BUILT_IN_COLS; ok && fm < fs; fm++ )
        fl_mapcolor( fm->index, fm->r, fm->g, fm->b );

    /* Make rest of the entry invalid so we don't accidently free a valid
       pixel */

    memset( lut + FL_BUILT_IN_COLS, 1,
            ( FL_MAX_COLS - FL_BUILT_IN_COLS ) * sizeof *lut );

    return ok;
}


/***************************************
 * Try to get a private colormap. Return 1 for success. Typically
 * this is the last color strategy we will try and in case it
 * fails, caller probably should terminate the program.
 ***************************************/

static int
get_private_cmap( int vmode )
{
    int ok,
        i;

    M_warn( "get_private_cmap", "getting private colormap" );

    /* Get a private colormap */

    fli_map( vmode ) = XCreateColormap( flx->display, fl_root,
                                        fli_visual( vmode ),
                                        vmode != FL_DirectColor ?
                                        AllocNone : AllocAll );
    if ( ! fli_map( vmode ) )
    {
        M_err( "get_private_cmap", "Can't create Colormap!" );
        exit( 0 );
    }

    lut = fl_state[ vmode ].lut;
    if ( vmode == FL_DirectColor )
        return alloc_direct_color( );

    /* Copy some default entries */

    be_nice( );

    /* Fill colormap with predetermined colors */

    fl_state[ vmode ].pcm = 1;
    ok = fill_map( );

    for ( i = FL_BUILT_IN_COLS; i < FL_MAX_COLS; i++ )
        lut[ i ] = i;

    M_warn( "get_private_cmap", "%s %s succesful",
            fli_vclass_name( vmode ), ok ? "" : "not" );

    return ok;
}


/***************************************
 * Use standard colormap only if user explicitly requests it as it
 * is the most un-flexible among shared,private and standard.
 ***************************************/

static int
get_standard_cmap( int vmode )
{
    FLI_IMAP *fm,
             *fs;
    XStandardColormap stdcmap;
    XStandardColormap *sc = &stdcmap;
    XColor xc;
    Atom mapid = ( vmode == FL_GrayScale || vmode == FL_StaticGray ) ?
                 XA_RGB_GRAY_MAP : XA_RGB_DEFAULT_MAP;

#if FL_DEBUG >= ML_ERR
    M_warn( "get_standard_cmap", "Getting standard colormap" );
#endif

    if ( ! XGetStandardColormap( flx->display, fl_root, &stdcmap, mapid ) )
    {
        M_err( "get_standard_cmap", "Can't get standard map" );
        return 0;
    }

    lut = fl_state[ vmode ].lut;

    /* we got the map. now figure out the pixel values */

    fli_map( vmode ) = sc->colormap;

    xc.flags = DoRed | DoGreen | DoBlue;
    for ( fm = fli_imap, fs = fm + FL_BUILT_IN_COLS; fm < fs; fm++ )
    {
        xc.red   = ( fm->r << 8 ) | 0xff;
        xc.green = ( fm->g << 8 ) | 0xff;
        xc.blue  = ( fm->b << 8 ) | 0xff;
        XAllocColor( flx->display, fli_colormap( vmode ), &xc );
        lut[ fm->index ] = xc.pixel;
    }

    fl_state[ vmode ].pcm = 1;
    return 1;
}


/***************************************
 ***************************************/

static int
get_shared_cmap( int vmode )
{
    int ok;

    /* Share colormap only if requested visual is the same as the default
       visual */

    if ( fli_visual( vmode ) == DefaultVisual( flx->display, fl_screen ) )
    {
        fli_map( vmode ) = DefaultColormap( flx->display, fl_screen );
        M_warn( "get_shared_cmap", "Using default map %ld for %s",
                fli_map( vmode ), fli_vclass_name( vmode ) );
    }
    else
    {
        fli_map( vmode ) = XCreateColormap( flx->display, fl_root,
                                            fli_visual( vmode ),
                                            vmode != FL_DirectColor ?
                                            AllocNone : AllocAll );
        M_warn( "get_shared_cmap", " NewMap %ld (0x%lx) for %s (ID = 0x%lx)",
                fli_map( vmode ), fli_map( vmode ), fli_vclass_name( vmode ),
                fli_visual( vmode )->visualid );
    }

    if ( ! fli_map( vmode ) )
    {
        M_err( "get_shared_cmap", "Error getting colormaps" );
        exit( 1 );
    }

#define PD( v )                                                          \
    if ( ( DefaultVisual( flx->display, fl_screen ) )->class == ( v ) )  \
        fprintf( stderr, "DefaultVisual = %s CurrentVisual = %s\n",          \
                 #v, fli_vclass_name( fli_class( vmode ) ) );

    if ( fli_cntl.debug )
    {
        PD( TrueColor );
        PD( PseudoColor );
        PD( DirectColor );
        PD( GrayScale );
        PD( StaticGray );
        PD( StaticColor );
    }

    lut = fl_state[ vmode ].lut;

    if ( vmode == FL_DirectColor )
        return alloc_direct_color( );

    /* Copy a few entries from the default colormap if we are using a map
       other than the defaulf */

    if ( fli_visual( vmode ) != DefaultVisual( flx->display, fl_screen ) )
        be_nice( );

    ok = fill_map( );

    /* If we can't do it, free the color we have already allocated so other
       applications may have an easier time getting colors */

    if ( ! ok )
    {
        M_warn( "get_shared_cmap", "can't share for %s",
                fli_vclass_name( vmode ) );
        fli_map( vmode ) = XCopyColormapAndFree( flx->display,
                                                 fli_map( vmode ) );
    }

    return ok;
}


/***************************************
 * Create GCs for a particular visual and depth
 ***************************************/

void
fli_create_gc( Window win )
{
    GC *flgcs,
       *flgce;
    FL_State *fs = fl_state + fl_vmode;

    /* If gc for this visual exists, do switch */

    if ( fl_state[ fl_vmode ].gc[ 0 ] )
    {
        flx->gc = fl_state[ fl_vmode ].gc[ 0 ];
        flx->textgc = fl_state[ fl_vmode ].textgc[ 0 ];

        if ( fl_state[ fl_vmode ].cur_fnt )
            XSetFont( flx->display, flx->textgc,
                      fl_state[ fl_vmode ].cur_fnt->fid );
        return;
    }

    /* Check if we need to dither */

    fli_dithered( fl_vmode ) = fli_depth( fl_vmode ) <= 2;

    /* Need to create new GCs */

    M_warn( "fli_create_gc", "For %s", fli_vclass_name( fl_vmode ) );

    if ( ! fli_gray_pattern[ 1 ] )
    {
        M_err( "fli_create_gc", "gray pattern not initialized" );
        exit( 1 );
    }

    flgcs = fs->gc;
    flgce = flgcs + sizeof fs->gc / sizeof *fs->gc;
    for ( ; flgcs < flgce; flgcs++ )
    {
        *flgcs = XCreateGC( flx->display, win, 0, 0 );
        XSetStipple( flx->display, *flgcs, FLI_INACTIVE_PATTERN );
        XSetGraphicsExposures( flx->display, *flgcs, 0 );
    }

    flx->gc = fl_state[ fl_vmode ].gc[ 0 ];

    /* Initialize text gc */

    flgcs = fs->textgc;
    flgce = flgcs + sizeof fs->textgc / sizeof *fs->textgc;
    for ( ; flgcs < flgce; flgcs++ )
    {
        *flgcs = XCreateGC( flx->display, win, 0, 0 );
        XSetStipple( flx->display, *flgcs, FLI_INACTIVE_PATTERN );
        XSetGraphicsExposures( flx->display, *flgcs, 0 );
    }

    flx->textgc = fl_state[ fl_vmode ].textgc[ 0 ];

    /* Initialize a dimmed GC */

    fl_state[ fl_vmode ].dimmedGC = XCreateGC( flx->display, win, 0, 0 );
    XSetStipple( flx->display, fl_state[ fl_vmode ].dimmedGC,
                 FLI_INACTIVE_PATTERN );
    XSetGraphicsExposures( flx->display, fl_state[ fl_vmode ].dimmedGC, 0 );
    XSetFillStyle( flx->display, fl_state[ fl_vmode ].dimmedGC, FillStippled );

    /* Special for B&W and 2bits displays */

    if ( fli_dithered( fl_vmode ) )
    {
        int i;

        fli_whitegc = XCreateGC( flx->display, win, 0, 0 );
        XSetForeground( flx->display, fli_whitegc, fl_get_flcolor( FL_WHITE ) );

        for ( i = 0; i < 3; i++ )
        {
            fli_bwgc[ i ] = XCreateGC( flx->display, win, 0, 0 );
            XSetStipple( flx->display, fli_bwgc[ i ], fli_gray_pattern[ i ] );
            XSetGraphicsExposures( flx->display, fli_bwgc[ i ], 0 );
            XSetFillStyle( flx->display, fli_bwgc[ i ], FillStippled );
        }
    }

    if ( fl_state[ fl_vmode ].cur_fnt )
        XSetFont( flx->display, flx->textgc,
                  fl_state[ fl_vmode ].cur_fnt->fid );
}



/***************************************
 *  Global routine to initialize all things related visual and colors
 ***************************************/

void
fli_init_colormap( int vmode )
{
    int i,
        ok;
    FLI_IMAP *fm = fli_imap;
    Colormap defmap;

    /* If map for this mode already exists, leave it alone, not only
       efficient but also necessary as fl_win_open may call init map */

    if ( fli_map( vmode ) )
    {
#if FL_DEBUG >= ML_DEBUG
        M_info( "fli_init_colormap", "%s is ok", fli_vclass_name( vmode ) );
#endif
        return;
    }

    /* Get max colors we can have, take care there are machines where an
       unsigned long isn't large enough to hold the number of colors) */

    if ( ( unsigned int ) fli_depth( vmode ) >=
                                             CHAR_BIT * sizeof max_server_cols )
        max_server_cols = ~ 0;
    else
        max_server_cols = 1L << fli_depth( vmode );

    predefined_cols = FL_min( FL_BUILT_IN_COLS, max_server_cols );
    M_info( "fli_init_colormap", "MaxColors = %d PredefCol = %d",
            max_server_cols, predefined_cols );

    fli_init_stipples( );

    if ( ! defaultc )
        defaultc = fl_malloc( FL_MAX_COLS * sizeof *defaultc );

    /* Initialize secondary lookup table */

    for ( fm = fli_imap, i = 0; i < FL_MAX_COLS; i++, fm++ )
    {
        defaultc[ i ].pixel = i;
        fm->grayval = FL_RGB2GRAY( fm->r, fm->g, fm->b );
        if ( i >= FL_BUILT_IN_COLS )
            fm->index = i;
    }

    /* Take a snapshot of the default colormap for later use by
       private_colormap */

    defmap = DefaultColormap( flx->display, fl_screen );
    cols_in_default_visual =
                          ( 1L << DefaultDepth( flx->display, fl_screen ) ) - 1;

    /* Some server may have a default visual with depth == 32 */

    if ( cols_in_default_visual <= 0 )
        cols_in_default_visual = 80;

    M_warn( "fli_init_colormap", "%ld (0x%lx)", defmap, defmap );

    XQueryColors( flx->display, defmap, defaultc,
                  FL_min( cols_in_default_visual, DEFAULT_SAVE ) );

    ok = 0;

    if ( fli_cntl.privateColormap )
        ok = get_private_cmap( vmode );
    else if ( fli_cntl.standardColormap )
        ok = get_standard_cmap( vmode );

    if ( ! ok && ! ( ok = get_shared_cmap( vmode ) ) )
    {
        /* If unable to share colormaps, we can either get a private colormap
           or force substitutions */
#if 1
        M_err( "fli_init_colormap",
               "Failed to share colors. Using private colormap" );
        ok = get_private_cmap( vmode );
#else
        ok = 1;
        fli_cntl.sharedColormap = 1;
        get_shared_cmap( vmode );
#endif
    }

    if ( ! ok )
    {
        M_err( "fli_init_colormap",
               "I screwed up or you have a weird workstatation" );
        exit( 1 );
    }

    M_warn( "fli_init_colormap", "%s Done", fli_vclass_name( vmode ) );

#if FL_DEBUG >= ML_WARN
    fli_dump_state_info( vmode, "fli_init_colormap" );
#endif
}


/***************************************
 ***************************************/

void
fli_free_colormap( int vmode )
{
    int i;

    for( i = 0; i < 3; i++ )
        if ( fli_gray_pattern[ i ] )
        {
            XFreePixmap( flx->display, fli_gray_pattern[ i ] );
            fli_gray_pattern[ i ] = None;
        }

    if ( fli_visual( vmode ) != DefaultVisual( flx->display, fl_screen ) )
        XFreeColormap( flx->display, fli_map( vmode ) );

    fli_safe_free( defaultc );
}



static unsigned long
get_rgb_pixel( FL_COLOR packed,
               int *    newpix );


/***************************************
 * Input col is an XForms color, e.g. FL_RED etc. The
 * return value is the true pixel value X understands.
 ***************************************/

unsigned long
fl_get_pixel( FL_COLOR col )
{
    if ( col == FL_NoColor )
        return fl_get_pixel( FL_COL1 );

    if ( flx->isRGBColor )
        return get_rgb_pixel( col, &flx->newpix );

    if ( col >= FL_MAX_COLS )
    {
        M_err( "fl_get_pixel", "Bad request %lu", col );
        return 0;
    }

    return fl_state[ fl_vmode ].lut[ col ];
}


/***************************************
 ***************************************/

void
fl_set_foreground( GC       gc,
                   FL_COLOR color )
{
    XSetForeground( fl_display, gc, fl_get_pixel( color ) );
}


/***************************************
 ***************************************/

void
fl_set_background( GC       gc,
                   FL_COLOR color )
{
    XSetBackground( fl_display, gc, fl_get_pixel( color ) );
}


/***************************************
 ***************************************/

void
fl_color( FL_COLOR col )
{
    static int vmode = -1;

    if ( flx->color != col || vmode != fl_vmode )
    {
        unsigned long p = fl_get_pixel( col );

        flx->color = col;
        vmode = fl_vmode;
        XSetForeground( flx->display, flx->gc, p );
        fli_free_newpixel( p );
    }
}


/***************************************
 ***************************************/

static unsigned long
get_rgb_pixel( FL_COLOR   packed,
               int      * newpix )
{
    FL_STATE *s = &fl_state[ fl_vmode ];
    unsigned long pixel;
    static Colormap lastcolormap;
    static XColor *xcolor;
    static int new_col;
    XColor xc;

    unsigned int r = FL_GETR( packed );
    unsigned int g = FL_GETG( packed );
    unsigned int b = FL_GETB( packed );

    *newpix = 0;
    if ( s->vclass == TrueColor || s->vclass == DirectColor )
        return rgb2pixel( r, g, b );
    else
    {
        int max_col;

        xc.flags = DoRed | DoGreen | DoBlue;
        xc.red   = ( r << 8 ) | 0xff;
        xc.green = ( g << 8 ) | 0xff;
        xc.blue  = ( b << 8 ) | 0xff;

        new_col++;

        if ( ( *newpix = XAllocColor( flx->display, s->colormap, &xc ) ) )
            return xc.pixel;

        /* Color allocation failed. Search for best match */

        if ( ( max_col = FL_min( 256, 1 << s->depth ) ) == 0 )
            max_col = 256;

        if ( ! xcolor )
            xcolor = fl_malloc( 256 * sizeof *xcolor );

        /* Not theoretically correct as colormap may have changed
         * since the last time we asked for colors. Take a chance for
         * performace. */

        if ( lastcolormap != s->colormap || new_col > 3 )
        {
            int i;

            for ( i = 0; i < max_col; i++ )
                xcolor[ i ].pixel = i;
            XQueryColors( flx->display, s->colormap, xcolor, max_col );
            lastcolormap = s->colormap;
            new_col = 0;
        }

        fli_find_closest_color( r, g, b, xcolor, max_col, &pixel );
        return pixel;
    }
}


/***************************************
 ***************************************/

static void
fli_free_newpixel( unsigned long pixel )
{
    if ( flx->newpix )
    {
        XFreeColors( flx->display, flx->colormap, &pixel, 1, 0 );
        flx->newpix = 0;
    }
}


/***************************************
 ***************************************/

void
fli_textcolor( FL_COLOR col )
{
    static int vmode = -1;
    static int switched;
    static GC textgc;

    if (    flx->textcolor != col
         || vmode != fl_vmode
         || flx->textcolor == lastmapped )
    {
        unsigned long p;

        lastmapped = FL_NoColor;

        flx->textcolor = col;

        vmode = fl_vmode;
        if ( col == FL_INACTIVE_COL && fli_dithered( vmode ) )
        {
            textgc = flx->textgc;
            flx->textgc = fl_state[ vmode ].dimmedGC;
            XSetFont( flx->display, flx->textgc,
                      fl_state[ vmode ].cur_fnt->fid );
            switched = 1;
        }
        else if ( switched )
        {
            flx->textgc = textgc;
            XSetFont( flx->display, flx->textgc,
                      fl_state[ vmode ].cur_fnt->fid );
            switched = 0;
        }

        p = fl_get_pixel( col );
        XSetForeground( flx->display, flx->textgc, p );
        fli_free_newpixel( p );
    }
}


/***************************************
 * Set the background color for drawing
 ***************************************/

void
fl_bk_color( FL_COLOR col )
{
    if ( flx->bkcolor != col )
    {
        unsigned long p = fl_get_pixel( col );

        flx->bkcolor = col;
        XSetBackground( flx->display, flx->gc, p );
        fli_free_newpixel( p );
    }
}


/***************************************
 * Set the background color for text
 ***************************************/

void
fli_bk_textcolor( FL_COLOR col )
{
    if ( flx->bktextcolor != col )
    {
        unsigned long p = fl_get_pixel( col );
        flx->bktextcolor = col;
        XSetBackground( flx->display, flx->textgc, p );
        fli_free_newpixel( p );
    }
}


/***************************************
 * Map color: it involves changing the internal colormap as well as
 * requesting the acutal pixel value. In case a request fails,
 * we subsititute the closest color
 ***************************************/

unsigned long
fl_mapcolor( FL_COLOR col,
             int      r,
             int      g,
             int      b )
{
    XColor exact;
    int i, j = -1;
    static int totalcols;
    static XColor *cur_mapvals[ 6 ],
                  *cur_map;
    unsigned long pixel;

    /* If requested color is reserved, warn */

    if ( col < FL_BUILT_IN_COLS )
        M_warn( "fl_mapcolor", "Changing reserved color" );

    /* Must invalidate color cache */

    if ( col == flx->color )
        flx->color = BadPixel;

    lut = fl_state[ fl_vmode ].lut;

    if ( col >= flmapsize )
    {
        M_err( "fl_mapcolor",
               "Only %d indexed colors are supported", flmapsize );
        return 0;
    }

    /* col is the external colorname, FL_RED etc, which is kept in
       fli_imap[].index. */

    if ( col == fli_imap[ col ].index )
        j = col;

    for ( i = 0; j < 0 && i < flmapsize; i++ )
        if ( col == fli_imap[ i ].index )
            j = i;

    if ( j < 0 )
        j = flmapsize - 1;

    /* In B&W too many colors collaps together */

    if (    fli_imap[ j ].r == r
         && fli_imap[ j ].g == g
         && fli_imap[ j ].b == b
         && r != 0
         && ! fli_dithered( fl_vmode )
         && lut[ col ] )
        return lut[ col ];

    fli_imap[ j ].r       = r;
    fli_imap[ j ].g       = g;
    fli_imap[ j ].b       = b;
    fli_imap[ j ].grayval = FL_RGB2GRAY( r, g, b );
    fli_imap[ j ].index   = col;

    lastmapped = col;

    M_warn( "fl_mapcolor", "mapping %ld (%d,%d,%d)", col, r, g, b );

    pixel       = lut[ col ];
    exact.red   = ( r << 8 ) | 0xff;
    exact.green = ( g << 8 ) | 0xff;
    exact.blue  = ( b << 8 ) | 0xff;
    exact.flags = DoRed | DoGreen | DoBlue;
    exact.pixel = pixel;

    if ( fl_vmode == DirectColor )
    {
        exact.pixel = lut[ col ] = rgb2pixel( r, g, b );
        XStoreColors( flx->display, fli_map( fl_vmode ), &exact, 1 );
        return lut[ col ];
    }

    /* pixel value known by the server */

    if ( ! allow_leakage && fli_depth( fl_vmode ) >= 4 && pixel != BadPixel )
        fl_free_pixels( &pixel, 1 );

    if ( XAllocColor( flx->display, fli_colormap( fl_vmode ), &exact ) )
    {
        lut[ col ] = exact.pixel;
        return lut[ col ];
    }

    /* Colormap is full. Warn once and substitute from now on */

    if ( ! cur_mapvals[ fl_vmode ] )
    {
        M_warn( "fl_mapcolor", "ColormapFull. Using substitutions" );

        totalcols = FL_min( FL_MAX_COLS, 1L << fli_depth( fl_vmode ) );
        cur_map = fl_calloc( totalcols + 1, sizeof *cur_map );
        cur_mapvals[ fl_vmode ] = cur_map;

        /* Take a snapshot of the color map */

        for ( i = 0; i < totalcols; i++ )
            cur_map[ i ].pixel = i;

        XQueryColors( flx->display, fli_map( fl_vmode ), cur_map, totalcols );
    }

    /* Search for the closest match */

    cur_map = cur_mapvals[ fl_vmode ];
    j = fli_find_closest_color( r, g, b, cur_map, totalcols, &pixel );

    if ( j < 0 )
    {
        M_err( "fl_mapcolor", "Something is very wrong" );
        exit( 1 );
    }

    /* j will be the stuff we want */

    lut[ col ] = cur_map[ j ].pixel;

    /* We still need to allocate the color, otherwise destroying the just
       requested color might accidentally free a reserved pixel */

    exact.red   = cur_map[ j ].red;
    exact.green = cur_map[ j ].green;
    exact.blue  = cur_map[ j ].blue;
    exact.pixel = cur_map[ j ].pixel;
    exact.flags = DoRed | DoGreen | DoBlue;

    if ( ! XAllocColor( flx->display, fli_colormap( fl_vmode ), &exact ) )
        M_warn( "fl_mapcolor", "Something is wrong - will proceed" );


#if FL_DEBUG >= ML_DEBUG
    M_warn( "fl_mapcolor", "(%d %d %d)<->(%d %d %d)",
            r, g, b, cur_map[ j ].red, cur_map[ j ].green, cur_map[ j ].blue );
#endif

    return lut[ col ];
}


/***************************************
 ***************************************/

long
fl_mapcolorname( FL_COLOR     col,
                 const char * name )
{
    XColor xc;

    if ( XParseColor( flx->display, fli_colormap( fl_vmode ),
                      ( char * ) name, &xc ) )
    {
        xc.red   = ( xc.red   >> 8 ) & 0xff;
        xc.green = ( xc.green >> 8 ) & 0xff;
        xc.blue  = ( xc.blue  >> 8 ) & 0xff;
        return fl_mapcolor( col, xc.red, xc.green, xc.blue );
    }

    return -1;
}


/***************************************
 * change internal colormap before initialization. This way,
 * FORMS default color can be changed
 ***************************************/

void
fl_set_icm_color( FL_COLOR col,
                  int      r,
                  int      g,
                  int      b )
{
    int i;

    for ( i = 0; i < flmapsize; i++ )
        if ( col == fli_imap[ i ].index )
        {
            if ( FL_is_gray( fl_vmode ) )
                fli_imap[ i ].grayval = FL_RGB2GRAY( r, g, b );
            else
            {
                fli_imap[ i ].r = r;
                fli_imap[ i ].g = g;
                fli_imap[ i ].b = b;
            }

            return;
        }
}


/***************************************
 * query internal  colormap
 ***************************************/

void
fl_get_icm_color( FL_COLOR col,
                  int *    r,
                  int *    g,
                  int *    b )
{
    int i;

    for ( i = 0; i < flmapsize; i++ )
        if ( col == fli_imap[ i ].index )
        {
            if ( FL_is_gray( fl_vmode ) )
                *r = *g = *b = fli_imap[ i ].grayval;
            else
            {
                *r = fli_imap[ i ].r;
                *g = fli_imap[ i ].g;
                *b = fli_imap[ i ].b;
            }

            return;
        }
}


/***************************************
 * query real colormap. r,g,b returned is the current color used
 ***************************************/

unsigned long
fl_getmcolor( FL_COLOR i,
              int *    r,
              int *    g,
              int *    b )
{
    XColor exact;

    if ( ( exact.pixel = fl_get_pixel( i ) ) >= max_server_cols )
    {
        *r = *g = *b = 0;
        return ( unsigned long ) -1;
    }

    XQueryColor( flx->display, fli_map( fl_vmode ), &exact );

    *r = ( exact.red   >> 8 ) & 0xff;
    *g = ( exact.green >> 8 ) & 0xff;
    *b = ( exact.blue  >> 8 ) & 0xff;

    return exact.pixel;
}


/*** End of Colormap routines  *******}***************/


/***************************************
 ***************************************/

int
fl_get_visual_depth( void )
{
    return fl_state[ fl_vmode ].depth;
}


/***************************************
 * print out the current state info. For debugging only
 ***************************************/

#if FL_DEBUG >= ML_WARN
void
fli_dump_state_info( int          mode,
                     const char * where )
{
    FL_State *fs = fl_state + mode;
    XVisualInfo xvi;

    if ( fli_cntl.debug )
    {
        fprintf( stderr, "In %s", where );
        fprintf( stderr, " VClass: %s", fli_vclass_name( fli_class( mode ) ) );
        fprintf( stderr, " VisualID: 0x%lx", fs->xvinfo->visualid );
        fprintf( stderr, " Depth: %d %d",
                 fli_depth( mode ), fs->xvinfo->depth );
        fprintf( stderr, " Colormap: 0x%lx\n", fli_map( mode ) );
    }

    /* Some more checks */

    if ( ! XMatchVisualInfo( flx->display, fl_screen, fli_depth( mode ),
                             fli_class( mode ), &xvi ) )
    {
        M_err( "fli_dump_state_info", "Can't match listed visual" );
        exit( 1 );
    }

    /* Possible on SGI with OpenGL selected visuals */

    if ( fli_visual( mode )->visualid != xvi.visualid )

        M_warn( "fli_dump_state_info", "inconsistent visualID, probably OK" );

    /* State info consistency */

    if ( fli_depth( mode ) != fs->xvinfo->depth )
    {
        M_err( "fli_dump_state_info", "Bad Depth" );
        exit( 1 );
    }

    if ( fli_class( mode ) != fs->xvinfo->class )
    {
        M_err( "fli_dump_state_info", "Bad visual class" );
        exit( 1 );
    }
}
#endif


/***************************************
 ***************************************/

int
fl_mode_capable( int mode,
                 int warn )
{
    int cap;

    if ( mode < 0 || mode > 5 )
    {
        M_err( "fl_mode_capable", "Bad mode = %d", mode );
        return 0;
    }

    cap = fli_depth( mode ) >= FL_MINDEPTH && fli_visual( mode );

    if ( ! cap && warn )
        M_warn( "fl_mode_capable", "Not capable of %s at depth = %d",
                fli_vclass_name( mode ), fli_depth( mode ) );

    return cap;
}


/***************************************
 * Convert a RGB triple into a pixel value usable in DirectColor
 * and TrueColor. Note the RGB triple is ONE-BYTE EACH.
 ***************************************/

static FL_COLOR
rgb2pixel( unsigned int r,
           unsigned int g,
           unsigned int b )
{
    FL_State *s = fl_state + fl_vmode;

    /* This one drops bits and looks bad if primary color resolution is less
       than 6, but server calculates color this way. A better way  should be
       r = ((float) r * ((1L << s->rbits) - 1) / 255.0 + 0.1); */

    if ( s->rbits < 8 )
    {
        r >>= 8 - s->rbits;
        g >>= 8 - s->gbits;
        b >>= 8 - s->bbits;
    }
    else if ( s->rbits > 8 )
    {
        r <<= 8 - s->rbits;
        g <<= 8 - s->gbits;
        b <<= 8 - s->bbits;
    }

    return   ( ( ( unsigned long ) r << s->rshift ) & s->rmask )
           | ( ( ( unsigned long ) g << s->gshift ) & s->gmask )
           | ( ( ( unsigned long ) b << s->bshift ) & s->bmask );
}


/***************************************
 * Create a colormap valid for the given visual. It also
 * fills the colormap with default XFORMS map
 ***************************************/

#define MAXFILL   ( FL_BUILT_IN_COLS + 1 )
#define MAXREAD   100

Colormap
fl_create_colormap( XVisualInfo * xv,
                    int           nfill )
{
    long black = BlackPixel( flx->display, fl_screen );
    long white = WhitePixel( flx->display, fl_screen );
    XColor xc;
    Colormap cmap;
    int depth = xv->depth == 32 ? 24:xv->depth;
    int maxcolors = 1 << depth;
    int maxread = FL_min( MAXREAD, maxcolors );
    XColor *cur_entries = fl_malloc( maxread * sizeof *cur_entries ),
           *dc;
    unsigned long pixels[ MAXREAD ],
                  allocated[ MAXREAD ];
    int keep = maxcolors / 32;

    cmap = XCreateColormap( flx->display, fl_root, xv->visual,
                            xv->class != FL_DirectColor ?
                            AllocNone : AllocAll );

    /* As a minimum try to preserve Black or White */

    xc.flags = DoRed | DoGreen | DoBlue;
    xc.pixel = 0;
    if ( black == 0 && nfill >= 0 )
    {
        xc.red = xc.green = xc.blue = 0;
        XAllocColor( flx->display, cmap, &xc );
    }
    else if ( white == 0 && nfill >= 0 )
    {
        xc.red = xc.green = xc.blue = 0xffff;
        XAllocColor( flx->display, cmap, &xc );
    }

    /* Now if have the same visual, we can do event more */

    if ( nfill > 0 && fl_vmode == xv->class && fl_vmode != DirectColor )
    {
        int i,
            k;

        nfill = FL_min( MAXFILL, nfill );
        nfill = FL_min( nfill, maxcolors );

        if ( nfill < 4 )        /* potentially 8+1+4 colors */
            nfill = 4;

        for ( i = 0; i < maxread; i++ )
            cur_entries[ i ].pixel = i;

        XQueryColors( flx->display, fli_map( fl_vmode ), cur_entries, maxread );

        dc = cur_entries;
        for ( k = i = 0; i < maxread; i++, dc++ )
        {
            allocated[ i ] = FL_NoColor;
            dc->flags = DoRed | DoGreen | DoBlue;
            if ( XAllocColor( flx->display, cmap, dc ) )
                allocated[ k++ ] = dc->pixel;
        }

        /* Now free the non-xforms colors, but keep some non-xforms entries */

        for ( k = 0, i = keep; i < maxread; i++ )
        {
            unsigned int p = allocated[ i ];
            int j,
                found;

            for ( j = found = 0; ! found && j < nfill; j++ )
                found =    p == fl_get_pixel( j )
                        || p == ( unsigned long ) white
                        || p == ( unsigned long ) black
                        || p == 34;

            if ( ! found && p != FL_NoColor )
                pixels[ k++ ] = p;
        }

        if ( k )
        {
            M_warn( "fl_create_colormap", "free %d\n", k );
            XFreeColors( flx->display, cmap, pixels, k, 0 );
        }
    }

    fl_free( cur_entries );
    return cmap;
}


/***************************************
 ***************************************/

void
fl_set_color_leak( int y )
{
    allow_leakage = y;
}


/***************************************
 * if an index is being for the first time, the corresponding pixel
 * is either reserverd or bad, need to trap it
 ***************************************/

static int
bad_color_handler( Display     * d    FL_UNUSED_ARG,
                   XErrorEvent * xev )
{
    if ( xev->error_code == BadAccess )
        M_warn( "bad_color_handler", "bad pixel" );

    return 0;
}


/***************************************
 ***************************************/

void
fl_free_pixels( unsigned long * pix,
                int             n )
{
    int ( *oh )( Display *, XErrorEvent * );

    oh = XSetErrorHandler( bad_color_handler );
    XFreeColors( flx->display, fli_map( fl_vmode ), pix, n, 0 );
    XSync( flx->display, 0 );
    XSetErrorHandler( oh );
}


/***************************************
 ***************************************/

void
fl_free_colors( FL_COLOR * c,
                int        n )
{
    int i,
        k,
        j = -1;
    unsigned long * pixels = fl_malloc( n * sizeof *pixels ),
                  *pix;

    lut = fl_state[ fl_vmode ].lut;
    pix = pixels;

    for ( k = 0; k < n; k++, c++, pix++ )
    {
        /* If requested color is reserved, warn */

        if ( *c < FL_FREE_COL1 )
            M_warn( "fl_free_colors", "Freeing reserved color" );

        /* Must invalidate color cache */

        if ( *c == flx->color )
            flx->color = BadPixel;

        for ( i = 0; j < 0 && i < flmapsize; i++ )
            if ( *c == fli_imap[ i ].index )
                j = i;

        if ( j < 0 )
            j = flmapsize - 1;

        /* Pixel value known by the server */

        *pix = lut[ *c ];

        /* Mark this pixel as bad */

        lut[ *c ] = BadPixel;
    }

    fl_free_pixels( pixels, n );
    fl_free( pixels );
}


/***************************************
 * (r,g,b) input should be 8bit each
 ***************************************/

#define LINEAR_COLOR_DISTANCE  0

int
fli_find_closest_color( int             r,
                        int             g,
                        int             b,
                        XColor        * map,
                        int             len,
                        unsigned long * pix )
{
    long mindiff = 0x7fffffffL,
         diff;
    int dr,
        dg,
        db;
    int i,
        k;

    for ( k = i = 0; i < len; i++ )
    {
        dr = r - ( ( map[ i ].red   >> 8 ) & 0xff );
        dg = g - ( ( map[ i ].green >> 8 ) & 0xff );
        db = b - ( ( map[ i ].blue  >> 8 ) & 0xff );

        /* Correct formula is (.299,.587,.114) */

#if LINEAR_COLOR_DISTANCE
        diff = 3 * FL_abs( dr ) + 4 * FL_abs( dg ) + 2 * FL_abs( db );
#else
        diff = 3 * ( dr * dr ) + 4 * ( dg * dg ) + 2 * ( db * db );
#endif

        if ( diff < 0 )
            fprintf( stderr, "dr = %d dg = %d db = %d diff = %ld\n",
                     dr, dg, db, diff );

        if ( diff < mindiff )
        {
            mindiff = diff;
            k = i;
            *pix = map[ i ].pixel;
        }
    }

    return k;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
