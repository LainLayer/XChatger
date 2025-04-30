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
 * \file flvisual.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  XForm will by default use the visual that has the most depth
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flinternal.h"


#ifdef  XlibSpecificationRelease
#define XlibVersion  ( XlibSpecificationRelease == 5 ) ? "R5": \
                       ( ( XlibSpecificationRelease == 6 ) ? "R6" : "Post-R6" )
#else
#define XlibVersion "Pre-R5"
#endif


/******************* Local variables ************************/

static int max_server_depth;


/********************************************************************
 * Setup the most appropriate visual for FORMS
 ****************************************************************{***/

/***************************************
 * Get the conversion factors from RGB->pixel in TrueColor and
 * DirectColor
 ***************************************/

static void
RGBmode_init( int v )
{
    FL_State *s = fl_state + v;

    fli_xvisual2flstate( s, s->xvinfo );

#if FL_DEBUG >= ML_WARN
    M_info( "RGBmode_init", "%s: bits_per_rgb = %d",
            fli_vclass_name( v ), s->rgb_bits );
    M_info( "RGBmode_init", "RS = %d GS = %d BS = %d",
            s->rshift, s->gshift, s->bshift );
    M_info( "RGBmode_init", "RB = %d GB = %d BB = %d",
            s->rbits, s->gbits, s->bbits );
#endif
}


/***************************************
 * User has the option to select visual class/depth independently via
 * fl_set_defaults() or through resource/command lines. The request is
 * stored in fli_cntl. This routine just checks if the request itself
 * is valid or not. It is possible both visual and depth are valid
 * but the combination is not. So need to follow this routine
 * with XMatchVisual().
 ***************************************/

static void
check_user_preference( int * vmode,
                       int * depth )
{
    int reqv = -1,
        reqd = 0;

    reqv = fli_cntl.vclass;
    reqd = fli_cntl.depth;

#if FL_DEBUG >= ML_WARN
    M_warn( "check_user_preference", "UserRequest: %s %d",
            reqv >= 0 ?
            fli_vclass_name( reqv ) : "None", reqd > 0 ? reqd : 0 );
#endif

    /* Need to check special value FL_DefaultVisual */

    if ( reqv == FL_DefaultVisual )
    {
        reqd = DefaultDepth( fl_display, fl_screen );
        reqv = DefaultVisual( fl_display, fl_screen )->class;
    }

    /* Here make a guess if incomplete request is made */

    if ( reqv >= 0 && reqd == 0 )
        reqd = fli_depth( reqv );

    /* If only depth is requested, select a visual */

    if ( reqd > 0 && reqv < 0 )
        reqv = reqd > 12 ? TrueColor : PseudoColor;

    if ( reqv >= 0 && reqd >= FL_MINDEPTH )
    {
        *vmode = reqv;
        *depth = reqd;
    }
}


/***************************************
 * Find best visual among each visual class and store all info
 * in fl_state structure
 ***************************************/

#define setmode( m, n )  ( fli_depth( m ) >= n && fl_mode_capable( m, n ) )


static int
select_best_visual( void )
{
    static XVisualInfo *xv;
    static XVisualInfo *bestv[ 6 ];
    static XVisualInfo xvt;     /* fl_state uses it */
    int xvn,
        i,
        j,
        depth;
    static int bvmode = -1;   /* initial default if no user prefernce */

    /* Have already done it */

    if ( xv )
        return bvmode;

    /* Request for a list of all supported visuals on fl_screen */

    xvt.screen = fl_screen;

    if ( ! ( xv = XGetVisualInfo( fl_display, VisualScreenMask, &xvt, &xvn ) ) )
    {
        M_err( "select_best_visual", " Can't get VisualInfo!" );
        exit( 1 );
    }

    /* Choose the visual that has the most colors among each class. */

    for ( i = 0; i < xvn; i++ )
    {
        depth = xv[ i ].depth;
        j = xv[ i ].class;

        /* Simply use visuals returned by GetVisualInfo and make sure xv is
           NOT freed */

        if ( ! bestv[ j ] || depth > bestv[ j ]->depth )
        {
            FL_State *fs = fl_state + j;

            bestv[ j ] = xv + i;
            fs->xvinfo = bestv[ j ];
            fs->depth = bestv[ j ]->depth;
            fs->vclass = bestv[ j ]->class;
            fs->rgb_bits = bestv[ j ]->bits_per_rgb;
            if ( depth > max_server_depth )
                max_server_depth = fs->depth;
        }
    }

#if FL_DEBUG >= ML_DEBUG
    if ( fli_cntl.debug )
    {
        M_warn( "select_best_visual", "XlibVersion: %s", XlibVersion );
        M_info( "select_best_visual", "DPI = %d", fl_dpi );
        M_warn( "select_best_visual", "No. of Visuals: %d", xvn );
        for ( j = 0; j < 6; j++ )
            if ( bestv[ j ] )
                fprintf( stderr,
                         "Best %11s: Id = 0x%lx Depth = %2u RGBbits = %d\n",
                         fli_vclass_name( fli_class( j ) ),
                         bestv[ j ]->visualid, bestv[ j ]->depth,
                         bestv[ j ]->bits_per_rgb );
    }
#endif

    /* Demand FL_MINDEPTH bits. Since V0.63, FL_MINDEPTH is 1, so this this
       check is basically a no-op unless something is wrong. */

    if ( max_server_depth < FL_MINDEPTH )
    {
        M_err( "select_best_visual",
               "MaxServerDepth = %d. XForms requires at least %d. Sorry",
               max_server_depth, FL_MINDEPTH );
        exit( 1 );
    }

    /* If depth is smaller than 10, RGBmode offers no advantage over
       PseudoColor in that PseudoColors offers better flexibility */

    if ( setmode( TrueColor, 12 ) )
        bvmode = TrueColor;
    else if ( setmode( DirectColor, 12 ) )
        bvmode = DirectColor;
    else if ( setmode( PseudoColor, FL_MINDEPTH ) )
        bvmode = PseudoColor;
    else if ( setmode( StaticColor, FL_MINDEPTH ) )
        bvmode = StaticColor;
    else if ( setmode( GrayScale, FL_MINDEPTH ) )
        bvmode = GrayScale;
    else if ( setmode( StaticGray, FL_MINDEPTH ) )
        bvmode = StaticGray;
    else if ( xvn )     /* have to take what we have */
        bvmode = xv[ 0 ].class;
    else
    {
        M_err( "select_best_visual", "Can't find an appropriate visual" );
        exit( 1 );
    }

    return bvmode;
}


/***************************************
 * After this routine, program should have selected a workable
 * visual/depth combination
 ***************************************/

int
fli_initialize_program_visual( void )
{
    int vmode,
        depth;
    static XVisualInfo xvt;
    static int visual_initialized;
    static int program_vclass;

    if ( visual_initialized )
        return program_vclass;

    vmode = select_best_visual( );

#if FL_DEBUG >= ML_WARN
    M_warn( "fli_initialize_program_visual",
            "Initial visual: %s (ID = 0x%lx) depth = %d",
            fli_vclass_name( vmode ), fli_visual( vmode )->visualid,
            fli_depth( vmode ) );
#endif

    /* Check program default, settable by user fl_vmode */

    if ( fl_vmode >= 0 )
        vmode = fl_vmode;

    depth = fli_depth( vmode );

    M_warn( "fli_initialize_program_visual", "ProgramDefault: %s %d",
            fli_vclass_name( vmode ), depth);

    /* Give user a chance to select a visual */

    check_user_preference( &vmode, &depth );

    M_warn( "fli_initialize_program_visual", "UserPreference: %s %d",
            fli_vclass_name( vmode ), depth );

    /* If requested a visualID directly, honor it here */

    if ( fli_requested_vid > 0 )
    {
        XVisualInfo xv,
                    *retxv;
        int nv;

        M_warn( "fli_initialize_program_visual", "UserRequestedVID: 0x%lx",
                fli_requested_vid );

        xv.visualid = fli_requested_vid;

        if ( ( retxv = XGetVisualInfo( fl_display, VisualIDMask, &xv, &nv ) ) )
        {
            FL_State *fs = fl_state + retxv->class;

            vmode = retxv->class;
            fs->xvinfo = retxv;
            fs->depth = retxv->depth;
            fs->vclass = retxv->class;
            fs->rgb_bits = retxv->bits_per_rgb;
        }
        else
        {
            M_err( "fli_initialize_program_visual", "Can't find visualID 0x%lx",
                   fli_requested_vid );
            fli_requested_vid = 0;
        }
    }

    /* Make sure the stuff flies. */

    if ( ! fli_requested_vid )
    {
        if ( XMatchVisualInfo( fl_display, fl_screen, depth, vmode, &xvt ) )
        {
            FL_State *fs = fl_state + xvt.class;

            vmode = xvt.class;
            fs->xvinfo = &xvt;
            fs->depth = xvt.depth;
            fs->vclass = xvt.class;
            fs->rgb_bits = xvt.bits_per_rgb;
        }
        else
        {
            /* Bogus request. Revert to the best visual we have found */

            M_err( "fli_initialize_program_visual",
                   "Bogus request: %s with depth = %d",
                   fli_vclass_name( vmode ), depth );

            vmode = select_best_visual( );
        }
    }

    program_vclass = vmode;

#if FL_DEBUG >= ML_WARN
    M_warn( "fli_initialize_program_visual",
            "SelectedVisual: %s (ID = 0x%lx) depth = %d",
            fli_vclass_name( vmode ), fli_visual( vmode )->visualid,
            fli_depth( vmode ) );
#endif

    /* If RGB Visual is supported, need to find out the masks and shifts
       stuff to be used in RGB -> pixel mapping */

    if ( fli_depth( TrueColor ) )
        RGBmode_init( TrueColor );

    if ( fli_depth( DirectColor ) )
        RGBmode_init( DirectColor );

    visual_initialized = 1;

    return program_vclass;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
