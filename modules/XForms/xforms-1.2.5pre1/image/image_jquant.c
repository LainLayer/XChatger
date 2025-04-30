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
 *  along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/*
 * Copyright (C) 1991-1996, Thomas G. Lane.
 * This file is part of the XForms library package.
 *
 * The 2-pass quantizer from the JPEG distribution by the
 * Independent JPEG group. Except for minor interface changes, the code
 * here is almost verbatim copy of the IJG's code, which
 * has the following copyright:
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "flimage.h"
#include "flimage_int.h"


/***************************************
 ***************************************/

void
fl_select_mediancut_quantizer( void )
{
    flimage_quantize_rgb = j2pass_quantize_rgb;
    flimage_quantize_packed = j2pass_quantize_packed;
}


#define R_SCALE 2       /* scale R distances by this much */
#define G_SCALE 3       /* scale G distances by this much */
#define B_SCALE 1       /* and B by this much */

#define C0_SCALE  R_SCALE
#define C1_SCALE  G_SCALE
#define C2_SCALE  B_SCALE

#define BITS_IN_JSAMPLE   FL_PCBITS
#define MAXJSAMPLE        ( ( 1<<BITS_IN_JSAMPLE )-1 )

typedef unsigned char JSAMPLE;

#define GETJSAMPLE( a )  ( ( a ) &0xff )

#define MAXNUMCOLORS     ( MAXJSAMPLE + 1 )  /* maximum size of colormap */

/* These will do the right thing for either R,G,B or B,G,R color order,
 * but you may not like the results for other color orders.
 */

#define HIST_C0_BITS  5     /* bits of precision in R/B histogram */
#define HIST_C1_BITS  6     /* bits of precision in G histogram */
#define HIST_C2_BITS  5     /* bits of precision in B/R histogram */

/* Number of elements along histogram axes. */

#define HIST_C0_ELEMS  ( 1 << HIST_C0_BITS )
#define HIST_C1_ELEMS  ( 1 << HIST_C1_BITS )
#define HIST_C2_ELEMS  ( 1 << HIST_C2_BITS )

/* These are the amounts to shift an input value to get a histogram index. */

#define C0_SHIFT  ( BITS_IN_JSAMPLE - HIST_C0_BITS )
#define C1_SHIFT  ( BITS_IN_JSAMPLE - HIST_C1_BITS )
#define C2_SHIFT  ( BITS_IN_JSAMPLE - HIST_C2_BITS )

typedef u_short histcell;   /* histogram cell; prefer an unsigned int type */
typedef histcell *histptr;  /* for pointers to histogram cells */
typedef histcell hist1d[HIST_C2_ELEMS];     /* typedefs for the array */
typedef hist1d *hist2d;     /* type for the 2nd-level pointers */
typedef hist2d *hist3d;     /* type for top-level pointer */

#if BITS_IN_JSAMPLE == 8
typedef short FSERROR;      /* 16 bits should be enough */
typedef int LOCFSERROR;     /* use 'int' for calculation temps */
#else
typedef int FSERROR;        /* may need more than 16 bits */
typedef int LOCFSERROR;     /* be sure calculation temps are big enough */
#endif

typedef FSERROR *FSERRPTR;  /* pointer to error array (in FAR storage!) */


typedef struct
{
    int  c0min,
         c0max;
    int  c1min,
         c1max;
    int  c2min,
         c2max;
    int  volume;
    long colorcount;
} box;

typedef box *boxptr;


typedef struct
{
    hist3d     histogram;              /* pointer to the 3D histogram array */
    FSERRPTR   fserrors;               /* accumulated-errors array */
    int      * error_limiter;          /* table for clamping applied error */
    int        on_odd_row;             /* flag to remember which row we're on */
    int      * colormap[ 3 ];          /* selected colormap */
    int        actual_number_of_colors;/* number of selected colors */
    FL_IMAGE * im;                     /* for progress monitor only          */
}
SPEC;


static void init_error_limit( SPEC * );

static void prescan_quantize( SPEC *,
                              unsigned char **,
                              unsigned char **,
                              unsigned char **,
                              int,
                              int) ;

static void select_colors( SPEC *,
                           int );

static void pass2_fs_dither( SPEC *,
                             unsigned char **,
                             unsigned char **,
                             unsigned char **,
                             unsigned short **,
                             int,
                             int );


/***************************************
 ***************************************/

static void
cleanup_spec( SPEC *sp )
{
    if ( sp->fserrors )
        fl_free( sp->fserrors );

    if ( sp->error_limiter )
        fl_free( sp->error_limiter - MAXJSAMPLE );

    sp->error_limiter = NULL;
    sp->fserrors = NULL;

    if ( sp->histogram )
    {
        int i;

        for ( i = 0; i < HIST_C0_ELEMS; i++ )
    {
        if ( sp->histogram[ i ] )
            fl_free( sp->histogram[ i ] );
        sp->histogram[ i ] = NULL;
    }
    }

    fl_free( sp->histogram );
    sp->histogram = NULL;

    fl_free( sp );
}


/***************************************
 ***************************************/

static SPEC *
alloc_spec( int   w,
            int   h     FL_UNUSED_ARG,
            int * rlut,
            int * glut,
            int * blut )
{
    int fs_size = ( w + 2 ) * ( 3 * sizeof( FSERROR ) ),
        i;
    SPEC *sp = fl_calloc( 1, sizeof *sp );
    int err = ! sp;

    if ( ! err )
        init_error_limit( sp );

    err = err || ! ( sp->fserrors = fl_calloc( 1, fs_size ) );
    err = err || ! ( sp->histogram = fl_calloc( 1,
                                          HIST_C0_ELEMS * sizeof( hist2d ) ) );
    for ( i = 0; ! err && i < HIST_C0_ELEMS; i++ )
        err = ! ( sp->histogram[ i ] = fl_calloc( 1,
                         HIST_C1_ELEMS * HIST_C2_ELEMS * sizeof( histcell ) ) );

    if ( err )
    {
        cleanup_spec( sp );
        sp = NULL;
    }
    else
    {
        sp->colormap[ 0 ] = rlut;
        sp->colormap[ 1 ] = glut;
        sp->colormap[ 2 ] = blut;
    }

    return sp;
}


/***************************************
 ***************************************/

int
j2pass_quantize_rgb( unsigned char  ** red,
                     unsigned char  ** green,
                     unsigned char  ** blue,
                     int               w,
                     int               h,
                     int               max_color,
                     unsigned short ** ci,
                     int             * actual_color,
                     int             * red_lut,
                     int             * green_lut,
                     int             * blue_lut,
                     FL_IMAGE        * im )
{
    SPEC *sp = alloc_spec( w, h, red_lut, green_lut, blue_lut );
    int i;

    if ( ! sp )
    {
        *actual_color = 0;
        if ( im )
            im->error_message( im, "Failed to allocate working memory" );
        return -1;
    }

    if ( *actual_color > 256 )
        *actual_color = 256;

    sp->im = im;

    /* get histogram  */

    prescan_quantize( sp, red, green, blue, w, h );

    select_colors( sp, max_color );

    /* re-init histogram for inverse lookup */

    for ( i = 0; i < HIST_C0_ELEMS; i++ )
        memset( sp->histogram[ i ], 0,
                HIST_C1_ELEMS * HIST_C2_ELEMS * sizeof( histcell ) );

    sp->on_odd_row = 0;
    pass2_fs_dither( sp, red, green, blue, ci, w, h );
    *actual_color = sp->actual_number_of_colors;
    cleanup_spec( sp );

    if ( im )
    {
        im->completed = im->h;
        im->visual_cue( im, "Quantization Done" );
    }

    return 0;
}


/***************************************
 ***************************************/

int
j2pass_quantize_packed( unsigned int   ** packed,
                        int               w,
                        int               h,
                        int               max_color,
                        unsigned short ** ci,
                        int             * actual_color,
                        int             * red_lut,
                        int             * green_lut,
                        int             * blue_lut,
                        FL_IMAGE        * im )
{
    SPEC *sp = alloc_spec( w, h, red_lut, green_lut, blue_lut );
    unsigned char **red = NULL,
                  **green = NULL,
                  **blue = NULL;
    int i,
        err;

    if ( ! sp )
    {
        if ( im )
            im->error_message( im, "Quantize: can't allocate memory" );
        *actual_color = 0;
        return -1;
    }

    sp->im = im;

    /* we can process the image one piece a time to avoid the heavy memory
       usage, but packed is not that common. For now, do it in one chunk */

    err =    ! ( red   = fl_get_matrix( h, w, sizeof **red   ) )
          || ! ( green = fl_get_matrix( h, w, sizeof **green ) )
          || ! ( blue  = fl_get_matrix( h, w, sizeof **blue  ) );

    if ( err )
    {
        const char *s = "Quantize: can't allocate memory";
        if ( im )
            im->error_message( im, s );
        else
            fprintf( stderr, "%s\n", s );

        fl_free_matrix( red );
        fl_free_matrix( green );
        fl_free_matrix( blue );

        return -1;
    }

    for ( i = w * h; --i >= 0; )
        FL_UNPACK( packed[ 0 ][ i ],
                   red[ 0 ][ i ], green[ 0 ][ i ], blue[ 0 ][ i ]);


    /* get histogram  */

    prescan_quantize( sp, red, green, blue, w, h );

    select_colors( sp, max_color );

    /* re-init histogram for inverse lookup */

    for ( i = 0; i < HIST_C0_ELEMS; i++ )
        memset( sp->histogram[ i ], 0,
                HIST_C1_ELEMS * HIST_C2_ELEMS * sizeof( histcell ) );

    sp->on_odd_row = 0;
    pass2_fs_dither( sp, red, green, blue, ci, w, h );
    *actual_color = sp->actual_number_of_colors;

    fl_free_matrix( red );
    fl_free_matrix( green );
    fl_free_matrix( blue );
    cleanup_spec( sp );

    if ( im )
    {
        im->completed = im->h;
        im->visual_cue( im, "Quantization Done" );
    }

    return 0;
}


/* log2(histogram cells in update box) for each axis; this can be adjusted */

#define BOX_C0_LOG  ( HIST_C0_BITS - 3 )
#define BOX_C1_LOG  ( HIST_C1_BITS - 3 )
#define BOX_C2_LOG  ( HIST_C2_BITS - 3 )

#define BOX_C0_ELEMS  ( 1 << BOX_C0_LOG )   /* # of hist cells in update box */
#define BOX_C1_ELEMS  ( 1 << BOX_C1_LOG )
#define BOX_C2_ELEMS  ( 1 << BOX_C2_LOG )

#define BOX_C0_SHIFT  ( C0_SHIFT + BOX_C0_LOG )
#define BOX_C1_SHIFT  ( C1_SHIFT + BOX_C1_LOG )
#define BOX_C2_SHIFT  ( C2_SHIFT + BOX_C2_LOG )


/***************************************
 * Locate the colormap entries close enough to an update box to be candidates
 * for the nearest entry to some cell(s) in the update box.  The update box
 * is specified by the center coordinates of its first cell.  The number of
 * candidate colormap entries is returned, and their colormap indexes are
 * placed in colorlist[].
 * This routine uses Heckbert's "locally sorted search" criterion to select
 * the colors that need further consideration.
 ***************************************/

static int
find_nearby_colors( SPEC    * sp,
                    int       minc0,
                    int       minc1,
                    int       minc2,
                    JSAMPLE   colorlist[ ] )
{
    int numcolors = sp->actual_number_of_colors;
    int maxc0,
        maxc1,
        maxc2;
    int centerc0,
        centerc1,
        centerc2;
    int i,
        x,
        ncolors;
    int minmaxdist,
        min_dist,
        max_dist,
        tdist;
    int mindist[ MAXNUMCOLORS ];    /* min distance to colormap entry i */

    /* Compute true coordinates of update box's upper corner and center. *
       Actually we compute the coordinates of the center of the upper-corner
       * histogram cell, which are the upper bounds of the volume we care
       about. * Note that since ">>" rounds down, the "center" values may be
       closer to * min than to max; hence comparisons to them must be "<=",
       not "<". */

    maxc0 = minc0 + ( ( 1 << BOX_C0_SHIFT ) - ( 1 << C0_SHIFT ) );
    centerc0 = ( minc0 + maxc0 ) >> 1;
    maxc1 = minc1 + ( ( 1 << BOX_C1_SHIFT ) - ( 1 << C1_SHIFT ) );
    centerc1 = ( minc1 + maxc1 ) >> 1;
    maxc2 = minc2 + ( ( 1 << BOX_C2_SHIFT ) - ( 1 << C2_SHIFT ) );
    centerc2 = ( minc2 + maxc2 ) >> 1;

    /* For each color in colormap, find:
        1. its minimum squared-distance to any point in the update box
           (zero if color is within update box)
        2. its maximum squared-distance to any point in the update box.
           Both of these can be found by considering only the corners of
           the box. We save the minimum distance for each color in mindist[];
           only the smallest maximum distance is of interest. */

    minmaxdist = 0x7FFFFFFFL;

    for ( i = 0; i < numcolors; i++ )
    {
        /* We compute the squared-c0-distance term, then add in the other
           two. */

        x = sp->colormap[ 0 ][ i ];
        if ( x < minc0 )
        {
            tdist = ( x - minc0 ) * C0_SCALE;
            min_dist = tdist * tdist;
            tdist = ( x - maxc0 ) * C0_SCALE;
            max_dist = tdist * tdist;
        }
        else if ( x > maxc0 )
        {
            tdist = ( x - maxc0 ) * C0_SCALE;
            min_dist = tdist * tdist;
            tdist = ( x - minc0 ) * C0_SCALE;
            max_dist = tdist * tdist;
        }
        else
        {
            /* within cell range so no contribution to min_dist */

            min_dist = 0;
            if ( x <= centerc0 )
            {
                tdist = ( x - maxc0 ) * C0_SCALE;
                max_dist = tdist * tdist;
            }
            else
            {
                tdist = ( x - minc0 ) * C0_SCALE;
                max_dist = tdist * tdist;
            }
        }

        x = sp->colormap[ 1 ][ i ];
        if ( x < minc1 )
        {
            tdist = ( x - minc1 ) * C1_SCALE;
            min_dist += tdist * tdist;
            tdist = ( x - maxc1 ) * C1_SCALE;
            max_dist += tdist * tdist;
        }
        else if ( x > maxc1 )
        {
            tdist = ( x - maxc1 ) * C1_SCALE;
            min_dist += tdist * tdist;
            tdist = (x - minc1 ) * C1_SCALE;
            max_dist += tdist * tdist;
        }
        else
        {
            /* within cell range so no contribution to min_dist */

            if ( x <= centerc1 )
            {
                tdist = ( x - maxc1 ) * C1_SCALE;
                max_dist += tdist * tdist;
            }
            else
            {
                tdist = ( x - minc1 ) * C1_SCALE;
                max_dist += tdist * tdist;
            }
        }

        x = sp->colormap[ 2 ][ i ];
        if ( x < minc2 )
        {
            tdist = ( x - minc2 ) * C2_SCALE;
            min_dist += tdist * tdist;
            tdist = ( x - maxc2 ) * C2_SCALE;
            max_dist += tdist * tdist;
        }
        else if ( x > maxc2 )
        {
            tdist = ( x - maxc2 ) * C2_SCALE;
            min_dist += tdist * tdist;
            tdist = ( x - minc2 ) * C2_SCALE;
            max_dist += tdist * tdist;
        }
        else
        {
            /* within cell range so no contribution to min_dist */

            if ( x <= centerc2 )
            {
                tdist = ( x - maxc2 ) * C2_SCALE;
                max_dist += tdist * tdist;
            }
            else
            {
                tdist = ( x - minc2 ) * C2_SCALE;
                max_dist += tdist * tdist;
            }
        }

        mindist[ i ] = min_dist;    /* save away the results */
        if ( max_dist < minmaxdist )
            minmaxdist = max_dist;
    }

    /* Now we know that no cell in the update box is more than minmaxdist *
       away from some colormap entry.  Therefore, only colors that are *
       within minmaxdist of some part of the box need be considered. */

    ncolors = 0;

    for ( i = 0; i < numcolors; i++ )
        if ( mindist[ i ] <= minmaxdist )
            colorlist[ ncolors++ ] = ( JSAMPLE ) i;

    return ncolors;
}


/***************************************
 * Find the closest colormap entry for each cell in the update box,
 * given the list of candidate colors prepared by find_nearby_colors.
 * Return the indexes of the closest entries in the bestcolor[] array.
 * This routine uses Thomas' incremental distance calculation method to
 * find the distance from a colormap entry to successive cells in the box.
 ***************************************/

static void
find_best_colors( SPEC    * sp,
                  int       minc0,
                  int       minc1,
                  int       minc2,
                  int       numcolors,
                  JSAMPLE   colorlist[ ],
                  JSAMPLE   bestcolor[ ] )
{
    int ic0,
        ic1,
        ic2;
    int i,
        icolor;
    int *bptr;      /* pointer into bestdist[] array */
    JSAMPLE *cptr;      /* pointer into bestcolor[] array */
    int dist0,
        dist1;      /* initial distance values */
    int dist2;      /* current distance in inner loop */
    int xx0,
        xx1;        /* distance increments */
    int xx2;
    int inc0,
        inc1,
        inc2;   /* initial values for increments */
    /* This array holds the distance to the nearest-so-far color for each
       cell */
    int bestdist[ BOX_C0_ELEMS * BOX_C1_ELEMS * BOX_C2_ELEMS ];

    /* Initialize best-distance for each cell of the update box */

    bptr = bestdist;
    for ( i = BOX_C0_ELEMS * BOX_C1_ELEMS * BOX_C2_ELEMS - 1; i >= 0; i-- )
        *bptr++ = 0x7FFFFFFFL;

    /* For each color selected by find_nearby_colors, * compute its distance
       to the center of each cell in the box. * If that's less than
       best-so-far, update best distance and color number. */

    /* Nominal steps between cell centers ("x" in Thomas article) */

#define STEP_C0  ( ( 1 << C0_SHIFT ) * C0_SCALE )
#define STEP_C1  ( ( 1 << C1_SHIFT ) * C1_SCALE )
#define STEP_C2  ( ( 1 << C2_SHIFT ) * C2_SCALE )

    for ( i = 0; i < numcolors; i++ )
    {
        icolor = GETJSAMPLE( colorlist[ i ] );

        /* Compute (square of) distance from minc0/c1/c2 to this color */

        inc0 = ( minc0 - GETJSAMPLE( sp->colormap[ 0 ][ icolor] ) ) * C0_SCALE;
        dist0 = inc0 * inc0;
        inc1 = ( minc1 - GETJSAMPLE( sp->colormap[ 1 ][ icolor ] ) ) * C1_SCALE;
        dist0 += inc1 * inc1;
        inc2 = ( minc2 - GETJSAMPLE( sp->colormap[ 2 ][ icolor ] ) ) * C2_SCALE;
        dist0 += inc2 * inc2;

        /* Form the initial difference increments */

        inc0 = inc0 * 2 * STEP_C0 + STEP_C0 * STEP_C0;
        inc1 = inc1 * 2 * STEP_C1 + STEP_C1 * STEP_C1;
        inc2 = inc2 * 2 * STEP_C2 + STEP_C2 * STEP_C2;

        /* Now loop over all cells in box, updating distance per Thomas
           method */

        bptr = bestdist;
        cptr = bestcolor;
        xx0 = inc0;
        for ( ic0 = BOX_C0_ELEMS - 1; ic0 >= 0; ic0-- )
        {
            dist1 = dist0;
            xx1 = inc1;

            for ( ic1 = BOX_C1_ELEMS - 1; ic1 >= 0; ic1-- )
            {
                dist2 = dist1;
                xx2 = inc2;

                for ( ic2 = BOX_C2_ELEMS - 1; ic2 >= 0; ic2-- )
                {
                    if ( dist2 < *bptr )
                    {
                        *bptr = dist2;
                        *cptr = ( JSAMPLE ) icolor;
                    }

                    dist2 += xx2;
                    xx2 += 2 * STEP_C2 * STEP_C2;
                    bptr++;
                    cptr++;
                }

                dist1 += xx1;
                xx1 += 2 * STEP_C1 * STEP_C1;
            }

            dist0 += xx0;
            xx0 += 2 * STEP_C0 * STEP_C0;
        }
    }
}


/***************************************
 * Fill the inverse-colormap entries in the update box that contains
 * histogram cell c0/c1/c2.  (Only that one cell MUST be filled, but
 * we can fill as many others as we wish.)
 ***************************************/

static void
fill_inverse_cmap( SPEC * cquantize,
                   int    c0,
                   int    c1,
                   int    c2 )
{
    hist3d histogram = cquantize->histogram;
    int minc0,
        minc1,
        minc2;  /* lower left corner of update box */
    int ic0,
        ic1,
        ic2;
    JSAMPLE *cptr;  /* pointer into bestcolor[] array */
    histptr cachep; /* pointer into main cache array */
    /* This array lists the candidate colormap indexes. */
    JSAMPLE colorlist[ MAXNUMCOLORS ];
    int numcolors;      /* number of candidate colors */
    /* This array holds the actually closest colormap index for each cell. */
    JSAMPLE bestcolor[ BOX_C0_ELEMS * BOX_C1_ELEMS * BOX_C2_ELEMS ];

    /* Convert cell coordinates to update box ID */

    c0 >>= BOX_C0_LOG;
    c1 >>= BOX_C1_LOG;
    c2 >>= BOX_C2_LOG;

    /* Compute true coordinates of update box's origin corner. * Actually we
       compute the coordinates of the center of the corner * histogram cell,
       which are the lower bounds of the volume we care about. */

    minc0 = ( c0 << BOX_C0_SHIFT ) + ( ( 1 << C0_SHIFT ) >> 1 );
    minc1 = ( c1 << BOX_C1_SHIFT ) + ( ( 1 << C1_SHIFT ) >> 1 );
    minc2 = ( c2 << BOX_C2_SHIFT ) + ( ( 1 << C2_SHIFT ) >> 1 );

    /* Determine which colormap entries are close enough to be candidates *
       for the nearest entry to some cell in the update box. */

    numcolors = find_nearby_colors( cquantize, minc0, minc1, minc2, colorlist );

    /* Determine the actually nearest colors. */

    find_best_colors( cquantize, minc0, minc1, minc2, numcolors, colorlist,
                      bestcolor );

    /* Save the best color numbers (plus 1) in the main cache array */

    c0 <<= BOX_C0_LOG;      /* convert ID back to base cell indexes */
    c1 <<= BOX_C1_LOG;
    c2 <<= BOX_C2_LOG;
    cptr = bestcolor;

    for ( ic0 = 0; ic0 < BOX_C0_ELEMS; ic0++ )
    {
        for ( ic1 = 0; ic1 < BOX_C1_ELEMS; ic1++ )
        {
            cachep = &histogram[ c0 + ic0 ][ c1 + ic1 ][ c2 ];

            for ( ic2 = 0; ic2 < BOX_C2_ELEMS; ic2++ )
                *cachep++ = ( histcell ) ( GETJSAMPLE( *cptr++ ) + 1 );
        }
    }
}


#define RIGHT_SHIFT( x, shft)   ( ( x ) >> ( shft ) )


/***************************************
 * This version performs Floyd-Steinberg dithering
 ***************************************/

static void
pass2_fs_dither( SPEC            * sp,
                 unsigned char  ** red,
                 unsigned char  ** green,
                 unsigned char  ** blue,
                 unsigned short ** output_buf,
                 int               width,
                 int               num_rows )
{
    hist3d histogram = sp->histogram;
    LOCFSERROR cur0,
               cur1,
               cur2;    /* current error or pixel value */
    LOCFSERROR belowerr0,
               belowerr1,
               belowerr2;       /* error for pixel below cur */
    LOCFSERROR bpreverr0,
               bpreverr1,
               bpreverr2;       /* error for below/prev col */
    FSERRPTR errorptr;          /* => fserrors[] at column before current */
    unsigned short *outptr;     /* => current output pixel */
    histptr cachep;
    int dir;            /* +1 or -1 depending on direction */
    int dir3;           /* 3*dir, for advancing inptr & errorptr */
    int row;
    int col;
    int *error_limit = sp->error_limiter;
    int *colormap0 = sp->colormap[0];
    int *colormap1 = sp->colormap[1];
    int *colormap2 = sp->colormap[2];
    unsigned char *r,
                  *g,
                  *b;

    if ( sp->im )
    {
        sp->im->completed = -1;
        sp->im->visual_cue( sp->im, "Dithering ..." );
    }

    for ( row = 0; row < num_rows; row++ )
    {
        r = red[   row ];
        g = green[ row ];
        b = blue[  row ];

        outptr = output_buf[ row ];

        if ( sp->on_odd_row )
        {
            /* work right to left in this row */

            r += width - 1;
            g += width - 1;
            b += width - 1;
            outptr += width - 1;
            dir = -1;
            dir3 = -3;
            errorptr = sp->fserrors +  (width + 1 ) * 3;    /* => entry after
                                                               last column */
            sp->on_odd_row = 0; /* flip for next time */
        }
        else
        {
            /* work left to right in this row */

            dir = 1;
            dir3 = 3;
            errorptr = sp->fserrors;    /* => entry before first real column */
            sp->on_odd_row = 1; /* flip for next time */
        }

        /* Preset error values: no error propagated to first pixel from left */

        cur0 = cur1 = cur2 = 0;

        /* and no error propagated to row below yet */

        belowerr0 = belowerr1 = belowerr2 = 0;
        bpreverr0 = bpreverr1 = bpreverr2 = 0;

        for ( col = 0; col < width; col++ )
        {

            /* curN holds the error propagated from the previous pixel on the
               current line.  Add the error propagated from the previous
               line * to form the complete error correction term for this
               pixel, and * round the error term (which is expressed * 16) to
               an integer. * RIGHT_SHIFT rounds towards minus infinity, so
               adding 8 is correct * for either sign of the error value. *
               Note: errorptr points to *previous* column's array entry. */
            
            cur0 = RIGHT_SHIFT( cur0 + errorptr[ dir3 + 0 ] + 8, 4 );
            cur1 = RIGHT_SHIFT( cur1 + errorptr[ dir3 + 1 ] + 8, 4 );
            cur2 = RIGHT_SHIFT( cur2 + errorptr[ dir3 + 2 ] + 8, 4 );

            /* Limit the error using transfer function set by init_error_limit.
               See comments with init_error_limit for rationale. */

            cur0 = error_limit[ cur0 ];
            cur1 = error_limit[ cur1 ];
            cur2 = error_limit[ cur2 ];

            /* Form pixel value + error, and range-limit to 0..MAXJSAMPLE.
               The maximum error is +- MAXJSAMPLE (or less with error limiting);
               this sets the required size of the range_limit array. */

            cur0 += *r;
            cur1 += *g;
            cur2 += *b;

            cur0 = FL_PCCLAMP( cur0 );
            cur1 = FL_PCCLAMP( cur1 );
            cur2 = FL_PCCLAMP( cur2 );

            /* Index into the cache with adjusted pixel value */

            cachep = &histogram[ cur0 >> C0_SHIFT ][ cur1 >> C1_SHIFT ][ cur2 >> C2_SHIFT ];

            /* If we have not seen this color before, find nearest colormap */
            /* entry and update the cache */

            if ( *cachep == 0 )
                fill_inverse_cmap( sp, cur0 >> C0_SHIFT, cur1 >> C1_SHIFT,
                                   cur2 >> C2_SHIFT );

            /* Now emit the colormap index for this cell */

            {
                int pixcode = *cachep - 1;
                *outptr = ( JSAMPLE ) pixcode;

                /* Compute representation error for this pixel */

                cur0 -= colormap0[ pixcode ];
                cur1 -= colormap1[ pixcode ];
                cur2 -= colormap2[ pixcode ];
            }

            /* Compute error fractions to be propagated to adjacent pixels. *
               Add these into the running sums, and simultaneously shift the
               * next-line error sums left by 1 column. */

            {
                LOCFSERROR bnexterr,
                           delta;

                bnexterr = cur0;    /* Process component 0 */
                delta = cur0 * 2;
                cur0 += delta;  /* form error * 3 */
                errorptr[ 0 ] = ( FSERROR ) ( bpreverr0 + cur0 );
                cur0 += delta;  /* form error * 5 */
                bpreverr0 = belowerr0 + cur0;
                belowerr0 = bnexterr;
                cur0 += delta;  /* form error * 7 */
                bnexterr = cur1;    /* Process component 1 */

                delta = cur1 * 2;
                cur1 += delta;  /* form error * 3 */
                errorptr[ 1 ] = ( FSERROR ) ( bpreverr1 + cur1 );
                cur1 += delta;  /* form error * 5 */
                bpreverr1 = belowerr1 + cur1;
                belowerr1 = bnexterr;
                cur1 += delta;  /* form error * 7 */
                bnexterr = cur2;    /* Process component 2 */

                delta = cur2 * 2;
                cur2 += delta;  /* form error * 3 */
                errorptr[ 2 ] = ( FSERROR ) ( bpreverr2 + cur2 );
                cur2 += delta;  /* form error * 5 */
                bpreverr2 = belowerr2 + cur2;
                belowerr2 = bnexterr;
                cur2 += delta;  /* form error * 7 */
            }

            /* At this point curN contains the 7/16 error value to be propagated
               to the next pixel on the current line, and all the errors for the
               next line have been shifted over.  We are therefore ready to move
               on. */

            r += dir;
            g += dir;
            b += dir;
            outptr += dir;
            errorptr += dir3;   /* advance errorptr to current column */
        }

        /* Post-loop cleanup: we must unload the final error values into the
           final fserrors[] entry.  Note we need not unload belowerrN
           because * it is for the dummy column before or after the actual
           array. */

        errorptr[ 0 ] = ( FSERROR ) bpreverr0;  /* unload prev errs into
                                                   array */
        errorptr[ 1 ] = ( FSERROR ) bpreverr1;
        errorptr[ 2 ] = ( FSERROR ) bpreverr2;
    }

    if( sp->im )
    {
        sp->im->completed = sp->im->total = sp->im->h;
        sp->im->visual_cue( sp->im, "Dithering done" );
    }
}


/***************************************
 * Shrink the min/max bounds of a box to enclose only nonzero elements,
 * and recompute its volume and population
 ***************************************/

static void
update_box( SPEC   * sp,
            boxptr   boxp )
{
    hist3d histogram = sp->histogram;
    histptr histp;
    int c0,
        c1,
        c2;
    int c0min,
        c0max,
        c1min,
        c1max,
        c2min,
        c2max;
    int dist0,
        dist1,
        dist2;
    long ccount;

    c0min = boxp->c0min;
    c0max = boxp->c0max;
    c1min = boxp->c1min;
    c1max = boxp->c1max;
    c2min = boxp->c2min;
    c2max = boxp->c2max;

    if ( c0max > c0min )
        for ( c0 = c0min; c0 <= c0max; c0++ )
            for ( c1 = c1min; c1 <= c1max; c1++)
            {
                histp = &histogram[ c0 ][ c1 ][ c2min ];

                for ( c2 = c2min; c2 <= c2max; c2++ )
                    if ( *histp++ != 0 )
                    {
                        boxp->c0min = c0min = c0;
                        goto have_c0min;
                    }
            }

 have_c0min:

    if ( c0max > c0min )
        for ( c0 = c0max; c0 >= c0min; c0-- )
            for ( c1 = c1min; c1 <= c1max; c1++ )
            {
                histp = &histogram[ c0 ][ c1 ][ c2min ];

                for ( c2 = c2min; c2 <= c2max; c2++ )
                    if ( *histp++ != 0 )
                    {
                        boxp->c0max = c0max = c0;
                        goto have_c0max;
                    }
            }

 have_c0max:

    if ( c1max > c1min )
        for ( c1 = c1min; c1 <= c1max; c1++ )
            for ( c0 = c0min; c0 <= c0max; c0++ )
            {
                histp = &histogram[ c0 ][ c1 ][ c2min ];

                for ( c2 = c2min; c2 <= c2max; c2++ )
                    if ( *histp++ != 0 )
                    {
                        boxp->c1min = c1min = c1;
                        goto have_c1min;
                    }
            }

  have_c1min:

    if ( c1max > c1min )
        for ( c1 = c1max; c1 >= c1min; c1-- )
            for ( c0 = c0min; c0 <= c0max; c0++ )
            {
                histp = &histogram[ c0 ][ c1 ][ c2min ];

                for ( c2 = c2min; c2 <= c2max; c2++ )
                    if ( *histp++ != 0 )
                    {
                        boxp->c1max = c1max = c1;
                        goto have_c1max;
                    }
            }

 have_c1max:

    if ( c2max > c2min )
        for ( c2 = c2min; c2 <= c2max; c2++ )
            for ( c0 = c0min; c0 <= c0max; c0++ )
            {
                histp = &histogram[ c0 ][ c1min ][ c2 ];

                for ( c1 = c1min; c1 <= c1max; c1++, histp += HIST_C2_ELEMS )
                    if ( *histp != 0 )
                    {
                        boxp->c2min = c2min = c2;
                        goto have_c2min;
                    }
            }

 have_c2min:

    if ( c2max > c2min )
        for ( c2 = c2max; c2 >= c2min; c2-- )
            for ( c0 = c0min; c0 <= c0max; c0++ )
            {
                histp = &histogram[ c0 ][ c1min ][ c2 ];

                for ( c1 = c1min; c1 <= c1max; c1++, histp += HIST_C2_ELEMS )
                    if ( *histp != 0 )
                    {
                        boxp->c2max = c2max = c2;
                        goto have_c2max;
                    }
            }

 have_c2max:

    /* Update box volume. * We use 2-norm rather than real volume here; this
       biases the method * against making long narrow boxes, and it has the
       side benefit that * a box is splittable iff norm > 0. * Since the
       differences are expressed in histogram-cell units, * we have to shift
       back to JSAMPLE units to get consistent distances; * after which, we
       scale according to the selected distance scale factors. */

    dist0 = ( ( c0max - c0min ) << C0_SHIFT ) * C0_SCALE;
    dist1 = ( ( c1max - c1min ) << C1_SHIFT ) * C1_SCALE;
    dist2 = ( ( c2max - c2min ) << C2_SHIFT ) * C2_SCALE;
    boxp->volume = dist0 * dist0 + dist1 * dist1 + dist2 * dist2;

    /* Now scan remaining volume of box and compute population */

    ccount = 0;
    for ( c0 = c0min; c0 <= c0max; c0++ )
        for ( c1 = c1min; c1 <= c1max; c1++ )
        {
            histp = &histogram[ c0 ][ c1 ][ c2min ];

            for ( c2 = c2min; c2 <= c2max; c2++, histp++ )
                if ( *histp != 0 )
            ccount++;
        }

    boxp->colorcount = ccount;
}


/***************************************
 * Find the splittable box with the largest color population
 * Returns NULL if no splittable boxes remain
 ***************************************/

static boxptr
find_biggest_color_pop( boxptr boxlist,
                        int    numboxes )
{
    boxptr boxp;
    int i;
    long maxc = 0;
    boxptr which = NULL;

    for ( i = 0, boxp = boxlist; i < numboxes; i++, boxp++ )
        if ( boxp->colorcount > maxc && boxp->volume > 0 )
        {
            which = boxp;
            maxc = boxp->colorcount;
        }

    return which;
}


/***************************************
 * Find the splittable box with the largest (scaled) volume
 * Returns NULL if no splittable boxes remain
 ***************************************/

static boxptr
find_biggest_volume( boxptr boxlist,
                     int    numboxes )
{
    boxptr boxp;
    int i;
    int maxv = 0;
    boxptr which = NULL;

    for ( i = 0, boxp = boxlist; i < numboxes; i++, boxp++ )
        if ( boxp->volume > maxv )
        {
            which = boxp;
            maxv = boxp->volume;
        }

    return which;
}


/***************************************
 * Repeatedly select and split the largest box until we have enough boxes
 ***************************************/

static int
median_cut( SPEC   * sp,
            boxptr   boxlist,
            int      numboxes,
            int      desired_colors )
{
    int n,
        lb;
    int c0,
        c1,
        c2,
        cmax;
    boxptr b1,
        b2;

    while ( numboxes < desired_colors )
    {
        /* Select box to split. * Current algorithm: by population for first
           half, then by volume. */

        if ( numboxes * 2 <= desired_colors )
            b1 = find_biggest_color_pop( boxlist, numboxes );
        else
            b1 = find_biggest_volume( boxlist, numboxes );

        if ( b1 == NULL )       /* no splittable boxes left! */
            break;

        b2 = &boxlist[ numboxes ];  /* where new box will go */

        /* Copy the color bounds to the new box. */

        b2->c0max = b1->c0max;
        b2->c1max = b1->c1max;
        b2->c2max = b1->c2max;
        b2->c0min = b1->c0min;
        b2->c1min = b1->c1min;
        b2->c2min = b1->c2min;

        /* Choose which axis to split the box on. * Current algorithm:
           longest scaled axis. * See notes in update_box about scaling
           distances. */

        c0 = ( ( b1->c0max - b1->c0min ) << C0_SHIFT ) * C0_SCALE;
        c1 = ( ( b1->c1max - b1->c1min ) << C1_SHIFT ) * C1_SCALE;
        c2 = ( ( b1->c2max - b1->c2min ) << C2_SHIFT ) * C2_SCALE;

        /* We want to break any ties in favor of green, then red, blue last.
         * This code does the right thing for R,G,B or B,G,R color orders
         only. */

#if RGB_RED == 0
        cmax = c1;
        n = 1;

        if ( c0 > cmax )
        {
            cmax = c0;
            n = 0;
        }

        if ( c2 > cmax )
            n = 2;
#else
        cmax = c1;
        n = 1;

        if ( c2 > cmax )
        {
            cmax = c2;
            n = 2;
        }

        if ( c0 > cmax )
        n = 0;
#endif

        /* Choose split point along selected axis, and update box bounds. *
           Current algorithm: split at halfway point. * (Since the box has
           been shrunk to minimum volume, * any split will produce two
           nonempty subboxes.) * Note that lb value is max for lower box, so
           must be < old max. */

        switch ( n )
        {
            case 0 :
                lb = ( b1->c0max + b1->c0min ) / 2;
                b1->c0max = lb;
                b2->c0min = lb + 1;
                break;

            case 1 :
                lb = ( b1->c1max + b1->c1min ) / 2;
                b1->c1max = lb;
                b2->c1min = lb + 1;
                break;

            case 2 :
                lb = ( b1->c2max + b1->c2min ) / 2;
                b1->c2max = lb;
                b2->c2min = lb + 1;
                break;
        }

        /* Update stats for boxes */

        update_box( sp, b1 );
        update_box( sp, b2 );
        numboxes++;
    }

    return numboxes;
}


/***************************************
 * Compute representative color for a box, put it in colormap[icolor]
 ***************************************/

static void
compute_color( SPEC   * sp,
               boxptr   boxp,
               int      icolor )
{
    /* Current algorithm: mean weighted by pixels (not colors) */
    /* Note it is important to get the rounding correct! */

    hist3d histogram = sp->histogram;
    histptr histp;
    int c0,
        c1,
        c2;
    int c0min,
        c0max,
        c1min,
        c1max,
        c2min, c2max;
    long count;
    long total = 0;
    long c0total = 0;
    long c1total = 0;
    long c2total = 0;

    c0min = boxp->c0min;
    c0max = boxp->c0max;
    c1min = boxp->c1min;
    c1max = boxp->c1max;
    c2min = boxp->c2min;
    c2max = boxp->c2max;

    for ( c0 = c0min; c0 <= c0max; c0++ )
        for ( c1 = c1min; c1 <= c1max; c1++ )
        {
            histp = &histogram[ c0][ c1 ][ c2min ];

            for ( c2 = c2min; c2 <= c2max; c2++ )
            {
                if ( ( count = *histp++ ) != 0 )
                {
                    total += count;
                    c0total += (   ( c0 << C0_SHIFT )
                                 + ( ( 1 << C0_SHIFT ) >> 1 ) ) * count;
                    c1total += (   ( c1 << C1_SHIFT )
                                 + ( ( 1 << C1_SHIFT ) >> 1 ) ) * count;
                    c2total += (   ( c2 << C2_SHIFT )
                                 + ( ( 1 << C2_SHIFT ) >> 1 ) ) * count;
                }
            }
        }

    sp->colormap[ 0 ][ icolor ] =
                          ( JSAMPLE ) ( ( c0total + ( total >> 1 ) ) / total );
    sp->colormap[ 1 ][ icolor ] =
                          ( JSAMPLE ) ( ( c1total + ( total >> 1 ) ) / total );
    sp->colormap[ 2 ][ icolor ] =
                          ( JSAMPLE ) ( ( c2total + ( total >> 1 ) ) / total );
}


/***************************************
 * Master routine for color selection
 ***************************************/

static void
select_colors( SPEC * sp,
               int    desired_colors )
{
    boxptr boxlist;
    int numboxes;
    int i;

    if ( sp->im )
        sp->im->visual_cue( sp->im, "Selecting Colors ..." );

    /* Allocate workspace for box list */

    boxlist = fl_malloc( desired_colors * sizeof( box ) );

    /* Initialize one box containing whole space */

    numboxes = 1;
    boxlist[ 0 ].c0min = 0;
    boxlist[ 0 ].c0max = MAXJSAMPLE >> C0_SHIFT;
    boxlist[ 0 ].c1min = 0;
    boxlist[ 0 ].c1max = MAXJSAMPLE >> C1_SHIFT;
    boxlist[ 0 ].c2min = 0;
    boxlist[ 0 ].c2max = MAXJSAMPLE >> C2_SHIFT;

    /* Shrink it to actually-used volume and set its statistics */

    update_box( sp, &boxlist[ 0 ] );

    /* Perform median-cut to produce final box list */

    numboxes = median_cut( sp, boxlist, numboxes, desired_colors );

    /* Compute the representative color for each box, fill colormap */

    for ( i = 0; i < numboxes; i++ )
        compute_color( sp, boxlist+ i, i );
    sp->actual_number_of_colors = numboxes;
    fl_free( boxlist );
}


/***************************************
 * get histogram
 ***************************************/

static void
prescan_quantize( SPEC           * sp,
                  unsigned char ** r,
                  unsigned char ** g,
                  unsigned char ** b,
                  int              width,
                  int              num_rows )
{
    histptr histp;
    hist3d histogram = sp->histogram;
    int row, col;

    if ( sp->im )
    {
        sp->im->completed = 0;
        sp->im->visual_cue( sp->im, "Getting Histogram ..." );
    }

    for ( row = 0; row < num_rows; row++ )
    {
        for ( col = width; --col >= 0; )
        {
            /* get pixel value and index into the histogram */

            histp = &histogram[ r[ row ][ col ] >> C0_SHIFT ]
                              [ g[ row ][ col ] >> C1_SHIFT ]
                              [ b[ row ][ col ] >> C2_SHIFT ];

            /* increment, check for overflow and undo increment if so. */

            if ( ++( *histp ) <= 0 )
                ( *histp )--;
        }
    }
}


/*
 * Initialize the error-limiting transfer function (lookup table).
 * The raw F-S error computation can potentially compute error values of up to
 * +- MAXJSAMPLE.  But we want the maximum correction applied to a pixel to be
 * much less, otherwise obviously wrong pixels will be created.  (Typical
 * effects include weird fringes at color-area boundaries, isolated bright
 * pixels in a dark area, etc.)  The standard advice for avoiding this problem
 * is to ensure that the "corners" of the color cube are allocated as output
 * colors; then repeated errors in the same direction cannot cause cascading
 * error buildup.  However, that only prevents the error from getting
 * completely out of hand; Aaron Giles reports that error limiting improves
 * the results even with corner colors allocated.
 * A simple clamping of the error values to about +- MAXJSAMPLE/8 works pretty
 * well, but the smoother transfer function used below is even better.  Thanks
 * to Aaron Giles for this idea.
 */

/***************************************
 * Allocate and fill in the error_limiter table
 ***************************************/

static void
init_error_limit( SPEC *sp )
{
    int *table;
    int in,
        out;

    table = fl_malloc( ( MAXJSAMPLE * 2 + 1 ) * sizeof( int ) );
    table += MAXJSAMPLE;    /* so can index -MAXJSAMPLE .. +MAXJSAMPLE */
    sp->error_limiter = table;

#define STEPSIZE ( ( MAXJSAMPLE+1 ) / 16 )

    /* Map errors 1:1 up to +- MAXJSAMPLE/16 */

    for ( out = in = 0; in < STEPSIZE; in++, out++ )
    {
        table[  in ] =  out;
        table[ -in ] = -out;
    }

    /* Map errors 1:2 up to +- 3*MAXJSAMPLE/16 */

    for ( ; in < STEPSIZE * 3; in++, out += ( in & 1 ) ? 0 : 1 )
    {
        table[  in ] =  out;
        table[ -in ] = -out;
    }

    /* Clamp the rest to final out value (which is (MAXJSAMPLE+1)/8) */

    for ( ; in <= MAXJSAMPLE; in++ )
    {
        table[  in ] =  out;
        table[ -in ] = -out;
    }
#undef STEPSIZE
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
