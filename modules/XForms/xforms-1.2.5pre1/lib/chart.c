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
 * \file chart.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao and Mark Overmars
 *  All rights reserved.
 *
 *  All chart objects. Absolutely needs prototypes for all
 *  drawing functions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include "include/forms.h"
#include "flinternal.h"

#ifndef M_PI
#define M_PI    3.14159265359
#endif

#define ARCINC  ( M_PI / 1800 )

#define MAX_CHART_LABEL_LEN  16

/* Object specific information */

typedef struct
{
    float    val;                          /* Value of the entry       */
    FL_COLOR col;                          /* Color of the entry       */
    FL_COLOR lcol;                         /* Label color of the entry */
    char     str[ MAX_CHART_LABEL_LEN ];   /* Label of the entry       */
} ENTRY;

typedef struct
{
    float      min,             /* the boundaries */
               max;
    int        numb;            /* number of entries */
    int        maxnumb;         /* maximal number of entries to display */
    int        autosize;        /* whether the x-axis should be scaled */
    int        lstyle,          /* item label font style & size */
               lsize;
    int        x,               /* drawing area */
               y,
               w,
               h;
    FL_COLOR   lcol;            /* default label color */
    ENTRY    * entries;         /* the entries */
    int        no_baseline;
} FLI_CHART_SPEC;


/***************************************
 * Draws a bar chart. x,y,w,h is the bounding box, entries the array of
 * numb entries and min and max the boundaries.
 ***************************************/

static void
draw_barchart( FL_OBJECT * ob,
               float       min,
               float       max )
{
    FLI_CHART_SPEC *sp = ob->spec;
    int x = sp->x,
        y = sp->y,
        w = sp->w,
        h = sp->h;
    int numb = sp->numb;
    int i,
        j,
        n;
    float bwidth;       /* Width of a bar */
    FL_Coord zeroh;     /* Height of zero value */
    FL_Coord val,
             xx,
             dx;
    float incr,         /* Increment per unit value */
          xfuzzy;
    float lh = fl_get_char_height( sp->lstyle, sp->lsize, &i, &j );
    ENTRY *e,
          *es,
          *entries = sp->entries;
    int lbox;
    float fx;

    incr = h / ( max - min );
    zeroh = y + h + min * incr;

    if ( -min * incr < lh )
    {
        incr = ( h - lh ) / max;
        zeroh = y + h - lh;
    }

    bwidth = ( double ) w / ( sp->autosize ? numb : sp->maxnumb );

    /* base line */

    if( ! sp->no_baseline )
        fl_line( x, zeroh + 0.5, x + w, zeroh + 0.5, ob->col2 );

    if ( min == 0.0 && max == 0.0 )
        return;         /* Nothing else to draw */

    /* Draw the bars */

    n = 1;
    if ( ( xfuzzy = bwidth - ( FL_Coord ) bwidth ) != 0.0 )
        n = 1.0 / xfuzzy + 2;

    for ( e = entries, xx = x, i = 0, es = e + numb; e < es; e++, i++ )
    {
        dx = bwidth + ( i % n ) * xfuzzy;
        if ( e->val != 0.0 )
        {
            val = e->val * incr;
            fl_rectbound( xx, zeroh - val, dx, val, e->col );
        }
        xx += dx;
    }

    /* Draw the labels */

    lbox = 0.8 * bwidth;

    for ( e = entries, es = e + numb, fx = x; e < es; fx += bwidth, e++ )
        fl_draw_text_beside( FL_ALIGN_BOTTOM, fx + 0.5 * ( bwidth - lbox ),
                             zeroh - lbox, lbox, lbox, e->lcol,
                             sp->lstyle, sp->lsize, e->str );
}


/***************************************
 * Draws a horizontal bar chart. x,y,w,h is the bounding box, entries the
 * array of numb entries and min and max the boundaries.
 ***************************************/

static void
draw_horbarchart( FL_OBJECT * ob,
                  float       min,
                  float       max )
{
    FLI_CHART_SPEC *sp = ob->spec;
    int x = sp->x,
        y = sp->y,
        w = sp->w,
        h = sp->h;
    int numb = sp->numb;
    float bwidth;       /* Width of a bar                       */
    float incr;         /* Increment per unit value             */
    FL_Coord lw,        /* Label width & Position of zero value */
             zeroh,
             dy,
             yy;
    int i,
        l,
        n;
    float yfuzzy;
    char *s;
    ENTRY *e,
          *entries = sp->entries;
    int lbox;

    /* Compute maximal label width */

    for ( lw = 0, i = 0; i < numb; i++ )
    {
        s = entries[ i ].str;
        l = fl_get_string_width( sp->lstyle, sp->lsize, s, strlen( s ) );
        if ( l > lw )
            lw = l;
    }

    if ( lw > 0.0 )
        lw = lw + 4.0;

    incr = ( float ) w / ( max - min );
    zeroh = x - min * incr + 0.1;

    if ( -min * incr < lw )
    {
        zeroh = x + lw;
        incr = ( w - lw ) / max;
    }

    bwidth = ( float ) h / ( sp->autosize ? numb : sp->maxnumb );

    /* Draw base line */

    if ( ! sp->no_baseline )
        fl_line( zeroh + 0.5, y, zeroh + 0.5, y + h, ob->col2 );

    if ( min == 0.0 && max == 0.0 )
        return;         /* Nothing else to draw */

    /* Draw the bars. Need to take care of round-off errors */

    yy = y;
    dy = bwidth;
    n = 2;
    if ( ( yfuzzy = bwidth - dy ) != 0 )
        n = 1.0 / yfuzzy + 2;

    for ( e = entries + numb - 1, i = 0; i < numb; i++, e-- )
    {
        dy = bwidth + ( i % n ) * yfuzzy;
        if ( e->val != 0.0 )
            fl_rectbound( zeroh, yy, e->val * incr, dy, e->col );
        yy += dy;
    }

    /* Draw the labels */

    lbox = 0.8 * bwidth;
    for ( e = entries + numb - 1, i = 0; i < numb; i++, e-- )
        fl_draw_text_beside( FL_ALIGN_LEFT, zeroh,
                             y + i * bwidth + 0.5 * ( bwidth - lbox ),
                             lbox, lbox, e->lcol, sp->lstyle,
                             sp->lsize, e->str );
}


/***************************************
 * Draws a line chart
 ***************************************/

static void
draw_linechart( FL_OBJECT * ob,
                float       min,
                float       max )
{
    FLI_CHART_SPEC *sp = ob->spec;
    int type = ob->type;
    int x = sp->x,
        y = sp->y,
        w = sp->w,
        h = sp->h;
    int i,
        numb = sp->numb;
    float ttt;
    float bwidth;       /* distance between points */
    float zeroh;        /* Height of zero value */
    float incr;         /* Increment per unit value */
    float lh = fl_get_char_height( sp->lstyle, sp->lsize, 0, 0 );
    ENTRY *e,
          *es,
          *entries = sp->entries;
    float xx,           /* tmp vars */
          val1,
          val2,
          val3;
    int lbox;

    incr = ( h - 2 * lh ) / ( max - min );
    zeroh = ( y + h ) - ( lh - min * incr );

    bwidth = ( float ) w / ( sp->autosize ? numb : sp->maxnumb );

    /* Draw the values */

    for ( i = 0; i < numb; i++ )
    {
        val3 = entries[ i ].val * incr;
        if ( type == FL_SPIKE_CHART )
        {
            val1 = ( i + 0.5 ) * bwidth;
            fli_reset_vertex( );
            fl_color( entries[ i ].col );
            fli_add_float_vertex( x + val1, zeroh );
            fli_add_float_vertex( x + val1, zeroh - val3 );
            fli_endline( );
        }
        else if ( type == FL_LINE_CHART && i != 0 )
        {
            e = entries + i - 1;
            fli_reset_vertex( );
            fl_color( e->col );
            fli_add_float_vertex( x + ( i - 0.5 ) * bwidth,
                                  zeroh - e->val * incr );
            fli_add_float_vertex( x + ( i + 0.5 ) * bwidth, zeroh - val3 );
            fli_endline( );
        }
        else if ( type == FL_FILLED_CHART && i != 0 )
        {
            e = entries + i - 1;
            val1 = ( i - 0.5 ) * bwidth;
            val2 = ( i + 0.5 ) * bwidth;

            fli_reset_vertex( );
            fl_color( e->col );
            fli_add_float_vertex( x + val1, zeroh );
            fli_add_float_vertex( x + val1, zeroh - e->val * incr );
            if (    ( e->val > 0.0 && entries[ i ].val < 0.0 )
                 || ( e->val < 0.0 && entries[ i ].val > 0.0 ) )
            {
                ttt = e->val / ( e->val - entries[ i ].val );
                fli_add_float_vertex( x + ( i - 0.5 + ttt ) * bwidth, zeroh );
                fli_add_float_vertex( x + ( i - 0.5 + ttt ) * bwidth, zeroh );
            }

            fli_add_float_vertex( x + val2, zeroh - val3 );
            fli_add_float_vertex( x + val2, zeroh );
            fli_endpolygon( );

            fli_reset_vertex( );
            fl_color( FL_BLACK );
            fli_add_float_vertex( x + val1, zeroh - e->val * incr );
            fli_add_float_vertex( x + val2, zeroh - val3 );
            fli_endline( );
        }
    }

    /* Draw base line */

    if ( ! sp->no_baseline )
        fl_line( x, zeroh + 0.5, x + w, zeroh + 0.5, ob->col2 );

    /* Draw the labels */

    lbox = 0.8 * bwidth;
    xx = x + 0.5 * ( bwidth - lbox );
    for ( e = entries, es = e + numb; e < es; e++, xx += bwidth )
    {
        if ( e->val < 0.0 )
            fl_draw_text_beside( FL_ALIGN_TOP, xx, zeroh - e->val * incr + 12,
                                 lbox, lbox, e->lcol, sp->lstyle,
                                 sp->lsize, e->str );
        else
            fl_draw_text_beside( FL_ALIGN_BOTTOM, xx,
                                 zeroh - e->val * incr - 12 - lbox,
                                 lbox, lbox, e->lcol, sp->lstyle,
                                 sp->lsize, e->str );
    }
}


/***************************************
 * Draws a pie chart. x,y,w,h is the bounding box, entries the array of
 * numb entries
 ***************************************/

static void
draw_piechart( FL_OBJECT * ob,
               int         special )
{
    FLI_CHART_SPEC *sp = ob->spec;
    int x = sp->x,
        y = sp->y,
        w = sp->w,
        h = sp->h;
    int i, numb = sp->numb;
    float xc,           /* center and radius */
          yc,
          rad;
    float tot;          /* sum of values */
    float incr;         /* increment in angle */
    float curang;       /* current angle we are drawing */
    float xl,           /* label position */
          yl;
    float txc,          /* temporary center */
          tyc;
    float lh = fl_get_char_height( sp->lstyle, sp->lsize, 0, 0 );
    int lbox;
    ENTRY *e,
          *entries = sp->entries;

    /* compute center and radius */

    xc = x + w / 2;
    yc = y + h / 2;
    rad = h / 2 - lh;

    if ( special )
    {
        yc += 0.1 * rad;
        rad = 0.9 * rad;
    }

    /* compute sum of values */

    for ( tot = 0.0f, i = 0; i < numb; i++ )
        if ( entries[ i ].val > 0.0 )
            tot += entries[ i ].val;

    if ( tot == 0.0 )
        return;

    incr = 3600.0 / tot;

    /* Draw the pie */

    curang = 0.0;
    for ( e = entries, i = 0; i < numb; i++, e++ )
        if ( e->val > 0.0 )
        {
            float tt = incr * e->val;

            txc = xc;
            tyc = yc;

            /* Correct for special pies */

            if ( special && i == 0 )
            {
                txc += 0.2 * rad * cos( ARCINC * ( curang + tt * 0.5 ) );
                tyc -= 0.2 * rad * sin( ARCINC * ( curang + tt * 0.5 ) );
            }

            tt += curang;
            fl_arcf( txc, tyc, rad, curang, tt, e->col );
            fl_arc( txc, tyc, rad, curang, tt, FL_BLACK );

            fli_reset_vertex( );
            fli_add_float_vertex( txc, tyc );
            fli_add_float_vertex( txc + rad * cos( ARCINC * curang ),
                                  tyc - rad * sin( ARCINC * curang ) );
            fli_endline( );

            curang += 0.5 * incr * e->val;
            lbox = 16;

            /* draw the label */

            xl = txc + 1.1 * rad * cos( ARCINC * curang );
            yl = tyc - 1.1 * rad * sin( ARCINC * curang );

            if ( xl < txc )
                fl_draw_text_beside( FL_ALIGN_LEFT, xl, yl - 0.5 * lbox,
                                     lbox, lbox, e->lcol, sp->lstyle,
                                     sp->lsize, e->str );
            else
                fl_draw_text_beside( FL_ALIGN_RIGHT, xl - lbox, yl - 0.5 * lbox,
                                     lbox, lbox, e->lcol, sp->lstyle,
                                     sp->lsize, e->str );

            curang += 0.5 * incr * e->val;
            fli_reset_vertex( );
            fli_add_float_vertex( txc, tyc );
            fli_add_float_vertex( txc + rad * cos( ARCINC * curang ),
                                  tyc - rad * sin( ARCINC * curang ) );
            fli_endline( );
        }
}


/***************************************
 * Draws a chart object
 ***************************************/

static void
draw_chart( FL_OBJECT * ob )
{
    FLI_CHART_SPEC *sp = ob->spec;
    FL_Coord absbw = FL_abs( ob->bw );
    float min = sp->min,
          max = sp->max;
    int i;

    /* Find bounding box */

    sp->x = ob->x + 3 + 2 * absbw;
    sp->y = ob->y + 3 + 2 * absbw;
    sp->w = ob->w - 6 - 4 * absbw;
    sp->h = ob->h - 6 - 4 * absbw;

    /* Find bounds */

    if ( min == max )
    {
        min = max = sp->numb ? sp->entries[ 0 ].val : 0.0;
        for ( i = 0; i < sp->numb; i++ )
        {
            if ( sp->entries[ i ].val < min )
                min = sp->entries[ i ].val;
            if ( sp->entries[ i ].val > max )
                max = sp->entries[ i ].val;
        }
    }

    /* min can equal to max if only one entry */

    if ( min == max )
    {
        min -= 1.0;
        max += 1.0;
    }

    /* Do the drawing */

    fl_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    if ( sp->numb == 0 )
    {
        fl_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                             ob->lcol, ob->lstyle, ob->lsize, ob->label );
        return;
    }

    fl_set_clipping( sp->x - 1, sp->y - 1, sp->w + 2, sp->h + 2 );

    switch ( ob->type )
    {
        case FL_BAR_CHART:
            draw_barchart( ob, min, max );
            break;

        case FL_HORBAR_CHART:
            draw_horbarchart( ob, min, max );
            break;

        case FL_PIE_CHART:
            draw_piechart( ob, 0 );
            break;

        case FL_SPECIALPIE_CHART:
            draw_piechart( ob, 1 );
            break;

        default:
            draw_linechart( ob, min, max );
            break;
    }

    fl_unset_clipping( );
}


/***************************************
 * Handles an event, returns whether value has changed
 ***************************************/

static int
handle_chart( FL_OBJECT * ob,
              int         event,
              FL_Coord    mx   FL_UNUSED_ARG,
              FL_Coord    my   FL_UNUSED_ARG,
              int         key  FL_UNUSED_ARG,
              void      * ev   FL_UNUSED_ARG )
{
#if FL_DEBUG >= ML_DEBUG
    M_info( "handle_chart", fli_event_name( event ) );
#endif

    switch ( event )
    {
        case FL_DRAW:
            draw_chart( ob );
            /* fall through */

        case FL_DRAWLABEL:
            fl_draw_object_label( ob );
            break;

        case FL_FREEMEM:
            if ( ( ( FLI_CHART_SPEC * ) ob->spec )->entries )
                fl_free( ( ( FLI_CHART_SPEC * ) ob->spec )->entries );
            fl_free( ob->spec );
            break;
    }

    return FL_RETURN_NONE;
}


/***************************************
 * creates a chart object
 ***************************************/

FL_OBJECT *
fl_create_chart( int          type,
                 FL_Coord     x,
                 FL_Coord     y,
                 FL_Coord     w,
                 FL_Coord     h,
                 const char * label )
{
    FL_OBJECT *obj;
    FLI_CHART_SPEC *sp;
    int i;

    obj = fl_make_object( FL_CHART, type, x, y, w, h, label, handle_chart );

    obj->boxtype = FL_CHART_BOXTYPE;
    obj->col1    = FL_CHART_COL1;
    obj->col2    = FL_BLACK;
    obj->align   = FL_CHART_ALIGN;
    obj->lcol    = FL_CHART_LCOL;
    obj->active  = 0;

    sp = obj->spec = fl_calloc( 1, sizeof *sp );

    sp->maxnumb = 512;
    sp->entries = fl_calloc( sp->maxnumb + 1, sizeof *sp->entries );
    for ( i = 0; i <= sp->maxnumb; i++ )
        sp->entries[ i ].val = 0.0;

    sp->autosize = 1;
    sp->min      = sp->max = 0.0;
    sp->lsize    = FL_TINY_SIZE;
    sp->lstyle   = FL_NORMAL_STYLE;
    sp->lcol     = FL_BLACK;

    return obj;
}


/***************************************
 * Adds a chart object
 ***************************************/

FL_OBJECT *
fl_add_chart( int          type,
              FL_Coord     x,
              FL_Coord     y,
              FL_Coord     w,
              FL_Coord     h,
              const char * label )
{
    FL_OBJECT *obj = fl_create_chart( type, x, y, w, h, label );

    fl_add_object( fl_current_form, obj );

    return obj;
}


/***************************************
 ***************************************/

void
fl_set_chart_lsize( FL_OBJECT * ob,
                    int         lsize )
{
    FLI_CHART_SPEC *sp = ob->spec;

    if ( sp->lsize != lsize )
    {
        sp->lsize = lsize;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_chart_lstyle( FL_OBJECT * ob,
                     int         lstyle )
{
    FLI_CHART_SPEC *sp = ob->spec;

    if ( sp->lstyle != lstyle )
    {
        sp->lstyle = lstyle;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_chart_lcolor( FL_OBJECT * ob,
                     FL_COLOR    lcol )
{
    FLI_CHART_SPEC *sp = ob->spec;

    if ( sp->lcol != lcol )
        sp->lcol = lcol;
}


/***************************************
 * Clears the contents of a chart
 ***************************************/

void
fl_clear_chart( FL_OBJECT * ob )
{
    ( ( FLI_CHART_SPEC * ) ob->spec )->numb = 0;
    fl_redraw_object( ob );
}


/***************************************
 * Add an item to the chart.
 ***************************************/

void
fl_add_chart_value( FL_OBJECT  * ob,
                    double       val,
                    const char * str,
                    FL_COLOR     col )
{
    FLI_CHART_SPEC *sp = ob->spec;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHART ) )
    {
        M_err( "fl_add_chart_value", "%s not a chart", ob ? ob->label : "" );
        return;
    }
#endif

    /* Shift entries if required */

    if ( sp->numb == sp->maxnumb )
    {
        int i;

        for ( i = 0; i < sp->numb - 1; i++ )
            sp->entries[ i ] = sp->entries[ i + 1 ];
        sp->numb--;
    }

    /* Fill in the new entry */

    sp->entries[ sp->numb ].val = val;
    sp->entries[ sp->numb ].col = col;
    sp->entries[ sp->numb ].lcol = sp->lcol;

    if ( str )
        fli_sstrcpy( sp->entries[sp->numb ].str, str, MAX_CHART_LABEL_LEN );
    else
        *sp->entries[sp->numb ].str = '\0';
    sp->numb++;

    fl_redraw_object( ob );
}


/***************************************
 * Inserts an item before indx to the chart.
 ***************************************/

void
fl_insert_chart_value( FL_OBJECT  * ob,
                       int          indx,
                       double       val,
                       const char * str,
                       FL_COLOR     col )
{
    FLI_CHART_SPEC *sp = ob->spec;
    int i;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHART ) )
    {
        M_err( "fl_insert_chart_value", "%s not a chart", ob ? ob->label : "" );
        return;
    }
#endif

    if ( indx < 1 || indx > sp->numb + 1 )
        return;

    /* Shift entries */

    for ( i = sp->numb; i >= indx; i-- )
        sp->entries[ i ] = sp->entries[ i - 1 ];

    if ( sp->numb < sp->maxnumb )
        sp->numb++;

    /* Fill in the new entry */

    sp->entries[ indx - 1 ].val = val;
    sp->entries[ indx - 1 ].col = col;

    if ( str != NULL )
        fli_sstrcpy( sp->entries[ indx - 1 ].str, str, MAX_CHART_LABEL_LEN );
    else
        *sp->entries[ indx - 1 ].str = '\0';

    fl_redraw_object( ob );
}


/***************************************
 * Replaces an item in the chart.
 ***************************************/

void
fl_replace_chart_value( FL_OBJECT  * ob,
                        int          indx,
                        double       val,
                        const char * str,
                        FL_COLOR     col )
{
    FLI_CHART_SPEC *sp = ob->spec;

    if ( indx < 1 || indx > sp->numb )
        return;

    sp->entries[ indx - 1 ].val = val;
    sp->entries[ indx - 1 ].col = col;

    if ( str )
        fli_sstrcpy( sp->entries[ indx - 1 ].str, str, MAX_CHART_LABEL_LEN );
    else
        *sp->entries[ indx - 1 ].str = '\0';

    fl_redraw_object( ob );
}


/***************************************
 * Sets the boundaries in the value for the object
 ***************************************/

void
fl_set_chart_bounds( FL_OBJECT * ob,
                     double      min,
                     double      max )
{
    FLI_CHART_SPEC *sp;

#if FL_DEBUG >= ML_ERR
    if ( ! IsValidClass( ob, FL_CHART ) )
    {
        M_err( "fl_set_chart_bounds", "%s not a chart", ob ? ob->label : "" );
        return;
    }
#endif

    sp = ob->spec;
    if ( sp->min != min || sp->max != max )
    {
        sp->min = min;
        sp->max = max;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_get_chart_bounds( FL_OBJECT * ob,
                     double    * min,
                     double    * max )
{
    FLI_CHART_SPEC *sp = ob->spec;

    *min = sp->min;
    *max = sp->max;
}


/***************************************
 * Sets the maximal number of values displayed in the chart
 ***************************************/

void
fl_set_chart_maxnumb( FL_OBJECT * ob,
                      int         maxnumb )
{
    FLI_CHART_SPEC *sp = ob->spec;
    int i, curmax;

    /* Fill in the new number */

    if ( maxnumb < 0 )
    {
        M_err( "fl_set_chart_maxnum", "Invalid maxnumb value" );
        return;
    }

    if ( maxnumb == sp->maxnumb )
        return;

    curmax = sp->maxnumb;

    if ( maxnumb > FL_CHART_MAX )
        sp->maxnumb = FL_CHART_MAX;
    else
        sp->maxnumb = maxnumb;

    if ( sp->maxnumb > curmax )
    {
        sp->entries = fl_realloc( sp->entries,
                                  ( sp->maxnumb + 1 ) * sizeof *sp->entries );
        for ( i = curmax; i <= sp->maxnumb; i++ )
            sp->entries[ i ].val = 0.0;
    }

   if ( ! sp->entries )
   {
       sp->maxnumb = curmax;
       sp->entries = fl_calloc( curmax + 1, sizeof *sp->entries );
       for ( i = 0; i <= curmax; i++ )
           sp->entries[ i ].val = 0.0;
       return;
   }

    /* Shift entries if required */

   if ( sp->numb > sp->maxnumb )
   {
       for ( i = 0; i < maxnumb; i++ )
           sp->entries[ i ] = sp->entries[ i + sp->numb - maxnumb ];
       sp->numb = sp->maxnumb;
       fl_redraw_object( ob );
    }
}


/***************************************
 * Sets whether the chart should autosize along the x-axis
 ***************************************/

void
fl_set_chart_autosize( FL_OBJECT * ob,
                       int         autosize )
{
    if ( ( ( FLI_CHART_SPEC * ) ob->spec )->autosize != autosize )
    {
        ( ( FLI_CHART_SPEC * ) ob->spec )->autosize = autosize;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

void
fl_set_chart_baseline( FL_OBJECT * ob,
                       int         iYesNo )
{
    if ( ( ( FLI_CHART_SPEC * ) ob->spec )->no_baseline != !iYesNo )
    {
        ( ( FLI_CHART_SPEC * ) ob->spec )->no_baseline = !iYesNo;
        fl_redraw_object( ob );
    }
}


/***************************************
 ***************************************/

#if 0
void
fl_get_chart_area( FL_OBJECT * ob,
                   int       * x,
                   int       * y,
                   int       * w,
                   int       * h )
{
    FLI_CHART_SPEC *sp = ob->spec;

    *x = sp->x;
    *y = sp->y;
    *w = sp->w;
    *h = sp->h;
}
#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
