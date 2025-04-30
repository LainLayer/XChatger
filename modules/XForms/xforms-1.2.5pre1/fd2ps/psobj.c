/*
 * This file is part of XForms.
 *
 * XForms is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or
 * (at your option) any later version.
 *
 * XForms is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with XForms. If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * \file psobj.c
 *
 *  This file is part of XForms package
 *  Copyright (c) 1997-2000  by T.C. Zhao
 *  All rights reserved.
 *
 *  Draw FL object in ps
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd2ps.h"
#include "flinternal.h"     /* for UPBOX8 etc */
#include <math.h>
#include <stdlib.h>

extern int fl_convert_shortcut(const char *str, long sc[]);
extern int fl_get_underline_pos(const char *label, const char *sc);

#ifndef M_PI
#define M_PI   3.14159265
#endif

static void ps_draw_object(FL_OBJECT * ob);

/***************************************
 * stuff that only need to be output once
 ***************************************/

static void
emit_prolog( void )
{
    static int emitted;

    if ( emitted )
        return;

    ps_verbatim( "%%!PS-Adobe-3.0%s\n", psinfo.eps ? " EPSF-2.0" : "" );
    ps_verbatim( "%%%%Creator: %s\n", get_version( ) );
    ps_verbatim( "%%%%CreateDate: %s\n", ascii_date( ) );
    ps_verbatim( "%%%%For: %s\n", whoami( ) );
    ps_verbatim( "%%%%Pages: %d\n", psinfo.pages );
    ps_verbatim( "%%%%Orientation: %s\n",
                 psinfo.landscape == 1 ? "Landscape" : "Portrait" );
    emitted = 1;
}


/***************************************
 * emit some basic macros
 ***************************************/

static void
emit_basic_defs( float xscale,
                 float yscale )
{
    static int emitted;

    if ( emitted )
        return;

    emitted = 1;

    ps_output( "/BD {bind def} def\n" );
    ps_output( "/M {moveto} bind def  /LT {lineto} BD\n" );
    ps_output( "/L {M LT}   bind def  /C  {closepath} BD\n" );
    ps_output( "/LW {setlinewidth} BD\n" );
    ps_output( "/S {stroke} BD /F {fill} BD\n" );
    ps_output( "/G {setgray} bind def /RGB {setrgbcolor} BD\n" );

    /* x y x y N */

    ps_output( "/P {3 1 roll M 2 exch 1 exch {pop LT} for C} BD\n" );
    ps_output( "/lines {3 1 roll M 2 exch 1 exch {pop LT} for S} BD\n" );
    ps_output( "/SX %.2g def /SY %.2g def\n", xscale, yscale );

#if 0
    if ( psinfo.epsf_import && ! psinfo.xpmtops_direct )
        emit_epsf_import_command( );
#endif

    ps_text_init( );
}


/***************************************
 * Since some of the internal coordinates defaults, such
 * as border width and line width, are expressed in pixels,
 * it is more convenient to work in pixel coordinates.
 * For point, mm units, we convert everything to a pseudo pixel
 * unit.
 *
 * psinfo.scale turns object coordinates into pseudo pixel unit
 * and xscale yscale turns pseudo pixel into point
 ***************************************/

void
get_scale_unit( int     unit,
                float * xscale,
                float * yscale )
{
    if ( unit == FL_COORD_PIXEL )
    {
        *xscale = 72.0 / psinfo.xdpi;
        *yscale = 72.0 / psinfo.ydpi;
        psinfo.xscale = psinfo.yscale = 1.0;
    }
    else if ( unit == FL_COORD_centiPOINT )
    {
        *xscale = *yscale = 0.8;              /* pixel size in point */
        psinfo.xscale = psinfo.yscale = 0.01 / *xscale;
    }
    else if ( unit == FL_COORD_POINT )
    {
        *xscale = *yscale = 0.8;              /* pixel size in point */
        psinfo.xscale = psinfo.yscale = 1     / *xscale;
    }
    else if ( unit == FL_COORD_centiMM )
    {
        *xscale = *yscale = 0.8;              /* pixel size in point */
        psinfo.xscale = psinfo.yscale = 0.01 * 72 / 25.4 / *xscale;
    }
    else
        fprintf( stderr, "Unknown coordinate unit\n" );
}


#define P2CM( n )  ( n / 72.0 * 2.45 )

/***************************************
 ***************************************/

static void
auto_orientation( float pw,
                  float ph,
                  float obw,
                  float obh )
{
    int plm, pbm, llm, lbm;

    plm = ( pw - obw ) / 2;
    pbm = ( ph - obh ) / 2;
    llm = ( pw - obh ) / 2;
    lbm = ( ph - obw ) / 2;

    /* Switch to landscape only if portrait won't fit */

    flps->landscape =    FL_abs( lbm - llm ) < FL_abs( pbm - plm )
                      && ( pbm < 0 || plm < 0 );
}


/***************************************
 ***************************************/

static void
ps_bgn_form( int          w,
             int          h,
             const char * label )
{
    float pw = psinfo.paper_w * 72,
          ph = psinfo.paper_h * 72;
    float fw, fh;
    float xscale, yscale;
    float bxi, byi, bxf, byf;   /* bounding box */
    float margin = 0.4 * 72;    /* about 1cm  */

    if ( ! label )
        label = "annonymous";

    get_scale_unit( psinfo.unit, &xscale, &yscale );

    /* Figure out bounding box. Note bounding box is always expressed in
       points */

    fw = w * psinfo.xscale * xscale;
    fh = h * psinfo.yscale * yscale;

    if ( psinfo.landscape == -1 )
        auto_orientation( pw - 2.0 * margin, ph - 2.0 * margin, fw, fh );

    emit_prolog( );

    if ( psinfo.landscape )
    {
        bxi = ( pw - fh ) * 0.5;
        byi = ( ph - fw ) * 0.5;
        bxf = bxi + fh + 0.5;
        byf = byi + fw + 0.5;
    }
    else
    {
        bxi = ( pw - fw ) * 0.5;
        byi = ( ph - fh ) * 0.5;
        bxf = bxi + fw + 0.5;
        byf = byi + fh + 0.5;
    }

    if ( bxi < -15.0 )
        fprintf( stderr, "Warning: %s %.2f cm too wide\n",
                 label, -P2CM( bxi ) );
    if ( bxi < -15.0 )
        fprintf( stderr, "Warning: %s %.2f cm too long\n",
                 label, -P2CM( byi ) );

    if ( psinfo.page == 1 )
    {
        ps_verbatim( "%%%%BoundingBox: %d %d %d %d\n",
                     ( int ) bxi, ( int ) byi, ( int ) bxf, ( int ) byf );
        ps_verbatim( "%%%%EndComments\n" );
        ps_verbatim( "%% paper name/size: %s (%gx%gin) ",
                     psinfo.paper_name ? psinfo.paper_name : "unknown",
                     psinfo.paper_w, psinfo.paper_h );
        ps_verbatim( " BW=%d DPI=%.1f \n",
                     psinfo.bw, psinfo.xdpi );
    }

    emit_basic_defs( xscale, yscale );

    ps_verbatim( "\n%%%%Page: %s %d\n",
                 ( label && *label ) ? label : "anonymous", psinfo.page );
    ps_verbatim( "%%%%PageBoundingBox: %d %d %d %d\n",
                 ( int ) bxi, ( int ) byi, ( int ) bxf, ( int ) byf );

    ps_verbatim( "\ngsave %%{\n" );
    ps_output( "%.1f %.1f translate  ", bxi, byi );
    if ( psinfo.landscape )
        ps_output( "%d 0 translate 90 rotate\n", ( int ) fh );

    /* Thinner lines look better */

    ps_output( "%.2f %.2f LW\n", 0.6, 0.6 );
    ps_output( "SX SY scale  " );
}


/***************************************
 * Since ob->{x,y,w,h} are int special care needs to be taken
 * to avoid numerical inaccuracies
 ***************************************/

static void
scale_object( FL_OBJECT * ob )
{
    int xi, yi, xf, yf;
    float delta = 0.4;

    if ( psinfo.xscale == 1.0 && psinfo.yscale == 1.0 )
        return;

    xi = ob->x * psinfo.xscale + delta;
    xf = ( ob->x + ob->w ) * psinfo.xscale + delta;
    ob->w = xf - xi;
    ob->x = xi;

    yi = ob->y * psinfo.yscale + delta;
    yf = ( ob->y + ob->h ) * psinfo.yscale + delta;
    ob->h = yf - yi;
    ob->y = yi;
}


/***************************************
 ***************************************/

static void
ps_end_form( void )
{
    ps_verbatim( "grestore %% }\n%s", psinfo.eps ? "" : "showpage\n\n" );
    ps_invalidate_color_cache( );
    ps_invalidate_font_cache( );
}


#include <ctype.h>

#define ALT_CHAR      '#'
#define CNTL_CHAR     '^'
#define FKEY_CHAR     '&'


/***************************************
 ***************************************/

int
fl_convert_shortcut(const char * str,
                    long       * sc )
{
    int i, j, offset, key;

    /* str might be obj->shortcut */

    i = j = offset = 0;

    while ( str[ i ] != '\0' )
    {
        if ( str[ i ] == ALT_CHAR )
            offset = FL_ALT_MASK;
        else if ( str[ i ] == CNTL_CHAR )
        {
            i++;
            if ( str[ i ] >= 'A' && str[ i ] <= 'Z' )
                sc[ j++ ] = str[ i ] - 'A' + 1 + offset;
            else if ( str[ i ] >= 'a' && str[ i ] <= 'z' )
                sc[ j++ ] = str[ i ] - 'a' + 1 + offset;
            else if ( str[ i ] == '[' )
                sc[ j++ ] = 27 + offset;
            else
                sc[ j++ ] = str[ i ] + offset;
            offset = 0;
        }
        else if ( str[ i ] == FKEY_CHAR )   /* special characters */
        {
            i++;
            if ( str[ i ] == FKEY_CHAR )
                sc[ j++ ] = FKEY_CHAR + offset;
            else if ( str[ i ] == 'A' )
                sc[ j++ ] = offset + XK_Up;
            else if ( str[ i ] == 'B' )
                sc[ j++ ] = offset + XK_Down;
            else if ( str[ i ] == 'C' )
                sc[ j++ ] = offset + XK_Right;
            else if ( str[ i ] == 'D' )
                sc[ j++ ] = offset + XK_Left;
            else if (    isdigit( ( unsigned char ) str[ i ] )
                      && ( key = atoi( str + i ) ) < 35 )
            {
                i += key >= 10;
                sc[ j++ ] = offset + XK_F1 + key - 1;
            }
            offset = 0;
        }
        else
        {
            sc[ j++ ] = str[ i ] + offset;
            offset = 0;
        }
        i++;
    }

    sc[ j ] = 0;

    return j;
}


static void
ps_draw_object_label( FL_OBJECT * ob )
{
    int align = fl_to_outside_lalign( ob->align );

    ( align != ob->align ? ps_draw_text : ps_draw_text_beside )
        ( align, ob->x, ob->y, ob->w, ob->h, ob->lcol,
          ob->lstyle, ob->lsize, ob->label );
}


/***************************************
 ***************************************/

static void
ps_draw_object_label_beside( FL_OBJECT * ob )
{
    ps_draw_text_beside( ob->align, ob->x, ob->y, ob->w, ob->h,
                         ob->lcol, ob->lstyle, ob->lsize, ob->label );
}


/***************************************
 ***************************************/

int
fl_get_underline_pos( const char * label,
                      const char * sc )
{
    int c;
    const char *p;

    /* Find the first non-special char in shortcut str */

    for ( c = 0, p = sc; ! c && *p; p++ )
    {
        if ( isalnum( ( unsigned char ) *p ) )
        {
            if ( p == sc )
                c = *p;
            else if (    *( p - 1 ) != FKEY_CHAR
                      && ! isdigit( ( unsigned char ) *( p - 1 ) ) )
                c = *p;
        }
    }

    if ( ! c )
        return -1;

    /* Find where the matches occur */

    if ( c == sc[ 0 ] )
        p = strchr( label, c );
    else if ( ! ( p = strchr( label, c ) ) )
        p = strchr( label, islower( c ) ? toupper( c ) : tolower( c ) );

    if ( ! p )
        return -1;

    return ( p - label ) + 1;
}


/***************************************
 ***************************************/

void
flps_set_object_shortcut( FL_OBJECT  * obj,
                          const char * sstr,
                          int          showit )
{
    long sc[ 16 ];
    int scsize, n;

    if ( obj == NULL )
    {
        fprintf( stderr, "fl_set_object_shortcut:Object is NULL\n" );
        return;
    }

    if ( ! sstr || ! *sstr )
        return;

    n = fl_convert_shortcut( sstr, sc );

    scsize = ( n + 1 ) * sizeof *obj->shortcut;
    obj->shortcut = realloc( obj->shortcut, scsize );
    memcpy( obj->shortcut, sc, scsize );

    if ( ! showit || ! obj->label || ! *obj->label || *obj->label == '@' )
        return;

    if (    ( n = fl_get_underline_pos( obj->label, sstr ) ) > 0
         && ! strchr( obj->label, *ul_magic_char ) )
    {
        char *q = obj->label;

        obj->label = malloc( strlen( q ) + 2 );
        strncpy( obj->label, q, n );
        obj->label[ n ] = *ul_magic_char;
        strcpy( obj->label + n + 1, q + n );
        free( q );
    }
}


#define ISUPBOX  FL_IS_UPBOX
#define DOWNBOX  FL_TO_DOWNBOX


/***************************************
 ***************************************/

static void
flps_draw_button( FL_OBJECT * ob )
{
    FL_COLOR col = ( ( SPEC * ) ob->spec )->int_val ? ob->col2 : ob->col1;
    FL_Coord dh, dw, ww, absbw = FL_abs( ob->bw );
    float off2 = 0.0;

    if ( ob->type == FL_HIDDEN_BUTTON )
        return;

    if ( ISUPBOX( ob->boxtype ) && ( ( SPEC * ) ob->spec )->int_val != 0 )
        ps_draw_box( DOWNBOX( ob->boxtype ), ob->x, ob->y, ob->w, ob->h, col,
                     ob->bw );
    else
        ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, col, ob->bw );

    dh = 0.6 * ob->h;
    dw = FL_min( 0.6 * ob->w, dh );

    ww = 0.75 * ob->h;
    if ( ww < dw + FL_abs( ob->bw ) + 1 + ( ob->bw > 0 ) )
        ww = dw + FL_abs( ob->bw ) + 1 + ( ob->bw > 0 );

    if ( ob->type == FL_RETURN_BUTTON )
    {
        ps_draw_text( 0, ob->x + ob->w - ww, ob->y + 0.2 * ob->h,
                      dw, dh, ob->lcol, 0, 0, "@returnarrow" );
        off2 = dw - 2;
    }

    if ( ob->type == FL_MENU_BUTTON && ob->boxtype == FL_UP_BOX )
    {
        dh = FL_max( 6 + ( ob->bw > 0 ), ob->h * 0.1 );
        dw = FL_max( 0.11 * ob->w, 13 );

        ps_draw_box( FL_UP_BOX,
                     ob->x + ob->w - dw - absbw - 2,
                     ob->y + ( ob->h - dh ) / 2,
                     dw, dh, ob->col1, -2 );
        off2 = dw - 1;
    }

    ob->w -= off2;
    ps_draw_object_label( ob );
    ob->w += off2;
}


/***************************************
 ***************************************/

static void
flps_draw_labelbutton( FL_OBJECT * ob )
{
    FL_COLOR save_col = ob->lcol;
    FL_Coord dh,
             dw,
             ww,
             absbw = FL_abs(ob->bw);

    ob->lcol = ( ( SPEC * ) ob->spec )->int_val ? ob->col2 : ob->lcol;

    dh = 0.6 * ob->h;
    dw = FL_min( 0.6 * ob->w, dh );
    ww = 0.75 * ob->h;

    if ( ww < dw + absbw + 1 + ( ob->bw > 0 ) )
        ww = dw + absbw + 1 + ( ob->bw > 0 );

    if ( ob->type == FL_RETURN_BUTTON )
        ps_draw_text( 0, ob->x + ob->w - ww, ob->y + 0.2 * ob->h,
                      dw, dh, ob->lcol, 0, 0, "@returnarrow" );

    ps_draw_object_label( ob );
    ob->lcol = save_col;
}


#define NEAR 600.0f
#define GRID 0.18


/***************************************
 ***************************************/

static void
flps_draw_thumbwheel( FL_OBJECT * ob )
{
    float absbw = FL_abs( ob->bw ),
          h2 = ob->h * 0.5,
          w2 = ob->w * 0.5;
    float x0 = ob->x + ob->w / 2,
          yo = ob->y + ob->h / 2;
    float x, y, w, h, dx, dy;
    double junk;
    float theta;
    float arc = M_PI * 0.49, delta = GRID;
    float offset = 0.0;
    FL_COLOR c1, c2;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );
    x = ob->x + absbw;
    y = ob->y + absbw;
    w = ob->w - 2 * absbw;
    h = ob->h - 2 * absbw;

    if ( ob->type == FL_VERT_THUMBWHEEL )
    {
        float extra = h2 * ( NEAR / ( NEAR - h2 ) - 0.96 );

        /* (fake) depth-cue */

        ps_rectf( x, y + 1, w, h - 1, FL_DARKER_COL1 );
        ps_rectf( x, yo - ob->h / 4.0, w, ob->h / 2.0, FL_COL1 );
        ps_rectf( x, yo - ob->h / 10.0, w, ob->h / 5.0, FL_LIGHTER_COL1 );

        for ( theta = arc + modf( offset / delta, &junk );
              theta > - arc; theta -= delta )
        {
            dy = ( h2 + extra ) * sin( theta );
            dx = ob->h - ( h2 + extra ) * cos( theta );
            y = yo + FL_nint( dy * NEAR / ( NEAR + dx ) );

            if ( y > ob->y + 3 && y < ob->y + ob->h - 3 )
            {
                int d = 1;
                if ( y < yo + h2 / 4 && y > yo - h2 / 4 )
                {
                    c1 = FL_LEFT_BCOL;
                    c2 = FL_RIGHT_BCOL;
                }
                else if ( y < ob->y + h2 / 5 || y > yo + h2 - h2 / 5 )
                {
                    c1 = FL_LIGHTER_COL1;
                    c2 = FL_BOTTOM_BCOL;
                    d = 0;
                }
                else
                {
                    c1 = FL_MCOL;
                    c2 = FL_BOTTOM_BCOL;
                }
                ps_line( x + 1, y - 1, x + w - 2, y - 1, c2 );
                ps_line( x + 1, y + d, x + w - 2, y + d, c1 );
            }
        }

        /* bottom */

        y = ob->y + absbw;
        ps_rectf( x - 1, ob->y + ob->h - 6, w, 3, FL_RIGHT_BCOL );

        /* top */

        ps_rectf( x - 1, y, w, 3, FL_RIGHT_BCOL );

        /* left */

        ps_line( x - 1, y, x - 1, y + h - 1, FL_BLACK );

        /* right */

        ps_rectf( x + w - 1, y, 2, h, FL_RIGHT_BCOL );

        /* highlight */

        ps_line( x + 1, yo - h2 + 10, x + 1, yo + h2 - 10, FL_LEFT_BCOL );
    }
    else
    {
        float extra = w2 * ( NEAR / ( NEAR - w2 ) - 0.96 );

        ps_rectf( x, y, w, h, FL_DARKER_COL1 );
        ps_rectf( x0 - w / 4, y, w / 2, h, FL_COL1 );
        dx = ob->w / 10;
        ps_rectf( x0 - dx, y, 2 * dx, h, FL_LIGHTER_COL1 );

        for ( theta = arc + modf(offset / delta, &junk );
              theta > - arc; theta -= delta)
        {
            dx = ( w2 + extra ) * sin( theta );
            dy = ob->w - ( w2 + extra ) * cos( theta );
            x = x0 + FL_nint( dx * NEAR / ( NEAR + dy ) );

            if ( x > ob->x + absbw + 1 && x < x0 + w2 - absbw - 2 )
            {
                int d = 1;

                if ( x < x0 + w2 / 4 && x > x0 - w2 / 4 )
                {
                    c1 = FL_LEFT_BCOL;
                    c2 = FL_RIGHT_BCOL;
                }
                else if ( x < ob->x + ( w2 / 4 ) || x > x0 + w2 - ( w2 / 4 ) )
                {
                    c1 = FL_LIGHTER_COL1;
                    c2 = FL_BOTTOM_BCOL;
                }
                else
                {
                    c1 = FL_MCOL;
                    c2 = FL_BOTTOM_BCOL;
                }

                ps_line( x - 1, y + 2, x - 1, yo + h2 - 2 * absbw, c1 );
                ps_line( x + d, y + 2, x + d, yo + h2 - 2 * absbw, c2 );
            }

            x = ob->x + absbw;
            w = ob->w - 2 * absbw;

            /* top shadow */

            ps_line( x, y - 1, x + w - 2, y - 1, FL_BLACK );
            ps_line( x, y, x + w - 4, y, FL_BLACK );

            /* bottom shadow */

            ps_line( x + 5, y + h - 2, x + w - 4, y + h - 2, FL_BLACK );
            ps_line( x, y + h - 1, x + w - 2, y + h - 1, FL_BLACK );
            ps_line( x, y + h, x + w - 2, y + h, FL_BLACK );

            /* left & right */

            ps_rectf( x, y - 1, 3, h + 1, FL_RIGHT_BCOL );
            ps_rectf( x + w - 4, y - 1, 3, h + 1, FL_RIGHT_BCOL );

            /* hight light */

            ps_line( x + 4, y + h - 2, x + w - 4, y + h - 2, FL_DARKER_COL1 );
            ps_line( x0 - w2 + 11, y + h - 2, x0 + w2 - 11, y + h - 2,
                     FL_TOP_BCOL );
        }
    }

    ps_draw_object_label( ob );
}


/***************************************
 ***************************************/

static void
flps_draw_lightbutton( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;
    float ww, hh, xx, yy, libox;
    float absbw = FL_abs( ob->bw ),
          bw2;
    long lightcol = sp->int_val > 0 ? ob->col2 : ob->col1;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    if ( ob->boxtype == FL_NO_BOX || ob->boxtype == FL_FLAT_BOX )
        absbw = FL_BOUND_WIDTH;

    if ( absbw < 3 )
        absbw = 3;

    /* Calculate and draw the light */

    hh = ob->h - 3 * absbw - 1;
    if ( hh < FL_LIGHTBUTTON_MINSIZE )
        hh = FL_LIGHTBUTTON_MINSIZE;
    ww = hh / 2;
    if ( ww < FL_LIGHTBUTTON_MINSIZE )
        ww = FL_LIGHTBUTTON_MINSIZE;
    if ( ww > ob->w / 6 )
        ww = ob->w / 6;

    xx = ob->x + 1.5 * absbw + 1.0;
    yy = ob->y + ob->h / 2 - hh / 2;

    absbw = FL_abs( ob->bw );

    /* Adjustment for non-rectangular boxes */

    if (    ob->boxtype == FL_ROUNDED3D_UPBOX
         || ob->boxtype == FL_ROUNDED3D_DOWNBOX )
    {
        hh -= 2;
        yy += 1;
        xx += 3 + ob->w * 0.01;
        ww -= 1;
    }
    else if ( ob->boxtype == FL_RSHADOW_BOX )
    {
        hh -= 1;
        xx += 1;
    }

    switch ( ob->boxtype )
    {
        case FL_UP_BOX:
        case FL_ROUNDED3D_UPBOX:
            libox = FL_DOWN_BOX;
            break;

        case FL_DOWN_BOX:
        case FL_ROUNDED3D_DOWNBOX:
            libox = FL_DOWN_BOX;
            break;

        case FL_FRAME_BOX:
        case FL_EMBOSSED_BOX:
        case FL_ROUNDED_BOX:
            libox = ob->boxtype;
            break;

        case FL_RFLAT_BOX:
        case FL_RSHADOW_BOX:
            libox = FL_ROUNDED_BOX;
            break;

        default:
            libox = FL_BORDER_BOX;
            break;
    }

    bw2 = absbw > 2 ? absbw - 1 : absbw;
    ps_draw_box( libox, xx, yy, ww, hh, lightcol, bw2 );

    /* Draw the label */

    if ( fl_is_center_lalign( ob->align ) )
        ps_draw_text( FL_ALIGN_LEFT, xx + ww, ob->y, 0, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        ps_draw_object_label( ob );

    ww = 0.75 * ob->h;
    if ( ww < absbw + 1 )
        ww = absbw + 1;

    if ( ob->type == FL_RETURN_BUTTON )
        ps_draw_text( 0, ob->x + ob->w - ww, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h,
                      ob->lcol, 0, 0, "@returnarrow" );
}


/***************************************
 ***************************************/

static void
flps_draw_roundbutton( FL_OBJECT * ob )
{
    float xx, yy, rr;
    float bw = FL_abs( ob->bw );

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h,
                 FL_ROUNDBUTTON_TOPCOL, ob->bw );

    rr = 0.3 * FL_min( ob->w, ob->h );
    rr = rr + 0.5;
    xx = ob->x + 1.5 * ( bw < 2 ? 2 : bw ) + rr + 1;
    yy = ob->y + ob->h / 2;

    ps_circ( 1, xx, yy, rr, ob->col1 );
    ps_circ( 0, xx, yy, rr, FL_BLACK );

    ps_circ( 1, xx, yy, rr, ob->col2 );
    ps_circ( 0, xx, yy, rr, FL_BLACK );

    if ( fl_is_center_lalign( ob->align ) )
        ps_draw_text( FL_ALIGN_LEFT, xx + rr + 1, ob->y, 0, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        ps_draw_object_label_beside( ob );

    if ( ob->type == FL_RETURN_BUTTON )
        ps_draw_text( 0, ob->x + ob->w - 0.8 * ob->h, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h,
                      ob->lcol, 0, 0, "@returnarrow" );
}


static void
flps_draw_scrollbutton( FL_OBJECT * ob )
{
    char *label = ob->label;
    int x = ob->x,
        y = ob->y,
        w = ob->w,
        h = ob->h;
    int absbw = FL_abs( ob->bw );
    int extra = absbw;
    int btype = FL_NO_BOX;
    SPEC *sp = ob->spec;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    if ( *label == '#' )
    {
        w = h = FL_min( ob->w, ob->h );
        x += ( ob->w - w ) / 2;
        y += (ob->h - h) / 2;
        label++;
    }

    if ( ob->boxtype != FL_NO_BOX && ob->boxtype != FL_FLAT_BOX )
    {
        extra += 1 + 0.051 * FL_min( w, h );
        absbw = 1;
    }

    if ( *label == '8' )
        btype = sp->int_val ? FLI_TRIANGLE_DOWNBOX8 : FLI_TRIANGLE_UPBOX8;
    else if ( *label == '2' )
        btype = sp->int_val ? FLI_TRIANGLE_DOWNBOX2 : FLI_TRIANGLE_UPBOX2;
    else if ( *label == '6' )
        btype = sp->int_val ? FLI_TRIANGLE_DOWNBOX6 : FLI_TRIANGLE_UPBOX6;
    else if ( *label == '4' )
        btype = sp->int_val ? FLI_TRIANGLE_DOWNBOX4 : FLI_TRIANGLE_UPBOX4;

    ps_draw_tbox( btype, x + extra, y + extra, w - 2 * extra, h - 2 * extra,
                  ob->col2, absbw );
}


/***************************************
 ***************************************/

static void
flps_draw_round3dbutton( FL_OBJECT * ob )
{
    float xx, yy, rr, cr;
    float bw = FL_abs( psinfo.bw );
    ALLSPEC *sp = ob->spec;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h,
                 FL_ROUND3DBUTTON_TOPCOL, ob->bw );

    rr = 0.3 * FL_min( ob->h, ob->w );
    xx = ob->x + 1.5 * ( bw < 2 ? 2 : bw ) + rr + 1;
    yy = ob->y + 0.5 * ob->h;

    if ( rr < bw * 0.5 )
        rr = bw / 2 + 1;

    ps_set_linewidth( bw, bw );

    cr = bw / 2;
    ps_arc( 0, xx, yy, rr - cr, 450, 2250, FL_BOTTOM_BCOL );
    ps_arc( 0, xx, yy, rr - cr, 0, 450, FL_TOP_BCOL );
    ps_arc( 0, xx, yy, rr - cr, 2250, 3600, FL_TOP_BCOL );

    ps_reset_linewidth( );

    if ( sp->int_val )
    {
        if ( ( cr = 0.8 * rr - 1.0 - bw * 0.5 ) < 1 )
            cr = 1;
        ps_circ( 1, xx, yy, cr, ob->col2 );
    }
    else
        ps_circ( 1, xx, yy, rr - bw, ob->col1 );

    if ( fl_is_center_lalign( ob->align ) )
        ps_draw_text( FL_ALIGN_LEFT, xx + rr + 1, ob->y, 0, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        ps_draw_object_label_beside( ob );

    if ( ob->type == FL_RETURN_BUTTON )
        ps_draw_text( 0, ob->x + ob->w - 0.8 * ob->h, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h,
                      ob->lcol, 0, 0, "@returnarrow" );
}


/***************************************
 ***************************************/

static void
flps_draw_checkbutton( FL_OBJECT * ob )
{
    float xx,
          yy,
          ww,
          hh,
          bw = FL_abs( ob->bw );
    SPEC *sp = ob->spec;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    ww = hh = 0.6 * FL_min( ob->w, ob->h );
    xx = ob->x + 1.5 * ( bw < 2 ? 2 : bw)  + 1.5;
    yy = ob->y + ( ob->h - hh ) / 2;

    if ( sp->int_val != 0.0 )
        ps_draw_checkbox( FL_DOWN_BOX, xx, yy, ww, hh, ob->col2, bw );
    else
        ps_draw_checkbox( FL_UP_BOX, xx, yy, ww, hh, ob->col1, bw );

    if ( fl_is_center_lalign( ob->align ) )
        ps_draw_text( FL_ALIGN_LEFT, xx + ww + 1, ob->y, 0, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, ob->label );
    else
        ps_draw_object_label_beside( ob );

    if ( ob->type == FL_RETURN_BUTTON )
        ps_draw_text( 0, ob->x + ob->w - 0.8 * ob->h, ob->y + 0.2 * ob->h,
                      0.6 * ob->h, 0.6 * ob->h,
                      ob->lcol, 0, 0, "@returnarrow" );
}


/***************************************
 ***************************************/

static void
flps_draw_pixmap( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;

    if ( FL_IS_UPBOX( ob->boxtype ) && sp->int_val != 0 )
        ps_draw_box( FL_TO_DOWNBOX(ob->boxtype), ob->x, ob->y,
                     ob->w, ob->h, ob->col1, ob->bw );
    else
        ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h,
                     ob->col1, ob->bw );

    if ( sp->file )
    {
        if ( ob->objclass == FL_BITMAP || ob->objclass == FL_BITMAPBUTTON )
            draw_bitmap( sp->file, ob->x, ob->y, ob->w, ob->h, ob->lcol,
                         ob->col1 );
        else
            draw_xpm( ob );
    }

    ps_draw_object_label( ob );
}


/*
 * Dial support
 */

static float xori, yori;

#define ROTx( x, y, a )  \
    ( xori + ( ( x ) - xori ) * cos( a ) + ( ( y ) - yori ) * sin( a ) )
#define ROTy( x, y, a )  \
    ( yori + ( ( x ) - xori ) * sin( a ) + ( ( y ) - yori ) * cos( a ) )


/***************************************
 ***************************************/

static void
rotate_it( Point * xp,
           float   x,
           float   y,
           float   a )
{
    xp->x = ROTx( x, y, a );
    xp->y = ROTy( x, y, a );
}


/***************************************
 ***************************************/

static void
flps_draw_dial( FL_OBJECT * ob )
{
    float x, y, w, h, radius;
    float dangle;
    SPEC *sp = ob->spec;
    Point xp[ 6 ];
    int boxtype, iradius;

    /* Get mapping  */

    sp->ax = ( sp->max - sp->min ) / ( sp->thetaf - sp->thetai );
    sp->bx = sp->max - sp->ax * sp->thetaf;

    dangle = ( sp->val - sp->bx ) / sp->ax;

    if ( sp->direction == FL_DIAL_CW )
        dangle = sp->origin - dangle;
    else
        dangle += sp->origin;

    if ( ( dangle = fmod( dangle, 360.0 ) ) < 0.0 )
        dangle += 360.0;

    w = ob->w - 3;
    h = ob->h - 3;

    x = xori = ob->x + ob->w / 2;
    y = yori = ob->y + ob->h / 2;

    if ( FL_IS_UPBOX( ob->boxtype ) )
        boxtype = FL_OVAL3D_UPBOX;
    else if ( FL_IS_DOWNBOX( ob->boxtype ) )
        boxtype = FL_OVAL3D_DOWNBOX;
    else if ( ob->boxtype == FL_FRAME_BOX )
        boxtype = FL_OVAL3D_FRAMEBOX;
    else if ( ob->boxtype == FL_EMBOSSED_BOX )
        boxtype = FL_OVAL3D_EMBOSSEDBOX;
    else
        boxtype = FL_OVAL_BOX;

    /* The dial itself */

    radius = 0.5 * FL_min(w, h);
    iradius = radius - 1;

    ps_draw_box( boxtype, x - radius, y - radius, 2 * radius, 2 * radius,
                 ob->col1, ob->bw );

    dangle *= M_PI / 180.0;

    /* The "hand" */

    if ( ob->type == FL_NORMAL_DIAL )
    {
        float r;

#if 0
        float xc = x + iradius - r - 2, yc = y;
        rotate_it( xp, xc, yc, dangle );

        if ( ( r = = FL_nint( 0.1 * radius ) ) < 1 )
            r = 1;
        ps_circ( 1, xp[ 0 ].x, xp[ 0 ].y, r, ob->col2 );
        ps_circ( 0, xp[ 0 ].x, xp[ 0 ].y, r, FL_BLACK );
#else
        r = 0.5 * iradius;
        r = FL_min( 15, r );
        rotate_it( xp,     x + iradius - 1,     y - 1.5, dangle );
        rotate_it( xp + 1, x + iradius - 1 - r, y - 1.5, dangle );
        rotate_it( xp + 2, x + iradius - 1 - r, y + 1.5, dangle );
        rotate_it( xp + 3, x + iradius - 1,     y + 1.5, dangle );
        ps_poly( 1, xp, 4, ob->col2 );
#endif
    }
    else if ( ob->type == FL_LINE_DIAL )
    {
        float dx = 0.1 + 0.08 * iradius,
              dy = 0.1 + 0.08 * iradius;

        rotate_it( xp, x, y, dangle );
        rotate_it( xp + 1, x + dx,            y - dy, dangle );
        rotate_it( xp + 2, x + iradius - 1.5, y,      dangle );
        rotate_it( xp + 3, x + dx,            y + dy, dangle );

        ps_poly( 1, xp, 4, ob->col2 );
        ps_poly( 0, xp, 4, FL_BLACK );
    }
    else if ( ob->type == FL_FILL_DIAL )
    {
        float ti, delta;

        delta = ( sp->val - sp->bx ) / sp->ax;
        delta = FL_abs( sp->thetai - delta );
        iradius -= boxtype != FL_OVAL_BOX;

        if ( sp->direction == FL_DIAL_CCW )
            ti = sp->thetai + sp->origin;
        else
            ti = sp->origin - sp->thetai;

        if ( ( ti = fmod( ti, 360.0 ) ) < 0.0 )
            ti += 360.0;

        /* Have to break the drawing into two parts if cross 0 */

        if ( sp->direction == FL_DIAL_CCW )
        {
            if ( delta > 360 - ti )
            {
                ps_pieslice( 1, xori - iradius, yori - iradius,
                             2 * iradius, 2 * iradius,
                             ti * 10, 3600, ob->col2 );
                ps_pieslice( 1, xori - iradius, yori - iradius,
                             2 * iradius, 2 * iradius,
                             0, ( delta - 360 + ti ) * 10, ob->col2 );
            }
            else
                ps_pieslice( 1, xori - iradius, yori - iradius, 2 * iradius,
                             2 * iradius, ti * 10, ( ti + delta ) * 10,
                             ob->col2 );
        }
        else
        {
            if ( delta > ti )
            {
                ps_pieslice( 1, xori - iradius, yori - iradius,
                             2 * iradius, 2 * iradius, 0, ti * 10, ob->col2 );
                ps_pieslice( 1, xori - iradius, yori - iradius,
                             2 * iradius, 2 * iradius,
                             3600 - ( delta - ti ) * 10, 3600, ob->col2 );
            }
            else
                ps_pieslice( 1, xori - iradius, yori - iradius, 2 * iradius,
                             2 * iradius, ( ti - delta ) * 10, ti * 10,
                             ob->col2);
        }

        rotate_it( xp,     xori + iradius - 1, yori, dangle );
        rotate_it( xp + 1, xori + iradius - 1, yori, ti * M_PI / 180.0 );
        ps_line( xori, yori, xp[ 0 ].x, xp[ 0 ].y, FL_BLACK );
        ps_line( xori, yori, xp[ 1 ].x, xp[ 1 ].y, FL_BLACK );
        if ( boxtype == FL_OVAL_BOX )
            ps_circ( 0, x, y, iradius, FL_BLACK );
    }
    else
        fprintf( stderr, "Unknown/unsupported dial type %d\n", ob->type );

    ps_draw_object_label_beside( ob );
}


/***************************************
 ***************************************/

static void
flps_draw_text( FL_OBJECT * ob )
{
    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );
    ps_draw_object_label( ob );
}


static void
flps_draw_box( FL_OBJECT * ob )
{
    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1,
                 psinfo.bw );
    ps_draw_object_label_beside( ob );
}


/***************************************
 ***************************************/

static void
flps_draw_choice( FL_OBJECT * ob )
{
    float off1 = 0, off2 = 0;
    SPEC *sp = ob->spec;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );


    if ( ob->type == FL_NORMAL_CHOICE2 )
    {
        int absbw = FL_abs( ob->bw );
        int dh = FL_max( 6 + ( ob->bw > 1 ), ob->h * 0.1 );
        int dw = FL_max( 0.11 * ob->w, 13 );
        int dbh = FL_max( absbw - 1.2, 1 );
        int align = fl_to_outside_lalign( sp->align );

        ps_draw_box( FL_UP_BOX, ob->x + ob->w - dw - absbw - 2,
                     ob->y + ( ob->h - dh ) / 2, dw, dh, ob->col1, -dbh );
        off1 = align == FL_ALIGN_CENTER ? ( dw / 2 ) :
            ( align == FL_ALIGN_LEFT ? - FL_abs( ob->bw ) : 0 );
        off2 = align == FL_ALIGN_RIGHT ? dw + 1 : 0;
    }

    ps_draw_object_label_beside( ob );

    /* Draw the choice string */

    if ( sp->int_val > 0 && sp->lines >= sp->int_val )
    {
        char *str = sp->content[ sp->int_val ];

        ps_draw_text( sp->align, ob->x - off1, ob->y,
                      ob->w - off2, ob->h, ob->col2,
                      sp->fontstyle, sp->fontsize,
                      str + ( str && ( *str == '\010' ) ) );
    }
}


static void
flps_draw_counter( FL_OBJECT * ob )
{
    int i, btype[ 5 ];
    float xx[ 5 ] = { 0.0, 0.0, 0.0, 0.0, 0.0 },
          ww[ 5 ] = { 0.0, 0.0, 0.0, 0.0, 0.0 };
    char str[ 30 ];
    SPEC *sp = ob->spec;

    for ( i = 0; i < 5; i++ )
        btype[ i ] = ob->boxtype;

    if ( btype[ 4 ] == FL_UP_BOX )
        btype[ 4 ] = FL_DOWN_BOX;

    /* Compute sizes */

    if ( ob->type == FL_NORMAL_COUNTER )
    {
        /* button is numbered 01 4 23 */

        ww[ 0 ] = ww[ 1 ] = ww[ 2 ] = ww[ 3 ] = FL_min( 0.16 * ob->w, ob->h );
        ww[ 4 ] = ob->w - 4 * ww[ 0 ];  /* must calculate this way */
        xx[ 0 ] = ob->x;
        xx[ 1 ] = xx[ 0 ] + ww[ 0 ];
        xx[ 4 ] = xx[ 1 ] + ww[ 1 ];
        xx[ 2 ] = xx[ 4 ] + ww[ 4 ];
        xx[ 3 ] = xx[ 2 ] + ww[ 2 ];
    }
    else
    {
        /* 1  4  2 */

        ww[ 1 ] = ww[ 2 ] = FL_min( 0.20 * ob->w, ob->h );
        ww[ 4 ] = ob->w - 2 * ww[ 1 ];
        xx[ 1 ] = ob->x;
        xx[ 4 ] = ob->x + ww[ 1 ];
        xx[ 2 ] = xx[ 4 ] + ww[ 4 ];
    }

    /* Create value string */

    sprintf( str, "%.*f", sp->prec, sp->val );

    /* Draw the thing */

    if ( ob->type == FL_NORMAL_COUNTER )
    {
        ps_draw_box( btype[ 0 ], xx[ 0 ], ob->y, ww[ 0 ], ob->h,
                     ob->col1, ob->bw );
        ps_draw_text( FL_ALIGN_CENTER, xx[ 0 ], ob->y, ww[ 0 ], ob->h, ob->col2,
                      0.0, 0, "@<<" );
    }

    ps_draw_box( btype[ 1 ], xx[ 1 ], ob->y, ww[ 1 ], ob->h, ob->col1, ob->bw );
    ps_draw_text( FL_ALIGN_CENTER, xx[ 1 ], ob->y, ww[ 1 ], ob->h, ob->col2,
                  0.0, 0, "@<" );
    ps_draw_box( btype[ 4 ], xx[ 4 ], ob->y, ww[ 4 ], ob->h, ob->col1, ob->bw );
    ps_draw_text( FL_ALIGN_CENTER, xx[ 4 ], ob->y, ww[ 4 ], ob->h,
                  ob->lcol, ob->lstyle, ob->lsize, str );
    ps_draw_box( btype[ 2 ], xx[ 2 ], ob->y, ww[ 2 ], ob->h, ob->col1, ob->bw );
    ps_draw_text( FL_ALIGN_CENTER, xx[ 2 ], ob->y, ww[ 2 ], ob->h, ob->col2,
                  0.0, 0, "@>" );

    if ( ob->type == FL_NORMAL_COUNTER )
    {
        ps_draw_box( btype[ 3 ], xx[ 3 ], ob->y, ww[ 3 ], ob->h,
                     ob->col1, ob->bw );
        ps_draw_text( FL_ALIGN_CENTER, xx[ 3 ], ob->y, ww[ 3 ], ob->h, ob->col2,
                      0.0, 0, "@>>" );
    }

    ps_draw_object_label_beside( ob );
}



/***************************************
 * Performs linear interpolation
 ***************************************/

static float
flinear( float val,
         float smin,
         float smax,
         float gmin,
         float gmax )
{
    if ( smin == smax )
        return gmax;
    else
        return gmin + ( gmax - gmin ) * ( val - smin ) / ( smax - smin );
}


#define is_horiz( t ) (    t == FL_HOR_SLIDER            \
                        || t == FL_HOR_FILL_SLIDER       \
                        || t == FL_HOR_NICE_SLIDER       \
                        || t == FL_HOR_BROWSER_SLIDER    \
                        || t == FL_HOR_BROWSER_SLIDER2   \
                        || t == FL_HOR_THIN_SLIDER       \
                        || t == FL_HOR_BASIC_SLIDER )

#define is_vert( t )  (    t == FL_VERT_SLIDER           \
                        || t == FL_VERT_FILL_SLIDER      \
                        || t == FL_VERT_NICE_SLIDER      \
                        || t == FL_VERT_BROWSER_SLIDER   \
                        || t == FL_VERT_BROWSER_SLIDER2  \
                        || t == FL_VERT_THIN_SLIDER      \
                        || t == FL_VERT_BASIC_SLIDER )

/* Minimum knob size */

#define MINKNOB_SB    18    /* for scrollbars on browser */
#define MINKNOB_SL     6    /* for regular sliders       */

/* Sliders that must have certain minimum value for the knob */

#define SLIDER_MIN( t ) (    t == FL_HOR_BROWSER_SLIDER    \
                          || t == FL_HOR_BROWSER_SLIDER2   \
                          || t == FL_VERT_BROWSER_SLIDER   \
                          || t == FL_VERT_BROWSER_SLIDER2 )

/***************************************
 ***************************************/

static void
ps_drw_slider_shape( int          boxtype,
                     float        x,
                     float        y,
                     float        w,
                     float        h,
                     long         col1,
                     long         col2,
                     int          sltype,
                     float        size,
                     float        val,
                     const char * str,
                     int          inv,
                     float        bw )
{
    float slx, sly, slw, slh;
    int slbox = boxtype, slbw = bw;
    float absbw = FL_abs( bw );

    if ( sltype == FL_VERT_FILL_SLIDER )
    {
        slh = ( inv ? ( 1 - val ) : val ) * ( h - 2 * absbw );
        sly = inv ? y + h - absbw - slh : y + absbw;
        slw = w - 2 * absbw;
        slx = x + absbw;
    }
    else if ( sltype == FL_HOR_FILL_SLIDER )
    {
        slw = val * ( w - 2 * absbw );
        slx = x + absbw;
        slh = h - 2 * absbw;
        sly = y + absbw;
    }
    else if ( is_vert( sltype ) )
    {
        slh = size * ( h - 2 * absbw );

        if ( SLIDER_MIN( sltype ) && slh < MINKNOB_SB )
            slh = MINKNOB_SB;
        else if ( slh < 2 * absbw + MINKNOB_SL )
            slh = 2 * absbw + MINKNOB_SL;

        if ( sltype == FL_VERT_BROWSER_SLIDER2 )
        {
            slh = size * h;
            sly = flinear( val, 1.0, 0.0, y, y + h - slh );
            slx = x + 1;
            slw = w - 2;
        }
        else if (    sltype == FL_VERT_THIN_SLIDER
                  || sltype == FL_VERT_BASIC_SLIDER )
        {
            slh = size * h;
            sly = flinear( val, 0.0, 1.0, y, y + h - slh );
            slx = x + absbw - 0.5;
            slw = w - 2 * absbw + 0.5;
        }
        else
        {
            if ( inv )
                sly = flinear( val, 1.0, 0.0, y + absbw, y + h - absbw - slh );
            else
                sly = flinear( val, 0.0, 1.0, y + absbw, y + h - absbw - slh );

            slw = w - 2 * absbw;
            slx = x + absbw;
        }
    }
    else if ( is_horiz( sltype ) )
    {
        slw = size * ( w - 2 * absbw );

        if ( SLIDER_MIN( sltype ) && slw < MINKNOB_SB )
            slw = MINKNOB_SB;
        else if ( slw < 2 * absbw + MINKNOB_SL )
            slw = 2 * absbw + MINKNOB_SL;

        if ( sltype == FL_HOR_BROWSER_SLIDER2 )
        {
            slw = size * w;
            slx = flinear( val, 0.0, 1.0, x, x + w - slw );
            slh = h - 2;
            sly = y + 1;
        }
        else if (    sltype == FL_HOR_THIN_SLIDER
                  || sltype == FL_HOR_BASIC_SLIDER )
        {
            slw = size * w;
            slx = flinear( val, 0.0, 1.0, x, x + w - slw );
            sly = y + absbw + 0.5;
            slh = h - 2 * absbw + 0.5;
        }
        else
        {
            slx = flinear( val, 0.0, 1.0, x + absbw, x + w - absbw - slw );
            slh = h - 2 * absbw;
            sly = y + absbw;
        }
    }
    else
    {
        fprintf( stderr, "Unknown slider type %d\n", sltype );
        return;
    }

    /* Start drawing */

    slbox = boxtype;
    slbw = bw;

    if (    sltype == FL_VERT_BROWSER_SLIDER2
         || sltype == FL_HOR_BROWSER_SLIDER2 )
        slbw = bw > 0 ? 1 : -1;

    if (    sltype != FL_HOR_THIN_SLIDER
         && sltype != FL_VERT_THIN_SLIDER
         && sltype != FL_HOR_BASIC_SLIDER
         && sltype != FL_VERT_BASIC_SLIDER )
        ps_draw_box( slbox, x, y, w, h, col1, slbw );

    if ( sltype == FL_VERT_NICE_SLIDER )
    {
        int xoff = absbw - 0.01;

        ps_draw_box( FL_FLAT_BOX, x + w / 2.0 - 2.0, y + absbw,
                     4.0, h - 2.0 * absbw, FL_BLACK, 0 );
        ps_draw_box( FL_UP_BOX, slx, sly, slw, slh, col1, bw );
        ps_draw_box( FL_DOWN_BOX, slx + xoff, sly + slh / 2.0 - 2.2,
                     slw - 2 * xoff, 5.5, col2, 1.1 );
    }
    else if ( sltype == FL_HOR_NICE_SLIDER )
    {
        int yoff = absbw - 0.4;

        ps_draw_box( FL_FLAT_BOX, x + absbw, y + h / 2 - 2,
                     w - 2 * absbw, 4.0, FL_BLACK, 0.0 );
        ps_draw_box( FL_UP_BOX, slx, sly, slw, slh, col1, bw );
        ps_draw_box( FL_DOWN_BOX, slx + slw / 2.0 - 2, sly + yoff,
                     5, slh - 2 * yoff, col2, 1.1 );
    }
    else
    {
        int absbw2,
            bw2;

        switch ( boxtype )
        {
            case FL_UP_BOX:
                slbox = FL_UP_BOX;
                break;

            case FL_DOWN_BOX:
                slbox = FL_UP_BOX;
                break;

            case FL_FRAME_BOX:
            case FL_EMBOSSED_BOX:
            case FL_ROUNDED_BOX:
                slbox = boxtype;
                break;

            case FL_RFLAT_BOX:
                slbox = FL_ROUNDED_BOX;
                break;

            case FL_RSHADOW_BOX:
                slbox = FL_ROUNDED_BOX;
                break;

            default:
                slbox = FL_FRAME_BOX;
                break;
        }

        absbw2 = absbw >= 2 ? absbw - 1 : absbw - ( bw < 0 );
        bw2 = bw > 0 ? absbw2 : - absbw2;

        ps_draw_box( slbox, slx, sly, slw, slh, col2, bw2 );

        if (    sltype == FL_VERT_BROWSER_SLIDER
             || sltype == FL_VERT_BROWSER_SLIDER2
             || sltype == FL_VERT_THIN_SLIDER )
        {
            int extra = ( bw2 < 0 );

            ps_draw_text( FL_ALIGN_CENTER,
                          slx - extra, sly, slw + 2 * extra, slh, 0,
                          FL_TINY_FONT, FL_NORMAL_STYLE, "@RippleLines" );
        }
        else if (    sltype == FL_HOR_BROWSER_SLIDER
                  || sltype == FL_HOR_BROWSER_SLIDER2
                  || sltype == FL_HOR_THIN_SLIDER )
            ps_draw_text( FL_ALIGN_CENTER, slx - 1, sly - 1, slw, slh + 2, 0,
                          FL_TINY_FONT, FL_NORMAL_STYLE, "@2RippleLines" );
    }

    /* Draw the label */

    ps_draw_text( FL_ALIGN_CENTER, slx, sly, slw, slh, 0, FL_NORMAL_STYLE,
                  FL_SMALL_FONT, str );
}


#define VAL_BOXW  FL_max( 35, 0.18 * ob->w )
#define VAL_BOXH  25


/***************************************
 ***************************************/

static void
flps_draw_slider( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;
    char valstr[ 32 ];
    float bx = ob->x,
          by = ob->y,
          bw = ob->w,
          bh = ob->h;   /* value box */
    float sx = ob->x,
          sy = ob->y,
          sw = ob->w,
          sh = ob->h;   /* slider  */
    float val;
    int inv;

    /* Draw the value box */

    if ( ob->objclass == FL_VALSLIDER )
    {
        if ( is_vert( ob->type ) )
        {
            bh = VAL_BOXH;
            by = ob->y + ob->h - 1 - bh;
            sh -= bh;;
        }
        else
        {
            bw = VAL_BOXW;
            sx += bw;
            sw -= bw;
        }

        sprintf( valstr, "%.*f", sp->prec, sp->val );
        ps_draw_box( ob->boxtype, bx, by, bw, bh, ob->col1, ob->bw );
        ps_draw_text_beside( FL_ALIGN_CENTER, bx, by, bw, bh,
                             ob->lcol, ob->lstyle, ob->lsize, valstr );
    }

    if ( sp->min == sp->max )
        val = 0.5;
    else
        val = ( sp->val - sp->min ) / ( sp->max - sp->min );

    inv = sp->min < sp->max;

    /* Draw the slider */

    if ( fl_is_center_lalign( ob->align ) )
        ps_drw_slider_shape( ob->boxtype, sx, sy, sw, sh, ob->col1, ob->col2,
                             ob->type, sp->slsize, val, ob->label, inv,
                             ob->bw );
    else
    {
        ps_drw_slider_shape( ob->boxtype, sx, sy, sw, sh, ob->col1, ob->col2,
                             ob->type, sp->slsize, val, "", inv, ob->bw );
        ps_draw_object_label_beside( ob );
    }
}


/*
 * SCROLL BAR
 */

#define is_hor_scrollbar( t ) (    t == FL_HOR_SCROLLBAR        \
                                || t == FL_HOR_THIN_SCROLLBAR   \
                                || t == FL_HOR_NICE_SCROLLBAR   \
                                || t == FL_HOR_BASIC_SCROLLBAR)


/***************************************
 ***************************************/

static void
get_geom( FL_OBJECT * parent,
          FL_OBJECT * up,
          FL_OBJECT * slider,
          FL_OBJECT * down )
{
    int x = parent->x,
        y = parent->y,
        w = parent->w,
        h = parent->h;
    int absbw = FL_abs( parent->bw );

    if ( is_hor_scrollbar( parent->type ) )
    {
        down->x = x;
        up->x = x + w - h;
        up->y = down->y = y;
        down->w = down->h = up->w = up->h = h;

        slider->x = x + h;
        slider->y = y;
        slider->w = w - 2 * h;
        slider->h = h;
    }
    else
    {
        up->x = down->x = x;
        up->y = y + h - w;
        down->y = y;
        up->w = up->h = down->w = down->h = w;

        slider->x = x;
        slider->y = y + w;
        slider->w = w;
        slider->h = h - 2 * w;
    }

    up->col1 = down->col1 = slider->col1 = parent->col1;
    up->col2 = down->col2 = slider->col2 = parent->col2;

    up->bw = down->bw = slider->bw = parent->bw;

    if ( absbw > 2 )
        absbw--;

    if ( parent->bw > 0 )
        up->bw = down->bw = absbw;
    else
        up->bw = down->bw = -absbw;

    slider->boxtype = parent->boxtype;

    if (    parent->type == FL_HOR_THIN_SCROLLBAR
         || parent->type == FL_VERT_THIN_SCROLLBAR
         || parent->type == FL_HOR_BASIC_SCROLLBAR
         || parent->type == FL_VERT_BASIC_SCROLLBAR )
    {
        up->boxtype = down->boxtype = FL_NO_BOX;
        if (    parent->type == FL_VERT_THIN_SCROLLBAR
             || parent->type == FL_VERT_BASIC_SCROLLBAR )
        {
            slider->y += absbw - 1;
            slider->h += 2 * (absbw - 1);
        }
        else
        {
            slider->x -= absbw - 1;
            slider->w += 2 * ( absbw - 1 );
        }
    }
    else
        up->boxtype = down->boxtype = parent->boxtype;
}


/***************************************
 ***************************************/

static void
flps_draw_scrollbar( FL_OBJECT * ob )
{
    FL_OBJECT *sld, *up, *down;
    int sltype;

    if (    ob->type == FL_HOR_THIN_SCROLLBAR
         || ob->type == FL_VERT_THIN_SCROLLBAR
         || ob->type == FL_HOR_BASIC_SCROLLBAR
         || ob->type == FL_VERT_BASIC_SCROLLBAR )
        ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h,
                     ob->col1, ob->bw );

    switch ( ob->type )
    {
        case FL_HOR_SCROLLBAR:
            sltype = FL_HOR_BROWSER_SLIDER2;
            break;

        case FL_VERT_SCROLLBAR:
            sltype = FL_VERT_BROWSER_SLIDER2;
            break;

        case FL_HOR_THIN_SCROLLBAR:
            sltype = FL_HOR_THIN_SLIDER;
            break;

        case FL_VERT_THIN_SCROLLBAR:
            sltype = FL_VERT_THIN_SLIDER;
            break;

        case FL_HOR_BASIC_SCROLLBAR:
            sltype = FL_HOR_BASIC_SLIDER;
            break;

        case FL_VERT_BASIC_SCROLLBAR:
            sltype = FL_VERT_BASIC_SLIDER;
            break;

        case FL_HOR_NICE_SCROLLBAR:
            sltype = FL_HOR_NICE_SLIDER;
            break;

        case FL_VERT_NICE_SCROLLBAR:
            sltype = FL_VERT_NICE_SLIDER;
            break;

        default:
            fprintf( stderr, "Unknown scrollbar type: %d\n", ob->type );
            sltype = FL_HOR_BROWSER_SLIDER2;
            break;
    }

    if ( is_hor_scrollbar( ob->type ) )
    {
        up = flps_make_object( FL_SCROLLBUTTON, FL_TOUCH_BUTTON, 1, 1, 1, 1,
                               "6", 0 );
        down = flps_make_object( FL_SCROLLBUTTON, FL_TOUCH_BUTTON, 1, 1, 1, 1,
                                 "4", 0 );
        sld = flps_make_object( FL_SLIDER, sltype, 1, 1, 1, 1,
                                "", 0 );
    }
    else
    {
        up = flps_make_object( FL_SCROLLBUTTON, FL_TOUCH_BUTTON, 1, 1, 1, 1,
                               "8", 0 );
        down = flps_make_object( FL_SCROLLBUTTON, FL_TOUCH_BUTTON, 1, 1, 1, 1,
                                 "2", 0 );
        sld = flps_make_object( FL_SLIDER, sltype, 1, 1, 1, 1,
                                "", 0 );
    }

    get_geom( ob, up, sld, down );

    sld->spec = ob->spec;

    ps_draw_object( up );
    ps_draw_object( sld );
    ps_draw_object( down );

    ps_draw_object_label_beside( ob );
}


/***************************************
 ***************************************/

static void
flps_draw_frame( FL_OBJECT * ob )
{
    ps_draw_frame( ob->type, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );
    ps_draw_object_label( ob );
}


/* In addition to computing the string length, it enlarges the
 * bounding box and leaves a copy of the string on the stack
 */

static void
ps_len( const char * s,
        int          style,
        int          size)
{
    ps_set_font( style, size );   /* this sets flfont height */
    ps_output( "(%s) dup stringwidth pop /w exch 6 add def\n", s );
    ps_output( "/h {H 2 add} bind def\n" );
}


/***************************************
 ***************************************/

static void
ps_boxf( long col )
{
    ps_color( col );
    ps_output( "x y " );                          /* (x,y) */
    ps_output( "x y h 1 sub add\n" );             /* (x, y+h - 1) */
    ps_output( "x w 1 sub add y h 1 sub add " );  /* (x+w-1, y+h-1) */
    ps_output( "x w 1 sub add y 4 P F\n" );       /* (x+w-1,y) */
}


/***************************************
 ***************************************/

static void
flps_draw_lframe( FL_OBJECT * ob )
{
    int align, margin, dy = 0;
    int est;

    ps_draw_frame( ob->type, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    if ( ob->type == FL_UP_FRAME || ob->type == FL_DOWN_FRAME )
        dy = ( FL_abs( ob->bw ) + 1 ) / 2;

    align = fl_to_outside_lalign( ob->align );

    margin = 11 + ob->w * 0.02;
    if ( ob->type == FL_ROUNDED_FRAME )
        margin += 7;

    est = strlen( ob->label ) * ob->lsize;

    /* Turn into pixels */

    est *= psinfo.xdpi / 75.0;

    if ( ob->w - est < 2 * margin )
        margin /= 2;

    if ( ob->w - est < 2 * margin )
        margin /= 2;

    ps_len( ob->label, ob->lstyle, ob->lsize );

    switch( align )
    {
        case FL_ALIGN_LEFT_BOTTOM :
            ps_output( "/x {%d %d add} bind def\n", ob->x, margin );
            ps_output( "/y {%d h -2 div add %d sub} bind def\n", ob->y, dy );
            break;

        case FL_ALIGN_BOTTOM :
            ps_output( "/x {%d %d w sub 2 div add} bind def\n", ob->x, ob->w );
            ps_output( "/y {%d h -2 div add %d sub} bind def\n", ob->y, dy );
            break;

        case FL_ALIGN_RIGHT_BOTTOM :
            ps_output( "/x {%d %d add w sub %d sub} bind def\n",
                       ob->x, ob->w, margin );
            ps_output( "/y {%d h -2 div add %d sub} bind def\n", ob->y, dy );
            break;

        case FL_ALIGN_TOP :
            ps_output( "/x {%d %d w sub 2 div add} bind def\n", ob->x, ob->w );
            ps_output( "/y {%d %d add h -2 div add %d add} bind def\n",
                       ob->y, ob->h, dy );
            break;

        case FL_ALIGN_RIGHT_TOP :
        case FL_ALIGN_RIGHT :
            ps_output( "/x {%d %d add w sub %d sub} bind def\n",
                       ob->x, ob->w, margin );
            ps_output( "/y {%d %d add h -2 div add %d add} bind def\n",
                       ob->y, ob->h, dy );
            break;

        default :
            ps_output( "/x {%d %d add} bind def\n", ob->x, margin );
            ps_output( "/y {%d %d add h -2 div add %d add} bind def\n",
                       ob->y, ob->h, dy );
            break;
    }

    ps_boxf( ob->col2 );
    ps_color( ob->lcol );
    ps_output( "x w 2 div add y h 2 div add -0.3 h mul add M Cshow\n" );
}


/***************************************
 ***************************************/

static void
flps_draw_positioner( FL_OBJECT * ob )
{
    ALLSPEC *sp = ob->spec;
    float absbw = FL_abs( ob->bw );
    float xo = ob->x + absbw + 1,
          yo = ob->y + absbw + 1;
    float w1 = ob->w - 2 * ( absbw + 1 ),
          h1 = ob->h - 2 * ( absbw + 1 );
    float xx, yy;

    if ( ob->type != FL_OVERLAY_POSITIONER )
        ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h,
                     ob->col1, ob->bw );

    ps_draw_object_label( ob );

    xx = flinear( sp->xval, sp->xmin, sp->xmax, xo, xo + w1 - 1.0 );
    yy = flinear( sp->yval, sp->ymin, sp->ymax, yo, yo + h1 - 1.0 );
    ps_line( xo, yy, xo + w1 - 1, yy, ob->col2 );
    ps_line( xx, yo, xx, yo + h1 - 1, ob->col2 );
}


#define IS_FLATBOX( b )  (    b == FL_FRAME_BOX      \
                           || b == FL_EMBOSSED_BOX   \
                           || b == FL_BORDER_BOX     \
                           || b == FL_ROUNDED_BOX )


/***************************************
 ***************************************/

static int
calc_sbw( FL_OBJECT * ob )
{
    int delta = FL_abs( ob->bw ) + 3 * ( ob->bw > 0 );
    int flat = IS_FLATBOX( ob->boxtype ) ? 2 : 0;

    if ( ob->w > 250 && ob->h > 250 )
        return 15 + delta - flat;
    else if ( ob->w < 150 || ob->h < 150 )
        return 13 + delta - flat;
    else
        return 14 + delta - flat;
}


/***************************************
 ***************************************/

static void
browser_partition( FL_OBJECT * ob,
                   int         sbw,
                   int       * tx,
                   int       * ty,
                   int       * tw,
                   int       * th )
{
    SPEC *sp = ob->spec;
    int dx = 0, dy = 0;

    *tx = ob->x;
    *ty = ob->y;
    *tw = ob->w;
    *th = ob->h;

    if ( sp->v_pref == FL_ON )
    {
        dx = sbw;
        *tw -= dx;
    }

    if ( sp->h_pref == FL_ON )
    {
        dy = sbw;
        *ty += dy;
        *th -= dy;
    }

    if ( sp->v_pref == FL_ON )
    {
        FL_OBJECT *vscb = flps_make_object( FL_SCROLLBAR,
                                            FL_VERT_THIN_SCROLLBAR,
                                            ob->x + ob->w - sbw,
                                            ob->y + dy, sbw, ob->h - dy, 0, 0 );

        /* Copy some attributes from parent */

        vscb->bw = ob->bw;
        vscb->boxtype = ob->boxtype;
        ( ( SPEC * ) vscb->spec )->slsize = 0.5;
        ( ( SPEC * ) vscb->spec )->val = 1;

        flps_draw_scrollbar( vscb );
    }

    if ( sp->h_pref == FL_ON )
    {
        FL_OBJECT *hscb = flps_make_object( FL_SCROLLBAR,
                                            FL_HOR_THIN_SCROLLBAR,
                                            ob->x, ob->y, ob->w - dx, sbw,
                                            0, 0 );

        /* Copy some attributes from parent */

        hscb->bw = ob->bw;
        hscb->boxtype = ob->boxtype;
        ( ( SPEC * ) hscb->spec )->slsize = 0.5;
        ( ( SPEC * ) hscb->spec )->val = 0;

        flps_draw_scrollbar( hscb );
    }
}


/***************************************
 ***************************************/

static void
flps_draw_browser( FL_OBJECT * ob )
{
    SPEC *sp = ob->spec;
    int absbw = FL_abs( ob->bw );
    int sbw;
    int tx, ty, tw, th;
    int m = absbw / 2 + 1;

    sbw = calc_sbw( ob );     /* scroll bar width */
    browser_partition( ob, sbw, &tx, &ty, &tw, &th );

    ps_draw_box( ob->boxtype, tx, ty, tw, th, ob->col1, ob->bw );

    ps_draw_object_label_beside( ob );

    /* Start clipping */

    ps_set_clipping( tx + absbw, ty + absbw, tw - 2 * absbw - 1,
                     th - 2 * absbw );

    if ( sp->content[ 1 ] )
    {
        char *str;
        int i, cur_size;

        str = malloc( 1 );
        *str = '\0';
        cur_size = 1;

        for ( i = 1; i <= sp->lines; i++ )
        {
            cur_size += strlen( sp->content[ i ] ) + 2;
            str = realloc( str, cur_size );
            strcat( str, sp->content[ i ] );
            strcat( str, "\n" );
        }

        ps_draw_text( FL_ALIGN_LEFT_TOP | FL_ALIGN_INSIDE,
                      tx + m, ty, tw, th, ob->lcol,
                      sp->fontstyle, sp->fontsize, str );

        free( str );
    }

    ps_unset_clipping( );
}


/***************************************
 ***************************************/

static void
flps_draw_input( FL_OBJECT * ob )
{
    long col = ob->focus ? ob->col2 : ob->col1;

    ob->align = fl_to_outside_lalign( ob->align );
    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, col, ob->bw );
    ps_draw_object_label_beside( ob );
}


/***************************************
 ***************************************/

static void
flps_draw_free( FL_OBJECT * ob )
{
    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );
}


/***************************************
 ***************************************/

static char *
default_filter( FL_OBJECT * ob  FL_UNUSED_ARG,
                double      totalsec )
{
    static char buf[ 32 ];
    int minutes;
    float sec;

    if ( totalsec >= 3600.0 )
    {
        int hr = totalsec / 3600.0 + 0.001;

        minutes = totalsec / 60.0 + 0.001;
        minutes -= hr * 60;
        sec = totalsec - 60 * ( minutes + 60 * hr );
        sprintf( buf, "%2d:%0d:%2.1f", hr, minutes, sec );
    }
    else if ( totalsec >= 60.0 )
    {
        minutes = totalsec / 60.0 + 0.001;
        sec = totalsec - minutes * 60;
        sprintf( buf, "%2d:%2.1f", minutes, sec );
    }
    else
        sprintf(buf, "%2.1f", totalsec);

    return buf;
}


/***************************************
 ***************************************/

static void
flps_draw_timer( FL_OBJECT * ob )
{
    char *str;
    SPEC *sp = ob->spec;

    if ( ob->type == FL_HIDDEN_TIMER )
        return;

    ps_draw_box( ob->boxtype, ob->x, ob->y, ob->w, ob->h, ob->col1, ob->bw );

    if ( ob->type == FL_VALUE_TIMER )
    {
        str = default_filter( ob, sp->val == 0.0 ? 100.0 : sp->val );
        ps_draw_text( FL_ALIGN_CENTER, ob->x, ob->y, ob->w, ob->h,
                      ob->lcol, ob->lstyle, ob->lsize, str );
        ob->align = fl_to_outside_lalign( ob->align ) ;
        if ( ob->align == FL_ALIGN_CENTER )
            ob->align = FL_ALIGN_LEFT;
    }

    ps_draw_object_label( ob );
}


/***************************************
 ***************************************/

static void
flps_draw_spinner( FL_OBJECT * ob )
{
    FL_OBJECT *input,
              *up,
              *down;

    if ( ob->w >= ob->h )
    {
        FL_Coord bwh = FL_max( ob->h / 2, 1 );
        ob->h = 2 * bwh;

        input = flps_make_object( FL_INPUT,
                                  ob->type == FL_INT_SPINNER ?
                                  FL_INT_INPUT : FL_FLOAT_INPUT,
                                  ob->x, ob->y, ob->w - bwh - 1, ob->h,
                                  "", NULL );
        up = flps_make_object( FL_BUTTON, FL_TOUCH_BUTTON,
                               ob->x + ob->w - bwh - 1, ob->y + bwh, bwh, bwh,
                               "@8>", NULL );
        down = flps_make_object( FL_BUTTON, FL_TOUCH_BUTTON,
                                 ob->x + ob->w - bwh - 1, ob->y, bwh, bwh,
                                 "@2>", NULL );
    }
    else
    {
        FL_Coord bwh = FL_max( ob->w / 2, 1 );
        ob->w = 2 * bwh;

        input = flps_make_object( FL_INPUT,
                                  ob->type == FL_INT_SPINNER ?
                                  FL_INT_INPUT : FL_FLOAT_INPUT,
                                  ob->x, ob->y + bwh, ob->w, ob->h - bwh - 1,
                                  "", NULL );
        up = flps_make_object( FL_BUTTON, FL_TOUCH_BUTTON,
                               ob->x + bwh, ob->y, bwh, bwh,
                               "@6>", NULL );
        down = flps_make_object( FL_BUTTON, FL_TOUCH_BUTTON,
                                 ob->x, ob->y, bwh, bwh,
                                 "@4>", NULL );
    }

    input->boxtype = FL_DOWN_BOX;
    input->col1 = ob->col1;
    input->col2 = ob->col2;

    ps_draw_object( input );
    ps_draw_object( up );
    ps_draw_object( down );

    ob->align = fl_to_outside_lalign( ob->align );
    ps_draw_object_label_beside( ob );
}


/****************** TABLES ****************************/

typedef void ( * DRAW )( FL_OBJECT * );

typedef struct {
    int  objclass;
    DRAW drawit;
} FLPS_draw;

static FLPS_draw flps_draw[ ] =
{
    { FL_BUTTON,        flps_draw_button        },
    { FL_LIGHTBUTTON,   flps_draw_lightbutton   },
    { FL_ROUNDBUTTON,   flps_draw_roundbutton   },
    { FL_LABELBUTTON,   flps_draw_labelbutton   },
    { FL_ROUND3DBUTTON, flps_draw_round3dbutton },
    { FL_SCROLLBUTTON,  flps_draw_scrollbutton  },
    { FL_CHECKBUTTON,   flps_draw_checkbutton   },
    { FL_PIXMAPBUTTON,  flps_draw_pixmap        },
    { FL_BITMAPBUTTON,  flps_draw_pixmap        },
    { FL_PIXMAP,        flps_draw_pixmap        },
    { FL_BITMAP,        flps_draw_pixmap        },
    { FL_SLIDER,        flps_draw_slider        },
    { FL_VALSLIDER,     flps_draw_slider        },
    { FL_SCROLLBAR,     flps_draw_scrollbar     },
    { FL_THUMBWHEEL,    flps_draw_thumbwheel    },
    { FL_BOX,           flps_draw_box           },
    { FL_TEXT,          flps_draw_text          },
    { FL_COUNTER,       flps_draw_counter       },
    { FL_DIAL,          flps_draw_dial          },
    { FL_CHOICE,        flps_draw_choice        },
    { FL_MENU,          flps_draw_text          },
    { FL_BROWSER,       flps_draw_browser       },
    { FL_POSITIONER,    flps_draw_positioner    },
    { FL_FRAME,         flps_draw_frame         },
    { FL_LABELFRAME,    flps_draw_lframe        },
    { FL_INPUT,         flps_draw_input         },
    { FL_FREE,          flps_draw_free          },
    { FL_TIMER,         flps_draw_timer         },
    { FL_SPINNER,       flps_draw_spinner       }
};

#define NOBJ   ( sizeof flps_draw / sizeof *flps_draw )

/***************************************
 ***************************************/

static void
ps_draw_object( FL_OBJECT * ob )
{
    FLPS_draw *d = flps_draw, *ds;

    for ( ds = d + NOBJ; d < ds; d++ )
    {
        if ( d->objclass == ob->objclass )
        {
            if ( psinfo.verbose )
                ps_verbatim( "%%%s {\n", find_class_name( ob->objclass ) );
            d->drawit( ob );
            if ( psinfo.verbose )
                ps_verbatim( "%%%s }\n", find_class_name( ob->objclass ) );
            return;
        }
    }

    if ( ob->objclass != FL_BEGIN_GROUP && ob->objclass != FL_END_GROUP )
        fprintf( stderr, "Unknown/unsupported object: %s (%d)\n",
                 find_class_name( ob->objclass ), ob->objclass );
}


/***************************************
 ***************************************/

void
ps_show_form( FL_FORM * form )
{
    FL_OBJECT *ob;

    ps_bgn_form( form->w, form->h, form->label );

    for ( ob = form->first; ob; ob = ob->next )
    {
        scale_object( ob );
        ps_draw_object( ob );
    }

    ps_end_form( );
    psinfo.page++;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
