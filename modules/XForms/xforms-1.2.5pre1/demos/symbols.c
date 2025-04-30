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
 * Show the built-in symbols
 *
 * This file is part of xforms package
 * T.C. Zhao and M. Overmars   (1997)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

const char * symbols[ ] =
{
    "@>",      "@<-",     "@9->",     "@DnLine", "@8>",    "@circle",   "@->|",
    "@>>",     "@square", "@4->|",    "@8->|",   "@<->",   "@UpArrow",  "@9+",
    "@->",     "@<",      "@DnArrow", "@+",      "@-->",   "@line",     "@3->",
    "@UpLine", "@>|",     "@2-->",    "@4>|",    "@8>|",   "@=",        "@menu",
    "@8=",     "@|>",     "@2|>",     "@-32|>",  "@+32|>", "@-2circle", NULL
};

#define N  ( sizeof symbols / sizeof * symbols - 1 )


/***************************************
 ***************************************/

static void
done_cb( FL_OBJECT * ob    FL_UNUSED_ARG,
         long        data  FL_UNUSED_ARG )
{
    exit( 0 );
}


/***************************************
 ***************************************/

FL_FORM *
make_symbols( void )
{
    const char **p;
    char buf[ 32 ];
    int x0 = 10,
        y0 = 10,
        dx = 35,
        dy = 35,
        ty = 17,
        n = 7;
    int xsep = 15,
        ysep = 5;
    int x,
        y,
        i,
        w,
        h;
    FL_OBJECT *obj;
    FL_FORM *form;

    form = fl_bgn_form( FL_FLAT_BOX,
                        w = 2 * x0 + n * dx + ( n - 1 ) * xsep,
                        h = 2 * y0 + ( 1 + N / n - ! ( N % n ) )
                                     * ( dy + ty + ysep ) );

    obj = fl_add_button( FL_HIDDEN_BUTTON, 0, 0, w, h, "" );

    fl_set_object_callback( obj, done_cb, 0 );

    for ( x = x0, y = y0, i = 1, p = symbols; *p; p++, i++ )
    {
        int txt_x, txt_y, txt_w, txt_h;

        obj = fl_add_box( FL_UP_BOX, x, y, dx, dy, *p );
        fl_set_object_lcolor( obj, FL_BOTTOM_BCOL );

        strcat( strcpy( buf, "@" ) , *p );
        obj = fl_add_box( FL_FLAT_BOX, x, y + dy, dx, ty, buf );

        fl_get_object_geometry( obj, &txt_x, &txt_y, &txt_w, &txt_h );
        w =   fl_get_string_width( fl_get_object_lstyle( obj ),
                                   fl_get_object_lsize( obj ),
                                   *p, strlen( *p ) )
            + 2 * fl_get_object_bw( obj );
        fl_set_object_geometry( obj, txt_x + ( txt_w - w ) / 2, txt_y,
                                w, txt_h );

        if ( i % n == 0 )
        {
            static int j = 1;

            x = x0;
            y = y0 +  j * ( dy + ty + ysep + 1);
            j++;
         }
         else
           x += dx +  xsep;
     }

     fl_end_form( );

     return form;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;

    fl_initialize( &argc, argv , 0, 0, 0 );
    form = make_symbols( );
    fl_show_form( form, FL_PLACE_FREE, FL_FULLBORDER, "test" );

    while ( fl_do_forms( ) )
        /* empty */;

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
