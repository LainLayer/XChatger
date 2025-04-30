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

/* test screen/world conversion in addition to showing the xyplot styles */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include <stdlib.h>

typedef struct
{
   int          type;
   const char * name;
   FL_COLOR     color;
} XYType;

#define VN( a, c )   { a, #a, c }

static XYType xytype[ ] =
{
    VN( FL_NORMAL_XYPLOT,     FL_BLACK ),
    VN( FL_SQUARE_XYPLOT,     FL_BLACK ),
    VN( FL_CIRCLE_XYPLOT,     FL_BLACK ),
    VN( FL_FILL_XYPLOT,       FL_BLACK ),
    VN( FL_POINTS_XYPLOT,     FL_BLACK ),
    VN( FL_LINEPOINTS_XYPLOT, FL_BLACK ),
    VN( FL_DASHED_XYPLOT,     FL_BLACK ),
    VN( FL_DOTTED_XYPLOT,     FL_BLACK ),
    VN( FL_DOTDASHED_XYPLOT,  FL_BLACK ),
    VN( FL_IMPULSE_XYPLOT,    FL_BLACK ),
    VN( FL_ACTIVE_XYPLOT,     FL_BLACK ),
    VN( FL_EMPTY_XYPLOT,      FL_BLACK ),
    VN( -1,                   0 ),
};

#define N ( sizeof xytype / sizeof *xytype - 1 )


static FL_OBJECT *xyplot[ N ];
static void create_form_xyplot( void );
static FL_FORM *fxyplot;
static float x[ N ][ 21 ],
             y[ N ][ 21 ];




/***************************************
 ***************************************/

static void
done_xyplot( FL_OBJECT * ob,
             long        q  FL_UNUSED_ARG )
{
    fl_hide_form( ob->form );
    fl_finish( );
    exit( 0 );
}


#include <math.h>

/***************************************
 ***************************************/

static int
post( FL_OBJECT * ob,
      int         ev,
      FL_Coord    mx,
      FL_Coord    my,
      int         key,
      void      * xev  FL_UNUSED_ARG )
{
    if ( ev == FL_PUSH || ev == FL_MOTION )
    {
        float wx, wy;
        char buf[ 64 ];

        fl_xyplot_s2w( ob, mx, my, &wx, &wy );
        sprintf( buf, "x=%d y=%d wx=%.1f wy=%.1f", mx, my, wx, wy );
        fl_show_oneliner( buf, ob->x + ob->form->x + 5, ob->y + ob->form->y );
/*       fl_object_ps_dump( ob,"test.ps" ); */
        ob->wantkey = FL_KEY_ALL;
        ob->input = 1;
    }
    else if ( ev == FL_RELEASE )
    {
        fl_hide_oneliner( );
    }
    else if( ev == FL_KEYPRESS )
    {
        fprintf( stderr,"key=%d\n",key );
    }

    return 0;
}


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    size_t i,
           j;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    create_form_xyplot( );

    /* Make sure double buffer also works */

//  for ( i = 0; i < 3; i++ )

    for ( i = 0; i < N; i++ )
    {
        fl_set_object_dblbuffer( xyplot[ i ], 1 );

        for( j = 0; j < 21; j++ )
        {
            x[ i ][ j ] = j * 3.1415 / 10 + 0.2;
            y[ i ][ j ] = sin( 2 * x[ i ][ j ] ) + cos( x[ i ][ j ] );
        }

        fl_set_xyplot_data( xyplot[ i ], x[ i ], y[ i ], 21, "TestTitle",
                            "X-axis", "Y|axis");
        if ( i == 0 )
            fl_add_xyplot_text( xyplot[ i ], x[ i ][ 15 ], 0.1,
                                "@2->", FL_ALIGN_TOP, FL_BLUE );
        else
            fl_add_xyplot_text( xyplot[ i ], x[ i ][ 8 ], 1.4,
                                "Text Inset", FL_ALIGN_CENTER, FL_BLUE );

        if ( i == 3 )
        {
            fl_set_xyplot_xgrid( xyplot[ i ], FL_GRID_MAJOR );
            fl_set_xyplot_xgrid( xyplot[ i ], FL_GRID_MINOR );
        }
        else if ( i == 0 )
        {
            fl_set_xyplot_xtics( xyplot[ i ], 7, 2 );
            fl_set_xyplot_xbounds( xyplot[ i ], 6, 0 );
        }
        else if ( i == 1 )
        {
            fl_set_xyplot_ytics( xyplot[ i ], 5, 2 );
            fl_set_xyplot_ybounds( xyplot[ i ], 2.4, -2.4 );
        }

        fl_set_object_posthandler( xyplot[ i ], post );
    }

    fl_show_form( fxyplot, FL_PLACE_MOUSE | FL_FREE_SIZE, FL_TRANSIENT,
                  "XYplot" );

     while ( fl_do_forms( ) )
         /* empty */;

     return 0;
}


/***************************************
 ***************************************/

static
void create_form_xyplot( void )
{
    FL_OBJECT *obj;
    XYType *xy  = xytype;
    int dx = 180,
        dy = 160;
    int i = 0,
        j = N / 3 + ( ( N % 3 ) ? 1 : 0 );

    if ( fxyplot )
        return;

    fxyplot = fl_bgn_form( FL_NO_BOX, 3 * ( dx + 20 ) + 20,
                           j * ( dy + 30 ) + 120 );

    fl_add_box( FL_UP_BOX, 0, 0, 3 * ( dx + 20 ) + 20, j * ( dy + 30 ) + 120,
                "" );

    for ( j = 0; xy->type != -1; j++ )
        for ( i = 0; i < 3 && xy->type != -1; i++ )
        {
            xyplot[ 3 * j + i ] = obj =
                fl_add_xyplot( xy->type, i * ( dx + 20 ) + 20 ,
                               j * ( dy + 30 ) + 60, dx, dy, xy->name );
            fl_set_object_lsize( obj, FL_TINY_SIZE );
            fl_set_object_color( obj, FL_COL1, xy->color );
            xy++;
        }

    obj = fl_add_button( FL_NORMAL_BUTTON, ( 3 * ( dx + 20 ) + 20 ) / 2 - 50,
                         j * ( dy + 30 ) + 60, 100, 30, "Exit" );
    fl_set_object_callback( obj, done_xyplot, 0 );

    obj = fl_add_text( FL_NORMAL_TEXT, ( 3 * ( dx + 20 ) + 20 ) / 2 - 90,
                       15, 240, 30, "FL_XYPLOT" );
    fl_set_object_lcolor( obj, FL_SLATEBLUE );
    fl_set_object_lsize( obj, FL_HUGE_SIZE );
    fl_set_object_lstyle( obj, FL_BOLD_STYLE|FL_EMBOSSED_STYLE );
    fl_set_object_boxtype( obj, FL_FLAT_BOX );

    fl_end_form( );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
