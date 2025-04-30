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
 * Showing the use of non-modal file selector
 *
 * T.C. Zhao and M. Overmars
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"
#include "fd/pmbrowse_gui.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

FD_ttt *fd_ttt;

static int load_file( const char *,
                      void       * );

/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, "FormDemo", 0, 0 );
    fd_ttt = create_form_ttt( );

    fl_show_form( fd_ttt->ttt, FL_PLACE_CENTER, FL_TRANSIENT, "PixmapBrowser" );

    fl_set_fselector_placement( FL_PLACE_FREE );
    fl_set_fselector_callback( load_file, 0 );
    fl_show_fselector( "Load a Pixmap file", NULL, "*.x?m", NULL );
    fl_do_forms( );
    return 0;
}


/***************************************
 ***************************************/

static int
load_file( const char * fname,
           void       * data  FL_UNUSED_ARG )
{
    char *p;
    struct stat buff;

    if ( ! fname || ! *fname )
    {
        fprintf( stderr, "Missing file name\n" );
        return 0;
    }

    if ( ! stat( fname, &buff ) )
    {
        if ( ! S_ISDIR( buff.st_mode ) )
        {
            if ( ( p = strrchr( fname, '.' ) ) )
            {
                if ( ! strcmp( p + 1, "xpm" ) )
                {
                    fl_hide_object( fd_ttt->bm );
                    fl_free_pixmap_pixmap( fd_ttt->pm );
                    fl_set_pixmap_file( fd_ttt->pm, fname );
                    fl_show_object( fd_ttt->pm );
                }
                else if ( ! strcmp( p + 1, "xbm" ) )
                {
                    fl_hide_object( fd_ttt->pm );
                    fl_set_bitmap_file( fd_ttt->bm, fname );
                     fl_show_object( fd_ttt->bm );
                }
                else
                {
                    fprintf( stderr, "Invalid file extension: %s\n", p + 1 );
                    return 0;
                }
            }
            else
            {
                fprintf( stderr, "Neither .xpm nor .xbm file\n" );
                return 0;
            }
        }
    }
    else
    {
        fprintf( stderr, "Can't stat() file %s\n", fname );
        return 0;
    }

    return 1;
}


/***************************************
 ***************************************/

void done( FL_OBJECT * ob  FL_UNUSED_ARG,
           long        q   FL_UNUSED_ARG )
{
    fl_finish( );
    exit( 0 );
}


/***************************************
 ***************************************/

void reload( FL_OBJECT * ob  FL_UNUSED_ARG,
             long        q   FL_UNUSED_ARG )
{
    fl_set_fselector_placement( FL_PLACE_MOUSE );
    fl_set_fselector_callback( load_file, 0 );
    fl_show_fselector( "Load a Pix/bitMap file", NULL, NULL, NULL );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
