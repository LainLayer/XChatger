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


/* Demo of the Use of a very long label */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/forms.h"


const char *label1 = "This demo shows the use of some very\n"
                     "long labels. The dynamic storage allocation\n"
                     "for such long labels should guarantee that\n"
                     "all of this works without any problem.";

const char *label2 = "This is the second string that should again\n"
                     "be a bit larger such that a new, larger amount\n"
                     "of storage has to be allocated for the label.\n"
                     "This is of course no problem. By the way,\n"
                     "dynamic allocation of storage saves a lot\n"
                     "of memory because for most objects the label\n"
                     "is much shorter than the 64 bytes that were\n"
                     "allocated for it in the previous version of\n"
                     "the Forms Library";

const char *label3 = "And now back to the first one:\n\n"
                     "This demo shows the use of some very\n"
                     "long labels. The dynamic storage allocation\n"
                     "for such long labels should guarantee that\n"
                     "all of this works without any problem.";


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FL_FORM *form;
    FL_OBJECT *strobj,
		      *but;

    fl_initialize( &argc, argv, "FormDemo", 0, 0 );

    form = fl_bgn_form( FL_UP_BOX, 400, 300 );

    strobj = fl_add_box( FL_DOWN_BOX, 10, 10, 380, 240, "Press Next" );
    fl_set_object_lsize( strobj, FL_NORMAL_SIZE );

    but = fl_add_button( FL_NORMAL_BUTTON, 160, 260, 80, 30, "Next" );

    fl_end_form( );

    fl_set_form_hotobject( form, but );

    fl_show_form( form, FL_PLACE_HOTSPOT, FL_TRANSIENT, "longlabel" );
    fl_do_forms( );

    fl_set_object_label( strobj, label1 );
    fl_do_forms( );

    fl_set_object_label( strobj, label2 );
    fl_do_forms( );

    fl_set_object_label( strobj, "Now we turn to a short label" );
    fl_do_forms( );

    fl_set_object_label( strobj, label3 );
    fl_set_object_label( but, "Quit" );
    fl_do_forms( );

    fl_finish( );
    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
