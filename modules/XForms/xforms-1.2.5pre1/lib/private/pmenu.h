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
 *  You should have received a copy of the GNU General Public License
 *  along with XForms.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file pmenu.h
 */

#ifndef PMENU_H_
#define PMENU_H_

#define MMAXITEMS  ( FL_MENU_MAXITEMS + 1 )  /* index 0 unused */


/* make sure that the first 5 elements are the same as FL_CHOICE.
 * fdesign assumes this */


typedef struct {
    int             numitems;               /* number of items in menu */
    int             val;                    /* last menu item selected */
    char          * items[ MMAXITEMS ];     /* individual menu items   */
    char          * shortcut[ MMAXITEMS ];  /* shortcuts for items */
    unsigned char   mode[ MMAXITEMS ];      /* menu item mode */
    int             align;                  /* onle here to mirror FL_CHOICE */
    int             extern_menu;            /* if external pop is used */
    short           showsymbol;             /* whether symbol is to be shown */
    short           shown;                  /* if shown                    */
    char            mval[ MMAXITEMS ];      /* entry value, position based */
    char            modechange[ MMAXITEMS ];
    int             cur_val;                /* counter for the value       */
    int             no_title;
    FL_PUP_CB       cb[ MMAXITEMS ];        /* item callback functions     */
} FLI_MENU_SPEC;

#endif


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
