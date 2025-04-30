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


#ifndef PINPUT_H
#define PINPUT_H

typedef struct {
    char        * str;              /* the input text                  */
    FL_COLOR      textcol;          /* text color                      */
    FL_COLOR      curscol;          /* cursor color                    */
    int           position;         /* cursor position (in chars)      */
    int           beginrange;       /* start of the range              */
    int           endrange;         /* end of the range                */
    int           size;             /* size of the string              */
    int           changed;          /* whether the field has changed   */
    int           drawtype;         /* if to draw text with background */
    int           noscroll;         /* true if no scrollis allowed     */
    int           maxchars;         /* limit for normal_input          */
    int           attrib1;
    int           attrib2;
    FL_INPUT_VALIDATOR validate;

    /* scroll stuff. */

    FL_OBJECT     * dummy;          /* only for the size of composite */
    FL_OBJECT     * hscroll;
    FL_OBJECT     * vscroll;
    FL_OBJECT     * input;
    int             xoffset;
    int             yoffset;
    int             screenlines;
    int             topline;
    int             lines;          /* total number of lines in the field   */
    int             xpos,           /* current cursor position in char,line */
                    ypos;
    int             cur_pixels;     /* current line length in pixels        */
    int             max_pixels;     /* max length of all lines              */
    int             max_pixels_line;
    int             charh;          /* character height                     */
    int             h,              /* text area                            */
                    w;
    double          hsize,
                    vsize;
    double          hval,
                    vval;
    double          hinc1,
                    hinc2;
    double          vinc1,
                    vinc2;
    int             h_pref,         /* scrollbar preference                 */
                    v_pref;
    int             vw,
                    vw_def;
    int             hh,
                    hh_def;
    int             h_on,
                    v_on;
    int             dead_area,
                    attrib;
    int             cursor_visible;
    int             field_char;
} FLI_INPUT_SPEC;


#endif /* INPUT_H */


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
