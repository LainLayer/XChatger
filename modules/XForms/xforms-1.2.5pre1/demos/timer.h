/*
 *
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with XForms; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 */


#ifndef FD_timerform_h_
#define FD_timerform_h_
/* Header file generated with fdesign. */

/**** Callback routines ****/

extern void expired(FL_OBJECT *, long);
extern void suspend_resume(FL_OBJECT *, long);
extern void reset(FL_OBJECT *, long);
extern void timer_direction(FL_OBJECT *, long);


/**** Forms and Objects ****/

typedef struct {
	FL_FORM *timerform;
	FL_OBJECT *timer;
	FL_OBJECT *down;
	void *vdata;
	long ldata;
} FD_timerform;

extern FD_timerform * create_form_timerform(void);

#endif /* FD_timerform_h_ */
