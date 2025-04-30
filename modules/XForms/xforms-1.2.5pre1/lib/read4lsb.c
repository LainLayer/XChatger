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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"
#include "flinternal.h"
#include "ulib.h"


/***************************************
 ***************************************/

int
fli_fget4LSBF( FILE * fp )
{
    int ret  = getc(fp);

    ret |= getc(fp) << 8;
    ret |= getc(fp) << 16;
    ret |= getc(fp) << 24;
    return ret;
}


/***************************************
 ***************************************/

int
fli_fput4LSBF( int    code,
              FILE * fp )
{
    putc(code & 0xff, fp);
    putc((code >> 8) & 0xff, fp);
    putc((code >> 16) & 0xff, fp);
    return putc((code >> 24) & 0xff, fp);
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
