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
 * \file interpol.c
 *
 *  This file is part of the XForms library package.
 *  Copyright (c) 1996-2002  T.C. Zhao
 *  All rights reserved.
 *
 * interpol1 interpolates a one-dimensional non-uniform
 * tabulated data onto a working grid, grid, using
 * nth order Lagrangian polynomial
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include "include/forms.h"
#include "flinternal.h"


/***************************************
 ***************************************/

int
fl_interpolate( const float * wx,
                const float * wy,
                int           nin,
                float       * x,
                float       * y,
                double        grid,
                int           ndeg )
{
    int i, j, k, l, jo, ih, im, idm, nout;
    double term, accum;

    if ( nin <= ndeg )
    {
        M_warn( "fl_interpolate", "too few points in interpol\n" );
        return -1;
    }

    nout = ( wx[ nin - 1 ] - wx[ 0 ] ) / grid + 1.01;

    x[ 0 ] = wx[ 0 ];
    y[ 0 ] = wy[ 0 ];

    /* Start the main loop */

    jo = 0;
    for ( i = 1; i < nout; i++ )
    {
        /* Better than x[i] = x[i-1] + grid; */

        x[ i ] = x[ 0 ] + i * grid;

        /* Center */

        j = jo;
        ih = nin;
        while ( ih - j > 1 )
        {
            im = ( ih + j ) / 2;
            if ( x[ i ] > wx[ im ] )
                j = im;
            else
                ih = im;
        }
        jo = j;
        j = j - ndeg / 2;
        if ( j < 0 )
            j = 0;
        if ( j > nin - ndeg - 1 )
            j = nin - ndeg - 1;

        /* Interpolate */

        accum = 0.0;
        idm = j + ndeg;
        for ( l = j; l <= idm; l++ )
        {
            term = wy[ l ];
            for ( k = j; k <= idm; k++ )
            {
                if ( l != k )
                    term *=   ( double ) ( x[ i ] - wx[ k ] )
                            / ( wx[ l ] - wx[ k ] );
            }
            accum += term;
        }
        y[ i ] = accum;
    }

    /* Make sure the ends are free of numerical errors */

    x[ nout - 1 ] = wx[ nin - 1 ];
    y[ nout - 1 ] = wy[ nin - 1 ];

    return nout;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
