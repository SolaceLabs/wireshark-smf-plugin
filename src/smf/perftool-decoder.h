/* perftool-decoder.h
 * Structured Data Type Dissector
 * Copyright 2007, Solace Corporation
 *
 * $Id: $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef PERFTOOL_DECODER_H_
#define PERFTOOL_DECODER_H_

#include "epan/proto.h"
#include "epan/tvbuff.h"

void
add_tooldata_block(proto_tree *bm_tree, int headerFieldIndex, tvbuff_t *tvb, int start_offset, int* length);


#endif /* PERFTOOL_DECODER_H_ */
