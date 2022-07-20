/* Osmocom CBC (Cell Broacast Centre) */

/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <string.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/cbsp_server.h>

/* remove a peer from the message */
int cbc_message_del_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer)
{
	struct cbc_message_peer *mp, *mp2;
	unsigned int i = 0;

	llist_for_each_entry_safe(mp, mp2, &cbcmsg->peers, list) {
		if (mp->peer == peer) {
			llist_del(&mp->list);
			talloc_free(mp);
			i++;
		}
	}
	OSMO_ASSERT(i == 0 || i == 1);
	return i;
}

struct cbc_message_peer *cbc_message_peer_get(struct cbc_message *cbcmsg, struct cbc_peer *peer)
{
	struct cbc_message_peer *mp;

	llist_for_each_entry(mp, &cbcmsg->peers, list) {
		if (mp->peer == peer)
			return mp;
	}
	return NULL;
}

#if 0
/* add a new peer to the message */
int cbc_message_add_peer(struct cbc_message *cbcmsg, struct cbc_peer *peer)
{
	struct cbc_message_peer *mp = talloc_zero(cbcmsg, struct cbc_message_peer);
	if (mp)
		return -ENOMEM;

	mp->peer = peer;
	llist_add_tail(&mp->list, &cbcmsg->peers);
	return 0;
}
#endif
