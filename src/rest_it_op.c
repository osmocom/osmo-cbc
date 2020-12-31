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


#include <errno.h>
#include <pthread.h>

#include <osmocom/core/it_q.h>

#include "rest_it_op.h"
#include "internal.h"

/***********************************************************************
 * HTTP THREAD
 ***********************************************************************/

/* allocate an inter-thread operation */
struct rest_it_op *rest_it_op_alloc(void *ctx)
{
	struct rest_it_op *op = talloc_zero(ctx, struct rest_it_op);
	if (!op)
		return NULL;
	pthread_mutex_init(&op->mutex, NULL);
	pthread_cond_init(&op->cond, NULL);

	return op;
}

/* enqueue an inter-thread operation in REST->main direction and wait for its completion */
int rest_it_op_send_and_wait(struct rest_it_op *op, unsigned int wait_sec)
{
	struct timespec ts;
	int rc = 0;

	LOGP(DREST, LOGL_DEBUG, "rest_it_op enqueue\n");

	rc = osmo_it_q_enqueue(g_cbc->it_q.rest2main, op, list);
	if (rc < 0)
		return rc;

	/* grab mutex before pthread_cond_timedwait() */
	pthread_mutex_lock(&op->mutex);
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += wait_sec;

	LOGP(DREST, LOGL_DEBUG, "rest_it_op wait....\n");

	while (rc == 0)
		rc = pthread_cond_timedwait(&op->cond, &op->mutex, &ts);

	if (rc == 0)
		pthread_mutex_unlock(&op->mutex);

	LOGP(DREST, LOGL_DEBUG, "rest_it_op completed\n");

	/* 'op' is implicitly owned by the caller again now, who needs to take care
	 * of releasing its memory */

	return rc;
}



/***********************************************************************
 * MAIN THREAD
 ***********************************************************************/


void rest2main_read_cb(struct osmo_it_q *q, void *item)
{
	struct rest_it_op *op = item;
	struct cbc_message *cbc_msg;

	/* FIXME: look up related message and dispatch to message FSM,
	 * which will eventually call pthread_cond_signal(&op->cond) */

	switch (op->operation) {
	case REST_IT_OP_MSG_CREATE:
		/* FIXME: send to message FSM who can addd it on RAN */
		cbc_message_new(&op->u.create.cbc_msg);
		break;
	case REST_IT_OP_MSG_DELETE:
		/* FIXME: send to message FSM who can remove it from RAN */
		cbc_msg = cbc_message_by_id(op->u.del.msg_id);
		if (cbc_msg) {
			cbc_message_delete(cbc_msg);
		} else {
			/* FIXME: immediately wake up? */
		}
		break;
	/* TODO: REPLACE */
	/* TODO: STATUS */
	default:
		break;
	}
	pthread_cond_signal(&op->cond); // HACK
}
