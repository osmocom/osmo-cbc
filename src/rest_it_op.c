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

#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/it_q.h>

#include <osmocom/cbc/cbc_data.h>
#include <osmocom/cbc/rest_it_op.h>
#include <osmocom/cbc/debug.h>

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
	/* set a 'safe' default for all kinds of error situations */
	rest_it_op_set_http_result(op, 500, "Internal Server Error");

	return op;
}

/* enqueue an inter-thread operation in REST->main direction and wait for its completion */
int rest_it_op_send_and_wait(struct rest_it_op *op)
{
	int rc = 0;

	LOGP(DREST, LOGL_DEBUG, "rest_it_op enqueue from %lu\n", pthread_self());

	rc = osmo_it_q_enqueue(g_cbc->it_q.rest2main, op, list);
	if (rc < 0)
		return rc;

	/* grab mutex before pthread_cond_wait() */
	pthread_mutex_lock(&op->mutex);

	LOGP(DREST, LOGL_DEBUG, "rest_it_op wait....\n");

	rc = pthread_cond_wait(&op->cond, &op->mutex);

	LOGP(DREST, LOGL_DEBUG, "rest_it_op completed with %d (HTTP %u)\n",
		rc, op->http_result.response_code);

	pthread_mutex_unlock(&op->mutex);

	/* 'op' is implicitly owned by the caller again now, who needs to take care
	 * of releasing its memory */

	return rc;
}



/***********************************************************************
 * MAIN THREAD
 ***********************************************************************/


void rest2main_read_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct rest_it_op *op = container_of(item, struct rest_it_op, list);
	struct cbc_message *cbc_msg;

	LOGP(DREST, LOGL_DEBUG, "%s(op=%p) from %lu\n", __func__, op, pthread_self());

	/* FIXME: look up related message and dispatch to message FSM,
	 * which will eventually call pthread_cond_signal(&op->cond) */

	switch (op->operation) {
	case REST_IT_OP_MSG_CREATE:
		cbc_message_new(&op->u.create.cbc_msg, op);
		break;
	case REST_IT_OP_MSG_DELETE:
		cbc_msg = cbc_message_by_id(op->u.del.msg_id);
		if (cbc_msg) {
			cbc_message_delete(cbc_msg, op);
		} else {
			rest_it_op_set_http_result(op, 404, "Unknown message ID");
			rest_it_op_complete(op);
		}
		break;
	/* TODO: REPLACE */
	/* TODO: STATUS */
	default:
		rest_it_op_set_http_result(op, 501, "Not Implemented");
		rest_it_op_complete(op);
		break;
	}
}

void rest_it_op_set_http_result(struct rest_it_op *op, uint32_t code, const char *body)
{
	if (!op)
		return;
	op->http_result.response_code = code;
	op->http_result.message = body;
}

/* signal completion of rest_it_op to whoever is waiting for it */
void rest_it_op_complete(struct rest_it_op *op)
{
	LOGP(DREST, LOGL_DEBUG, "%s(op=%p) complete\n", __func__, op);
	if (!op)
		return;
	pthread_cond_signal(&op->cond);
}
