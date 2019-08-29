#pragma once

#include <stdint.h>
#include <pthread.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/it_q.h>

#include "cbc_data.h"

enum rest_it_operation {
	REST_IT_OP_NONE,
	REST_IT_OP_MSG_CREATE,
	REST_IT_OP_MSG_DELETE,
	_NUM_REST_IT_OP
};

/* create a new SMSCB message */
struct rest_it_op_create {
	struct cbc_message cbc_msg;
};

/* delete a SMSCB message from our state and all peers */
struct rest_it_op_delete {
	uint16_t msg_id;
};

/* Inter-Thread operation from REST thread to main thread */
struct rest_it_op {
	struct llist_head list;

	/* condition variable for REST thread to pthread_cond_wait on */
	pthread_cond_t cond;
	/* mutex required around cond */
	pthread_mutex_t mutex;

	enum rest_it_operation operation;
	union {
		struct rest_it_op_create create;
		struct rest_it_op_delete del;
	} u;
};

int rest_it_op_send_and_wait(struct rest_it_op *op, unsigned int wait_sec);
