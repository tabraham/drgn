// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Chains of named handlers.
 */

#ifndef DRGN_HANDLER_H
#define DRGN_HANDLER_H

// This should be embedded as the first member in a structure containing the
// handler implementation.
struct drgn_handler {
	const char *name;
	bool free;
	struct drgn_handler *next_registered;
	struct drgn_handler *next_enabled;
};

struct drgn_handler_list {
	struct drgn_handler *registered;
	struct drgn_handler *enabled;
};

void drgn_handler_list_deinit(struct drgn_handler_list *list);

struct drgn_error *drgn_handler_list_register(struct drgn_handler_list *list,
					      struct drgn_handler *handler,
					      size_t enable_index,
					      const char *what);

struct drgn_error *drgn_handler_list_registered(struct drgn_handler_list *list,
						const char ***names_ret,
						size_t *count_ret);

struct drgn_error *drgn_handler_list_set_enabled(struct drgn_handler_list *list,
						 const char * const *names,
						 size_t count,
						 const char *what);

struct drgn_error *drgn_handler_list_enabled(struct drgn_handler_list *list,
					     const char ***names_ret,
					     size_t *count_ret);

#define drgn_handler_list_for_each_enabled(type, handler, list)			\
	for (type *handler = (type *)(list)->enabled; handler;			\
	     handler = (type *)((struct drgn_handler *)handler)->next_enabled)

#endif /* DRGN_HANDLER_H */
