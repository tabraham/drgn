// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdlib.h>
#include <string.h>

#include "cleanup.h"
#include "drgn.h"
#include "handler.h"
#include "hash_table.h"
#include "util.h"

void drgn_handler_list_deinit(struct drgn_handler_list *list)
{
	struct drgn_handler *handler = list->registered;
	while (handler) {
		struct drgn_handler *next = handler->next_registered;
		if (handler->free) {
			free((char *)handler->name);
			free(handler);
		}
		handler = next;
	}
}

struct drgn_error *drgn_handler_list_register(struct drgn_handler_list *list,
					      struct drgn_handler *handler,
					      size_t enable_idx,
					      const char *what)
{
	struct drgn_handler **registeredp = &list->registered;
	while (*registeredp) {
		if (strcmp(handler->name, (*registeredp)->name) == 0) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "duplicate %s name '%s'",
						 what, handler->name);
		}
		registeredp = &(*registeredp)->next_registered;
	}
	handler->next_registered = NULL;
	*registeredp = handler;
	if (enable_idx != DRGN_HANDLER_REGISTER_DONT_ENABLE) {
		struct drgn_handler **enabledp = &list->enabled;
		for (size_t i = 0; i < enable_idx && *enabledp; i++)
			enabledp = &(*enabledp)->next_enabled;
		handler->next_enabled = *enabledp;
		*enabledp = handler;
	}
	return NULL;
}

struct drgn_error *drgn_handler_list_registered(struct drgn_handler_list *list,
						const char ***names_ret,
						size_t *count_ret)
{
	size_t n = 0;
	for (struct drgn_handler *handler = list->registered; handler;
	     handler = handler->next_registered)
		n++;
	const char **names = malloc_array(n, sizeof(names[0]));
	if (!names)
		return &drgn_enomem;
	size_t i = 0;
	for (struct drgn_handler *handler = list->registered; handler;
	     handler = handler->next_registered)
		names[i++] = handler->name;
	*names_ret = names;
	*count_ret = n;
	return NULL;
}

static inline const char *drgn_handler_entry_to_key(const uintptr_t *entry)
{
	return ((struct drgn_handler *)(*entry & ~1))->name;
}

DEFINE_HASH_TABLE(drgn_handler_table, uintptr_t, drgn_handler_entry_to_key,
		  c_string_key_hash_pair, c_string_key_eq);

struct drgn_error *drgn_handler_list_set_enabled(struct drgn_handler_list *list,
						 const char * const *names,
						 size_t count, const char *what)
{
	if (count == 0) {
		list->enabled = NULL;
		return NULL;
	}
	_cleanup_(drgn_handler_table_deinit)
		struct drgn_handler_table table = HASH_TABLE_INIT;
	for (struct drgn_handler *cur = list->registered; cur;
	     cur = cur->next_registered) {
		uintptr_t entry = (uintptr_t)cur;
		if (drgn_handler_table_insert(&table, &entry, NULL) < 0)
			return &drgn_enomem;
	}
	for (size_t i = 0; i < count; i++) {
		struct drgn_handler_table_iterator it =
			drgn_handler_table_search(&table, &names[i]);
		if (!it.entry) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "%s '%s' not found", what,
						 names[i]);
		}
		if (*it.entry & 1) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "%s '%s' enabled multiple times",
						 what, names[i]);
		}
		*it.entry |= 1;
	}
	struct drgn_handler **handlerp = &list->enabled;
	for (size_t i = 0; i < count; i++) {
		struct drgn_handler_table_iterator it =
			drgn_handler_table_search(&table, &names[i]);
		struct drgn_handler *handler =
			(struct drgn_handler *)(*it.entry & ~1);
		*handlerp = handler;
		handlerp = &handler->next_enabled;
	}
	*handlerp = NULL;
	return NULL;
}

struct drgn_error *drgn_handler_list_enabled(struct drgn_handler_list *list,
					     const char ***names_ret,
					     size_t *count_ret)
{
	size_t n = 0;
	for (struct drgn_handler *handler = list->enabled; handler;
	     handler = handler->next_enabled)
		n++;
	const char **names = malloc_array(n, sizeof(names[0]));
	if (!names)
		return &drgn_enomem;
	size_t i = 0;
	for (struct drgn_handler *handler = list->enabled; handler;
	     handler = handler->next_enabled)
		names[i++] = handler->name;
	*names_ret = names;
	*count_ret = n;
	return NULL;
}
