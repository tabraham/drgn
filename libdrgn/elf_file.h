// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * ELF files.
 *
 * See @ref ElfFile.
 */

#ifndef DRGN_ELF_FILE_H
#define DRGN_ELF_FILE_H

#include <elfutils/libdw.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>

#include "binary_buffer.h"
#include "elf_sections.h" // IWYU pragma: export
#include "platform.h"

struct drgn_module;

/**
 * @ingroup Internals
 *
 * @defgroup ElfFile ELF files
 *
 * ELF file handling.
 *
 * @{
 */

/**
 * Read the raw data from an ELF section, decompressing it first if it is
 * compressed.
 *
 * @warning If the section is `SHT_NOBITS`, this returns an `Elf_Data` with
 * `d_size >= 0 && d_buf == NULL`.
 */
struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret);

static inline bool elf_data_contains_ptr(Elf_Data *data, const void *ptr)
{
	uintptr_t bufi = (uintptr_t)data->d_buf;
	uintptr_t ptri = (uintptr_t)ptr;
	return ptri >= bufi && ptri - bufi < data->d_size;
}

/** An ELF file used by a @ref drgn_module. */
struct drgn_elf_file {
	/** Module using this file. */
	struct drgn_module *module;
	/** Filesystem path to this file. */
	char *path;
	char *image; // TODO: document
	int fd; // TODO: document
	bool is_loadable; // TODO: document
	bool needs_relocation; // TODO: document
	/** libelf handle. */
	Elf *elf;
	// TODO
	Dwarf *_dwarf;
	/**
	 * Platform of this file.
	 *
	 * This should take precedence over @ref drgn_program::platform when
	 * parsing this file. Note that there are some cases where it doesn't
	 * make sense for the program and file platforms to differ (e.g., stack
	 * unwinding), in which case the file should be ignored if its platform
	 * doesn't match the program's.
	 */
	struct drgn_platform platform;
	/** Important ELF sections. */
	Elf_Scn *scns[DRGN_SECTION_INDEX_NUM];
	/** Data cached for important ELF sections. */
	Elf_Data *scn_data[DRGN_SECTION_INDEX_NUM_DATA];
	// TODO: need to populate these
	/**
	 * If the file has a debugaltlink file, the debugaltlink file's
	 * `.debug_info` section data.
	 */
	Elf_Data *alt_debug_info_data;
	/**
	 * If the file has a debugaltlink file, the debugaltlink file's
	 * `.debug_str` section data.
	 */
	Elf_Data *alt_debug_str_data;
};

struct drgn_error *drgn_elf_file_create(struct drgn_module *module,
					const char *path, int fd, char *image,
					Elf *elf, struct drgn_elf_file **ret);

void drgn_elf_file_destroy(struct drgn_elf_file *file);

struct drgn_error *
drgn_elf_file_apply_relocations(struct drgn_elf_file *file);

// TODO: document
struct drgn_error *
drgn_elf_file_read_section(struct drgn_elf_file *file,
			   enum drgn_section_index scn,
			   Elf_Data **ret);

struct drgn_error *drgn_elf_file_get_dwarf(struct drgn_elf_file *file,
					   Dwarf **ret);

static inline bool
drgn_elf_file_is_little_endian(const struct drgn_elf_file *file)
{
	return drgn_platform_is_little_endian(&file->platform);
}

static inline bool drgn_elf_file_bswap(const struct drgn_elf_file *file)
{
	return drgn_platform_bswap(&file->platform);
}

static inline uint8_t
drgn_elf_file_address_size(const struct drgn_elf_file *file)
{
	return drgn_platform_address_size(&file->platform);
}

static inline uint64_t
drgn_elf_file_address_mask(const struct drgn_elf_file *file)
{
	return drgn_platform_address_mask(&file->platform);
}

static inline bool drgn_elf_file_has_dwarf(const struct drgn_elf_file *file)
{
	return (file->scns[DRGN_SCN_DEBUG_INFO]
		&& file->scns[DRGN_SCN_DEBUG_ABBREV]);
}

struct drgn_error *
drgn_elf_file_section_error(struct drgn_elf_file *file, Elf_Scn *scn,
			    Elf_Data *data, const char *ptr,
			    const char *message)
	__attribute__((__returns_nonnull__));

struct drgn_error *
drgn_elf_file_section_errorf(struct drgn_elf_file *file, Elf_Scn *scn,
			     Elf_Data *data, const char *ptr,
			     const char *format, ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 5, 6)));

struct drgn_elf_file_section_buffer {
	struct binary_buffer bb;
	struct drgn_elf_file *file;
	Elf_Scn *scn;
	Elf_Data *data;
};

struct drgn_error *drgn_elf_file_section_buffer_error(struct binary_buffer *bb,
						      const char *ptr,
						      const char *message);

static inline void
drgn_elf_file_section_buffer_init(struct drgn_elf_file_section_buffer *buffer,
				  struct drgn_elf_file *file, Elf_Scn *scn,
				  Elf_Data *data)
{
	binary_buffer_init(&buffer->bb, data->d_buf, data->d_size,
			   drgn_elf_file_is_little_endian(file),
			   drgn_elf_file_section_buffer_error);
	buffer->file = file;
	buffer->scn = scn;
	buffer->data = data;
}

// TODO: document
static inline void
drgn_elf_file_section_buffer_init_index(struct drgn_elf_file_section_buffer *buffer,
					struct drgn_elf_file *file,
					enum drgn_section_index scn)
{
	drgn_elf_file_section_buffer_init(buffer, file, file->scns[scn],
					  file->scn_data[scn]);
}

// TODO: document
static inline struct drgn_error *
drgn_elf_file_section_buffer_read(struct drgn_elf_file_section_buffer *buffer,
				  struct drgn_elf_file *file,
				  enum drgn_section_index scn)
{
	Elf_Data *data;
	struct drgn_error *err = drgn_elf_file_read_section(file, scn, &data);
	if (err)
		return err;
	drgn_elf_file_section_buffer_init(buffer, file, file->scns[scn], data);
	return NULL;
}

/** @} */

#endif /* DRGN_ELF_FILE_H */
