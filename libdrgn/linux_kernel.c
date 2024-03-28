// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <dirent.h>
#include <elf.h>
#include <elfutils/libdwelf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "array.h"
#include "binary_buffer.h"
#include "cleanup.h"
#include "debug_info.h"
#include "drgn.h"
#include "error.h"
#include "hash_table.h"
#include "helpers.h"
#include "hexlify.h"
#include "io.h"
#include "linux_kernel.h"
#include "log.h"
#include "platform.h"
#include "program.h"
#include "type.h"
#include "util.h"

#include "drgn_program_parse_vmcoreinfo.inc"

struct drgn_error *read_memory_via_pgtable(void *buf, uint64_t address,
					   size_t count, uint64_t offset,
					   void *arg, bool physical)
{
	struct drgn_program *prog = arg;
	return linux_helper_read_vm(prog, prog->vmcoreinfo.swapper_pg_dir,
				    address, buf, count);
}

struct drgn_error *proc_kallsyms_symbol_addr(const char *name,
					     unsigned long *ret)
{
	struct drgn_error *err;
	FILE *file;
	char *line = NULL;
	size_t n = 0;

	file = fopen("/proc/kallsyms", "r");
	if (!file)
		return drgn_error_create_os("fopen", errno, "/proc/kallsyms");

	for (;;) {
		char *addr_str, *sym_str, *saveptr, *end;

		errno = 0;
		if (getline(&line, &n, file) == -1) {
			if (errno) {
				err = drgn_error_create_os("getline", errno,
							   "/proc/kallsyms");
			} else {
				err = &drgn_not_found;
			}
			break;
		}

		addr_str = strtok_r(line, "\t ", &saveptr);
		if (!addr_str || !*addr_str)
			goto invalid;
		if (!strtok_r(NULL, "\t ", &saveptr))
			goto invalid;
		sym_str = strtok_r(NULL, "\t\n ", &saveptr);
		if (!sym_str)
			goto invalid;

		if (strcmp(sym_str, name) != 0)
			continue;

		errno = 0;
		*ret = strtoul(line, &end, 16);
		if (errno || *end) {
invalid:
			err = drgn_error_create(DRGN_ERROR_OTHER,
						"could not parse /proc/kallsyms");
			break;
		}
		err = NULL;
		break;
	}
	free(line);
	fclose(file);
	return err;
}

/*
 * Before Linux kernel commit 23c85094fe18 ("proc/kcore: add vmcoreinfo note to
 * /proc/kcore") (in v4.19), /proc/kcore didn't have a VMCOREINFO note. Instead,
 * we can read from the physical address of the vmcoreinfo note exported in
 * sysfs.
 */
struct drgn_error *read_vmcoreinfo_fallback(struct drgn_program *prog)
{
	struct drgn_error *err;
	FILE *file;
	uint64_t address;
	size_t size;
	Elf64_Nhdr *nhdr;

	file = fopen("/sys/kernel/vmcoreinfo", "r");
	if (!file) {
		return drgn_error_create_os("fopen", errno,
					    "/sys/kernel/vmcoreinfo");
	}
	if (fscanf(file, "%" SCNx64 "%zx", &address, &size) != 2) {
		fclose(file);
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "could not parse /sys/kernel/vmcoreinfo");
	}
	fclose(file);

	_cleanup_free_ char *buf = malloc(size);
	if (!buf)
		return &drgn_enomem;

	err = drgn_program_read_memory(prog, buf, address, size, true);
	if (err)
		return err;

	/*
	 * The first 12 bytes are the Elf{32,64}_Nhdr (it's the same in both
	 * formats). The name is padded up to 4 bytes, so the descriptor starts
	 * at byte 24.
	 */
	nhdr = (Elf64_Nhdr *)buf;
	if (size < 24 || nhdr->n_namesz != 11 ||
	    memcmp(buf + sizeof(*nhdr), "VMCOREINFO", 10) != 0 ||
	    nhdr->n_descsz > size - 24) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"VMCOREINFO is invalid");
		return err;
	}

	return drgn_program_parse_vmcoreinfo(prog, buf + 24, nhdr->n_descsz);
}

static struct drgn_error *linux_kernel_get_page_shift(struct drgn_program *prog,
						      struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_INT,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_signed(ret, qualified_type,
				      prog->vmcoreinfo.page_shift, 0);
}

static struct drgn_error *linux_kernel_get_page_size(struct drgn_program *prog,
						     struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_unsigned(ret, qualified_type,
					prog->vmcoreinfo.page_size, 0);
}

static struct drgn_error *linux_kernel_get_page_mask(struct drgn_program *prog,
						     struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_unsigned(ret, qualified_type,
					~(prog->vmcoreinfo.page_size - 1), 0);
}

static struct drgn_error *
linux_kernel_get_uts_release(struct drgn_program *prog, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog,
					       DRGN_C_TYPE_CHAR,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = DRGN_QUALIFIER_CONST;
	size_t len = strlen(prog->vmcoreinfo.osrelease);
	err = drgn_array_type_create(prog, qualified_type, len + 1,
				     &drgn_language_c, &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_from_buffer(ret, qualified_type,
					   prog->vmcoreinfo.osrelease, len + 1,
					   0, 0);
}

// jiffies is defined as an alias of jiffies_64 via the Linux kernel linker
// script, so it is not included in debug info.
static struct drgn_error *linux_kernel_get_jiffies(struct drgn_program *prog,
						   struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_object jiffies_64;
	drgn_object_init(&jiffies_64, prog);
	err = drgn_program_find_object(prog, "jiffies_64", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &jiffies_64);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			err = &drgn_not_found;
		}
		goto out;
	}
	if (jiffies_64.kind != DRGN_OBJECT_REFERENCE) {
		err = &drgn_not_found;
		goto out;
	}
	uint64_t address = jiffies_64.address;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = DRGN_QUALIFIER_VOLATILE;
	if (drgn_type_size(qualified_type.type) == 4 &&
	    !drgn_type_little_endian(qualified_type.type))
		address += 4;
	err = drgn_object_set_reference(ret, qualified_type, address, 0, 0);
out:
	drgn_object_deinit(&jiffies_64);
	return err;
}

static struct drgn_error *
linux_kernel_get_vmcoreinfo(struct drgn_program *prog, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog,
					       DRGN_C_TYPE_CHAR,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = DRGN_QUALIFIER_CONST;
	err = drgn_array_type_create(prog, qualified_type, prog->vmcoreinfo.raw_size,
				     &drgn_language_c, &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_from_buffer(ret, qualified_type, prog->vmcoreinfo.raw,
					   prog->vmcoreinfo.raw_size, 0, 0);
}

// The vmemmap address can vary depending on architecture, kernel version,
// configuration options, and KASLR. However, we can get it generically from the
// section_mem_map of any valid mem_section.
static struct drgn_error *
linux_kernel_get_vmemmap_address(struct drgn_program *prog, uint64_t *ret)
{
	static const uint64_t SECTION_HAS_MEM_MAP = 0x2;
	static const uint64_t SECTION_MAP_MASK = ~((UINT64_C(1) << 6) - 1);
	struct drgn_error *err;

	struct drgn_object mem_section, root, section;
	drgn_object_init(&mem_section, prog);
	drgn_object_init(&root, prog);
	drgn_object_init(&section, prog);

	err = drgn_program_find_object(prog, "vmemmap_populate", NULL,
				       DRGN_FIND_OBJECT_FUNCTION, &mem_section);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			// !CONFIG_SPARSEMEM_VMEMMAP
			drgn_error_destroy(err);
			err = &drgn_not_found;
		}
		goto out;
	}

	err = drgn_program_find_object(prog, "mem_section", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &mem_section);
	if (err)
		goto out;

	const uint64_t nr_section_roots = prog->vmcoreinfo.mem_section_length;
	uint64_t sections_per_root;
	if (drgn_type_kind(mem_section.type) == DRGN_TYPE_ARRAY) {
		// If !CONFIG_SPARSEMEM_EXTREME, mem_section is
		// struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT],
		// and SECTIONS_PER_ROOT is 1.
		sections_per_root = 1;
	} else {
		// If CONFIG_SPARSEMEM_EXTREME, mem_section is
		// struct mem_section **mem_section, and SECTIONS_PER_ROOT is
		// PAGE_SIZE / sizeof(struct mem_section).
		struct drgn_type *mem_section_type = mem_section.type;
		for (int i = 0; i < 2; i++) {
			if (drgn_type_kind(mem_section_type) != DRGN_TYPE_POINTER) {
unrecognized_mem_section_type:
				err = drgn_type_error("mem_section has unrecognized type '%s'",
						      mem_section.type);
				goto out;
			}
			mem_section_type = drgn_type_type(mem_section_type).type;
		}
		if (drgn_type_kind(mem_section_type) != DRGN_TYPE_STRUCT)
			goto unrecognized_mem_section_type;
		uint64_t sizeof_mem_section = drgn_type_size(mem_section_type);
		if (sizeof_mem_section == 0)
			goto unrecognized_mem_section_type;
		sections_per_root =
			prog->vmcoreinfo.page_size / sizeof_mem_section;
	}

	// Find a valid section.
	for (uint64_t i = 0; i < nr_section_roots; i++) {
		err = drgn_object_subscript(&root, &mem_section, i);
		if (err)
			goto out;
		bool truthy;
		err = drgn_object_bool(&root, &truthy);
		if (err)
			goto out;
		if (!truthy)
			continue;

		for (uint64_t j = 0; j < sections_per_root; j++) {
			err = drgn_object_subscript(&section, &root, j);
			if (err)
				goto out;
			err = drgn_object_member(&section, &section,
						 "section_mem_map");
			if (err)
				goto out;
			uint64_t section_mem_map;
			err = drgn_object_read_unsigned(&section,
							&section_mem_map);
			if (err)
				goto out;
			if (section_mem_map & SECTION_HAS_MEM_MAP) {
				*ret = section_mem_map & SECTION_MAP_MASK;
				err = NULL;
				goto out;
			}
		}
	}
	err = &drgn_not_found;

out:
	drgn_object_deinit(&section);
	drgn_object_deinit(&root);
	drgn_object_deinit(&mem_section);
	return err;
}

static struct drgn_error *linux_kernel_get_vmemmap(struct drgn_program *prog,
						   struct drgn_object *ret)
{
	struct drgn_error *err;
	if (prog->vmemmap.kind == DRGN_OBJECT_ABSENT) {
		// Silence -Wmaybe-uninitialized false positive last seen with
		// GCC 13 by initializing to zero.
		uint64_t address = 0;
		err = linux_kernel_get_vmemmap_address(prog, &address);
		if (err)
			return err;
		struct drgn_qualified_type qualified_type;
		err = drgn_program_find_type(prog, "struct page *", NULL,
					     &qualified_type);
		if (err)
			return err;
		err = drgn_object_set_unsigned(&prog->vmemmap, qualified_type,
					       address, 0);
		if (err)
			return err;
	}
	return drgn_object_copy(ret, &prog->vmemmap);
}

#include "linux_kernel_object_find.inc" // IWYU pragma: keep

/*
 * /lib/modules/$(uname -r)/modules.dep.bin maps all installed kernel modules to
 * their filesystem path (and dependencies, which we don't care about). It is
 * generated by depmod; the format is a fairly simple serialized radix tree.
 *
 * modules.dep(5) contains a warning: "These files are not intended for editing
 * or use by any additional utilities as their format is subject to change in
 * the future." But, the format hasn't changed since 2009, and pulling in
 * libkmod is overkill since we only need a very small subset of its
 * functionality (plus our minimal parser is more efficient). If the format
 * changes in the future, we can reevaluate this.
 */

void depmod_index_deinit(struct depmod_index *depmod)
{
	if (depmod->len > 0)
		munmap(depmod->addr, depmod->len);
	free(depmod->path);
}

struct depmod_index_buffer {
	struct binary_buffer bb;
	struct depmod_index *depmod;
};

static struct drgn_error *depmod_index_buffer_error(struct binary_buffer *bb,
						    const char *pos,
						    const char *message)
{
	struct depmod_index_buffer *buffer =
		container_of(bb, struct depmod_index_buffer, bb);
	return drgn_error_format(DRGN_ERROR_OTHER, "%s: %#tx: %s",
				 buffer->depmod->path,
				 pos - (const char *)buffer->depmod->addr,
				 message);
}

static void depmod_index_buffer_init(struct depmod_index_buffer *buffer,
				     struct depmod_index *depmod)
{
	binary_buffer_init(&buffer->bb, depmod->addr, depmod->len, false,
			   depmod_index_buffer_error);
	buffer->depmod = depmod;
}

static struct drgn_error *depmod_index_validate(struct depmod_index *depmod)
{
	struct drgn_error *err;
	struct depmod_index_buffer buffer;
	depmod_index_buffer_init(&buffer, depmod);
	uint32_t magic;
	if ((err = binary_buffer_next_u32(&buffer.bb, &magic)))
		return err;
	if (magic != 0xb007f457) {
		return binary_buffer_error(&buffer.bb,
					   "invalid magic 0x%" PRIx32, magic);
	}
	uint32_t version;
	if ((err = binary_buffer_next_u32(&buffer.bb, &version)))
		return err;
	if (version != 0x00020001) {
		return binary_buffer_error(&buffer.bb,
					   "unknown version 0x%" PRIx32,
					   version);
	}
	return NULL;
}

__attribute__((__format__(__printf__, 2, 3)))
static struct drgn_error *depmod_index_init(struct depmod_index *depmod,
					    const char *path_format,
					    ...)
{
	struct drgn_error *err;

	va_list ap;
	va_start(ap, path_format);
	int r = vasprintf(&depmod->path, path_format, ap);
	va_end(ap);
	if (r < 0)
		return &drgn_enomem;

	int fd = open(depmod->path, O_RDONLY);
	if (fd == -1) {
		err = drgn_error_create_os("open", errno, depmod->path);
		goto out_path;
	}

	struct stat st;
	if (fstat(fd, &st) == -1) {
		err = drgn_error_create_os("fstat", errno, depmod->path);
		goto out_fd;
	}

	if (st.st_size > SIZE_MAX) {
		err = &drgn_enomem;
		goto out_fd;
	}

	void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		err = drgn_error_create_os("mmap", errno, depmod->path);
		goto out_fd;
	}

	depmod->addr = addr;
	depmod->len = st.st_size;

	err = depmod_index_validate(depmod);
	if (err)
		depmod_index_deinit(depmod);
out_fd:
	close(fd);
out_path:
	if (err)
		free(depmod->path);
	return err;
}

/*
 * Look up the path of the kernel module with the given name.
 *
 * @param[in] name Name of the kernel module.
 * @param[out] path_ret Returned path of the kernel module, relative to
 * /lib/modules/$(uname -r). This is @em not null-terminated. @c NULL if not
 * found.
 * @param[out] len_ret Returned length of @p path_ret.
 */
static struct drgn_error *depmod_index_find(struct depmod_index *depmod,
					    const char *name,
					    const char **path_ret,
					    size_t *len_ret)
{
	static const uint32_t INDEX_NODE_MASK = UINT32_C(0x0fffffff);
	static const uint32_t INDEX_NODE_CHILDS = UINT32_C(0x20000000);
	static const uint32_t INDEX_NODE_VALUES = UINT32_C(0x40000000);
	static const uint32_t INDEX_NODE_PREFIX = UINT32_C(0x80000000);

	struct drgn_error *err;
	struct depmod_index_buffer buffer;
	depmod_index_buffer_init(&buffer, depmod);

	/* depmod_index_validate() already checked that this is within bounds. */
	buffer.bb.pos += 8;
	uint32_t offset;
	for (;;) {
		if ((err = binary_buffer_next_u32(&buffer.bb, &offset)))
			return err;
		if ((offset & INDEX_NODE_MASK) > depmod->len) {
			return binary_buffer_error(&buffer.bb,
						   "offset is out of bounds");
		}
		buffer.bb.pos = (const char *)depmod->addr + (offset & INDEX_NODE_MASK);

		if (offset & INDEX_NODE_PREFIX) {
			const char *prefix;
			size_t prefix_len;
			if ((err = binary_buffer_next_string(&buffer.bb,
							     &prefix,
							     &prefix_len)))
				return err;
			if (strncmp(name, prefix, prefix_len) != 0)
				goto not_found;
			name += prefix_len;
		}

		if (offset & INDEX_NODE_CHILDS) {
			uint8_t first, last;
			if ((err = binary_buffer_next_u8(&buffer.bb, &first)) ||
			    (err = binary_buffer_next_u8(&buffer.bb, &last)))
				return err;
			if (*name) {
				uint8_t cur = *name;
				if (cur < first || cur > last)
					goto not_found;
				if ((err = binary_buffer_skip(&buffer.bb,
							      4 * (cur - first))))
					return err;
				name++;
				continue;
			} else {
				if ((err = binary_buffer_skip(&buffer.bb,
							      4 * (last - first + 1))))
					return err;
				break;
			}
		} else if (*name) {
			goto not_found;
		} else {
			break;
		}
	}
	if (!(offset & INDEX_NODE_VALUES))
		goto not_found;

	uint32_t value_count;
	if ((err = binary_buffer_next_u32(&buffer.bb, &value_count)))
		return err;
	if (!value_count)
		goto not_found; /* Or is this malformed? */

	/* Skip over priority. */
	if ((err = binary_buffer_skip(&buffer.bb, 4)))
		return err;

	const char *colon = memchr(buffer.bb.pos, ':',
				   buffer.bb.end - buffer.bb.pos);
	if (!colon) {
		return binary_buffer_error(&buffer.bb,
					   "expected string containing ':'");
	}
	*path_ret = buffer.bb.pos;
	*len_ret = colon - buffer.bb.pos;
	return NULL;

not_found:
	*path_ret = NULL;
	return NULL;
}

struct drgn_error *
drgn_module_try_vmlinux_files(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	const char *osrelease = state->module->prog->vmcoreinfo.osrelease;

	static const char * const debug_dir_paths[] = {
		// Debian, Ubuntu:
		"%s/boot/vmlinux-%s",
		// Fedora, CentOS:
		"%s/lib/modules/%s/vmlinux",
		// SUSE:
		"%s/lib/modules/%s/vmlinux.debug",
	};
	STRING_BUILDER(sb);
	for (size_t i = 0; state->debug_directories[i]; i++) {
		if (state->debug_directories[i][0] != '/')
			continue;
		array_for_each(format, debug_dir_paths) {
			if (!string_builder_appendf(&sb, *format,
						    state->debug_directories[i],
						    osrelease)
			    || !string_builder_null_terminate(&sb))
				return &drgn_enomem;
			err = drgn_module_try_file_internal(state, sb.str, -1,
							    true, NULL);
			if (err || drgn_module_try_files_done(state))
				return err;
			sb.len = 0;
		}
	}

	// Other places where vmlinux might be installed:
	static const char * const paths[] = {
		"/boot/vmlinux-%s",
		"/lib/modules/%s/build/vmlinux",
		"/lib/modules/%s/vmlinux",
	};
	array_for_each(format, paths) {
		if (!string_builder_appendf(&sb, *format, osrelease)
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_file_internal(state, sb.str, -1, true,
						    NULL);
		if (err || drgn_module_try_files_done(state))
			return err;
		sb.len = 0;
	}
	return NULL;
}

struct drgn_error *
drgn_module_try_linux_kmod_files(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;
	struct depmod_index *modules_dep = &prog->dbinfo.modules_dep;

	if (!modules_dep->addr) {
		err = depmod_index_init(modules_dep,
					"/lib/modules/%s/modules.dep.bin",
					prog->vmcoreinfo.osrelease);
		if (err) {
			if (!drgn_error_should_log(err))
				return err;
			drgn_error_log_warning(prog, err,
					       "couldn't open depmod index: ");
			drgn_error_destroy(err);
			modules_dep->path = NULL;
			modules_dep->addr = MAP_FAILED;
			modules_dep->len = 0;
		} else {
			drgn_log_debug(prog, "opened depmod index %s",
				       modules_dep->path);
		}
	}
	if (modules_dep->len == 0)
		return NULL;

	const char *depmod_path;
	size_t depmod_path_len;
	err = depmod_index_find(modules_dep, module->name, &depmod_path,
				&depmod_path_len);
	if (err) {
		drgn_error_log_warning(prog, err,
				       "couldn't parse depmod index: ");
		drgn_error_destroy(err);
		return NULL;
	}
	if (!depmod_path) {
		drgn_log_warning(prog, "couldn't find %s in depmod index",
				 module->name);
		return NULL;
	}
	drgn_log_debug(prog, "found %.*s in depmod index",
		       depmod_path_len > INT_MAX
		       ? INT_MAX : (int)depmod_path_len,
		       depmod_path);

	// Get the length of the path with one extension after ".ko" removed if
	// present (e.g., ".gz", ".xz", or ".zst").
	const char *name = memrchr(depmod_path, '/', depmod_path_len);
	if (name)
		name = name + 1;
	else
		name = depmod_path;
	const char *name_end = depmod_path + depmod_path_len;
	size_t ko_len = depmod_path_len;
	for (int j = 0; j < 2; j++) {
		char *dot = memrchr(name, '.', name_end - name);
		if (!dot)
			break;
		if (name_end - dot == 3
		    && dot[1] == 'k' && dot[2] == 'o') {
			ko_len = name_end - depmod_path;
			break;
		}
		name_end = dot;
	}

	const char *osrelease = prog->vmcoreinfo.osrelease;
	STRING_BUILDER(sb);
	for (size_t i = 0; state->debug_directories[i]; i++) {
		if (state->debug_directories[i][0] != '/')
			continue;
		// Debian, Ubuntu:
		// $debug_dir/lib/modules/$(uname -r)/$ko_name
		if (!string_builder_appendf(&sb, "%s/lib/modules/%s/",
					    state->debug_directories[i],
					    osrelease)
		    || !string_builder_appendn(&sb, depmod_path, ko_len)
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_file_internal(state, sb.str, -1, true,
						    NULL);
		if (err || drgn_module_try_files_done(state))
			return err;

		// Fedora, CentOS, SUSE:
		// $debug_dir/lib/modules/$(uname -r)/$ko_name.debug
		if (!string_builder_append(&sb, ".debug")
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_file_internal(state, sb.str, -1, true,
						    NULL);
		if (err || drgn_module_try_files_done(state))
			return err;
	}

	// TODO: not sure about checking compressed file.
	sb.len = 0;
	if (!string_builder_appendf(&sb, "/lib/modules/%s/", osrelease) ||
	    !string_builder_appendn(&sb, depmod_path, depmod_path_len) ||
	    !string_builder_null_terminate(&sb))
		return &drgn_enomem;
	return drgn_module_try_file_internal(state, sb.str, -1, true, NULL);
}

// This has a weird calling convention so that the caller can call
// drgn_error_format_os() itself.
static const char *get_gnu_build_id_from_note_file(int fd,
						   void **bufp,
						   size_t *buf_capacityp,
						   const void **build_id_ret,
						   size_t *build_id_len_ret)
{
	struct stat st;
	if (fstat(fd, &st) < 0)
		return "fstat";

	if (st.st_size > SSIZE_MAX
	    || !alloc_or_reuse(bufp, buf_capacityp, st.st_size))
		return "";

	ssize_t r = read_all(fd, *bufp, st.st_size);
	if (r < 0)
		return "read";
	*build_id_len_ret = parse_gnu_build_id_from_note(*bufp, r, 4, false,
							 build_id_ret);
	return NULL;
}

static struct drgn_error *
get_build_id_from_sys_kernel_notes(void **buf_ret,
				   const void **build_id_ret,
				   size_t *build_id_len_ret)
{
	static const char path[] = "/sys/kernel/notes";
	_cleanup_close_ int fd = open(path, O_RDONLY);
	if (fd == -1)
		return drgn_error_create_os("open", errno, path);

	_cleanup_free_ void *buf = NULL;
	size_t buf_capacity = 0;
	const char *message = get_gnu_build_id_from_note_file(fd, &buf,
							      &buf_capacity,
							      build_id_ret,
							      build_id_len_ret);
	if (message && message[0])
		return drgn_error_create_os(message, errno, path);
	else if (message)
		return &drgn_enomem;
	*buf_ret = no_cleanup_ptr(buf);
	return NULL;
}

// Arbitrary limit on the number iterations to make through the modules list in
// order to avoid getting stuck in a cycle.
static const int MAX_MODULE_LIST_ITERATIONS = 10000;

struct linux_kernel_loaded_module_iterator {
	struct drgn_module_iterator it;
	bool yielded_vmlinux;
	int module_list_iterations_remaining;
	// `struct module` type.
	struct drgn_qualified_type module_type;
	// `struct list_head *` in next module to yield.
	struct drgn_object node;
	// Address of `struct list_head modules`.
	uint64_t modules_head;
};

static void
linux_kernel_loaded_module_iterator_destroy(struct drgn_module_iterator *_it)
{
	struct linux_kernel_loaded_module_iterator *it =
		container_of(_it, struct linux_kernel_loaded_module_iterator, it);
	drgn_object_deinit(&it->node);
	free(it);
}

static struct drgn_error *
yield_vmlinux(struct linux_kernel_loaded_module_iterator *it,
	      struct drgn_module **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	bool new;
	err = drgn_module_find_or_create_main(prog, "kernel", ret, &new);
	if (err || !new)
		return err;

	if (prog->vmcoreinfo.build_id_len > 0) {
		// Since Linux kernel commit 0935288c6e00 ("kdump: append kernel
		// build-id string to VMCOREINFO") (in v5.9), we can get the
		// build ID from VMCOREINFO.
		err = drgn_module_set_build_id(*ret, prog->vmcoreinfo.build_id,
					       prog->vmcoreinfo.build_id_len);
		if (err)
			goto delete_module;
		drgn_log_debug(prog,
			       "found kernel build ID %s in VMCOREINFO",
			       (*ret)->build_id_str);
	} else if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		// Before that, on the live kernel, we can get the build ID from
		// /sys/kernel/notes.
		_cleanup_free_ void *build_id_buf = NULL;
		const void *build_id;
		size_t build_id_len;
		err = get_build_id_from_sys_kernel_notes(&build_id_buf,
							 &build_id,
							 &build_id_len);
		if (err)
			goto delete_module;
		if (build_id_len > 0) {
			err = drgn_module_set_build_id(*ret, build_id,
						       build_id_len);
			if (err)
				goto delete_module;
			drgn_log_debug(prog,
				       "found kernel build ID %s in /sys/kernel/notes",
				       (*ret)->build_id_str);
		} else {
			drgn_log_debug(prog,
				       "couldn't find kernel build ID in /sys/kernel/notes");
		}
	} else {
		// Otherwise, we can't get the build ID.
		drgn_log_debug(prog, "couldn't find kernel build ID");
	}
	return NULL;

delete_module:
	drgn_module_delete(*ret);
	return err;
}

static struct drgn_error *
kernel_module_set_build_id_live(struct drgn_module *module)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	_cleanup_free_ char *path;
	if (asprintf(&path, "/sys/module/%s/notes", module->name) < 0) {
		path = NULL;
		return &drgn_enomem;
	}
	_cleanup_closedir_ DIR *dir = opendir(path);
	if (!dir) {
		if (errno == ENOENT) {
			drgn_log_debug(prog, "opendir: %s: %m", path);
			return NULL;
		} else {
			return drgn_error_create_os("opendir", errno, path);
		}
	}

	_cleanup_free_ void *buf = NULL;
	size_t capacity = 0;

	struct dirent *ent;
	while ((errno = 0, ent = readdir(dir))) {
		if (ent->d_type == DT_DIR)
			continue;

		_cleanup_close_ int fd = openat(dirfd(dir), ent->d_name,
						O_RDONLY);
		if (fd < 0) {
			return drgn_error_format_os("openat", errno, "%s/%s",
						    path, ent->d_name);
		}

		const void *build_id;
		size_t build_id_len;
		const char *message =
			get_gnu_build_id_from_note_file(fd, &buf, &capacity,
							&build_id,
							&build_id_len);
		if (message && message[0]) {
			return drgn_error_format_os(message, errno, "%s/%s",
						    path, ent->d_name);
		} else if (message) {
			return &drgn_enomem;
		}
		if (build_id_len > 0) {
			err = drgn_module_set_build_id(module, build_id,
						       build_id_len);
			if (!err) {
				drgn_log_debug(prog,
					       "found build ID %s in %s/%s",
					       module->build_id_str, path,
					       ent->d_name);
			}
			return err;
		}
	}
	if (errno)
		return drgn_error_create_os("readdir", errno, path);
	drgn_log_debug(prog, "couldn't find build ID in %s", path);
	return NULL;
}

static struct drgn_error *
kernel_module_set_build_id(struct drgn_module *module,
			   const struct drgn_object *module_obj,
			   bool use_sys_module)
{
	if (use_sys_module)
		return kernel_module_set_build_id_live(module);

	struct drgn_error *err;
	struct drgn_program *prog = module->prog;
	const bool bswap = drgn_platform_bswap(&prog->platform);

	DRGN_OBJECT(attrs, prog);
	DRGN_OBJECT(attr, prog);
	DRGN_OBJECT(tmp, prog);
	_cleanup_free_ void *buf = NULL;
	size_t capacity = 0;

	// n = mod->notes_attrs->notes
	uint64_t n;
	err = drgn_object_member(&attrs, module_obj, "notes_attrs");
	if (err)
		return err;
	err = drgn_object_member_dereference(&tmp, &attrs, "notes");
	if (err)
		return err;
	err = drgn_object_read_unsigned(&tmp, &n);
	if (err)
		return err;

	// attrs = mod->notes_attrs->attrs
	err = drgn_object_member_dereference(&attrs, &attrs, "attrs");
	if (err)
		return err;

	for (uint64_t i = 0; i < n; i++) {
		// attr = attrs[i]
		err = drgn_object_subscript(&attr, &attrs, i);
		if (err)
			return err;

		// address = attr.private
		err = drgn_object_member(&tmp, &attr, "private");
		if (err)
			return err;
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			return err;

		// size = attr.size
		err = drgn_object_member(&tmp, &attr, "size");
		if (err)
			return err;
		uint64_t size;
		err = drgn_object_read_unsigned(&tmp, &size);
		if (err)
			return err;

		if (size > SIZE_MAX || !alloc_or_reuse(&buf, &capacity, size))
			return &drgn_enomem;

		err = drgn_program_read_memory(prog, buf, address, size, false);
		if (err)
			return err;

		const void *build_id;
		size_t build_id_len =
			parse_gnu_build_id_from_note(buf, size, 4, bswap,
						     &build_id);
		if (build_id_len > 0) {
			err = drgn_module_set_build_id(module, build_id,
						       build_id_len);
			if (!err) {
				drgn_log_debug(prog,
					       "found build ID %s in notes_attrs",
					       module->build_id_str);
			}
			return err;
		}
	}
	drgn_log_debug(prog,
		       "couldn't find build ID in notes_attrs");
	return NULL;
}

static struct drgn_error *
kernel_module_set_section_addresses_live(struct drgn_module *module)
{
	struct drgn_program *prog = module->prog;

	_cleanup_free_ char *path;
	if (asprintf(&path, "/sys/module/%s/sections", module->name) < 0) {
		path = NULL;
		return &drgn_enomem;
	}
	_cleanup_closedir_ DIR *dir = opendir(path);
	if (!dir)
		return drgn_error_format_os("opendir", errno, path);

	struct dirent *ent;
	while ((errno = 0, ent = readdir(dir))) {
		if (ent->d_type == DT_DIR)
			continue;

		_cleanup_close_ int fd = openat(dirfd(dir), ent->d_name,
						O_RDONLY);
		if (fd < 0) {
			return drgn_error_format_os("openat", errno, "%s/%s",
						    path, ent->d_name);
		}

		_cleanup_fclose_ FILE *file = fdopen(fd, "r");
		if (!file)
			return drgn_error_create_os("fdopen", errno, NULL);
		uint64_t address;
		if (fscanf(file, "%" SCNx64, &address) != 1) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "could not parse %s/%s",
						 path, ent->d_name);
		}

		drgn_log_debug(prog, "found section %s@0x%" PRIx64 " in %s",
			       ent->d_name, address, path);
		if (!drgn_module_set_section_address(module, ent->d_name,
						     address))
			return &drgn_enomem;
	}
	if (errno)
		return drgn_error_format_os("readdir", errno, path);
	return NULL;
}

static struct drgn_error *
kernel_module_set_section_addresses(struct drgn_module *module,
				    const struct drgn_object *module_obj,
				    bool use_sys_module)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	DRGN_OBJECT(tmp, prog);

	// As of Linux 6.0, the .data..percpu section is not included in the
	// section attributes. (kernel/module/sysfs.c:add_sect_attrs() only
	// creates attributes for sections with the SHF_ALLOC flag set, but
	// kernel/module/main.c:layout_and_allocate() clears the SHF_ALLOC flag
	// for the .data..percpu section.) However, we need this address so that
	// global per-CPU variables will be relocated correctly. Get it from
	// `struct module`.
	err = drgn_object_member(&tmp, module_obj, "percpu");
	if (!err) {
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			return err;
		drgn_log_debug(prog, "module percpu is 0x%" PRIx64, address);
		// struct module::percpu is NULL if the module doesn't have any
		// per-CPU data.
		if (address) {
			if (!drgn_module_set_section_address(module,
							     ".data..percpu",
							     address))
				return &drgn_enomem;
		}
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// struct module::percpu doesn't exist if !SMP.
		drgn_error_destroy(err);
	} else {
		return err;
	}

	if (use_sys_module) {
		err = kernel_module_set_section_addresses_live(module);
		// We could be debugging /proc/kcore without root privileges via
		// an fd that we were passed. If we didn't have permission to
		// access the files in /sys/module/$module/sections, fall back
		// to the non-live path.
		if (!err || err->code != DRGN_ERROR_OS || err->errnum != EACCES)
			return err;
		drgn_error_log_debug(prog, err, "falling back to sect_attrs: ");
		drgn_error_destroy(err);
	}

	DRGN_OBJECT(attrs, prog);
	DRGN_OBJECT(attr, prog);

	err = drgn_object_member(&attrs, module_obj, "sect_attrs");
	if (err)
		return err;

	// i = mod->sect_attrs->nsections
	err = drgn_object_member_dereference(&tmp, &attrs, "nsections");
	if (err)
		return err;
	uint64_t i;
	err = drgn_object_read_unsigned(&tmp, &i);
	if (err)
		return err;

	// attrs = mod->sect_attrs->attrs
	err = drgn_object_member_dereference(&attrs, &attrs, "attrs");
	if (err)
		return err;

	while (i-- > 0) {
		// attr = attrs[i]
		err = drgn_object_subscript(&attr, &attrs, i);
		if (err)
			return err;

		// address = attr.address
		err = drgn_object_member(&tmp, &attr, "address");
		if (err)
			return err;
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			return err;

		// Since Linux kernel commit ed66f991bb19 ("module: Refactor
		// section attr into bin attribute") (in v5.8), the section name
		// is module_sect_attr.battr.attr.name. Before that, it is
		// simply module_sect_attr.name.

		// attr = attr.battr.attr
		err = drgn_object_member(&attr, &attr, "battr");
		if (!err) {
			err = drgn_object_member(&attr, &attr, "attr");
			if (err)
				return err;
		} else {
			if (err->code != DRGN_ERROR_LOOKUP)
				return err;
			drgn_error_destroy(err);
		}
		err = drgn_object_member(&tmp, &attr, "name");
		if (err)
			return err;
		_cleanup_free_ char *name = NULL;
		err = drgn_object_read_c_string(&tmp, &name);
		if (err)
			return err;

		drgn_log_debug(prog,
			       "found section %s@0x%" PRIx64 " in sect_attrs",
			       name, address);
		if (!drgn_module_set_section_address(module, name, address))
			return &drgn_enomem;
	}
	return NULL;
}

static struct drgn_error *
kernel_module_find_or_create_internal(const struct drgn_object *module_obj,
				      struct drgn_module **ret, bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(module_obj);

	struct drgn_module_key key;
	key.kind = DRGN_MODULE_LINUX_KERNEL_LOADABLE;
	uint64_t name_offset;
	err = drgn_type_offsetof(module_obj->type, "name", &name_offset);
	if (err)
		return err;
	if (name_offset >= drgn_object_size(module_obj)
	    || !memchr(drgn_object_buffer(module_obj) + name_offset, '\0',
		       drgn_object_size(module_obj) - name_offset)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "couldn't read module name");
	}
	key.linux_kernel_loadable.name =
		drgn_object_buffer(module_obj) + name_offset;

	DRGN_OBJECT(mem, prog);
	DRGN_OBJECT(val, prog);
	bool layout_in_module = false;
	err = drgn_object_member(&mem, module_obj, "mem");
	if (!err) {
		// Since Linux kernel commit ac3b43283923 ("module: replace
		// module_layout with module_memory") (in v6.4), the base and
		// size are in the `struct module_memory mem[MOD_TEXT]` member
		// of `struct module`.
		err = drgn_program_find_object(prog, "MOD_TEXT", NULL,
					       DRGN_FIND_OBJECT_CONSTANT, &val);
		if (err)
			return err;
		union drgn_value mod_mem_type;
		err = drgn_object_read_integer(&val, &mod_mem_type);
		if (err)
			return err;
		err = drgn_object_subscript(&mem, &mem, mod_mem_type.uvalue);
		if (err)
			return err;
	} else {
		if (err->code != DRGN_ERROR_LOOKUP)
			return err;
		drgn_error_destroy(err);
		// Between that and Linux kernel commit 7523e4dc5057 ("module:
		// use a structure to encapsulate layout.") (in v4.5), the base
		// and size are in the `struct module_layout core_layout` member
		// of `struct module`.
		err = drgn_object_member(&mem, module_obj, "core_layout");
		if (err) {
			if (err->code != DRGN_ERROR_LOOKUP)
				return err;
			drgn_error_destroy(err);
			// Before that, they are directly in the `struct
			// module`.
			layout_in_module = true;
		}
	}
	if (layout_in_module)
		err = drgn_object_member(&val, module_obj, "module_core");
	else
		err = drgn_object_member(&val, &mem, "base");
	if (err)
		return err;
	err = drgn_object_read_unsigned(&val,
					&key.linux_kernel_loadable.base_address);
	if (err)
		return err;

	drgn_log_debug(prog,
		       "found loaded kernel module %s@0x%" PRIx64,
		       key.linux_kernel_loadable.name,
		       key.linux_kernel_loadable.base_address);

	bool new;
	err = drgn_module_find_or_create(prog, &key,
					 key.linux_kernel_loadable.name, ret,
					 &new);
	if (!err && new_ret)
		*new_ret = new;
	if (err || !new)
		return err;

	if (layout_in_module)
		err = drgn_object_member(&val, module_obj, "core_size");
	else
		err = drgn_object_member(&val, &mem, "size");
	if (err)
		goto err_module;
	uint64_t size;
	err = drgn_object_read_unsigned(&val, &size);
	if (err)
		goto err_module;

	drgn_log_debug(prog, "module size is %" PRIu64, size);
	err = drgn_module_set_address_range(*ret,
					    key.linux_kernel_loadable.base_address,
					    key.linux_kernel_loadable.base_address + size);
	if (err)
		goto err_module;


	// If we're debugging the running kernel, we can use
	// /sys/module/$module/notes and /sys/module/$module/sections instead of
	// getting the equivalent information from the core dump. This fast path
	// can be disabled via an environment variable for testing. It may also
	// be disabled if we encounter permission issues using
	// /sys/module/$module/sections.
	// TODO: check if looking this up and falling back for every module is a
	// problem.
	bool use_sys_module = false;
	if (prog->flags & DRGN_PROGRAM_IS_LOCAL) {
		char *env = getenv("DRGN_USE_SYS_MODULE");
		use_sys_module = !env || atoi(env);
	}
	err = kernel_module_set_build_id(*ret, module_obj, use_sys_module);
	if (err)
		goto err_module;
	err = kernel_module_set_section_addresses(*ret, module_obj,
						  use_sys_module);
	if (err)
		goto err_module;

	return NULL;

err_module:
	drgn_module_delete(*ret);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_find_or_create_linux_kernel_loadable(const struct drgn_object *module_obj,
						 struct drgn_module **ret,
						 bool *new_ret)
{
	struct drgn_error *err;

	// kernel_module_find_or_create_internal() expects a `struct module`
	// value.
	struct drgn_object mod;
	if (drgn_type_kind(drgn_underlying_type(module_obj->type))
	    == DRGN_TYPE_POINTER) {
		drgn_object_init(&mod, drgn_object_program(module_obj));
		err = drgn_object_dereference(&mod, module_obj);
		if (!err)
			err = drgn_object_read(&mod, &mod);
		module_obj = &mod;
		if (err)
			goto out;
	} else if (module_obj->kind != DRGN_OBJECT_VALUE) {
		drgn_object_init(&mod, drgn_object_program(module_obj));
		err = drgn_object_read(&mod, module_obj);
		module_obj = &mod;
		if (err)
			goto out;
	}

	err = kernel_module_find_or_create_internal(module_obj, ret, new_ret);
out:
	if (module_obj == &mod)
		drgn_object_deinit(&mod);
	return err;
}

static struct drgn_error *
yield_kernel_module(struct linux_kernel_loaded_module_iterator *it,
		    struct drgn_module **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	DRGN_OBJECT(mod, prog);
	for (;;) {
		uint64_t addr;
		err = drgn_object_read_unsigned(&it->node, &addr);
		if (err) {
list_walk_err:
			if (drgn_error_should_log(err)) {
				drgn_error_log_error(prog, err,
						     "couldn't read next module: ");
				drgn_error_destroy(err);
				*ret = NULL;
				err = NULL;
			}
			return err;
		}
		if (addr == it->modules_head) {
			drgn_log_debug(prog,
				       "found end of loaded kernel module list");
			*ret = NULL;
			return NULL;
		}

		if (it->module_list_iterations_remaining == 0) {
			drgn_log_warning(prog,
					 "too many entries or cycle in modules list; "
					 "can't iterate remaining kernel modules");
			*ret = NULL;
			return NULL;
		}
		it->module_list_iterations_remaining--;

		err = drgn_object_container_of(&mod, &it->node, it->module_type,
					       "list");
		if (err)
			goto list_walk_err;

		err = drgn_object_dereference(&mod, &mod);
		if (err)
			goto list_walk_err;
		// We need several fields from the `struct module`. Especially
		// for /proc/kcore, it is faster to read the entire structure
		// (which is <2kB as of Linux 6.5) from the core dump all at
		// once than it is to read each field individually.
		err = drgn_object_read(&mod, &mod);
		if (err)
			goto list_walk_err;

		err = drgn_object_member(&it->node, &mod, "list");
		if (err)
			goto list_walk_err;
		err = drgn_object_member(&it->node, &it->node, "next");
		if (err)
			goto list_walk_err;

		err = kernel_module_find_or_create_internal(&mod, ret, NULL);
		if (err && drgn_error_should_log(err)) {
			drgn_error_log_error(prog, err, "ignoring module: ");
			drgn_error_destroy(err);
			continue;
		}
		return err;
	}
}

static struct drgn_error *
linux_kernel_loaded_module_iterator_next(struct drgn_module_iterator *_it,
					 struct drgn_module **ret)
{
	struct drgn_error *err;
	struct linux_kernel_loaded_module_iterator *it =
		container_of(_it, struct linux_kernel_loaded_module_iterator, it);
	struct drgn_program *prog = it->it.prog;

	if (!it->yielded_vmlinux) {
		it->yielded_vmlinux = true;
		return yield_vmlinux(it, ret);
	}

	// Start the module list walk if we haven't yet.
	if (!it->module_type.type) {
		err = drgn_program_find_type(prog, "struct module", NULL,
					     &it->module_type);
		if (!err) {
			err = drgn_program_find_object(prog, "modules", NULL,
						       DRGN_FIND_OBJECT_VARIABLE,
						       &it->node);
		}
		if (err && err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			if (!prog->dbinfo.main_module
			    || !prog->dbinfo.main_module->debug_file) {
				drgn_log_warning(prog,
						 "can't find loaded modules without kernel debug info");
			} else {
				drgn_log_debug(prog,
					       "kernel does not have loadable module support");
			}
			*ret = NULL;
			return NULL;
		} else if (err) {
			return err;
		}
		if (it->node.kind != DRGN_OBJECT_REFERENCE) {
			drgn_log_error(prog,
				       "can't get address of modules list");
			*ret = NULL;
			return NULL;
		}
		it->modules_head = it->node.address;
		err = drgn_object_member(&it->node, &it->node, "next");
		if (!err)
			err = drgn_object_read(&it->node, &it->node);
		if (err) {
			if (!drgn_error_should_log(err))
				return err;
			drgn_error_log_error(prog, err,
					     "couldn't read modules list: ");
			drgn_error_destroy(err);
			*ret = NULL;
			return NULL;
		}
	}

	return yield_kernel_module(it, ret);
}

struct drgn_error *
linux_kernel_loaded_module_iterator_create(struct drgn_program *prog,
					   struct drgn_module_iterator **ret)
{
	struct linux_kernel_loaded_module_iterator *it = calloc(1, sizeof(*it));
	if (!it)
		return &drgn_enomem;
	drgn_module_iterator_init(&it->it, prog,
				  linux_kernel_loaded_module_iterator_destroy,
				  linux_kernel_loaded_module_iterator_next);
	it->module_list_iterations_remaining = MAX_MODULE_LIST_ITERATIONS;
	drgn_object_init(&it->node, prog);
	*ret = &it->it;
	return NULL;
}
