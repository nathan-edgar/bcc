/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <stdbool.h>

#define NSEC_PER_SEC		1000000000ULL

struct ksym {
	const char *name;
	unsigned long addr;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name);

struct sym {
	const char *name;
	unsigned long start;
	unsigned long size;
};

struct syms;

struct syms *syms__load_pid(int tgid);
struct syms *syms__load_file(const char *fname);
void syms__free(struct syms *syms);
const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr);

struct syms_cache;

struct syms_cache *syms_cache__new(int nr);
struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid);
void syms_cache__free(struct syms_cache *syms_cache);

struct partition {
	char *name;
	unsigned int dev;
};

struct partitions;

struct partitions *partitions__load(void);
void partitions__free(struct partitions *partitions);
const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev);
const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name);

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);
void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		unsigned int step, const char *val_type);

unsigned long long get_ktime_ns(void);
int bump_memlock_rlimit(void);

bool is_kernel_module(const char *name);

#endif /* __TRACE_HELPERS_H */
