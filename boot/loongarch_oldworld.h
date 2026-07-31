#ifndef LOONGARCH_OLDWORLD_H
#define LOONGARCH_OLDWORLD_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "bootparams.h"
#include "efi.h"

/* LoongArch legacy EFI/BPI compatibility, based on the Linux/AOSC
 * legacy-firmware series (legacy_boot.c and the LoongArch EFI stub). */
bool loongarch_oldworld_detect(const void *system_table);
bool loongarch_oldworld_present(void);
uintptr_t loongarch_phys_addr(uintptr_t addr);
void loongarch_oldworld_efi_fix(efi_memory_desc_t *map, size_t size, size_t desc_size);
void loongarch_oldworld_parse(efi_system_table_t *table);
void loongarch_oldworld_set_e820(boot_params_t *params);
int loongarch_bpi_version(void);
bool loongarch_bpi1000(void);

#endif
