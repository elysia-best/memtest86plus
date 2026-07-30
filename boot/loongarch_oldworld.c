#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "boot.h"
#include "bootparams.h"
#include "efi.h"
#include "string.h"
#include "loongarch_oldworld.h"

#if defined(__loongarch_lp64)
#include <larchintrin.h>
#include "registers.h"
#endif

#define DMW1_VA UINT64_C(0x8000000000000000)
#define BPI_MAX_ENTRIES 128
#define BPI_MEM_SIG UINT64_C(0x000000004d454d)

static const efi_guid_t bpi_guid = { 0x4660f721, 0x2ec5, 0x416a, {0x89,0x9a,0x43,0x18,0x02,0x50,0xa0,0xc9} };
static bool oldworld;
static int bpi_version_value;

typedef struct __attribute__((packed)) { uint64_t signature; uint32_t length; uint8_t revision, checksum; uint64_t next; } bpi_ext_hdr_t;
typedef struct __attribute__((packed)) { uint64_t signature, systemtable, extlist, flags; } bpi_hdr_t;
typedef struct __attribute__((packed)) { uint32_t type; uint64_t start, size; } bpi_mem_entry_t;
typedef struct __attribute__((packed)) { bpi_ext_hdr_t h; uint8_t count; bpi_mem_entry_t entries[]; } bpi_mem_t;
typedef struct { uint64_t start, end; uint32_t type; } bpi_range_t;

static bpi_range_t bpi_ranges[BPI_MAX_ENTRIES];
static size_t bpi_range_count;

static uint8_t checksum(const void *p, size_t n) { const uint8_t *b = p; uint8_t s = 0; while (n--) s += *b++; return s; }
static bool add_overflow(uint64_t a, uint64_t b, uint64_t *out) { if (b > UINT64_MAX - a) return true; *out = a + b; return false; }

bool loongarch_oldworld_detect(void)
{
#if defined(__loongarch_lp64)
    /* OldWorld EFI enters with DMW1 enabled for PLV0. This is the same
     * discriminator used by the upstream-derived LoongArch EFI stub patch. */
    oldworld = !!(__csrrd_d(LOONGARCH_CSR_DMWIN1) & UINT64_C(0x10));
#else
    oldworld = false;
#endif
    return oldworld;
}
bool loongarch_oldworld_present(void) { return oldworld; }
uintptr_t loongarch_phys_addr(uintptr_t addr) { return (oldworld && (addr & DMW1_VA)) ? (addr & ~DMW1_VA) : addr; }

static bool guid_equal(const efi_guid_t *a, const efi_guid_t *b) { return memcmp(a, b, sizeof(*a)) == 0; }

void loongarch_oldworld_parse(efi_system_table_t *table)
{
    bpi_range_count = 0; bpi_version_value = 0;
    if (!table || !table->config_tables) return;
    efi_config_table_t *ct = (efi_config_table_t *)loongarch_phys_addr((uintptr_t)table->config_tables);
    for (uintn_t i = 0; i < table->num_config_tables; i++) {
        if (!guid_equal(&ct[i].guid, &bpi_guid)) continue;
        bpi_hdr_t *h = (bpi_hdr_t *)loongarch_phys_addr((uintptr_t)ct[i].table);
        if (!h) return;
        uint64_t sig = h->signature;
        if ((sig & UINT64_C(0xffffff)) != UINT64_C(0x495042)) return;
        /* The wire signatures are the eight-byte strings BPI01000 and
         * BPI01001. Parse all five decimal digits; the public version drops
         * the leading zero and is therefore 1000 or 1001. */
        int ver = 0;
        for (int j = 3; j < 8; j++) {
            char digit = (char)(sig >> (j * 8));
            if (digit < '0' || digit > '9') return;
            ver = ver * 10 + digit - '0';
        }
        if (ver != 1000 && ver != 1001) return;
        bpi_version_value = ver;
        /* Copy the validated MEM extension into static storage while EFI's
         * original DMW mappings are still live. Startup replaces DMW1. */
        uintptr_t ext = loongarch_phys_addr((uintptr_t)h->extlist);
        for (size_t guard = 0; ext && guard < BPI_MAX_ENTRIES; guard++) {
            bpi_ext_hdr_t *eh = (bpi_ext_hdr_t *)ext;
            uint32_t len = eh->length;
            if (len < sizeof(*eh) || len > (1u << 20) || checksum(eh, len) != 0) return;
            if (eh->signature == BPI_MEM_SIG && len >= sizeof(bpi_mem_t)) {
                bpi_mem_t *mm = (bpi_mem_t *)eh;
                size_t count = mm->count;
                if (count > BPI_MAX_ENTRIES || sizeof(*mm) + count * sizeof(mm->entries[0]) > len) return;
                for (size_t j = 0; j < count; j++) {
                    uint64_t end;
                    if (mm->entries[j].size == 0 || add_overflow(mm->entries[j].start, mm->entries[j].size, &end)) return;
                    bpi_ranges[bpi_range_count++] = (bpi_range_t){mm->entries[j].start, end, mm->entries[j].type};
                }
            }
            ext = loongarch_phys_addr((uintptr_t)eh->next);
        }
        return;
    }
}

void loongarch_oldworld_efi_fix(efi_memory_desc_t *map, size_t size, size_t desc_size)
{
    if (!map || desc_size < sizeof(*map)) return;
    for (size_t off = 0; off + sizeof(*map) <= size; off += desc_size) {
        efi_memory_desc_t *d = (efi_memory_desc_t *)((uint8_t *)map + off);
        d->phys_addr = loongarch_phys_addr(d->phys_addr);
        d->virt_addr = loongarch_phys_addr(d->virt_addr);
    }
}

static uint32_t bpi_to_e820(uint32_t type) { return (type == 1 || type == 5) ? E820_RAM : (type == 3 ? E820_ACPI : E820_RESERVED); }
static unsigned e820_priority(uint32_t type)
{
    switch (type) {
      case E820_NVS: return 4;
      case E820_RESERVED: return 3;
      case E820_ACPI: return 2;
      case E820_RAM: return 1;
      default: return 0;
    }
}

void loongarch_oldworld_set_e820(boot_params_t *p)
{
    if (!p || !bpi_range_count) return;
    e820_entry_t all[E820_MAP_SIZE + BPI_MAX_ENTRIES]; size_t n = 0;
    for (size_t i = 0; i < p->e820_entries && n < E820_MAP_SIZE; i++) all[n++] = p->e820_map[i];
    for (size_t i = 0; i < bpi_range_count && n < sizeof(all)/sizeof(all[0]); i++) all[n++] = (e820_entry_t){bpi_ranges[i].start, bpi_ranges[i].end - bpi_ranges[i].start, bpi_to_e820(bpi_ranges[i].type)};
    uint64_t points[(E820_MAP_SIZE + BPI_MAX_ENTRIES) * 2]; size_t np = 0;
    for (size_t i = 0; i < n; i++) { points[np++] = all[i].addr; points[np++] = all[i].addr + all[i].size; }
    for (size_t i = 1; i < np; i++) { uint64_t x = points[i]; size_t j = i; while (j && points[j-1] > x) { points[j] = points[j-1]; j--; } points[j] = x; }
    size_t out = 0;
    for (size_t i = 0; i + 1 < np && out < E820_MAP_SIZE; i++) {
        uint64_t a = points[i], b = points[i+1]; if (a == b) continue; uint32_t type = E820_NONE;
        /* BPI is the RAM inventory, while EFI remains authoritative for
         * reservations. Splitting at every boundary makes reserved/NVS win
         * without requiring allocation or an interval container. */
        for (size_t j = 0; j < n; j++) if (a >= all[j].addr && b <= all[j].addr + all[j].size && e820_priority(all[j].type) > e820_priority(type)) type = all[j].type;
        if (!type) continue;
        if (out && p->e820_map[out-1].type == type && p->e820_map[out-1].addr + p->e820_map[out-1].size == a) p->e820_map[out-1].size += b-a;
        else p->e820_map[out++] = (e820_entry_t){a,b-a,type};
    }
    p->e820_entries = out;
}
int loongarch_bpi_version(void) { return bpi_version_value; }
bool loongarch_bpi1000(void) { return bpi_version_value == 1000; }
