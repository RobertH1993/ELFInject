#include <elf.h>
#include <unistd.h>
#include <stdint.h>

#define P_FLAG_EXEC 0x01
#define P_FLAG_READ 0x04



Elf64_Phdr* find_elf64_code_segment(uint8_t *data, Elf64_Ehdr* elf_header, uint16_t *section_id);

Elf64_Phdr* find_elf64_gap(uint8_t *data, Elf64_Ehdr* elf_header, uint64_t *gap_offset, uint64_t *gap_size);

Elf64_Shdr * find_elf64_section (uint8_t *data, char *name);


