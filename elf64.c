#include "elf64.h"
#include <stdio.h>
#include <string.h>

Elf64_Phdr* find_elf64_code_segment(uint8_t *data, Elf64_Ehdr* elf_header, uint16_t *section_id){
  Elf64_Phdr * program_header = (Elf64_Phdr*)&data[elf_header->e_phoff];
  Elf64_Phdr* code_segment = NULL;
  for(uint16_t i = 0; i < elf_header->e_phnum; i++){
    if(program_header->p_type == PT_LOAD && (program_header->p_flags & P_FLAG_EXEC) && (program_header->p_flags & P_FLAG_READ)){
      code_segment = program_header;
	  if(section_id){ *section_id = i; }
	  break;
	}
	program_header = (Elf64_Phdr*)&data[elf_header->e_phoff + (elf_header->e_phentsize * i)];
  }

  return code_segment;
}

Elf64_Phdr* find_elf64_gap(uint8_t *data, Elf64_Ehdr* elf_header, uint64_t *gap_offset, uint64_t *gap_size){
  //Find code segment
  uint16_t section_id = 0;
  Elf64_Phdr* code_segment = find_elf64_code_segment(data, elf_header, &section_id);
  if(!code_segment){
    printf("[-] Unable to find code segment!\n");
	return NULL;
  }

  //Calculate next code segment
  uint16_t next_section_id = section_id + 1;
  if(next_section_id > elf_header->e_phnum){
    printf("[-] Unable to find segment after code segment!\n");
	return NULL;
  }
  Elf64_Phdr* next_segment = (Elf64_Phdr*)&data[elf_header->e_phoff + (elf_header->e_phentsize * next_section_id)];

  //Calculate gap_offset and gap_size
  *gap_offset = code_segment->p_offset + code_segment->p_filesz;
  *gap_size = next_segment->p_offset - *gap_offset;

  printf("[+] Gap found at 0x%x (%d bytes available)\n", *gap_offset, *gap_size);
  return code_segment;
}


Elf64_Shdr * find_elf64_section (uint8_t *data, char *name){
  Elf64_Ehdr* elf_hdr = (Elf64_Ehdr *) data;
  Elf64_Shdr *shdr = (Elf64_Shdr *)(data + elf_hdr->e_shoff);
  Elf64_Shdr *sh_strtab = &shdr[elf_hdr->e_shstrndx];
  const char *const sh_strtab_p = data + sh_strtab->sh_offset;
 
  char *sname = NULL;
  for (uint16_t i = 0; i < elf_hdr->e_shnum; i++)
    {
      sname = (char*) (sh_strtab_p + shdr[i].sh_name);
      if (!strcmp (sname, name))  return &shdr[i];
    }
  
  return NULL;
}


