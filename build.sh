#!/bin/bash

gcc main.c elf64.c -o inject
nasm -f elf64 -o payload.o payload.asm;ld -o payload payload.o
