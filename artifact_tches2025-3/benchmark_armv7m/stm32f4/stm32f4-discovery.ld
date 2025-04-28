/*
 * This file is part of the libopencm3 project.
 *
 * Copyright (C) 2009 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2011 Stephen Caudle <scaudle@doceme.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 

/* Linker script for ST STM32F4DISCOVERY (STM32F407VG, 1024K flash, 128K RAM).

/* Define memory regions.
MEMORY
{

    ram (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
    rom (rx) : ORIGIN = 0x08000000, LENGTH = 1024K
    ccm (rwx) : ORIGIN = 0x10000000, LENGTH = 64K

}

/* Include the common ld script.
INCLUDE cortex-m-generic.ld
*/

EXTERN(vector_table)
ENTRY(reset_handler)
MEMORY
{
 ram (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
 rom (rx) : ORIGIN = 0x08000000, LENGTH = 1024K
 ccm (rwx) : ORIGIN = 0x10000000, LENGTH = 64K
}
SECTIONS
{
 .text : {
  *(.vectors)
  *(.text*)
  . = ALIGN(4);
  *(.rodata*)
  . = ALIGN(4);
 } >rom
 .preinit_array : {
  . = ALIGN(4);
  __preinit_array_start = .;
  KEEP (*(.preinit_array))
  __preinit_array_end = .;
 } >rom
 .init_array : {
  . = ALIGN(4);
  __init_array_start = .;
  KEEP (*(SORT(.init_array.*)))
  KEEP (*(.init_array))
  __init_array_end = .;
 } >rom
 .fini_array : {
  . = ALIGN(4);
  __fini_array_start = .;
  KEEP (*(.fini_array))
  KEEP (*(SORT(.fini_array.*)))
  __fini_array_end = .;
 } >rom
 .ARM.extab : {
  *(.ARM.extab*)
 } >rom
 .ARM.exidx : {
  __exidx_start = .;
  *(.ARM.exidx*)
  __exidx_end = .;
 } >rom
 . = ALIGN(4);
 _etext = .;
 .data : {
  _data = .;
  *(.data*)
  . = ALIGN(4);
  _edata = .;
 } >ram AT >rom
 _data_loadaddr = LOADADDR(.data);
 .bss : {
  *(.bss*)
  *(COMMON)
  . = ALIGN(4);
  _ebss = .;
 } >ram
 .ccm : {
  *(.ccmram*)
  . = ALIGN(4);
 } >ccm AT >rom
 /DISCARD/ : { *(.eh_frame) }
 . = ALIGN(4);
 end = .;
}
PROVIDE(_stack = ORIGIN(ram) + LENGTH(ram));
