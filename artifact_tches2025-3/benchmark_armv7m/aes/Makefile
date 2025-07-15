.PHONY: flash clean

PREFIX	?= arm-none-eabi
CC		= $(PREFIX)-gcc
LD		= $(PREFIX)-gcc
OBJCOPY	= $(PREFIX)-objcopy
OBJDUMP	= $(PREFIX)-objdump
GDB		= $(PREFIX)-gdb

OPENCM3DIR = ../../libopencm3
ARMNONEEABIDIR = /usr/arm-none-eabi
STM32DIR = ../stm32f4

all: firmware_m4.bin
firmware_m4.%: ARCH_FLAGS = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
firmware_m4.o: CFLAGS += -DSTM32F4
$(STM32DIR)/stm32f4_wrapper.o: CFLAGS += -DSTM32F4
firmware_m4.elf: LDSCRIPT = $(STM32DIR)/stm32f4-discovery.ld
firmware_m4.elf: LDFLAGS += -L$(OPENCM3DIR)/lib/ -lopencm3_stm32f4
firmware_m4.elf: OBJS += $(STM32DIR)/stm32f4_wrapper.o 
firmware_m4.elf: $(STM32DIR)/stm32f4_wrapper.o $(OPENCM3DIR)/lib/libopencm3_stm32f4.a

CFLAGS		+= -O3 \
		   -Wall -Wextra -Wimplicit-function-declaration \
		   -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
		   -Wundef -Wshadow \
		   -I$(ARMNONEEABIDIR)/include -I$(OPENCM3DIR)/include \
		   -fno-common $(ARCH_FLAGS) -MD
LDFLAGS		+= --static -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group \
		   -T$(LDSCRIPT) -nostartfiles -Wl,--gc-sections,--no-print-gc-sections \
		   $(ARCH_FLAGS)
LDFLAGS 	+= -lm

# Cymric
OBJS += $(wildcard aes/*.c aes/*.s)
OBJS += $(wildcard modes/cymric/*.c)
# OCB
OBJS += $(wildcard modes/ocb/*.c)
# XOCB
OBJS += $(wildcard modes/xocb/*.c)
# GCM
OBJS += $(wildcard modes/gcm/*.c)
# GCMSIV
OBJS += $(wildcard modes/gcmsiv/*.c)
# GHASH
OBJS += modes/ghash.c


%.bin: %.elf
	$(OBJCOPY) -Obinary $^ $@

%.elf: %.o $(OBJS) $(LDSCRIPT)
	$(LD) -o $@ $< -O3 $(OBJS) $(LDFLAGS)

firmware%.o: main.c
	$(CC) $(CFLAGS) -o $@ -c $^

%.o: %.c 
	$(CC) $(CFLAGS) -o $@ -c $^

flash:
	st-flash --reset write firmware_m4.bin 0x8000000

clean:
	rm -f *.o *.d *.elf *.bin
