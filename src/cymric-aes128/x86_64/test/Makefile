TARGET = main

CC     = gcc
CFLAGS = -Wall -Wextra -Wstrict-prototypes -march=native

LINKER = gcc
LFLAGS = $(CFLAGS) -lm

SRCDIR   = ..
OBJDIR   = .
BINDIR   = .

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

$(BINDIR)/$(TARGET): main.o $(OBJECTS) 
	$(LINKER) main.o $(OBJECTS) $(LFLAGS) -o $@

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f prog *.o
