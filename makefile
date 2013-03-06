# testfile make

CFLAGS=-O -Wall
CC=gcc
OBJS=id3_tag_repair.o
EXE=id3repair

# output execute
$(EXE): $(OBJS)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

# compile c source code
%.o: %.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<

#clean
clean:
	@rm *.o *.exe
