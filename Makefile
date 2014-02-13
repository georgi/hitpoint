OUTPUT := hitpoint.a
PWD := $(shell pwd)
OBJ := hitpoint.o http-parser/libhttp_parser.o sds/sds.o

build: $(OBJ)
	ar rcs $(OUTPUT) $(OBJ)

%.o: %.c
	gcc -g -Wall -c $< -o $@

http-parser/libhttp_parser.o:
	cd http-parser && make libhttp_parser.o
