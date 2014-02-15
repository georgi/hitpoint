hitpoint.o: hitpoint.c
	gcc -Wall -c hitpoint.c -o hitpoint.o

http-parser/http_parser.h:
	git submodule init && git submodule update

sds/sds.h:
	git submodule init && git submodule update
