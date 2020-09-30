all: raw

raw: raw.o
	@ echo 'Building binary using GCC linker: $@'
	gcc -o raw raw.o -W -Wall
	@ echo 'Finished building binary: $@'
	@ echo ' '

raw.o: raw.c
	@ echo 'Building target using GCC compiler: $<'
	gcc -o raw.o raw.c -c -W -Wall 
	@ echo ' '

clean:
	rm -rf *.o *~ raw