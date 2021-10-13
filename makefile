COMPILER = gcc
CFLAGS = -Wall -pedantic -g

EXES = generate_ciphertext decrypt_ciphertext parallel_search_keyspace

all: ${EXES}


generate_ciphertext:  generate_ciphertext.c 
	${COMPILER} ${CFLAGS}  generate_ciphertext.c -Wall -pedantic -lcrypto -o generate_ciphertext

decrypt_ciphertext:  decrypt_ciphertext.c 
	${COMPILER} ${CFLAGS}  decrypt_ciphertext.c  -Wall -pedantic -lcrypto -o decrypt_ciphertext


parallel_search_keyspace:  parallel_search_keyspace.c
	${COMPILER} ${CFLAGS}  parallel_search_keyspace.c  -Wall -pedantic -lcrypto -o parallel_search_keyspace

clean: 
	rm -f *~ *.o ${EXES}