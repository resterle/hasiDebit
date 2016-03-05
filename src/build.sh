gcc -c auto_auth.c -o auto_auth.o
gcc -std=c99 desfire-test.c auto_auth.o -o desfire-test -lfreefare -lnfc
