all:  beaglepup_tcp  beaglepup_tls

beaglepup_tcp: beaglepup_tcp.c
	gcc -lrt -lmraa -lm -o beaglepup_tcp beaglepup_tcp.c -Wall -Wextra

beaglepup_tls: beaglepup_tls.c
	gcc -lrt -lmraa -lm -o beaglepup_tls beaglepup_tls.c -Wall -Wextra -lssl -lcrypto

.PHONY: clean dist

tar_files = README Makefile beaglepup_tcp.c beaglepup_tls.c

clean:
	rm -f beaglepup_tcp beaglepup_tls beaglepup.tar.gz

dist:
	tar -z -c -f beaglepup.tar.gz $(tar_files)
