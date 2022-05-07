all: rng discovery control

CFLAGS=

# utils
rng: common.o utils.o rng.c
	cc $(CFLAGS) rng.c common.o utils.o -o rng

discovery: common.o utils.o discovery.c
	cc $(CFLAGS) discovery.c common.o utils.o -o discovery

control: common.o utils.o control.c
	cc $(CFLAGS) control.c common.o utils.o -o control

# library
common.o: common.c common.h
	cc $(CFLAGS) -c common.c

utils.o: utils.c utils.h
	cc $(CFLAGS) -c utils.c

# misc
clean:
	rm -f common.o utils.o rng discovery control rng.o discovery.o control.o

lint:
	cc $(CFLAGS) -c common.c utils.c rng.c discovery.c control.c -Wall -Wextra -Wno-pointer-sign 

lint_full:
	cc $(CFLAGS) -c common.c utils.c rng.c discovery.c control.c -Wall -Wextra

.PHONY: lint lint_full
