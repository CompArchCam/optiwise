ARCH = $(shell uname -m)

all: $(patsubst %.c,bin.$(ARCH)/%,$(wildcard *.c))

bin.$(ARCH)/%: %.c | bin.$(ARCH)
	$(CC) -g -O3 $< -o $@
bin.$(ARCH):
	mkdir -p $@
clean:
	rm -rf bin.$(ARCH)
