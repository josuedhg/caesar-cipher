obj-m += caesar-cipher.o
KDIR ?= /lib/modules/$(shell uname -r)/build
 
all:
	make -C $(KDIR)  M=`pwd` modules
 
clean:
	make -C $(KDIR)  M=`pwd` clean

test: all
	sudo insmod caesar-cipher.ko
	gcc caesar-cipher-test.c -o caesar-cipher-test
	./caesar-cipher-test
	sudo rmmod caesar-cipher
