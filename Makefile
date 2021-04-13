PWD=$(shell pwd)
KHEADERS=$(shell uname -r)

obj-m += src/

default:
	make -C /lib/modules/$(KHEADERS)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KHEADERS)/build M=$(PWD) clean
