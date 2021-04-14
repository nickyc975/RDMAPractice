PWD=$(shell pwd)
KHEADERS=$(shell uname -r)

obj-m += src/

default:
	make -C /lib/modules/$(KHEADERS)/build M=$(PWD) modules

install_host: default
	-@sudo rmmod cjl-rdma-host
	@sudo insmod src/cjl-rdma-host.ko

clean:
	make -C /lib/modules/$(KHEADERS)/build M=$(PWD) clean
