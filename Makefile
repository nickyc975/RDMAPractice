PWD=$(shell pwd)
KHEADERS=$(shell uname -r)

obj-m += src/

default:
	make -C /lib/modules/$(KHEADERS)/build M=$(PWD) modules

.PHONY: install_host
install_host: default
	-@sudo rmmod cjl-rdma-host
	@sudo insmod src/cjl-rdma-host.ko

.PHONY: install_target
install_target: default
	-@sudo rmmod cjl-rdma-target
	@sudo insmod src/cjl-rdma-target.ko

install: install_target install_host

listen: install_target
	@echo l $(shell cat address.txt) > /proc/cjl_rdma_target

connect: install_host
	@echo c $(shell cat address.txt) > /proc/cjl_rdma_host

clean:
	make -C /lib/modules/$(KHEADERS)/build M=$(PWD) clean
