KROOT ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m += bad_udp.o
module:
	@$(MAKE) -C $(KROOT) M=$(PWD) CC=$(CC) modules

clean:
	$(MAKE) -C $(KROOT) M=$(PWD) C=1 clean
