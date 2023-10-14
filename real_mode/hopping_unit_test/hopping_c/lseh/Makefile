ifneq ($(KERNELRELEASE),)
    obj-m := sseh.o
    sseh-objs := hopping_core.o hmac.o md5.o sha256.o
else
    PWD := $(shell pwd)
    KVER := $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.o *.mod* *.order *.symvers
endif
