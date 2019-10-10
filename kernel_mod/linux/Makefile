obj-m = dnp.o
dnp-y = dnpfamily.o dnpdatagramprotocol.o
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean