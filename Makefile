obj-m := soft_peripherals.o

default: soft_peripherals

all: clean soft_peripherals

clean:
	make -C ${KERNEL_PATH} M=$(PWD) clean

soft_peripherals:
	ARCH=arm make -C ${KERNEL_PATH} M=$(PWD) EXTRA_CFLAGS="-DDEBUG" modules
