lkm-softperipherals
===================

Software Peripherals Example Linux Kernel Module

Description:
============
This is a Linux kernel module for the Software Defined Peripherals example.
The `soft_peripherals` module creates devices which are used to read and write data via software defined peripherals,
which emulate protocols like UART using GPIO pins. They are a firmware running on the secondary core.
Communication between the module and the firmware is realized using RPMsg.

The example has been tested in the following configuration:

* __UDOO Neo__ board with __NXP i.MX 6SoloX__ dual core processor

* __ARM Cortex-A9__ core running Linux and this kernel module

* __ARM Cortex-M4__ core running __Zephyr RTOS__ firmware, which can be found here:

[https://github.com/NXPmicro/zephyr/tree/soft\_periph/samples/soft\_periph/](https://github.com/NXPmicro/zephyr/tree/soft\_periph/samples/soft\_periph/)

The module takes parameter `soft_periph_config` which describes the devices to create and its configuration:

    # insmod soft_peripherals.ko soft_periph_config='"UART(name=*u0*,txpin=*5.14*,rxpin=*5.15*,baud=*9600*,format=*8N1*);UART(name=*u1*,txpin=*5.12*,rxpin=*5.13*,baud=*19200*,format=*8N1*);"'

The above example creates two devices:

* `/dev/ttySoft0u0` - to emulate UART protocol using GPIO port 5 and pin 14 for TX and 15 for RX. The baud rate is 9600, 8 data bits, no parity and one stop bit.

* `/dev/ttySoft1u1` - to emulate UART protocol using GPIO port 5 and pin 12 for TX and 13 for RX. The baud rate is 19200, 8 data bits, no parity and one stop bit.

The module fills the `soft_periph_config_entry`'s `struct uart` for each of this devices and sends it in a raw binary form to the remote core using RPMsg endpoint 99.
Data written to `/dev/ttySoft0u0` are sent to the remote core via RPMsg endpoint 100. Firmware toggles the GPIO pin 5.14 to emulate the configured protocol output.
Firmware decodes UART data received on the GPIO pin 5.15 and sends it to the primary core, to be read from `/dev/ttySoft0u0`.

Similarly `/dev/ttySoft1u1` exchanges the data using RPMsg endpoint 101.

Cross-compiling using GNU Arm Embedded Toolchain:
=================================================

Make sure your kernel has been compiled with the RPMsg support:

    CONFIG_RPMSG=y

For the instructions about how to enable RPMsg on the UDOO Neo board / UDOObuntu Linux distribution, look here:

[https://gitlab.com/OK2NMZ/embedded-linux-crash-course/blob/master/HandsOn\_remote\_processor\_messaging/README.md](https://gitlab.com/OK2NMZ/embedded-linux-crash-course/blob/master/HandsOn\_remote\_processor\_messaging/README.md)

Set the following environmental variables similarly to this:

    $ export ARCH=arm
    $ export CROSS_COMPILE=~/bin/gcc-arm-none-eabi-4_9-2015q3/bin/arm-none-eabi-
    $ export KERNEL_PATH=path_to_the_kernel_source

Then run make:

    $ make

The module is built into the file `soft_peripherals.ko`.

Building of the Zephyr firmware is described here:

[https://docs.zephyrproject.org/latest/getting\_started/getting\_started.html](https://docs.zephyrproject.org/latest/getting\_started/getting\_started.html)

The path to the Zephyr firmware is `samples/soft_periph/`.

Known limitations:
==================
`/dev/ttySoftX` are just simple character devices, not serial TTY devices. Therefore it is not possible to use `ioctl` and change baud rate etc.

Each device can be opened once for read and once for write at the same time.

Data received for a device not opened for reading are discarded.

Module reloading is not supported.

The only implemented protocol at the moment is UART, 8N1.

Maximum baud rate is limited by the firmware running on a remote core and the number of devices.
The testing configuration has been run with 1 device on 115200 or 4 devices on 57600.

When using multiple baud rates, the highest value has to be divisible by all the others.

The information about parity errors, framing errors, overflow or underrun is not propagated to the kernel module.

The secondary core firmware has to be running before Linux starts. It could be loaded by U-Boot.
