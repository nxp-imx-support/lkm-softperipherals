/*
 * Copyright (C) 2018, NXP
 *
 * SPDX-License-Identifier: GPL-2.0+ and/or BSD-3-Clause
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/rpmsg.h>
#include <linux/kfifo.h>
#include <linux/cdev.h>
#include <linux/mutex.h>

#define CLASS_NAME "rpmsg"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("NXP");
MODULE_DESCRIPTION("Software peripheral implementation via AMP/RPMsg");
MODULE_VERSION("0.9");

static int probed;

/* Stores the device number -- determined automatically */
static int    majorNumber;

/* The device driver class */
static struct class *SoftPeriphClass;

/* The device driver device */
static struct device *SoftPeriphDevice;

/* The prototype functions for the character driver */
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static int soft_periph_set_config(const char *val,
				  const struct kernel_param *kp);
static const struct kernel_param_ops soft_periph_config_ops = {
	.set = soft_periph_set_config,
	.get = param_get_charp,
};

/* "UART(name=*u1*,txpin=*P1.31*,rxpin=*P2.1*,baud=*9600*,format=*8N1*);" */
module_param_cb(soft_periph_config, &soft_periph_config_ops, NULL, S_IRUGO);
MODULE_PARM_DESC(soft_periph_config,
"Configuration communicated to the AMP coprocessor implementing software peripherals.");

static const struct file_operations fops = {
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
};

enum soft_periph_type {
	SOFT_PERIPH_UART,
	SOFT_PERIPH_SPI,
	SOFT_PERIPH_TERMINATOR
};

enum soft_periph_uart_flags {
	UART_HAS_RX = 1,
	UART_HAS_TX = 2,
	/*4, 8, 16 ...*/
};

#define FIFO_SIZE (8192)
#define SOFT_PERIPH_ENTRY_SIZE (16)
#define SOFT_PERIPH_MAX_DEVICES (8)

struct soft_periph_config_entry {
	struct device *dev;
	struct cdev cdev;
	struct mutex lockrx;
	struct mutex locktx;
	int openrx;
	int opentx;
	int hasrx;
	int hastx;
	int idx;
	struct kfifo fifo; /* RX FIFO for synchronous read-out */
	wait_queue_head_t rx_fifo_not_empty;
	struct rpmsg_endpoint *ept;
	enum soft_periph_type type;
	char name[16];

	union {
		char *raw[SOFT_PERIPH_ENTRY_SIZE];
		struct {

			uint8_t type;
			uint8_t flags;

			uint8_t txport;
			uint8_t txpin;
			uint8_t rxport;
			uint8_t rxpin;
			uint16_t padding;
			uint32_t baud; /* 115200 */
			char format[4]; /* 8N1 - data bits, parity, stop bits */
		} uart;

		struct {

			uint8_t type;
			uint8_t flags;

			uint8_t mosiport;
			uint8_t mosipin;
			uint8_t misoport;
			uint8_t misopin;
			uint8_t clkport;
			uint8_t clkpin;
			uint8_t csport;
			uint8_t cspin;
			uint16_t padding;
			uint32_t speed;
		} spi;
	};
};

static struct soft_periph_config_entry
			 soft_periph_config_parsed[SOFT_PERIPH_MAX_DEVICES + 1];
static int soft_periph_config_devices_count;

static int _find_copy_str(const char *searched, char *name, char *out,
			  int maxlen)
{
	char *strp;
	char *strp2;
	int i;
	int len = strlen(name);
	strp = strstr(searched, name);
	if (strp == NULL)
		return -1;

	if (strp[len] != '=')
		return -1;

	if (strp[len+1] != '*')
		return -1;

	strp += len+2;

	strp2 = strchr(strp, '*');
	if (strp2 == NULL)
		return -2;

	len = strp2 - strp;

	if (len >= maxlen)
		return -3;

	for (i = 0; i < len; i++)
		out[i] = *strp++;

	out[i] = '\0';
	return 0;
}

static int _find_copy_u32(const char *searched, char *name, uint32_t *out)
{
	char *strp;
	char *strp2;
	int len = strlen(name);
	strp = strstr(searched, name);
	if (strp == NULL)
		return -1;

	if (strp[len] != '=')
		return -1;

	if (strp[len+1] != '*')
		return -1;

	strp += len+2;

	strp2 = strchr(strp, '*');
	if (strp2 == NULL)
		return -2;

	if (sscanf(strp, "%d", out) == 1)
		return 0;

	return -3;
}

/* Validates and sets soft_periph_config_parsed */
static int soft_periph_set_config(const char *val,
				  const struct kernel_param *kp)
{
	char tmp[32];
	int tmppin, tmpport;
	char *strp;
	const char *startPos = val;
	char *endPos;
	int i;
	#define SP_CHECK_CONFIG(x) do { if ((x) != 0) goto err; } while (0)

	pr_info("SoftPeriph: config = <%s>\n", val);

	for (i = 0; i < SOFT_PERIPH_MAX_DEVICES; i++) {
		strp = strchr(startPos, ';');
		if (strp != NULL) {
			endPos = strp;
			if (!strncmp(startPos, "UART", 4)) {
				pr_info("SoftPeriph: Adding UART node\n");
				soft_periph_config_parsed[i].type =
							SOFT_PERIPH_UART;
				soft_periph_config_parsed[i].uart.type =
							SOFT_PERIPH_UART;
				soft_periph_config_parsed[i].openrx = 0;
				soft_periph_config_parsed[i].opentx = 0;
				soft_periph_config_parsed[i].idx = i;
				soft_periph_config_parsed[i].uart.flags = 0;

				SP_CHECK_CONFIG(_find_copy_str(startPos,
					"name",
					soft_periph_config_parsed[i].name,
					16));

				memset(tmp, 0, 32);
				SP_CHECK_CONFIG(_find_copy_str(startPos,
					"txpin",
					tmp,
					32));
				if (strlen(tmp) != 0) {
					if (sscanf(tmp, "%d.%d", &tmpport,
						   &tmppin) != 2)
						goto err;
					soft_periph_config_parsed[i].uart.txport
							= (uint8_t)tmpport;
					soft_periph_config_parsed[i].uart.txpin
							= (uint8_t)tmppin;
					soft_periph_config_parsed[i].uart.flags
							|= UART_HAS_TX;
					soft_periph_config_parsed[i].hastx = 1;
				} else {
					soft_periph_config_parsed[i].uart.txport
									= 0xFF;
					soft_periph_config_parsed[i].uart.txport
									= 0xFF;
					soft_periph_config_parsed[i].hastx = 0;
				}

				memset(tmp, 0, 32);
				SP_CHECK_CONFIG(_find_copy_str(startPos,
					"rxpin",
					tmp,
					32));
				if (strlen(tmp) != 0) {
					if (sscanf(tmp, "%d.%d", &tmpport,
						   &tmppin) != 2)
						goto err;
					soft_periph_config_parsed[i].uart.rxport
							= (uint8_t)tmpport;
					soft_periph_config_parsed[i].uart.rxpin
							= (uint8_t)tmppin;
					soft_periph_config_parsed[i].uart.flags
							|= UART_HAS_RX;
					soft_periph_config_parsed[i].hasrx = 1;
				} else {
					soft_periph_config_parsed[i].uart.rxport
									= 0xFF;
					soft_periph_config_parsed[i].uart.rxport
									= 0xFF;
					soft_periph_config_parsed[i].hasrx = 0;
				}

				SP_CHECK_CONFIG(_find_copy_str(startPos,
							       "format",
				  soft_periph_config_parsed[i].uart.format, 4));

				SP_CHECK_CONFIG(_find_copy_u32(startPos,
							       "baud",
				      &soft_periph_config_parsed[i].uart.baud));


			} else if (!strncmp(startPos, "SPI", 3)) {
				pr_info("SoftPeriph: Adding SPI node\n");
				soft_periph_config_parsed[i].type =
								SOFT_PERIPH_SPI;
			} else {
				pr_info("SoftPeriph: Done adding nodes\n");
				break;
			}
			startPos = endPos + 1;
		} else {
			pr_info(
			"SoftPeriph: Done adding nodes - no new nodes found\n");
			break;
		}
	}
	soft_periph_config_parsed[i].type = SOFT_PERIPH_TERMINATOR;
	soft_periph_config_devices_count = i;

	return 0;

err:
	return -EINVAL;
}

/*
 *
 * mmmmm  mmmmm  m    m
 * #   "# #   "# ##  ##  mmm    mmmm
 * #mmmm" #mmm#" # ## # #   "  #" "#
 * #   "m #      # "" #  """m  #   #
 * #    " #      #    # "mmm"  "#m"#
 *                              m  #
 *                               ""
 */

#define SOFT_PERIPH_ANNOUNCE_EP (99)
#define SOFT_PERIPH_TXRX_EP_BASE (100)

static void rpmsg_soft_periph_cb(struct rpmsg_channel *rpdev, void *data,
				 int len, void *priv, u32 src)
{
	int retlen;
	struct soft_periph_config_entry *entry = NULL;
	int idx = (src-SOFT_PERIPH_TXRX_EP_BASE);
	print_hex_dump(KERN_INFO, "SoftPeriph: incoming message:",
		       DUMP_PREFIX_NONE, 16, 1, data, len, true);

	entry = (struct soft_periph_config_entry *)priv;
	if ((idx >= 0) && (idx < soft_periph_config_devices_count)) {
		if (entry->openrx) {
			pr_info("SoftPeriph: Data for device id %d", idx);
			retlen = kfifo_in(&entry->fifo, data, len);
			pr_info(
			      "SoftPeriph: kfifo_in returns %d, requested %d\n",
				retlen, len);

			if (retlen < len) { /* Too fast, dropping...  */
				pr_info("SoftPeriph: dropping...\n");
			}

			/* Notify blocked readers, if any */
			wake_up_interruptible(&entry->rx_fifo_not_empty);
		} else {
			pr_info(
			  "SoftPeriph: dropping data for closed device id %d\n",
				idx);
		}
	} else {
		pr_info("SoftPeriph: Received data at unknown endpoint (%d)\n",
			src);
	}
}

static int rpmsg_soft_periph_probe(struct rpmsg_channel *rpdev)
{
	int err;
	int i;
	struct rpmsg_endpoint *ept = NULL;
	char buffer[SOFT_PERIPH_ENTRY_SIZE*SOFT_PERIPH_MAX_DEVICES];

	probed = 1;

	pr_info("SoftPeriph: new channel 0x%x -> 0x%x\n",
		rpdev->src, rpdev->dst);

	for (i = 0; i < soft_periph_config_devices_count; i++) {
		ept = rpmsg_create_ept(rpdev, rpmsg_soft_periph_cb,
		   &soft_periph_config_parsed[i], SOFT_PERIPH_TXRX_EP_BASE + i);
		if (NULL == ept) {
			pr_info(
				"SoftPeriph: cannot create endpoints for devices\n");
			return -1;
		}

		soft_periph_config_parsed[i].ept = ept;
		memcpy(&buffer[i * SOFT_PERIPH_ENTRY_SIZE],
		      soft_periph_config_parsed[i].raw, SOFT_PERIPH_ENTRY_SIZE);
	}

	/* send a message on our channel */
	err = rpmsg_sendto(rpdev, buffer,
		soft_periph_config_devices_count * SOFT_PERIPH_ENTRY_SIZE,
		SOFT_PERIPH_ANNOUNCE_EP);
	if (err) {
		pr_info("SoftPeriph: rpmsg_send failed: %d\n", err);
		return err;
	}

	pr_info("SoftPeriph: Devices ready for input / output\n");

	return 0;
}

static void rpmsg_soft_periph_remove(struct rpmsg_channel *rpdev)
{
	pr_info("SoftPeriph: rpmsg sample client driver is removed\n");
}

static struct rpmsg_device_id rpmsg_driver_soft_periph_id_table[] = {
	{ .name = "rpmsg-software-peripheral" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_driver_soft_periph_id_table);

static struct rpmsg_driver rpmsg_soft_periph_client = {
	.drv.name       = KBUILD_MODNAME,
	.id_table       = rpmsg_driver_soft_periph_id_table,
	.probe          = rpmsg_soft_periph_probe,
	.callback       = rpmsg_soft_periph_cb,
	.remove         = rpmsg_soft_periph_remove,
};

/*
 *
 * mmmmm  mm   m mmmmm mmmmmmm      m mmmmmm m    m mmmmm mmmmmmm
 *   #    #"m  #   #      #        #  #       #  #    #      #
 *   #    # #m #   #      #       #   #mmmmm   ##     #      #
 *   #    #  # #   #      #      #    #       m""m    #      #
 * mm#mm  #   ## mm#mm    #     #     #mmmmm m"  "m mm#mm    #
 *                             "
 */

static int __init SoftPeriph_init(void)
{
	int i;
	char deviceName[32];
	dev_t baseDev;
	dev_t currDev;
	int ret;
	probed = 0;
	pr_info("SoftPeriph: Initializing the SoftPeriph LKM\n");

	/* Try to dynamically allocate a major number for the device */
	ret = alloc_chrdev_region(&baseDev, 0, SOFT_PERIPH_MAX_DEVICES,
	THIS_MODULE->name);
	if (ret < 0) {
		pr_alert("SoftPeriph failed to register a major number\n");
		return majorNumber;
	}
	majorNumber = MAJOR(baseDev);
	pr_info(
	  "SoftPeriph: registered correctly with major number %d and name %s\n",
		majorNumber, THIS_MODULE->name);

	/* Register the device class */
	SoftPeriphClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(SoftPeriphClass)) {
		unregister_chrdev(majorNumber, THIS_MODULE->name);
		pr_alert("Failed to register device class\n");
		return PTR_ERR(SoftPeriphClass);
	}
	pr_info("SoftPeriph: device class registered correctly\n");

	for (i = 0; i < SOFT_PERIPH_MAX_DEVICES; i++) {
		pr_info("SoftPeriph: Device n.%d\n", i);
		if (soft_periph_config_parsed[i].type == SOFT_PERIPH_UART) {
			pr_info("SoftPeriph: UART {\n");
			pr_info("SoftPeriph: \tname <%s>\n",
				soft_periph_config_parsed[i].name);
			pr_info("SoftPeriph: \ttxpin <%d.%d>\n",
				soft_periph_config_parsed[i].uart.txport,
				soft_periph_config_parsed[i].uart.txpin);
			pr_info("SoftPeriph: \trxpin <%d.%d>\n",
				soft_periph_config_parsed[i].uart.rxport,
				soft_periph_config_parsed[i].uart.rxpin);
			pr_info("SoftPeriph: \tformat <%s>\n",
				soft_periph_config_parsed[i].uart.format);
			pr_info("SoftPeriph: \tbaud <%d>\n",
				soft_periph_config_parsed[i].uart.baud);
			pr_info("SoftPeriph: }\n");

			/* Register the device driver */
			sprintf(deviceName, "ttySoft%d%s",
				i, soft_periph_config_parsed[i].name);
		} else if (soft_periph_config_parsed[i].type ==
			   SOFT_PERIPH_TERMINATOR) {
			pr_info("SoftPeriph: END\n");
			break;
		} else {
			pr_info("SoftPeriph: ERROR!!!\n");
			break;
		}

		currDev = MKDEV(MAJOR(baseDev), MINOR(baseDev) + i);

		SoftPeriphDevice = device_create(SoftPeriphClass, NULL, currDev,
						 NULL, deviceName);
		if (IS_ERR(SoftPeriphDevice)) {
			/* Clean up if there is an error */
			/* Repeated but the alternative is goto statements */
			class_destroy(SoftPeriphClass);
			unregister_chrdev(majorNumber, THIS_MODULE->name);
			pr_alert("SoftPeriph: Failed to create the device\n");
			return PTR_ERR(SoftPeriphDevice);
		}

		cdev_init(&soft_periph_config_parsed[i].cdev, &fops);
		soft_periph_config_parsed[i].cdev.owner = THIS_MODULE;

		if (cdev_add(&soft_periph_config_parsed[i].cdev, currDev, 1)) {
			/* Repeated but the alternative is goto statements */
			class_destroy(SoftPeriphClass);
			unregister_chrdev(majorNumber, THIS_MODULE->name);
			pr_alert("SoftPeriph: Failed to add the device\n");
			return PTR_ERR(SoftPeriphClass);
		}

		mutex_init(&soft_periph_config_parsed[i].lockrx);
		mutex_init(&soft_periph_config_parsed[i].locktx);

	}

	pr_info("SoftPeriph: Nodes created successfully\n");

	i = register_rpmsg_driver(&rpmsg_soft_periph_client);
	if (i < 0) {
		/* Repeated but the alternative is goto statements */
		class_destroy(SoftPeriphClass);
		unregister_chrdev(majorNumber, THIS_MODULE->name);
		pr_info("SoftPeriph: failed to register rpmsg driver\n");
		return i;
	}

	return 0;
}

static void __exit SoftPeriph_exit(void)
{
	/* remove the device */
	device_destroy(SoftPeriphClass, MKDEV(majorNumber, 0));

	/* unregister the device class */
	class_unregister(SoftPeriphClass);

	/* remove the device class */
	class_destroy(SoftPeriphClass);

	/* unregister the major number */
	unregister_chrdev(majorNumber, THIS_MODULE->name);

	unregister_rpmsg_driver(&rpmsg_soft_periph_client);

	pr_info("SoftPeriph: Goodbye from the LKM!\n");
}

/*
  mmmm  mmmmmm mmmmm  mmmmm    mm   m
 #"   " #      #   "#   #      ##   #
 "#mmm  #mmmmm #mmmm"   #     #  #  #
     "# #      #   "m   #     #mm#  #
 "mmm#" #mmmmm #    " mm#mm  #    # #mmmmm

*/

static int dev_open(struct inode *inodep, struct file *filep)
{
	struct soft_periph_config_entry *entry = NULL;

	pr_info("SoftPeriph: Device has been opened\n");
	BUG_ON(!inodep);
	BUG_ON(!filep);

	if (!probed) {
		pr_info("SoftPeriph: Not yet probed!\n");
		return -EBUSY;
	}

	entry = container_of(inodep->i_cdev, struct soft_periph_config_entry,
			     cdev);
	pr_info("SoftPeriph: entry %p, inodep %p, i_cdev %p",
		entry, inodep, inodep->i_cdev);

	if ((filep->f_mode & FMODE_READ) && (entry->hasrx == 0)) {
		pr_info("SoftPeriph: Device has no read capability.\n");
		return -EPERM;
	}

	if ((filep->f_mode & FMODE_WRITE) && (entry->hastx == 0)) {
		pr_info("SoftPeriph: Device has no write capability.\n");
		return -EPERM;
	}

	if (filep->f_mode & FMODE_WRITE) {
		if (!mutex_trylock(&entry->locktx)) {
			pr_info(
		       "SoftPeriph: Multiple open in write mode not allowed\n");
			pr_info("SoftPeriph: %p %p %p %p\n",
				entry, inodep->i_cdev,
				&soft_periph_config_parsed[0],
				&soft_periph_config_parsed[1]);
			return -EBUSY;
		}

		entry->opentx = 1;
	}

	if (filep->f_mode & FMODE_READ) {
		/* Ensure that only one process
		 * has access to our device at any one time
		 */
		if (!mutex_trylock(&entry->lockrx)) {
			pr_info(
			"SoftPeriph: Multiple open in read mode not allowed\n");
			pr_info("SoftPeriph: %p %p %p %p\n",
				entry, inodep->i_cdev,
				&soft_periph_config_parsed[0],
				&soft_periph_config_parsed[1]);

			if (filep->f_mode & FMODE_WRITE) {
				entry->opentx = 0;
				mutex_unlock(&entry->locktx);
			}

			return -EBUSY;
		}

		if (kfifo_alloc(&entry->fifo, FIFO_SIZE, GFP_KERNEL)) {
			pr_info("SoftPeriph: Allocate kfifo failed!\n");

			if (filep->f_mode & FMODE_WRITE) {
				entry->opentx = 0;
				mutex_unlock(&entry->locktx);
			}

			mutex_unlock(&entry->lockrx);

			return -ENOMEM;
		}
		init_waitqueue_head(&entry->rx_fifo_not_empty);

		entry->openrx = 1;
	}

	filep->private_data = entry;

	return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len,
			loff_t *offset) {

	int copied = 0;
	int ret = -1;
	struct soft_periph_config_entry *entry = NULL;

	BUG_ON(!filep);
	BUG_ON(!buffer);

	entry = (struct soft_periph_config_entry *)filep->private_data;
	BUG_ON(!entry);
	pr_info("SoftPeriph: Reading %d bytes from device %d\n",
		(int)len, entry->idx);

	if (kfifo_is_empty(&entry->fifo)) {
		if (filep->f_flags & O_NONBLOCK) {
			pr_info("SoftPeriph: RX FIFO empty\n");
			return -EAGAIN;
		} else {
			pr_info("SoftPeriph: RX FIFO empty, blocking\n");
		}

		if (wait_event_interruptible(entry->rx_fifo_not_empty,
					     !kfifo_is_empty(&entry->fifo))) {
			pr_info("SoftPeriph: -ERESTARTSYS\n");
			return -ERESTARTSYS;
		}
	}

	ret = kfifo_to_user(&entry->fifo, buffer, len, &copied);
	pr_info("SoftPeriph: Read returns %d, copied %d\n", ret, copied);

	return ret ? ret : copied;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len,
			 loff_t *offset) {
	int err;
	struct soft_periph_config_entry *entry = NULL;
	char txbuff[512];
	BUG_ON(!filep);

	pr_info("SoftPeriph: called dev_write(%p, %p, %d, %p)\n", filep, buffer,
		(int)len, offset);

	entry = (struct soft_periph_config_entry *)filep->private_data;
	BUG_ON(!entry);

	if (copy_from_user(txbuff, buffer, len)) {
		pr_info("SoftPeriph: user to kernel buff copy error.\n");
		return -1;
	}

	pr_info("SoftPeriph: Writing %d bytes to device %d\n", (int)len,
		entry->idx);

	BUG_ON(!(entry->ept));
	BUG_ON(!(entry->ept->rpdev));

	err = rpmsg_sendto(entry->ept->rpdev, txbuff, len, entry->ept->addr);
	if (err) {
		pr_info("SoftPeriph: rpmsg_sendto failed: %d\n", err);
		return err;
	}

	pr_info("SoftPeriph: dev_write returns %d\n", len);

	return len;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
	struct soft_periph_config_entry *entry = NULL;

	BUG_ON(!inodep);
	BUG_ON(!filep);

	pr_info("SoftPeriph: Device successfully closed\n");

	entry = (struct soft_periph_config_entry *)filep->private_data;

	if (filep->f_mode & FMODE_READ) {
		entry->openrx = 0;
		kfifo_free(&entry->fifo);
		mutex_unlock(&entry->lockrx);
	}

	if (filep->f_mode & FMODE_WRITE) {
		entry->opentx = 0;
		mutex_unlock(&entry->locktx);
	}

	return 0;
}

module_init(SoftPeriph_init);
module_exit(SoftPeriph_exit);
