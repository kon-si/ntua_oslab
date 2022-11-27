/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Konstantinos Sideris
 * Christos Marres
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	int ret = 0;
	
	WARN_ON ( !(sensor = state->sensor));
	
	if (sensor->msr_data[state->type]->last_update != state->buf_timestamp)
    	{
        debug("State needs refreshing!\n");
        ret = 1; /* If the kernel buffer data timestamp is different from the user 
        buffer data timestamp then the state needs to be refreshed */
    	}

	return ret; /* Return 1 if state needs refresh else return 0 */
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	unsigned long flags;
	struct lunix_sensor_struct *sensor;
	sensor = state->sensor;
	long int result;

	uint16_t data;
	uint32_t timestamp;
	
	debug("entering\n");

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	spin_lock_irqsave(&sensor->lock, flags);
	data = sensor->msr_data[state->type]->values[0]; 
	/* Grab data from the kernel buffer */
	timestamp = sensor->msr_data[state->type]->last_update; 
	/* Grab kernel buffer data timestamp */
	spin_unlock_irqrestore(&sensor->lock, flags);

	if(timestamp > state->buf_timestamp)
	{ /* If kernel buffer data timestamp is different from the user 
        buffer data timestamp update the sensor state */
		switch (state->type) 
		{ /* Find the sensor type and get the correct value 
		from the corresponding lookup table */
			case BATT: result = lookup_voltage[data]; break;
			case TEMP: result = lookup_temperature[data]; break;
			case LIGHT: result = lookup_light[data]; break;
			default: return -EAGAIN; break;
		}

		state->buf_timestamp = timestamp;
		/* Format data as a number with 3 decimals digits */
		state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%ld.%03ld\n", result/1000, result%1000);
	}
	else
	{ /* If kernel buffer data timestamp is not different from the user 
        buffer data timestamp exit with error EAGAIN */
		debug("MSR Timestamp: %d\nbuf_timestamp: %d", timestamp, state->buf_timestamp);
		return -EAGAIN;
	}
	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	int ret;
	unsigned int minor;
	unsigned int type;
	unsigned int sensor;
	struct lunix_chrdev_state_struct *state;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/* Associate this open file with the relevant sensor based on 
	the minor number of the device node [/dev/sensor<NO>-<TYPE>] */
	minor = iminor(inode); /* Find the minor nuber from the special /dev file inode */
	type = minor%8; /* minor = sensor*8 + type => type = minor%8 */
	sensor = minor/8; /* minor = sensor*8 + type => sensor = minor/8 */
	debug("Minor number decoded. Sensor:%d and Type:%d\n", sensor, type);

	/* Allocate a new Lunix character device private state structure */
	state = kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL); 
	state->type = type;
	state->sensor = &lunix_sensors[sensor];

	/* Initialise the sensor's state buffer info */
    	state->buf_lim = 0;
    	state->buf_timestamp = 0;
    	filp->private_data = state;

	/* Initialise the semaphore */
	sema_init(&state->lock,1);
    	ret = 0;

out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/*Release allocated memory*/
	debug("Releasing allocated memory!\n");
   	kfree(filp->private_data);
    	debug("Done releasing memory!");
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	debug("Inside read!");

	if (down_interruptible(&state->lock))
	{ /* Lock semaphore to prevent race conditions with father-child proccesses */
		ret = -ERESTARTSYS;
		goto out;
	}

	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) 
	{
		while (lunix_chrdev_state_update(state) == -EAGAIN) 
		{
            		up(&state->lock);
            		if (filp->f_flags & O_NONBLOCK) 
                	return -EAGAIN; /* If we called lunix_chrdev_read with O_NONBLOCK flag return -EAGAIN*/
            		if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
                	return -ERESTARTSYS; /* Make proccess sleep until it is woken up by lunix_chrdev_state_needs_refresh */
            		if (down_interruptible(&state->lock))
                	return -ERESTARTSYS; /* When the proccess wakes up lock the semaphore */
		}
	}

	debug("After update, start reading");
	
	/* Determine the number of cached bytes to copy to userspace */
	if (*f_pos + cnt >= state->buf_lim)
		cnt = state->buf_lim - *f_pos;

	/* Copy to user space */
	if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt))
	{
        	ret = -EFAULT; /* If unsuccesful exit with error EFAULT */
        	goto out;
    	}
    	
	*f_pos += cnt; /* Update the buffer offset */
	ret = cnt;

	if (*f_pos == state->buf_lim)
        *f_pos = 0; /* Auto-rewind on EOF mode */
out:
	up(&state->lock); /* Unlock semaphore */
	debug("Done reading, returning");
	return ret; /* Return number of bytes read */
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);

	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "Lunix-TNG");
	/*  Register a range of device numbers  */
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	/* Add the char device to the system  */
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
