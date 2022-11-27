/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int *syscall_type;
	int *host_fd;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sgs[0] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[1] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* Lock semaphore to prevent race conditions with father-child proccesses */
	if (down_interruptible(&crdev->lock)) {
		ret = -EINTR;
		debug("down_interruptible() interrupted by signal");
		goto fail;
	}

	err = virtqueue_add_sgs(crdev->vq, sgs, 1, 1, &syscall_type_sg, GFP_ATOMIC);
	if (err < 0) {
		ret = err;
                debug("virtqueue_add_sgs() error");
		up(&crdev->lock);
                goto fail;
	}
	if(!virtqueue_kick(crdev->vq)) {
		ret = -EAGAIN;
                debug("virtqueue_kick() error");
		up(&crdev->lock);
                goto fail;
	}
	/* Do nothing until we receive response from host */
	while (virtqueue_get_buf(crdev->vq, &len) == NULL);
		
	up(&crdev->lock);

	/* If host failed to open() return -ENODEV. */
	if (crof->host_fd < 0) {
		ret = -ENODEV;
		debug("host open error %d", crof->host_fd);
	}
	else {
		debug("host open /dev/crypto with cfd %d", crof->host_fd);
	}
		
fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int *syscall_type, len;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
        sgs[0] = &syscall_type_sg;
        sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
        sgs[1] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	if (down_interruptible(&crdev->lock)) {
		ret = -EINTR;
		debug("down_interruptible() interrupted by signal");
                goto fail_close;
	}

        err = virtqueue_add_sgs(crdev->vq, sgs, 2, 0, &syscall_type_sg, GFP_ATOMIC);
	if (err < 0) {
                ret = err;
                debug("virtqueue_add_sgs() error");
		up(&crdev->lock);
                goto fail_close;
        }
	if(!virtqueue_kick(crdev->vq)) {
                ret = -EAGAIN;
                debug("virtqueue_kick() error");
                up(&crdev->lock);
                goto fail_close;
        }
        /* Do nothing until we receive response from host */
        while (virtqueue_get_buf(crdev->vq, &len) == NULL);

        up(&crdev->lock);

fail_close:
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err, *host_ret = NULL;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, cmd_type_sg,  host_fd_sg, sess_sg, key_sg, ses_sg, cryp_sg, inv_sg, host_ret_sg, src_sg, dst_sg, *sgs[11];
	unsigned int num_out, num_in, len;
	unsigned char *src = NULL, *dst = NULL, *key = NULL, *inv = NULL;
	unsigned int *syscall_type, *cmd_type = NULL;
	uint32_t *ses = NULL;
	struct session_op *sess = NULL;
	struct crypt_op *cryp = NULL;
	#define INV_SIZE 16

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
        sgs[num_out++] = &host_fd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");

		cmd_type = kzalloc(sizeof(*cmd_type), GFP_KERNEL);
		*cmd_type = VIRTIO_CRYPTODEV_IOCTL_CIOCGSESSION;
		sg_init_one(&cmd_type_sg, cmd_type, sizeof(*cmd_type));
		sgs[num_out++] = &cmd_type_sg;
	
		sess = kzalloc(sizeof(*sess), GFP_KERNEL);
		if (copy_from_user(sess, (struct session_op *)arg, sizeof(*sess))) {
            		debug("copy_from_user sess failed");
            		ret = -EFAULT;
            		goto fail_ioctl;
        	}
		sg_init_one(&sess_sg, sess, sizeof(*sess));
                sgs[num_out++] = &sess_sg;

		key = kzalloc(sess->keylen, GFP_KERNEL);
		if (copy_from_user(key, sess->key, sess->keylen)) {
                        debug("copy_from_user key failed");
                        ret = -EFAULT;
                        goto fail_ioctl;
                }
		sg_init_one(&key_sg, key, sess->keylen);
                sgs[num_out++] = &key_sg;

		sg_init_one(&sess_sg, sess, sizeof(*sess));
                sgs[num_out + num_in++] = &sess_sg;

		host_ret = kzalloc(sizeof(*host_ret), GFP_KERNEL);
		sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
                sgs[num_out + num_in++] = &host_ret_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");

		cmd_type = kzalloc(sizeof(*cmd_type), GFP_KERNEL);
                *cmd_type = VIRTIO_CRYPTODEV_IOCTL_CIOCFSESSION;
                sg_init_one(&cmd_type_sg, cmd_type, sizeof(*cmd_type));
                sgs[num_out++] = &cmd_type_sg;
		
		ses = kzalloc(sizeof(uint32_t), GFP_KERNEL);
		if (copy_from_user(ses, (uint32_t *)arg, sizeof(*ses))) {
            		debug("copy_from_user ses failed");
            		ret = -EFAULT;
            		goto fail_ioctl;
        	}
		sg_init_one(&ses_sg, ses, sizeof(*ses));
                sgs[num_out++] = &ses_sg;

		host_ret = kzalloc(sizeof(*host_ret), GFP_KERNEL);
                sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
                sgs[num_out + num_in++] = &host_ret_sg;
		
		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		
		cmd_type = kzalloc(sizeof(*cmd_type), GFP_KERNEL);
                *cmd_type = VIRTIO_CRYPTODEV_IOCTL_CIOCCRYPT;
                sg_init_one(&cmd_type_sg, cmd_type, sizeof(*cmd_type));
                sgs[num_out++] = &cmd_type_sg;

		cryp = kzalloc(sizeof(*cryp), GFP_KERNEL);
		if (copy_from_user(cryp, (struct crypt_op *)arg, sizeof(*cryp))) {
            		debug("copy_from_user cryp failed");
            		ret = -EFAULT;
            		goto fail_ioctl;
        	}
		sg_init_one(&cryp_sg, cryp, sizeof(*cryp));
                sgs[num_out++] = &cryp_sg;
		
		inv = kzalloc(INV_SIZE, GFP_KERNEL);
                if (copy_from_user(inv, cryp->iv, INV_SIZE)) {
                        debug("copy_from_user inv failed");
                        ret = -EFAULT;
                        goto fail_ioctl;
                }
		sg_init_one(&inv_sg, inv, sizeof(*inv));
                sgs[num_out++] = &inv_sg;				
		
		src = kzalloc(cryp->len, GFP_KERNEL);
                if (copy_from_user(src, cryp->src, cryp->len)) {
                        debug("copy_from_user src failed");
                        ret = -EFAULT;
                        goto fail_ioctl;
                }
		sg_init_one(&src_sg, src, cryp->len);
                sgs[num_out++] = &src_sg;
	
		dst = kzalloc(cryp->len, GFP_KERNEL);
		sg_init_one(&dst_sg, dst, cryp->len);
                sgs[num_out + num_in++] = &dst_sg;
		
		host_ret = kzalloc(sizeof(*host_ret), GFP_KERNEL);
                sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
                sgs[num_out + num_in++] = &host_ret_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	/**
	 * Wait for the host to process our data.
	 **/
	/* Lock semaphore to prevent race conditions with father-child proccesses */
        if (down_interruptible(&crdev->lock)) {
                ret = -EINTR;
                debug("down_interruptible() interrupted by signal");
                goto fail_ioctl;
        }

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	if (err < 0) {
                ret = err;
                debug("virtqueue_add_sgs() error");
		up(&crdev->lock);
                goto fail_ioctl;
        }
	if(!virtqueue_kick(crdev->vq)) {
                ret = -EAGAIN;
                debug("virtqueue_kick() error");
                up(&crdev->lock);
                goto fail_ioctl;
        }
	/* Do nothing until we receive response from host */
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	up(&crdev->lock);
	
	switch (cmd) {
	case CIOCGSESSION:
		 if (copy_to_user((struct session_op *)arg, sess, sizeof(*sess))) {
            		debug("copy to user sess error");
            		ret = -EFAULT;
            		goto fail_ioctl;
        	}
		break;
	case CIOCCRYPT:
		 if (copy_to_user(((struct crypt_op *)arg)->dst, dst, cryp->len)) {
            		debug("copy to user cryp error");
            		ret = -EFAULT;
            		goto fail_ioctl;
        	}
		break;
	}
	ret = *host_ret;
	
fail_ioctl:
	kfree(host_ret);
	kfree(dst);
	kfree(src);
	kfree(inv);
	kfree(ses);
	kfree(key);
	kfree(sess);
	kfree(cmd_type);
	kfree(syscall_type);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
