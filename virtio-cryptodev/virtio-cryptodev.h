#ifndef VIRTIO_CRYPTODEV_H
#define VIRTIO_CRYPTODEV_H

#define DEBUG(str) \
    printf("[VIRTIO-CRYPTODEV] FILE[%s] LINE[%d] FUNC[%s] STR[%s]\n", \
           __FILE__, __LINE__, __func__, str);
#define DEBUG_IN() DEBUG("IN")

#define VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN  0
#define VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE 1
#define VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL 2

#define VIRTIO_CRYPTODEV_IOCTL_CIOCGSESSION 3
#define VIRTIO_CRYPTODEV_IOCTL_CIOCFSESSION 4
#define VIRTIO_CRYPTODEV_IOCTL_CIOCCRYPT 5

#define TYPE_VIRTIO_CRYPTODEV "virtio-cryptodev"

#define CRYPTODEV_FILENAME  "/dev/crypto"

typedef struct VirtCryptodev {
    VirtIODevice parent_obj;
} VirtCryptodev;

#endif /* VIRTIO_CRYPTODEV_H */
