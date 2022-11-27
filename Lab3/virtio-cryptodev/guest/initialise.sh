#!/bin/bash

make clean
make

/sbin/rmmod virtio_crypto.ko
/sbin/insmod virtio_crypto.ko

./crypto_dev_nodes.sh
