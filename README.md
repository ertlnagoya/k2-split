
# K2-split : I/O Scheduler using splitting mechanism for improving Real-Time performance in eMMC
K2-split is a simple I/O scheduler developed as a Linux kernel module, targeting real-time systems equipped with eMMC. The primary objective of K2-split is to finely divide high-load I/O operations with large access sizes and control the waiting time of real-time processes. The scheduling policy of K2-split is priority-based, utilizing the scheduling policy and queue structure of the K2 scheduler.

## How to build and run the scheduler
To build this kernel module, a build environment for the Linux kernel is required. Currently, the scheduler has been tested for building and execution on kernel version 6.5.0.

To compile the module
```
make
```
Afterwards the binary can be inserted into the module directory by executing
```
make install
```
To load K2-split
```
modprobe k2-split
```
To set k2-split
```
echo k2-split > /sys/block/<device name>/queue/scheduler
```
Since K2-split utilizes internal kernel functions, modifying and rebuilding the kernel source code is necessary. Specifically, ```EXPORT_SYMBOL``` declarations were added to three functions—```blk_mq_get_new_requests```,```blk_mq_bio_to_request```, and ```bio_set_ioprio```—to make them accessible from the module. Additionally, K2-split was developed for kernel version 6.5.0 and is unlikely to work with other versions.

## How to use K2-split
K2-split adopts priority-based scheduling and utilizes process I/O priorities. I/O requests from the real-time class are processed with higher priority compared to other classes (best-effort and idle). Therefore, it is necessary to appropriately set the I/O priority of processes using the ionice command. Additionally, I/O belonging to non-real-time priority classes undergoes I/O splitting, which can significantly reduce throughput. 

K2-split provides a configuration parameter to set the maximum I/O size for non-real-time classes via ```/sys/block/<device name>/queue/iosched/max_sectors```. For example, to set the maximum issued size to 4 KiB, write 4 to ```/sys/block/<device name>/queue/iosched/max_sectors```. 

It is important to properly configure the ```/sys/block/<device name>/queue/nr_requests``` parameter, which specifies the maximum number of requests that can exist within the block layer. The number of splits should be set so that the total number of requests present in the block layer after splitting does not exceed the configured nr_requests parameter.

If the number of requests after splitting exceeds the nr_requests parameter, the kernel may crash or freeze. Therefore, careful configuration is essential to ensure system stability.