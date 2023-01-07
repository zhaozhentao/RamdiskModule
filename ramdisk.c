#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/device.h>
#include <linux/blk-mq.h>
#include <linux/list.h>

static int dev_major = 0;

struct block_dev {
    sector_t capacity;
    u8 *data;
    struct blk_mq_tag_set tag_set;
    struct request_queue *queue;
    struct gendisk *gdisk;
};

static struct block_dev *block_device = NULL;

static struct block_device_operations blockdev_ops = {
    .owner = THIS_MODULE
};

static int do_request(struct request *rq, unsigned int *nr_bytes) {
    int ret = 0;
    struct bio_vec bvec;
    struct req_iterator iter;
    struct block_dev *dev = rq->q->queuedata;
    loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
    loff_t dev_size = (loff_t)(dev->capacity << SECTOR_SHIFT);

    rq_for_each_segment(bvec, rq, iter) {
        unsigned long b_len = bvec.bv_len;

        void* b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

        if ((pos + b_len) > dev_size) {
            b_len = (unsigned long)(dev_size - pos);
        }

        if (rq_data_dir(rq) == WRITE) {
            memcpy(dev->data + pos, b_buf, b_len);
        } else {
            memcpy(b_buf, dev->data + pos, b_len);
        }

        pos += b_len;
        *nr_bytes += b_len;
    }

    return ret;
}

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data* bd) {
    unsigned int nr_bytes = 0;
    blk_status_t status = BLK_STS_OK;
    struct request *rq = bd->rq;

    blk_mq_start_request(rq);

    if (do_request(rq, &nr_bytes) != 0) {
        status = BLK_STS_IOERR;
    }

    if (blk_update_request(rq, status, nr_bytes)) {
        BUG();
    }

    __blk_mq_end_request(rq, status);

    return status;
}

static struct blk_mq_ops mq_ops = {
    .queue_rq = queue_rq,
};

static int __init ramdisk_init(void) {
    dev_major = register_blkdev(dev_major, KBUILD_MODNAME);

    if (dev_major <= 0) {
        pr_err("Unable to get major number\n");
        return -EBUSY;
    }

    block_device = kmalloc(sizeof(struct block_dev), GFP_KERNEL);

    if (block_device == NULL) {
        pr_err("Failed to allocate struct block_device\n");
        unregister_blkdev(dev_major, KBUILD_MODNAME);
        return -ENOMEM;
    }

    block_device->capacity = (16 * 1024 * 1024) >> 9;

    block_device->data = __vmalloc(block_device->capacity << 9, GFP_NOIO | __GFP_ZERO);

    if (block_device->data == NULL) {
        pr_err("Failed to allocate device IO buffer\n");
        unregister_blkdev(dev_major, KBUILD_MODNAME);
        kfree(block_device);
        return -ENOMEM;
    }

    pr_info("Initializing queue\n");

    block_device->queue = blk_mq_init_sq_queue(&block_device->tag_set, &mq_ops, 128, BLK_MQ_F_SHOULD_MERGE);

    if (block_device->queue == NULL) {
        pr_err("Failed to allocate device queue\n");
        vfree(block_device->data);

        unregister_blkdev(dev_major, KBUILD_MODNAME);
        kfree(block_device);

        return -ENOMEM;
    }

    block_device->queue->queuedata = block_device;

    block_device->gdisk = alloc_disk(1);
    block_device->gdisk->flags = GENHD_FL_NO_PART_SCAN;
    block_device->gdisk->major = dev_major;
    block_device->gdisk->first_minor = 0;
    block_device->gdisk->fops = &blockdev_ops;
    block_device->gdisk->queue = block_device->queue;
    block_device->gdisk->private_data = block_device;
    strcpy(block_device->gdisk->disk_name, "my_ramdisk");

    // 设置设备名称，会在 /dev 目录下生成 my_ramdisk 设备文件
    pr_info("Adding disk %s\n", block_device->gdisk->disk_name);
    set_capacity(block_device->gdisk, block_device->capacity);
    add_disk(block_device->gdisk);

    return 0;
}

static void __exit ramdisk_exit(void) {
    if (block_device->gdisk) {
        del_gendisk(block_device->gdisk);
        put_disk(block_device->gdisk);
    }

    if (block_device->queue) {
        blk_cleanup_queue(block_device->queue);
    }

    vfree(block_device->data);

    unregister_blkdev(dev_major, KBUILD_MODNAME);
    kfree(block_device);
}

module_init(ramdisk_init);
module_exit(ramdisk_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhaozhentao");
MODULE_DESCRIPTION("ramdisk module");
