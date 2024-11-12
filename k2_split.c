// SPDX-License-Identifier: GPL-2.0
/*
 * K2 - A prototype of a work-constraining I/O scheduler
 *
 * Copyright (c) 2019 Till Miemietz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
//#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/ioprio.h>
#include <linux/blk_types.h>

/*elevator.hの追加部*/
#include <linux/percpu.h>
#include <linux/hashtable.h>
#include <trace/events/block.h>


#define ELV_HASH_BITS 6
#define ELV_NAME_MAX	(16)

typedef unsigned int __bitwise blk_insert_t;


/*elevator.hがインストールしたカーネルヘッダにないので前方宣言*/

enum elv_merge {
	ELEVATOR_NO_MERGE	= 0,
	ELEVATOR_FRONT_MERGE	= 1,
	ELEVATOR_BACK_MERGE	= 2,
	ELEVATOR_DISCARD_MERGE	= 3,
};

enum rq_qos_id {
	RQ_QOS_WBT = 0,
	RQ_QOS_LATENCY = 1,
	RQ_QOS_COST = 2,
};

struct elevator_queue
{
	struct elevator_type *type;
	void *elevator_data;
	struct kobject kobj;
	struct mutex sysfs_lock;
	unsigned long flags;
	DECLARE_HASHTABLE(hash, ELV_HASH_BITS);
};

struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};

struct elevator_mq_ops {
	int (*init_sched)(struct request_queue *, struct elevator_type *);
	void (*exit_sched)(struct elevator_queue *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*depth_updated)(struct blk_mq_hw_ctx *);

	bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
	bool (*bio_merge)(struct request_queue *, struct bio *, unsigned int);
	int (*request_merge)(struct request_queue *q, struct request **, struct bio *);
	void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
	void (*requests_merged)(struct request_queue *, struct request *, struct request *);
	void (*limit_depth)(blk_opf_t, struct blk_mq_alloc_data *);
	void (*prepare_request)(struct request *);
	void (*finish_request)(struct request *);
	void (*insert_requests)(struct blk_mq_hw_ctx *hctx, struct list_head *list,
			blk_insert_t flags);
	struct request *(*dispatch_request)(struct blk_mq_hw_ctx *);
	bool (*has_work)(struct blk_mq_hw_ctx *);
	void (*completed_request)(struct request *, u64);
	void (*requeue_request)(struct request *);
	struct request *(*former_request)(struct request_queue *, struct request *);
	struct request *(*next_request)(struct request_queue *, struct request *);
	void (*init_icq)(struct io_cq *);
	void (*exit_icq)(struct io_cq *);
};

struct elevator_type
{
	/* managed by elevator core */
	struct kmem_cache *icq_cache;

	/* fields provided by elevator implementation */
	struct elevator_mq_ops ops;

	size_t icq_size;	/* see iocontext.h */
	size_t icq_align;	/* ditto */
	struct elv_fs_entry *elevator_attrs;
	const char *elevator_name;
	const char *elevator_alias;
	const unsigned int elevator_features;
	struct module *elevator_owner;
#ifdef CONFIG_BLK_DEBUG_FS
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
#endif

	/* managed by elevator core */
	char icq_cache_name[ELV_NAME_MAX + 6];	/* elvname + "_io_cq" */
	struct list_head list;
};

struct rq_qos {
	const struct rq_qos_ops *ops;
	struct gendisk *disk;
	enum rq_qos_id id;
	struct rq_qos *next;
};

struct rq_qos_ops {
	void (*throttle)(struct rq_qos *, struct bio *);
	void (*track)(struct rq_qos *, struct request *, struct bio *);
	void (*merge)(struct rq_qos *, struct request *, struct bio *);
	void (*issue)(struct rq_qos *, struct request *);
	void (*requeue)(struct rq_qos *, struct request *);
	void (*done)(struct rq_qos *, struct request *);
	void (*done_bio)(struct rq_qos *, struct bio *);
	void (*cleanup)(struct rq_qos *, struct bio *);
	void (*queue_depth_changed)(struct rq_qos *);
	void (*exit)(struct rq_qos *);
};

void elv_rb_add(struct rb_root *root, struct request *rq);
void elv_rb_del(struct rb_root *root, struct request *rq);
struct request *elv_rb_find(struct rb_root *root, sector_t sector);
void elv_rqhash_del(struct request_queue *q, struct request *rq);
struct elevator_queue *elevator_alloc(struct request_queue *q,
				  struct elevator_type *e);
void elv_rqhash_del(struct request_queue *q, struct request *rq);
void elv_rqhash_add(struct request_queue *q, struct request *rq);
void elv_rqhash_reposition(struct request_queue *q, struct request *rq);
struct request *elv_rqhash_find(struct request_queue *q, sector_t offset);
bool elv_bio_merge_ok(struct request *rq, struct bio *bio);
struct elevator_queue *elevator_alloc(struct request_queue *q,
				  struct elevator_type *e);
int elv_register(struct elevator_type *e);
int elv_unregister(struct elevator_type *e);

 void rq_qos_track(struct request_queue *q, struct request *rq,
				struct bio *bio);
struct request *blk_mq_get_new_requests(struct request_queue *q,
			struct blk_plug *plug,
			struct bio *bio,
			unsigned int nsegs);
void blk_mq_bio_to_request(struct request *rq, struct bio *bio,
		unsigned int nr_segs);
void bio_set_ioprio(struct bio *bio);

void bio_chain(struct bio *bio, struct bio *parent);

static bool rq_mergeable(struct request *rq)
{
	if (blk_rq_is_passthrough(rq))
		return false;

	if (req_op(rq) == REQ_OP_FLUSH)
		return false;

	if (req_op(rq) == REQ_OP_WRITE_ZEROES)
		return false;

	if (req_op(rq) == REQ_OP_ZONE_APPEND)
		return false;

	if (rq->cmd_flags & REQ_NOMERGE_FLAGS)
		return false;
	if (rq->rq_flags & RQF_NOMERGE_FLAGS)
		return false;

	return true;
}

/*
 * blk_mq_sched_request_inserted() is EXPORT_SYMBOL_GPL'ed, but it is declared
 * in the header file block/blk-mq-sched.h, which is not part of the installed
 * kernel headers a module is built against (only part of the full source).
 * Therefore, we forward-declare it again here.
 * (implicitly declared functions are an error.)
 */
//extern void blk_mq_sched_request_inserted(struct request *rq);
bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs, struct request **merged_request);

/* helper functions for getting / setting configurations via sysfs */
ssize_t k2_max_inflight_show(struct elevator_queue *eq, char *s);

ssize_t k2_max_inflight_set(struct elevator_queue *eq, const char *s, 
                            size_t size);

ssize_t k2_max_sectors_show(struct elevator_queue *eq, char *s);

ssize_t k2_max_sectors_set(struct elevator_queue *eq, const char *s, 
                            size_t size);

//max_sectorsを追加
struct k2_data {
	unsigned int inflight;
	unsigned int max_inflight;

	unsigned int max_sectors;

	/* further group real-time requests by I/O priority */
	struct list_head rt_reqs[IOPRIO_BE_NR];
	struct list_head be_reqs;

	/* Sector-ordered lists for request merging */
	struct rb_root sort_list[2];

	spinlock_t lock;
};

/* configurations entries for sysfs (/sys/block/<dev>/queue/iosched/)
max_sectorsは負荷プロセスの最大発行サイズ（=分割数）を設定する */
static struct elv_fs_entry k2_attrs[] = {
    __ATTR(max_inflight, S_IRUGO | S_IWUSR, k2_max_inflight_show, 
                                            k2_max_inflight_set),
	__ATTR(max_sectors, S_IRUGO | S_IWUSR, k2_max_sectors_show, 
											k2_max_sectors_set),
    __ATTR_NULL
};


ssize_t k2_max_inflight_show(struct elevator_queue *eq, char *s) 
{
	struct k2_data *k2d = eq->elevator_data;

	return(sprintf(s, "%u\n", k2d->max_inflight));
}

ssize_t k2_max_sectors_show(struct elevator_queue *eq, char *s) 
{
	struct k2_data *k2d = eq->elevator_data;

	return(sprintf(s, "%u\n", k2d->max_sectors));
}

ssize_t k2_max_inflight_set(struct elevator_queue *eq, const char *s, 
                            size_t size)
{

	struct k2_data *k2d = eq->elevator_data;
	unsigned int old_max;
	unsigned int new_max;
	unsigned long flags;

	if (kstrtouint(s, 10, &new_max) >= 0) {
		spin_lock_irqsave(&k2d->lock, flags);
		old_max           = k2d->max_inflight;
		k2d->max_inflight = new_max;
		spin_unlock_irqrestore(&k2d->lock, flags);
		printk(KERN_INFO "k2_split: max_inflight set to %u\n", 
			k2d->max_inflight);
		
		return(size);
	}

	/* error, leave max_inflight as is */
	return(size);
}

//4の倍数しか受け付けないように設定
ssize_t k2_max_sectors_set(struct elevator_queue *eq, const char *s, 
                            size_t size)
{

	struct k2_data *k2d = eq->elevator_data;
	unsigned int old_max;
	unsigned int new_max;
	unsigned long flags;

	if (kstrtouint(s, 10, &new_max) >= 0) {

		if(new_max%4 != 0){
			new_max -= new_max%4;
		}
		if(new_max < 4){
			new_max = 4;
		}
		spin_lock_irqsave(&k2d->lock, flags);
		old_max           = k2d->max_sectors;
		k2d->max_sectors = new_max;
		spin_unlock_irqrestore(&k2d->lock, flags);
		printk(KERN_INFO "k2_split: max_sectors set to %u\n", 
			k2d->max_sectors);
		
		return(size);
	}

	/* error, leave max_inflight as is */
	return(size);
}

static inline struct rb_root *k2_rb_root(struct k2_data *k2d, 
						struct request *rq)
{
	return &k2d->sort_list[rq_data_dir(rq)];
}

static void k2_add_rq_rb(struct k2_data *k2d, struct request *rq)
{
	struct rb_root *root = k2_rb_root(k2d, rq);

	elv_rb_add(root, rq);
}

static inline void k2_del_rq_rb(struct k2_data *k2d, struct request *rq)
{
	elv_rb_del(k2_rb_root(k2d, rq), rq);
}

static void k2_remove_request(struct request_queue *q, struct request *r)
{
	struct k2_data *k2d = q->elevator->elevator_data;

	list_del_init(&r->queuelist);

	/*
	 * During an insert merge r might have not been added to the rb-tree yet
	 */
	if (!RB_EMPTY_NODE(&r->rb_node))
		k2_del_rq_rb(k2d, r);

	elv_rqhash_del(q, r);
	if (q->last_merge == r)
		q->last_merge = NULL;
}

/* Initialize the scheduler. */
/*max_inflightの初期値を1に変更*/
static int k2_init_sched(struct request_queue *rq, struct elevator_type *et) 
{
	struct k2_data        *k2d;
	struct elevator_queue *eq;
	unsigned i;

	eq = elevator_alloc(rq, et);
	if (eq == NULL)
		return(-ENOMEM);
    
	/* allocate scheduler data from mem pool of request queue */
	k2d = kzalloc_node(sizeof(struct k2_data), GFP_KERNEL, rq->node);
	if (k2d == NULL) {
		kobject_put(&eq->kobj);
		return(-ENOMEM);
	}
	eq->elevator_data = k2d;

	k2d->inflight     =  0;
	k2d->max_inflight = 1;
	k2d->max_sectors = 1024;
	for (i = 0; i < IOPRIO_BE_NR; i++)
		INIT_LIST_HEAD(&k2d->rt_reqs[i]);

	INIT_LIST_HEAD(&k2d->be_reqs);

	k2d->sort_list[READ] = RB_ROOT;
	k2d->sort_list[WRITE] = RB_ROOT;

	spin_lock_init(&k2d->lock);

	rq->elevator = eq;
	printk(KERN_INFO "k2_split: I/O scheduler set up.\n"); 
	return(0);
}

/* Leave the scheduler. */
static void k2_exit_sched(struct elevator_queue *eq) 
{
	struct k2_data *k2d = eq->elevator_data;

	kfree(k2d);
}

static void k2_completed_request(struct request *r, u64 now) 
{
	struct k2_data *k2d = r->q->elevator->elevator_data;
	unsigned long flags;
	unsigned int  counter;
	unsigned int  max_inf; 

	spin_lock_irqsave(&k2d->lock, flags);
	/* avoid negative counters */
	if (k2d->inflight > 0)
		k2d->inflight--;

	/* 
	 * Read both counters here to avoid stall situation if max_inflight  
	 * is modified simultaneously.
	 */
	counter = k2d->inflight;
	max_inf = k2d->max_inflight;
	spin_unlock_irqrestore(&k2d->lock, flags);

	/* 
	 * This completion call creates leeway for dispatching new requests.
	 * Rerunning the hw queues have to be done manually since we throttle
	 * request dispatching. Mind that this has to be executed in async mode.
	 */
	if (counter == (max_inf - 1))
		blk_mq_run_hw_queues(r->q, true);
}

static bool _k2_has_work(struct k2_data *k2d)
{
	unsigned int  i;

	assert_spin_locked(&k2d->lock);

	if (k2d->inflight >= k2d->max_inflight)
		return(false);

	if (! list_empty(&k2d->be_reqs))
		return(true);

	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (! list_empty(&k2d->rt_reqs[i])) {
			return(true);
		}
	}

	return(false);
}

static bool k2_has_work(struct blk_mq_hw_ctx *hctx) 
{
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	bool has_work;
	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);
	has_work = _k2_has_work(k2d);
	spin_unlock_irqrestore(&k2d->lock, flags);
    
	return(has_work);
}

static void k2_ioprio_from_task(int *class, int *value) 
{
	if (current->io_context == NULL || 
		!ioprio_valid(current->io_context->ioprio)) {
		*class = task_nice_ioclass(current);
		*value = IOPRIO_NORM;
	} else {
		*class = IOPRIO_PRIO_CLASS(current->io_context->ioprio);
		*value = IOPRIO_PRIO_VALUE(*class, current->io_context->ioprio);
	}
}

void __rq_qos_track(struct rq_qos *rqos, struct request *rq, struct bio *bio)
{
	do {
		if (rqos->ops->track)
			rqos->ops->track(rqos, rq, bio);
		rqos = rqos->next;
	} while (rqos);
}

void rq_qos_track(struct request_queue *q, struct request *rq,
				struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_track(q->rq_qos, rq, bio);
}


/*plugの取得*/
struct blk_plug *blk_mq_plug(struct bio *bio)
{

	/*
	 * For regular block devices or read operations, use the context plug
	 * which may be NULL if blk_start_plug() was not executed.
	 */
	return current->plug;
}

//分割の有無判定
bool bio_may_exceed_limits(struct bio *bio,
					 const struct queue_limits *lim)
{
	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
	case REQ_OP_WRITE_ZEROES:
		return true; /* non-trivial splitting decisions */
	default:
		break;
	}

	/*
	 * All drivers must accept single-segments bios that are <= PAGE_SIZE.
	 * This is a quick and dirty check that relies on the fact that
	 * bi_io_vec[0] is always valid if a bio has data.  The check might
	 * lead to occasional false negatives when bios are cloned, but compared
	 * to the performance impact of cloned bios themselves the loop below
	 * doesn't matter anyway.
	 */
	return lim->chunk_sectors || bio->bi_vcnt != 1 ||
		bio->bi_io_vec->bv_len + bio->bi_io_vec->bv_offset > PAGE_SIZE;
}


/*分割数の決定*/
unsigned int k2_split_number(struct request *r,int prio_class){
	if(prio_class != IOPRIO_CLASS_IDLE){
		return 1;
	}
	int split_number = 2;
	if(r->bio->bi_iter.bi_size%split_number==0){
		return split_number;
	}else{
		return 2;
	}
}

/*分割可否の判定*/
bool k2_split_check(struct bio *bio,unsigned int max_bytes){
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	unsigned int bio_size = bio->bi_iter.bi_size;

	if(!bio_may_exceed_limits(bio,&q->limits)){
		return false;
	}else{
		if(bio_size < max_bytes || bio_size%max_bytes != 0){
			return false;
		}else{
			return true;
		}
	}
}

/*bioの分割*/
struct bio *k2_split_bio(struct bio *bio,int max_bytes,unsigned int *nr_segs){
	struct bio *split;
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	struct bio_set *bs = &bio->bi_bdev->bd_disk->bio_split;

	split = bio_split_rw(bio,&q->limits,nr_segs,bs,max_bytes);
	if(split){
		split->bi_opf |= REQ_NOMERGE;
		bio_issue_init(&split->bi_issue,bio_sectors(split));
		bio_chain(split, bio);
	}
	return split;
}

/*分割後のbioをリクエストへ変換*/
struct request *k2_bio_to_request(struct bio *bio,unsigned int nr_segs){
	
	struct request *rq;
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	struct blk_plug *plug = blk_mq_plug(bio);

	rq = blk_mq_get_new_requests(q,plug,bio,nr_segs);
	if(!rq){
		 //printk(KERN_DEBUG "null\n");
		return NULL;
	}
	 //printk(KERN_DEBUG "get new req\n");
	rq_qos_track(q, rq, bio);
	blk_mq_bio_to_request(rq, bio, nr_segs);
	return rq;
}

/*元々のリクエスト内容を分割に伴いupdateする*/
void k2_request_update(struct request *rq, struct bio *bio,unsigned int nr_segs){
	rq->nr_phys_segments = nr_segs;
	rq->__data_len = bio->bi_iter.bi_size;
	rq->__sector = bio->bi_iter.bi_sector;
}

/* Inserts a request into the scheduler queue. For now, at_head is ignored! */
/*動的分割機構の追加*/
static void k2_insert_requests(struct blk_mq_hw_ctx *hctx, struct list_head *rqs,
				blk_insert_t at_head) 
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);
	while (!list_empty(rqs)) {
		struct request *r;
		int    prio_class;
		int    prio_value;

		r = list_first_entry(rqs, struct request, queuelist);
		list_del_init(&r->queuelist);

		/* if task has no io prio, derive it from its nice value */
		if (ioprio_valid(r->ioprio)) {
			prio_class = IOPRIO_PRIO_CLASS(r->ioprio);
			prio_value = IOPRIO_PRIO_VALUE(prio_class, r->ioprio);
		} else {
			 //printk(KERN_DEBUG "aaa");
			k2_ioprio_from_task(&prio_class, &prio_value);
		}

		//printk(KERN_DEBUG "%d\n",prio_class);

		k2_add_rq_rb(k2d, r);
		
		if (rq_mergeable(r)) {
			elv_rqhash_add(q, r);
			if (!q->last_merge)
				q->last_merge = r;
		}

		
		/*
		  動的分割機構の追加部分
		*/
		//printk(KERN_DEBUG "start split\n");
		unsigned int split_number = k2_split_number(r,prio_class);
		unsigned int prev_maxsectors = hctx->queue->limits.max_sectors;

		//printk(KERN_DEBUG "split_number:%d & bio_list init\n",split_number);


		if(split_number > 1){
			struct bio *split;
			struct bio *bio = r->bio;
			//unsigned max_bytes = (bio->bi_iter.bi_size) / split_number;
			unsigned max_bytes = 4096 * (k2d->max_sectors / 4); //コンフィギュレーションで設定した最大値を格納
			//printk(KERN_DEBUG "bio_size:%d,max_bytes:%d \n",bio->bi_iter.bi_size,max_bytes);
			hctx->queue->limits.max_sectors = max_bytes; //limitsを最大発行サイズで上書き
			unsigned int bio_size;
			do{
				unsigned int nr_segs = 1;
				if(!k2_split_check(bio,max_bytes)){
					//printk(KERN_DEBUG "no_split_bio\n");
					break;
				}
				split = k2_split_bio(bio,max_bytes,&nr_segs);
				if(!split){
					//splitがNULLの場合は引数のbioがこれ以上分割できない最小値であるので，リクエスト構造体のupdateを行う
					k2_request_update(r,bio,nr_segs);
					break;
				}
				bio_size = bio->bi_iter.bi_size;
				//printk(KERN_DEBUG "split_bio_size:%d,max_bytes:%d \n",bio_size,max_bytes);

				bio_set_ioprio(split);
				struct request *new_request = k2_bio_to_request(split,nr_segs);
				//printk(KERN_DEBUG "generate request\n");

				//分割後のリクエストにio優先度を付与
				if (ioprio_valid(new_request->ioprio)) {
					prio_class = IOPRIO_PRIO_CLASS(new_request->ioprio);
					prio_value = IOPRIO_PRIO_VALUE(prio_class, new_request->ioprio);
				} else {
					k2_ioprio_from_task(&prio_class, &prio_value);
				}

				//swキューに挿入
				if (prio_class == IOPRIO_CLASS_RT) {
					if (prio_value >= IOPRIO_BE_NR || prio_value < 0)
						prio_value = IOPRIO_NORM;
					list_add_tail(&new_request->queuelist, &k2d->rt_reqs[prio_value]);
				} else {
					list_add_tail(&new_request->queuelist, &k2d->be_reqs);
				}
			}while(bio_size >= max_bytes);
		}
		/*
		  動的分割機構終了
		*/

		if (prio_class == IOPRIO_CLASS_RT) {
			if (prio_value >= IOPRIO_BE_NR || prio_value < 0)
				prio_value = IOPRIO_NORM;
			list_add_tail(&r->queuelist, &k2d->rt_reqs[prio_value]);
		} else {
			list_add_tail(&r->queuelist, &k2d->be_reqs);
		}	
		/* leave a message for tracing */
		//blk_mq_sched_request_inserted(r);
		trace_block_rq_insert(r);
		hctx->queue->limits.max_sectors = prev_maxsectors; //デフォルトのlimitに戻す
	}
	spin_unlock_irqrestore(&k2d->lock, flags);
}

static struct request *k2_dispatch_request(struct blk_mq_hw_ctx *hctx) 
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	struct request *r;
	unsigned long flags;
	unsigned int  i;

	spin_lock_irqsave(&k2d->lock, flags);
    
	/* inflight counter may have changed since last call to has_work */
	if (k2d->inflight >= k2d->max_inflight)
		goto abort;
    
	/* always prefer real-time requests */
	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (!list_empty(&k2d->rt_reqs[i])) {
			r = list_first_entry(&k2d->rt_reqs[i], struct request, 
					     queuelist);
			//printk("k2 rt dispatch\n");
			goto end;
		}
	}

	/* no rt rqs waiting: choose other workload */
	if (!list_empty(&k2d->be_reqs)) {
		r = list_first_entry(&k2d->be_reqs, struct request, queuelist);
		//printk("k2 no_rt dispatch\n");
		goto end;
	}

abort:
	/* both request lists are empty or inflight counter is too high */
	spin_unlock_irqrestore(&k2d->lock, flags);    
	return(NULL);

end:
	k2_remove_request(q, r);
	k2d->inflight++;
	r->rq_flags |= RQF_STARTED;
	spin_unlock_irqrestore(&k2d->lock, flags);
	printk("k2 dispatch request : %d\n",r->__data_len);
	return(r);
}

/*blk_mq_sched_try_mergeにnr_seqとして1を与える*/
static bool k2_bio_merge(struct request_queue *q, struct bio *bio,unsigned int nr_seqs)
{

	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *free = NULL;
	unsigned long flags;
	bool ret;

	return false; //デッドロック防止のためにすぐにリターン

	spin_lock_irqsave(&k2d->lock, flags);
	ret = blk_mq_sched_try_merge(q, bio, nr_seqs, &free);
	spin_unlock_irqrestore(&k2d->lock, flags);

	if (free)
		blk_mq_free_request(free);

	return(ret);
}

static int k2_request_merge(struct request_queue *q, struct request **r, 
				struct bio *bio)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *__rq;
	sector_t sector = bio_end_sector(bio);

	assert_spin_locked(&k2d->lock);

	// should request merging cross I/O prios?

	__rq = elv_rb_find(&k2d->sort_list[bio_data_dir(bio)], sector);
	if (__rq) {
		BUG_ON(sector != blk_rq_pos(__rq));

		if (elv_bio_merge_ok(__rq, bio)) {
			*r = __rq;
			return(ELEVATOR_FRONT_MERGE);
		}
	}

	return(ELEVATOR_NO_MERGE);
}

static void k2_request_merged(struct request_queue *q, struct request *req,
				enum elv_merge type)
{
	struct k2_data *k2d = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	if (type == ELEVATOR_FRONT_MERGE) {
		k2_del_rq_rb(k2d, req);
		k2_add_rq_rb(k2d, req);
	}
}

/*
 * This function is called to notify the scheduler that the requests
 * rq and 'next' have been merged, with 'next' going away.
 */
static void k2_requests_merged(struct request_queue *q, struct request *rq,
				struct request *next)
{
	k2_remove_request(q, next);
}

static void k2_finish_request(struct request *rq)
{

}

/*.ops.mqから.opsに変更*/
static struct elevator_type k2_iosched = {
	.ops = {
		.init_sched        = k2_init_sched,
		.exit_sched        = k2_exit_sched,

		.insert_requests   = k2_insert_requests,
		.has_work          = k2_has_work,
		.dispatch_request  = k2_dispatch_request,
		.completed_request = k2_completed_request,
		.finish_request = k2_finish_request,

		.bio_merge         = k2_bio_merge,
		.request_merge     = k2_request_merge,
		.request_merged    = k2_request_merged,
		.requests_merged   = k2_requests_merged,
	},
	//.uses_mq        = true,
	.elevator_attrs = k2_attrs,
	.elevator_name  = "k2_split",
	.elevator_owner = THIS_MODULE,
};

static int __init k2_init(void) 
{
	printk(KERN_INFO "k2_split: Loading K2 I/O scheduler.\n");
	return(elv_register(&k2_iosched));
}

static void __exit k2_exit(void) 
{
	printk(KERN_INFO "k2_split: Unloading K2 I/O scheduler.\n");
	elv_unregister(&k2_iosched);
}

module_init(k2_init);
module_exit(k2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Till Miemietz");
MODULE_DESCRIPTION("A work-constraining I/O scheduler with real-time notion.");
MODULE_VERSION("0.1");
