/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <numa.h>
#include <numaif.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/queue.h>
#include "wd.h"

#define SYSFS_HUGEPAGE_PATH		"/sys/kernel/mm/hugepages"
#define HUGETLB_FLAG_ENCODE_SHIFT	26

#define BITS_PER_LONG			((int)sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(bits) \
	(((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define BIT_MASK(nr)			((unsigned long)(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)			((nr) / BITS_PER_LONG)
#define BITMAP_FIRST_WORD_MASK(start) \
	(~0UL << ((start) & (BITS_PER_LONG - 1)))

#define __round_mask(x, y)		((__typeof__(x))((y)-1))
#define round_down(x, y)		((x) & ~__round_mask(x, y))

#define __maybe_unused			__attribute__((__unused__))

struct wd_lock {
	__u32 lock;
};

static inline void wd_spinlock(struct wd_lock *lock)
{
	while (__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE))
		while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED));
}

static inline void wd_unspinlock(struct wd_lock *lock)
{
	__atomic_clear(&lock->lock, __ATOMIC_RELEASE);
}

/*
 * one memzone may include some continuous block in mempool
 * @addr: Base address of blocks in this memzone
 * @blk_num: Number of blocks in this memzone
 * @begin: Begin position in mempool bitmap
 * @end: End position in mempool bitmap
 */
struct memzone {
	void *addr;
	size_t blk_num;
	size_t begin;
	size_t end;
	TAILQ_ENTRY(memzone) node;
};
TAILQ_HEAD(memzone_list, memzone);

/*
 * @blk_elem: All the block unit addrs saved in blk_elem
 * @depth: The block pool deph, stack depth
 * @top: The stack top pos for blk_elem
 * @blk_size: The size of one block
 * @mp: Record from which mempool
 * @mz_list: List of memzone allocated from mempool
 * @free_block_num: Number of free blocks currently
 */
struct blkpool {
	void **blk_elem;
	size_t depth;
	size_t top;
	size_t blk_size;
	struct mempool *mp;
	struct memzone_list mz_list;
	unsigned long free_block_num;
	struct wd_lock lock;
};

struct sys_hugepage_config {
	/* unit is Byte */
	unsigned long page_size;
	size_t total_num;
	size_t free_num;
	TAILQ_ENTRY(sys_hugepage_config) node;
};
TAILQ_HEAD(sys_hugepage_list, sys_hugepage_config);

struct bitmap {
	unsigned long *map;
	unsigned long bits;
	unsigned long map_byte;
};

struct mempool {
	enum wd_page_type page_type;
	int page_size;
	int page_num;
	int blk_size;
	/* numa node id */
	int node;
	/* fd for page pin */
	int fd;
	void *addr;
	size_t size;
	size_t real_size;
	struct bitmap *bitmap;
	/* use self-define lock to avoid to use pthread lib in libwd */
	struct wd_lock lock;
	struct sys_hugepage_list hp_list;
	unsigned long free_blk_num;
};

/* bitmap functions */
/**
 * This function is copied from kernel head file. It finds first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 *
 * fix me: this can be done by glibc function.
 */
static __always_inline unsigned long wd_ffs(unsigned long word)
{
	int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static struct bitmap *create_bitmap(int bits)
{
	struct bitmap *bm = calloc(1, sizeof(*bm));
	if (!bm)
		return NULL;

	bm->map = calloc(BITS_TO_LONGS(bits), sizeof(unsigned long));
	if (!bm->map) {
		free(bm);
		return NULL;
	}

	bm->bits = bits;
	bm->map_byte = BITS_TO_LONGS(bits);

	return bm;
}

/* destory bitmap */
static void destory_bitmap(struct bitmap *bm)
{
	free(bm->map);
	free(bm);
}

/* This function copies from kernel/lib/find_bit.c */
static unsigned long _find_next_bit(unsigned long *map, unsigned long bits,
				    unsigned long start, unsigned long invert)
{
	unsigned long tmp, mask;

	/* fix me: unlikely */
	if (start >= bits)
		return bits;

	tmp = map[start / BITS_PER_LONG];
	tmp ^= invert;

	mask = BITMAP_FIRST_WORD_MASK(start);
	tmp &= mask;
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start > bits)
			return bits;

		tmp = map[start / BITS_PER_LONG];
		tmp ^= invert;
	}

	return MIN(start + wd_ffs(tmp), bits);
}

static unsigned long find_next_zero_bit(struct bitmap *bm, unsigned long start)
{
	return _find_next_bit(bm->map, bm->bits, start, ~0UL);
}

static unsigned long __maybe_unused find_next_bit(struct bitmap *bm,
						  unsigned long start)
{
	return _find_next_bit(bm->map, bm->bits, start, 0UL);
}

static void set_bit(struct bitmap *bm, int pos)
{
	unsigned long *map = bm->map;
	unsigned long mask = BIT_MASK(pos);
	unsigned long *p = map + BIT_WORD(pos);

	*p  |= mask;
}

static void clear_bit(struct bitmap *bm, int pos)
{
	unsigned long *map = bm->map;
	unsigned long mask = BIT_MASK(pos);
	unsigned long *p = map + BIT_WORD(pos);

	*p &= ~mask;
}

/**
 * test_and_set_bit - Set a bit if value in nr in 0.
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * Return true if set, false if not set.
 */
static int test_and_set_bit(struct bitmap *bm, int nr)
{
	unsigned long *p = bm->map + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);

	if (!(*p & mask)) {
		*p |= mask;
		return true;
	}

	return false;
}

inline static size_t wd_get_page_size(void)
{
	return sysconf(_SC_PAGESIZE);
}

void *wd_blockpool_alloc(handle_t blockpool)
{
	struct blkpool *bp = (struct blkpool*)blockpool;
	void *p;

	if (!bp)
		return NULL;

	if (bp->top > 0) {
		wd_spinlock(&bp->lock);
		bp->top--;
		bp->free_block_num--;
		p = bp->blk_elem[bp->top];
		wd_unspinlock(&bp->lock);
		return p;
	}

	return NULL;
}

void wd_blockpool_free(handle_t blockpool, void *addr)
{
	struct blkpool *bp = (struct blkpool*)blockpool;

	if (!bp || !addr)
		return;

	if (bp->top < bp->depth) {
		wd_spinlock(&bp->lock);
		bp->blk_elem[bp->top] = addr;
		bp->top++;
		bp->free_block_num++;
		wd_unspinlock(&bp->lock);
	}
}

static int alloc_memzone(struct blkpool *bp, void *addr, size_t blk_num,
			 size_t begin, size_t end)
{
	struct memzone *zone;

	zone = calloc(1, sizeof(struct memzone));
	if (!zone) {
		return -ENOMEM;
	}

	zone->addr = addr;
	zone->blk_num = blk_num;
	zone->begin = begin;
	zone->end = end;
	TAILQ_INSERT_TAIL(&bp->mz_list, zone, node);

	return 0;
}

static void free_mem_to_mempool(struct blkpool *bp)
{
	struct mempool *mp = bp->mp;
	struct memzone *iter;
	size_t blks;
	int i;

	while ((iter = TAILQ_LAST(&bp->mz_list, memzone_list))) {
		for (i = iter->begin; i <= iter->end; i++)
			clear_bit(mp->bitmap, i);
		blks = iter->end - iter->begin + 1;
		mp->free_blk_num += blks;
		mp->real_size += blks * mp->blk_size;

		TAILQ_REMOVE(&bp->mz_list, iter, node);
		free(iter);
	}
}

/* In this case, multiple blocks are in one mem block */
static int alloc_mem_multi_in_one(struct mempool *mp, struct blkpool *bp)
{
	int blk_num_per_memblk = mp->blk_size / bp->blk_size;
	int blk_num = bp->depth;
	int start = 0, pos, ret;

	while (blk_num > 0) {
		pos = find_next_zero_bit(mp->bitmap, start);
		if (pos == mp->bitmap->bits) {
			ret = -EBUSY;
			goto err_free_memzone;
		}
		set_bit(mp->bitmap, pos);

		if (alloc_memzone(bp, mp->addr + pos * mp->blk_size,
				  MIN(blk_num, blk_num_per_memblk),
				  pos, pos) < 0) {
			ret = -ENOMEM;
			goto err_clear_bit;
		}

		mp->free_blk_num--;
		mp->real_size -= mp->blk_size;
		blk_num -= blk_num_per_memblk;
		start = pos++;
	}

	return 0;

err_clear_bit:
	clear_bit(mp->bitmap, pos);
err_free_memzone:
	free_mem_to_mempool(bp);
	return ret;
}

/*
 * In this case, multiple continuous mem blocks should be allocated for one
 * block in blkpool
 */
static int alloc_mem_one_need_multi(struct mempool *mp, struct blkpool *bp)
{
	int memblk_num_per_blk = bp->blk_size / mp->blk_size +
				 (bp->blk_size % mp->blk_size ? 1 : 0);
	int start = 0, pos_first, pos, pos_last, i, j;
	int blk_num = bp->depth;
	int ret;

	while (blk_num > 0) {
		pos_first = find_next_zero_bit(mp->bitmap, start);
		if (pos_first == mp->bitmap->bits) {
			ret = -EBUSY;
			goto err_free_memzone;
		}
		set_bit(mp->bitmap, pos_first);
		pos = pos_first + 1;

		for (i = 0; i < memblk_num_per_blk - 1; i++) {
			if (!test_and_set_bit(mp->bitmap, pos++)) {
				break;
			}
		}

		if (i == memblk_num_per_blk - 1) {
			/* alloc memzone and insert list */
			if (alloc_memzone(bp,
				mp->addr + pos_first * mp->blk_size,
				1, pos_first, pos - 1) < 0) {
				pos_last = pos - 1;
				ret = -ENOMEM;
				goto err_clear_bit;

			}
			blk_num--;
		} else {
			pos_last = pos - 2;
			ret = -EBUSY;
			goto err_clear_bit;
		}

		mp->free_blk_num -= memblk_num_per_blk;
		mp->real_size -= mp->blk_size * memblk_num_per_blk;
		start = pos;
	}

	return 0;

err_clear_bit:
	for (j = pos_last; j >= pos_first; j--)
		clear_bit(mp->bitmap, j);
err_free_memzone:
	free_mem_to_mempool(bp);
	return ret;
}

static int alloc_mem_from_mempool(struct mempool *mp, struct blkpool *bp)
{
	if (bp->blk_size * bp->depth > mp->real_size) {
		WD_ERR("Fail to create blockpool as mempool too small: %lu\n",
		       mp->real_size);
		return -ENOMEM;
	}

	TAILQ_INIT(&bp->mz_list);

	if (mp->blk_size >= bp->blk_size)
		return alloc_mem_multi_in_one(mp, bp);

	return alloc_mem_one_need_multi(mp, bp);
}

static int init_blkpool_elem(struct blkpool *bp)
{
	struct memzone *iter;
	int i, index = 0;

	bp->blk_elem = calloc(bp->depth, sizeof(void *));
	if (!bp->blk_elem)
		return -ENOMEM;

	TAILQ_FOREACH(iter, &bp->mz_list, node) {
		for (i = 0; i < iter->blk_num; i++)
			bp->blk_elem[index++] = iter->addr + i * bp->blk_size;
	}

	return 0;
}

handle_t wd_blockpool_create(handle_t mempool, size_t block_size,
			     size_t block_num)
{
	struct mempool *mp = (struct mempool*)mempool;
	struct blkpool *bp;
	int ret;

	if (!mp) {
		WD_ERR("Mempool is NULL\n");
		return 0;
	}

	bp = calloc(1, sizeof(struct blkpool));
	if (!bp)
		return 0;

	bp->top = block_num;
	bp->depth = block_num;
	bp->blk_size = block_size;
	bp->free_block_num = block_num;
	bp->mp = mp;

	wd_spinlock(&mp->lock);
	ret = alloc_mem_from_mempool(mp, bp);
	wd_unspinlock(&mp->lock);
	if (ret < 0) {
		WD_ERR("Fail to allocate memory from mempool\n");
		goto err_free_bp;
	}

	ret = init_blkpool_elem(bp);
	if (ret < 0) {
		WD_ERR("Fail to init blockpool\n");
		goto err_free_mem;
	}

	return (handle_t)bp;

err_free_mem:
	wd_spinlock(&mp->lock);
	free_mem_to_mempool(bp);
	wd_unspinlock(&mp->lock);
err_free_bp:
	free(bp);
	return 0;
}

void wd_blockpool_destory(handle_t blockpool)
{
	struct blkpool *bp = (struct blkpool *)blockpool;

	wd_spinlock(&bp->mp->lock);
	free_mem_to_mempool(bp);
	wd_unspinlock(&bp->mp->lock);
	free(bp->blk_elem);
	free(bp);
}

/* todo: merge with same function in wd.c */
static int get_value_from_sysfs(char *path)
{
	char buf[MAX_ATTR_STR_SIZE];
	ssize_t size;
	int fd;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		WD_ERR("Fail to open %s\n", path);
		return -errno;
	}

	size = read(fd, buf, sizeof(buf));
	if (size <= 0) {
		WD_ERR("Fail to read %s\n", path);
		return -errno;
	}

	return strtol(buf, NULL, 10);
}

/* hp_dir is e.g. /sys/kernel/mm/hugepages/hugepages-64kB */
static int get_hugepage_info_per_type(struct dirent *hp_dir,
				      struct sys_hugepage_config *cfg)
{
	char path[MAX_ATTR_STR_SIZE];
	char *name = hp_dir->d_name;
	unsigned long size;
	char *size_pos;
	int ret;

	size_pos = index(name, '-');
	if (!size_pos)
		return -1;
	size_pos++;

	errno = 0;
	size = strtol(size_pos, NULL, 10);
	if (errno)
		return -errno;
	cfg->page_size = size << 10;

	snprintf(path, sizeof(path), "%s/%s/nr_hugepages", SYSFS_HUGEPAGE_PATH,
		 name);	
	ret = get_value_from_sysfs(path);
	if (ret < 0)
		return ret;
	cfg->total_num = ret;

	snprintf(path, sizeof(path), "%s/%s/free_hugepages",
		 SYSFS_HUGEPAGE_PATH, name);
	ret = get_value_from_sysfs(path);
	if (ret < 0)
		return ret;
	cfg->free_num = ret;

	return 1;
}

/* This function also sorts hugepage from small to big */
static int get_hugepage_info(struct mempool *mp)
{
	struct sys_hugepage_config *tmp, *iter;
	struct dirent *hp_dir;
	DIR *dir;
	int ret;

	dir = opendir(SYSFS_HUGEPAGE_PATH);
	if (!dir) {
		WD_ERR("Fail to open %s\n", SYSFS_HUGEPAGE_PATH);
		return -errno;
	}

	TAILQ_INIT(&mp->hp_list);
	for (hp_dir = readdir(dir); hp_dir != NULL; hp_dir = readdir(dir)) {
		if (!strncmp(hp_dir->d_name, ".", 1) ||
		    !strncmp(hp_dir->d_name, "..", 2))
			continue;

		tmp = calloc(1, sizeof(*tmp));
		if (!tmp) {
			WD_ERR("Fail to allocate memory\n");
			goto err_free_list;
		}
		ret = get_hugepage_info_per_type(hp_dir, tmp);
		if (ret < 0) {
			WD_ERR("Fail to get hugepage info\n");
			goto err_free;
		}

		/* list: page size small -> big */
		TAILQ_FOREACH(iter, &mp->hp_list, node) {
			if (tmp->page_size < iter->page_size) {
				TAILQ_INSERT_BEFORE(iter, tmp, node);
				break;
			}
		}

		if (!iter)
			TAILQ_INSERT_TAIL(&mp->hp_list, tmp, node);
	}

	closedir(dir);

	return 0;

err_free:
	free(tmp);
err_free_list:
	while ((tmp = TAILQ_LAST(&mp->hp_list, sys_hugepage_list))) {
		TAILQ_REMOVE(&mp->hp_list, tmp, node);
		free(tmp);
	}
	return -1;
}

static void put_hugepage_info(struct mempool *mp)
{
	struct sys_hugepage_config *tmp;

	while ((tmp = TAILQ_LAST(&mp->hp_list, sys_hugepage_list))) {
		TAILQ_REMOVE(&mp->hp_list, tmp, node);
		free(tmp);
	}
}

static int alloc_mem_from_hugepage(struct mempool *mp)
{
	unsigned long max_node = numa_max_node() + 1;
	unsigned long node_mask = 1 << mp->node;
	struct sys_hugepage_config *iter;
	unsigned long bits = sizeof(iter->page_size) * 8;
	size_t page_num, real_size;
	int ret, flags = 0;
	void *p;

	ret = get_hugepage_info(mp);
	if (ret < 0)
		return ret;

	/* find proper hugepage: use small huge page if possible */
	TAILQ_FOREACH(iter, &mp->hp_list, node) {
		if (iter->page_size * iter->free_num >= mp->size)
			break;
	}
	if (!iter) {
		WD_ERR("Fail to find proper hugepage\n");
		ret = -ENOMEM;
		goto err_put_info;
	}

	/* alloc hugepage and bind */
	page_num = mp->size / iter->page_size +
		   (mp->size % iter->page_size ? 1 : 0);
	real_size = page_num * iter->page_size;
	/*
	 * man mmap will tell, flags of mmap can be used to indicate hugepage
	 * size. In fact, after kernel 3.18, it has been supported. See more
	 * in kernel header file: linux/include/uapi/linux/mman.h. As related
	 * macro has not been put into glibc, we caculate them here, e.g.
	 * flags for 64KB is 16 << 26.
	 */
	flags = _find_next_bit(&iter->page_size, bits, 0, 0UL) <<
		HUGETLB_FLAG_ENCODE_SHIFT;
	p = mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_PRIVATE |
		 MAP_ANONYMOUS | MAP_HUGETLB | flags, -1, 0);
	if (p == MAP_FAILED) {
		WD_ERR("Fail to allocate huge page\n");
		ret = -ENOMEM;
		goto err_put_info;
	}

	/* fixme: I am not sure node_mask and max_node's value are right here */
	ret = mbind(p, real_size, MPOL_BIND, &node_mask, max_node, 0);
	if (ret < 0) {
		WD_ERR("Fail to mbind huge page, %d\n", errno);
		goto err_unmap;
	}

	mp->page_type = WD_HUGE_PAGE;
	mp->page_size = iter->page_size;
	mp->page_num = page_num;
	mp->addr = p;
	mp->real_size = real_size;

	return 0;

err_unmap:
	munmap(p, real_size);
err_put_info:
	put_hugepage_info(mp);
	return ret;
}

static void free_hugepage_mem(struct mempool *mp)
{
	munmap(mp->addr, mp->page_size * mp->page_num);
	put_hugepage_info(mp);
}

static int alloc_mem_and_pin(struct mempool *mp)
{
	size_t page_size = wd_get_page_size();
	size_t page_num = mp->size / page_size + (mp->size % page_size ? 1 : 0);
	size_t real_size = page_size * page_num;
	int fd, ret, node = mp->node;
	struct uacce_pin_address addr;
	unsigned long node_mask = 1 << node;
	unsigned long max_node = numa_max_node() + 1;
	void *p;

	p = mmap(NULL, real_size, PROT_READ | PROT_WRITE, MAP_PRIVATE |
		 MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		WD_ERR("Fail to do mmap\n");
		return -1;
	}

	/* fixme: I am not sure node_mask and max_node's value are right here */
	ret = mbind(p, real_size, MPOL_BIND, &node_mask, max_node, 0);
	if (ret < 0) {
		WD_ERR("Fail to do mbind, maybe there is no memory in NUMA node %d\n",
		       node);
		goto err_unmap;
	}

	fd = open("/dev/uacce_ctrl", O_RDWR);
	if (fd < 0) {
		WD_ERR("Fail to open\n");
		ret = -errno;
		goto err_unmap;
	}

	addr.addr = (unsigned long)p;
	addr.size = real_size;
	ret = ioctl(fd, UACCE_CMD_PIN, &addr);
	if (ret < 0) {
		WD_ERR("Fail to pin\n");
		goto err_close;
	}

	mp->page_type = WD_NORMAL_PAGE;
	mp->page_size = page_size;
	mp->page_num = page_num;
	mp->fd = fd;
	mp->addr = p;
	mp->real_size = real_size;

	return 0;

err_close:
	close(fd);
err_unmap:
	munmap(p, real_size);	
	return ret;
}

static void free_pin_mem(struct mempool *mp)
{
	struct uacce_pin_address addr;

	addr.addr = (unsigned long)mp->addr;
	addr.size = mp->page_size * mp->page_num;
	ioctl(mp->fd, UACCE_CMD_UNPIN, &addr);

	close(mp->fd);
	munmap(mp->addr, mp->page_size * mp->page_num);
}

static int alloc_mempool_memory(struct mempool *mp)
{
	int ret;

	/* try to alloc from hugepage firstly */
	ret = alloc_mem_from_hugepage(mp);
	if (!ret) {
		return 0;
	}

	ret = alloc_mem_and_pin(mp);
	if (ret < 0) {
		WD_ERR("Fail to mmap and pin\n");
		free_hugepage_mem(mp);
		return -ENOMEM;
	}

	return 0;
}

static void free_mempool_memory(struct mempool *mp)
{
	if (mp->page_type == WD_HUGE_PAGE)
		munmap(mp->addr, mp->page_size * mp->page_num);
	else
		free_pin_mem(mp);
}

static int init_mempool(struct mempool *mp)
{
	int bits = mp->page_size * mp->page_num / mp->blk_size;
	struct bitmap *bm;

	bm = create_bitmap(bits);
	if (!bm)
		return -1;
	mp->bitmap = bm;
	mp->free_blk_num = bits;

	return 0;
}

static void uninit_mempool(struct mempool *mp)
{
	destory_bitmap(mp->bitmap);
	mp->bitmap = NULL;
}

handle_t wd_mempool_create(size_t size, int node)
{
	struct mempool *mp;
	int ret;

	if (!size || node < 0 || node > numa_max_node()) {
		return 0;
	}

	mp = calloc(1, sizeof(*mp));
	if (!mp) {
		return 0;
	}
	mp->node = node;
	mp->size = size;
	/* Let's set it as 4KB temporarily */
	mp->blk_size = 4 << 10;

	ret = alloc_mempool_memory(mp);
	if (ret < 0) {
		goto free_pool;
	}

	ret = init_mempool(mp);
	if (ret < 0) {
		goto free_pool_memory;
	}

	return (handle_t)mp;

free_pool_memory:
	free_mempool_memory(mp);
free_pool:
	free(mp);
	return 0;
}

void wd_mempool_destory(handle_t mempool)
{
	struct mempool *mp = (struct mempool *)mempool;
	
	/* todo: consider ref_count here */
	uninit_mempool(mp);
	free_mempool_memory(mp);
	free(mp);
}

void wd_mempool_stats(handle_t mempool, struct wd_mempool_stats *stats)
{
	struct mempool *mp = (struct mempool *)mempool;

	wd_spinlock(&mp->lock);

	stats->page_type = mp->page_type;
	stats->page_size = mp->page_size;
	stats->page_num = mp->page_num;
	stats->blk_size = mp->blk_size;
	stats->blk_num = mp->page_num * mp->page_size / mp->blk_size;
	stats->free_blk_num = mp->free_blk_num;
	stats->blk_usage_rate = (stats->blk_num - mp->free_blk_num) * 100 /
				stats->blk_num;

	wd_unspinlock(&mp->lock);
}

void wd_blockpool_stats(handle_t blockpool, struct wd_blockpool_stats *stats)
{
	struct blkpool *bp = (struct blkpool*)blockpool;
	unsigned long size = 0;
	struct memzone *iter;

	wd_spinlock(&bp->lock);

	stats->block_size = bp->blk_size;
	stats->block_num = bp->depth;
	stats->free_block_num = bp->free_block_num;
	stats->block_usage_rate = (bp->depth - bp->free_block_num) * 100 /
				  bp->depth;

	TAILQ_FOREACH(iter, &bp->mz_list, node) {
		size += (iter->end - iter->begin + 1) * bp->mp->blk_size;
	}
	stats->mem_waste_rate = (size - bp->blk_size * bp->depth) * 100 / size;

	wd_unspinlock(&bp->lock);
}
