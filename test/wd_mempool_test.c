#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "../include/wd.h"

#if 0
We consider three problems: 1. Rate of memory usage;
2. performance of alloc/free; 3. memory fragmentation.

1. mempool create from huge page 
2. mempool create from mmap + pin

3. mempool create from huge page, blk pool small block size
4. mempool create from huge page, blk pool big block size

5. mempool create from mmap + pin, blk pool small block size
6. mempool create from mmap + pin, blk pool big block size
#endif

struct test_option {
	unsigned long mp_size;
	int node;
	unsigned long blk_size;
	unsigned long blk_num;
};

static void parse_cmd_line(int argc, char *argv[], struct test_option *opt)
{
        int option_index = 0;
	int c;

        static struct option long_options[] = {
            {"mp_size", required_argument, 0,  1},
            {"node", required_argument, 0,  2},
            {"blk_size", required_argument, 0,  3},
            {"blk_num", required_argument, 0,  4},
            {"perf", required_argument, 0,  5},
            {"thread_num", required_argument, 0,  6},
            {0, 0, 0, 0}
        };

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 1:
			opt->mp_size = strtol(optarg, NULL, 0);
			break;
		case 2:
			opt->node = strtol(optarg, NULL, 0);
			break;
		case 3:
			opt->blk_size = strtol(optarg, NULL, 0);
			break;
		case 4:
			opt->blk_num = strtol(optarg, NULL, 0);
			break;
		default:
			printf("bad input parameter, exit\n");
			exit(-1);
		}
	}
}

static void dump_mp_bp(struct wd_mempool_stats *mp_s,
		       struct wd_blockpool_stats *bp_s)
{
	printf("mp page_type        : %d\n", mp_s->page_type);
	printf("mp page_size        : %lu\n", mp_s->page_size);
	printf("mp page_num         : %lu\n", mp_s->page_num);
	printf("mp blk_size         : %lu\n", mp_s->blk_size);
	printf("mp blk_num          : %lu\n", mp_s->blk_num);
	printf("mp free_blk_num     : %lu\n", mp_s->free_blk_num);
	printf("mp blk_usage_rate   : %lu%%\n", mp_s->blk_usage_rate);

	printf("bp block_size       : %lu\n", bp_s->block_size);
	printf("bp block_num        : %lu\n", bp_s->block_num);
	printf("bp free_block_num   : %lu\n", bp_s->free_block_num);
	printf("bp block_usage_rate : %lu%%\n", bp_s->block_usage_rate);
	printf("bp mem_waste_rate   : %lu%%\n", bp_s->mem_waste_rate);
}

int main(int argc, char *argv[])
{
	struct wd_blockpool_stats bp_stats = {0};
	struct wd_mempool_stats mp_stats = {0};
	struct test_option opt = {0};
	handle_t mp, bp;
	int ret = 0, i;
	char *p;

	parse_cmd_line(argc, argv, &opt);

	mp = wd_mempool_create(opt.mp_size, opt.node);
	if (!mp) {
		printf("Fail to create mempool\n");
		return -1;
	}

	bp = wd_blockpool_create(mp, opt.blk_size, opt.blk_num);
	if (!bp) {
		printf("Fail to create blkpool\n");
		return -1;
	}
#if 0
	p = wd_blockpool_alloc(bp);
	if (!p) {
		ret = -1;
		printf("Fail to alloc mem\n");
	}

	for (i = 0; i < 10; i++) {
		*(p + i) = 8;
	}
#endif
	wd_mempool_stats(mp, &mp_stats);
	wd_blockpool_stats(bp, &bp_stats);

	dump_mp_bp(&mp_stats, &bp_stats);

//	while (1);

//	wd_blockpool_destory(bp);
	wd_mempool_destory(mp);

	return 0;
}
