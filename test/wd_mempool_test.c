#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
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

#define WD_MEM_MAX_THREAD		20

struct test_option {
	unsigned long mp_size;
	int node;
	unsigned long blk_size[WD_MEM_MAX_THREAD];
	unsigned long blk_num[WD_MEM_MAX_THREAD];
	unsigned long sleep_value[WD_MEM_MAX_THREAD];
	unsigned long perf;
	unsigned thread_num;
};

struct test_opt_per_thread {
	unsigned long mp_size;
	int node;
	unsigned long blk_size;
	unsigned long blk_num;
	unsigned long sleep_value;
	unsigned thread_num;

	handle_t mp, bp;
};

static void show_help(void)
{
	printf(" --mp_size <size>  mempool size\n"
	       " --node <node>     numa node of mempool\n"
	       " --blk_size_array <\"size1 size2 ...\">\n"
	       "                  size of each block pool\n "
	       " --blk_num_array <\"num1 num2 ...\">\n"
	       "                 block num of each block pool\n"
	       " --sleep_value <\"value1 value2 ...\">\n"
	       "               test thread will sleep some time between\n"
	       "               allocating and freeing memory, these values\n"
	       "               are for this purpose\n"
	       " --perf <mode> 0 for mempool, 1 for block pool\n"
	       " --thread_num <mode> if perf mode 0, thread is for blockpool\n"
	       "                     create/destory from mempool. if perf\n"
	       "                     mode 1, thread is for alloc/free memory\n"
	       "                     in blockpool\n"
	       " --help show this help\n");
}

static void parse_value_in_string(unsigned long *array, unsigned long num,
				  char *string)
{
}

static int parse_cmd_line(int argc, char *argv[], struct test_option *opt)
{
        int option_index = 0;
	int ret, c;

        static struct option long_options[] = {
            {"mp_size", required_argument, 0,  1},
            {"node", required_argument, 0,  2},
            {"blk_size_array", required_argument, 0,  3},
            {"blk_num_array", required_argument, 0,  4},
            {"sleep_value", required_argument, 0,  5},
            {"perf", required_argument, 0,  6},
            {"thread_num", required_argument, 0,  7},
            {"help", no_argument, 0,  8},
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
			parse_value_in_string(opt->blk_size, WD_MEM_MAX_THREAD,
					      optarg);
			break;
		case 4:
			parse_value_in_string(opt->blk_num, WD_MEM_MAX_THREAD,
					      optarg);
			break;
		case 5:
			parse_value_in_string(opt->sleep_value,
					      WD_MEM_MAX_THREAD, optarg);
			break;
		case 6:
			opt->perf = strtol(optarg, NULL, 0);
			break;
		case 7:
			opt->thread_num = strtol(optarg, NULL, 0);
			break;
		case 8:
			show_help();
			ret = -1;
			break;
		default:

			printf("bad input parameter, exit\n");
			exit(-1);
		}
	}

	return 0;
}

static void dump_mp_bp(struct wd_mempool_stats *mp_s,
		       struct wd_blockpool_stats *bp_s)
{
	printf("mp page_type        : %s\n", mp_s->page_type ? "pin" : "hugepage");
	printf("mp page_size        : %lu\n", mp_s->page_size);
	printf("mp page_num         : %lu\n", mp_s->page_num);
	printf("mp blk_size         : %lu\n", mp_s->blk_size);
	printf("mp blk_num          : %lu\n", mp_s->blk_num);
	printf("mp free_blk_num     : %lu\n", mp_s->free_blk_num);
	printf("mp blk_usage_rate   : %lu%%\n\n", mp_s->blk_usage_rate);

	printf("bp block_size       : %lu\n", bp_s->block_size);
	printf("bp block_num        : %lu\n", bp_s->block_num);
	printf("bp free_block_num   : %lu\n", bp_s->free_block_num);
	printf("bp block_usage_rate : %lu%%\n", bp_s->block_usage_rate);
	printf("bp mem_waste_rate   : %lu%%\n", bp_s->mem_waste_rate);
}

void *alloc_free_thread(void *data)
{
	struct test_opt_per_thread *opt = data;
	int ret, i, j;
	char *p;

	/* fix me: temporarily make iterate num to 100 */
	for (i = 0; i < 100; i++) {
		p = wd_blockpool_alloc(opt->bp);
		if (!p) {
			ret = -1;
			printf("Fail to alloc mem\n");
		}

		for (j = 0; j < 10; j++) {
			*(p + j) = 8;
		}

		sleep(opt->sleep_value);

		wd_blockpool_free(opt->bp, p);
	}

	return NULL;
}

void *blk_test_thread(void *data)
{
	struct test_opt_per_thread *opt = data;
	struct wd_blockpool_stats bp_stats = {0};
	struct wd_mempool_stats mp_stats = {0};
	handle_t mp, bp;

	mp = wd_mempool_create(opt->mp_size, opt->node);
	if (!mp) {
		printf("Fail to create mempool\n");
		return (void *)-1;
	}

	bp = wd_blockpool_create(mp, opt->blk_size, opt->blk_num);
	if (!bp) {
		printf("Fail to create blkpool\n");
		return (void *)-1;
	}

	if (!opt->thread_num) {
		sleep(opt->sleep_value);
		/* fix me: need a opt? */
		if (1) {
			wd_mempool_stats(mp, &mp_stats);
			wd_blockpool_stats(bp, &bp_stats);
			dump_mp_bp(&mp_stats, &bp_stats);
		}
	} else {
		/* create thread_num threads to allocate/free memory */
		pthread_t threads[WD_MEM_MAX_THREAD];
		int i;

		for (i = 0; i < opt->thread_num; i++)
			opt->mp = mp;
			opt->bp = bp;
			pthread_create(&threads[i], NULL, alloc_free_thread, &opt);
		for (i = 0; i < opt->thread_num; i++) {
			pthread_join(threads[i], NULL);
		}
	}

	wd_blockpool_destory(bp);
	wd_mempool_destory(mp);

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t threads[WD_MEM_MAX_THREAD];
	struct test_opt_per_thread per_thread_opt[WD_MEM_MAX_THREAD] = {0};
	struct test_option opt = {0};
	int i, ret, bp_thread_num;

	ret = parse_cmd_line(argc, argv, &opt);
	if (ret < 0)
		return -1;

	if (!opt.perf) {
		bp_thread_num = opt.thread_num;
	} else {
		bp_thread_num = 1;
	}

	for (i = 0; i < bp_thread_num; i++) {
		per_thread_opt[i].mp_size = opt.mp_size;
		per_thread_opt[i].node = opt.node;
		per_thread_opt[i].blk_size = opt.blk_size[i];
		per_thread_opt[i].blk_num = opt.blk_num[i];
		per_thread_opt[i].sleep_value = opt.sleep_value[i];
		per_thread_opt[i].thread_num = !opt.perf ? 0 : opt.thread_num;

		pthread_create(&threads[i], NULL, blk_test_thread, &opt);
	}

	for (i = 0; i < bp_thread_num; i++) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}
