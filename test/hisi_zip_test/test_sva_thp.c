#include "test_lib.h"
#include "thp-utils.h"

/*
 * Calling map_huge_memory alone would immediately allocate a huge page on the
 * first fault. Here we want khugepaged to find this range and collapse it, so
 * map and set pages one by one. We can't do bigger chunks because khugepaged
 * doesn't work with compound pages.
 *
 * When @half is set, only initialize half the pages. If
 * /sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none is less than
 * 256, then khugepaged won't collapse the pages until someone faults in the
 * missing pages.
 */
int map_huge_single(void *buf, size_t nr_pages, bool half)
{
        int i;
        void *page;

        for (i = 0; i < nr_pages; i++) {
                if (half && i % 2)
                        /* Create a pte_none entry */
                        page = map_huge_memory(buf + PAGE(i), PAGE_SIZE);
                else
                        /* Map and allocate the page immediately */
                        page = map_and_set_memory(buf + PAGE(i), PAGE_SIZE);
                if (!page)
                        return 1;
        }

        return 0;
}

