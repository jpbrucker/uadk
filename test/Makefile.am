AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../include

bin_PROGRAMS=wd_mempool_test
wd_mempool_test_SOURCES=wd_mempool_test.c
wd_mempool_test_LDADD=-L../.libs -lwd -lpthread
wd_mempool_test_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

SUBDIRS=. hisi_hpre_test hisi_sec_test hisi_zip_test
