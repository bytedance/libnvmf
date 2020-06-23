INCLUDES += -I../include

CFLAGS += -D_GNU_SOURCE
CFLAGS += $(INCLUDES)
CFLAGS += -g -O2 -fno-strict-aliasing
CFLAGS += -Wall -Wstrict-prototypes -Werror -fPIC
ifneq ($(MALLOC_DEBUG),)
CFLAGS += -DMALLOC_DEBUG
endif

LIBS = ../lib/libnvmf.a -lpthread
ifneq ($(USE_RDMA),)
LIBS += -lrdmacm -libverbs
endif

%.o: %.c 
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

fio:
	$(CC) nvmf-fio.c $(CFLAGS) $(LIBS) $(OBJS) -o nvmf-fio

dd:
	$(CC) nvmf-dd.c $(CFLAGS) $(LIBS) $(OBJS) -o nvmf-dd

check:
	$(CC) nvmf-check.c $(CFLAGS) $(LIBS) $(OBJS) -o nvmf-check

header:
	$(CC) test-header.c $(CFLAGS) $(OBJS) -o test-header

llist:
	$(CC) test-llist.c $(CFLAGS) $(OBJS) -lpthread -o test-llist

clean:
	rm -f *.d *.o test-header test-llist nvmf-dd nvmf-fio nvmf-check
