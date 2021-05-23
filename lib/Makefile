INCLUDES += -I../include

CFLAGS += -D_GNU_SOURCE

ifneq ($(LAT_DEBUG),)
CFLAGS += -DLAT_DEBUG
endif

ifneq ($(DEBUG),)
CFLAGS += -DDEBUG
endif

ifneq ($(MALLOC_DEBUG),)
CFLAGS += -DMALLOC_DEBUG
endif

CFLAGS += $(INCLUDES)
CFLAGS += -g -O2 -fno-strict-aliasing
#CFLAGS += -g -O0 -fno-strict-aliasing
CFLAGS += -Wall -Wstrict-prototypes -Werror -fPIC -Wno-format-truncation -Wno-unused-result

LIBS = -lpthread
OBJS = ctrl.o transport.o transport-tcp.o fabrics.o event.o queue.o options.o utils.o slab.o buddy.o log.o

ifneq ($(USE_RDMA),)
OBJS += transport-rdma.o
CFLAGS += -DUSE_RDMA
LIBS += -lrdmacm -libverbs
endif

%.o: %.c 
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

libnvmf: $(OBJS)
	$(CC) -shared $(CFLAGS) $(LIBS) $(OBJS) -o libnvmf.so
	$(AR) rcs libnvmf.a $(OBJS)

clean:
	rm -f *.d *.o *.so *.a
