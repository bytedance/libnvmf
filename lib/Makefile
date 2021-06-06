PREFIX = /usr
VERSION = 0.1
LIB_NAME = libnvmf
#### config end ####

include pkg-config.mk

INCLUDES += -I../include -I../include/nvmf
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

$(LIB_NAME): $(OBJS)
	$(CC) -shared $(CFLAGS) $(LIBS) $(OBJS) -o libnvmf.so
	$(AR) rcs libnvmf.a $(OBJS)

pkgconfig:
	$(file > $(LIB_NAME).pc.in,$(PKG_DESCRIBE_CONFIG))
	$(file > $(LIB_NAME).pc,$(PKG_PATH_CONFIG))
	@cat $(LIB_NAME).pc.in >> $(LIB_NAME).pc
	@rm -f $(LIB_NAME).pc.in

clean:
	rm -f *.d *.o *.so *.a *.pc *.pc.in

install: $(LIB_NAME) pkgconfig
	cp -R ../include/nvmf $(PREFIX)/include/nvmf
	mkdir -p $(PREFIX)/lib
	cp libnvmf.a libnvmf.so $(PREFIX)/lib
	cp $(LIB_NAME).pc  /usr/share/pkgconfig
