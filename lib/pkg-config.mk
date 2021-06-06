define PKG_PATH_CONFIG
prefix=$(PREFIX)
libdir=$${prefix}/lib
includedir=$${prefix}/include
endef

define PKG_DESCRIBE_CONFIG
Name: libnvmf
Description: The NVMe over Fabrics userspace library
Version: ${VERSION}
Cflags: -I$${includedir}
Libs: -L$${libdir} $(LIBS) -lnvmf
endef
