KMOD = linfdescfs
SRCS = linfdesc_vfsops.c linfdesc_vnops.c vnode_if.h

.include <bsd.kmod.mk>
