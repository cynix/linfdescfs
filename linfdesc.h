/*-
 * Copyright (c) 1992, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 2017 Brian Chu. All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef _KERNEL

#define LFD_FORCE_UNMOUNT 0x01

struct linfdesc_mount {
	struct vnode *lfd_root;
	int lfd_flags;
};

#define FD_ROOT 1
#define FD_DESC 3

typedef enum {
	LFDN_ROOT,
	LFDN_DESC,
} linfdesc_node_type;

struct linfdesc_node {
	LIST_ENTRY(linfdesc_node) lfd_link;
	struct vnode *lfd_vnode;
	linfdesc_node_type lfd_type;
	int lfd_fd;
	int lfd_idx;
};

#define VFSTOLFD(mp) ((struct linfdesc_mount *)(mp)->mnt_data)
#define VTOLFD(vp) ((struct linfdesc_node *)(vp)->v_data)

extern struct mtx linfdesc_hashmtx;

extern vfs_init_t linfdesc_init;
extern vfs_uninit_t linfdesc_uninit;
extern int linfdesc_allocvp(linfdesc_node_type, int fd, int idx, struct mount *, struct vnode **);

#endif /* _KERNEL */
