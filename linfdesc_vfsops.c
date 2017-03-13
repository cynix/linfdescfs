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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/vnode.h>

#include "linfdesc.h"

static MALLOC_DEFINE(M_LINFDESC_MOUNT, "linfdesc_mount", "linfdescfs mount data");

static vfs_cmount_t linfdesc_cmount;
static vfs_mount_t linfdesc_mount;
static vfs_unmount_t linfdesc_unmount;
static vfs_statfs_t linfdesc_statfs;
static vfs_root_t linfdesc_root;

static int
linfdesc_cmount(struct mntarg *ma, void *data, uint64_t flags)
{
	return kernel_mount(ma, flags);
}

static int
linfdesc_mount(struct mount *mp)
{
	struct linfdesc_mount *lmp;
	struct thread *td = curthread;
	struct vnode *rvp;
	int error = 0;

	if (!prison_allow(td->td_ucred, PR_ALLOW_MOUNT_FDESCFS))
		return (EPERM);

	if (mp->mnt_flag & (MNT_UPDATE | MNT_ROOTFS))
		return (EOPNOTSUPP);

	lmp = malloc(sizeof(struct linfdesc_mount), M_LINFDESC_MOUNT, M_WAITOK);
	lmp->lfd_root = NULL;
	lmp->lfd_flags = 0;
	mp->mnt_data = (qaddr_t)lmp;

	error = linfdesc_allocvp(LFDN_ROOT, -1, FD_ROOT, mp, &rvp);
	if (error) {
		mp->mnt_data = NULL;
		free(lmp, M_LINFDESC_MOUNT);
		return (error);
	}

	rvp->v_type = VDIR;
	rvp->v_vflag |= VV_ROOT;
	lmp->lfd_root = rvp;
	VOP_UNLOCK(rvp, 0);

	vfs_getnewfsid(mp);
	vfs_mountedfrom(mp, "linfdescfs");
	return (0);
}

static int
linfdesc_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct vnode *vp = VFSTOLFD(mp)->lfd_root;

	vget(vp, LK_EXCLUSIVE | LK_RETRY, curthread);
	*vpp = vp;
	return (0);
}

static int
linfdesc_statfs(struct mount *mp, struct statfs *sp)
{
	struct thread *td = curthread;
	struct filedesc *fdp;
	int lim, i, last, freefds;
	uint64_t limit;

	/* Calculate fd limit */
	lim = lim_cur(td, RLIMIT_NOFILE);
	limit = racct_get_limit(td->td_proc, RACCT_NOFILE);
	if (lim > limit)
		lim = limit;

	fdp = td->td_proc->p_fd;
	FILEDESC_SLOCK(fdp);

	last = min(fdp->fd_nfiles, lim);
	freefds = 0;

	/* Count holes */
	for (i = fdp->fd_freefile; i < last; i++)
		if (fdp->fd_ofiles[i].fde_file == NULL)
			++freefds;

	/* The array may not have reached the limit yet */
	if (fdp->fd_nfiles < lim)
		freefds += (lim - fdp->fd_nfiles);

	FILEDESC_SUNLOCK(fdp);

	sp->f_flags = 0;
	sp->f_bsize = PAGE_SIZE;
	sp->f_iosize = PAGE_SIZE;
	sp->f_blocks = 1;
	sp->f_bfree = 0;
	sp->f_bavail = 0;
	sp->f_files = lim + 1; /* Allow for . */
	sp->f_ffree = freefds;
	return (0);
}

static int
linfdesc_unmount(struct mount *mp, int mntflags)
{
	struct linfdesc_mount *lmp = VFSTOLFD(mp);
	caddr_t data;
	int error, flags = 0;

	lmp = VFSTOLFD(mp);
	if (mntflags & MNT_FORCE) {
		mtx_lock(&linfdesc_hashmtx);
		lmp->lfd_flags |= LFD_FORCE_UNMOUNT;
		mtx_unlock(&linfdesc_hashmtx);
		flags |= FORCECLOSE;
	}

	if ((error = vflush(mp, 1, flags, curthread)) != 0)
		return (error);

	mtx_lock(&linfdesc_hashmtx);
	data = mp->mnt_data;
	mp->mnt_data = NULL;
	mtx_unlock(&linfdesc_hashmtx);
	free(data, M_LINFDESC_MOUNT);
	return (0);
}

static struct vfsops linfdesc_vfsops = {
	.vfs_cmount = linfdesc_cmount,
	.vfs_init = linfdesc_init,
	.vfs_mount = linfdesc_mount,
	.vfs_root = linfdesc_root,
	.vfs_statfs = linfdesc_statfs,
	.vfs_uninit = linfdesc_uninit,
	.vfs_unmount = linfdesc_unmount,
};

VFS_SET(linfdesc_vfsops, linfdescfs, VFCF_SYNTHETIC | VFCF_JAIL);
