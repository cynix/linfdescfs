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
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/dirent.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include "linfdesc.h"

#define	NLFDCACHE 4
#define LFD_NHASH(idx) (&linfdesc_hashtbl[(idx) & linfdesc_hashmask])
static LIST_HEAD(linfdesc_hashhead, linfdesc_node) *linfdesc_hashtbl;
static u_long linfdesc_hashmask;
struct mtx linfdesc_hashmtx;

static vop_getattr_t linfdesc_getattr;
static vop_lookup_t linfdesc_lookup;
static vop_open_t linfdesc_open;
static vop_readdir_t linfdesc_readdir;
static vop_readlink_t linfdesc_readlink;
static vop_reclaim_t linfdesc_reclaim;

static struct vop_vector linfdesc_vnodeops = {
	.vop_default = &default_vnodeops,

	.vop_access = VOP_NULL,
	.vop_getattr = linfdesc_getattr,
	.vop_lookup = linfdesc_lookup,
	.vop_open = linfdesc_open,
	.vop_pathconf = vop_stdpathconf,
	.vop_readdir = linfdesc_readdir,
	.vop_readlink = linfdesc_readlink,
	.vop_reclaim = linfdesc_reclaim,
};

static void linfdesc_insmntque_dtr(struct vnode *, void *);
static void linfdesc_remove_entry(struct linfdesc_node *);

int
linfdesc_init(struct vfsconf *vfsp)
{
	mtx_init(&linfdesc_hashmtx, "linfdescfs_hash", NULL, MTX_DEF);
	linfdesc_hashtbl = hashinit(NLFDCACHE, M_CACHE, &linfdesc_hashmask);
	return (0);
}

int
linfdesc_uninit(struct vfsconf *vfsp)
{
	hashdestroy(linfdesc_hashtbl, M_CACHE, linfdesc_hashmask);
	mtx_destroy(&linfdesc_hashmtx);
	return (0);
}

int
linfdesc_allocvp(linfdesc_node_type type, int fd, int idx, struct mount *mp, struct vnode **vpp)
{
	struct linfdesc_hashhead *head = LFD_NHASH(idx);
	struct linfdesc_mount *lmp;
	struct linfdesc_node *np, *np2;
	struct vnode *vp, *vp2;
	struct thread *td = curthread;
	int error = 0;

loop:
	mtx_lock(&linfdesc_hashmtx);
	lmp = VFSTOLFD(mp);
	if (lmp == NULL || lmp->lfd_flags & LFD_FORCE_UNMOUNT) {
		mtx_unlock(&linfdesc_hashmtx);
		return (-1);
	}

	LIST_FOREACH(np, head, lfd_link) {
		if (np->lfd_idx == idx && np->lfd_vnode->v_mount == mp) {
			/* Found existing vnode */
			vp = np->lfd_vnode;
			VI_LOCK(vp);
			mtx_unlock(&linfdesc_hashmtx);
			if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, td))
				goto loop;
			*vpp = vp;
			return (0);
		}
	}
	mtx_unlock(&linfdesc_hashmtx);

	np = malloc(sizeof(struct linfdesc_node), M_TEMP, M_WAITOK);
	error = getnewvnode("linfdescfs", mp, &linfdesc_vnodeops, &vp);
	if (error) {
		free(np, M_TEMP);
		return (error);
	}
	np->lfd_vnode = vp;
	np->lfd_type = type;
	np->lfd_fd = fd;
	np->lfd_idx = idx;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	vp->v_data = np;
	switch (type) {
	case LFDN_ROOT:
		vp->v_type = VDIR;
		break;

	case LFDN_DESC:
		vp->v_type = VLNK;
		break;

	default:
		panic("linfdesc_allocvp");
		break;
	}

	error = insmntque1(vp, mp, linfdesc_insmntque_dtr, NULL);
	if (error) {
		*vpp = NULLVP;
		return (error);
	}

	mtx_lock(&linfdesc_hashmtx);
	lmp = VFSTOLFD(mp);
	if (lmp == NULL || lmp->lfd_flags & LFD_FORCE_UNMOUNT) {
		mtx_unlock(&linfdesc_hashmtx);
		vgone(vp);
		vput(vp);
		*vpp = NULLVP;
		return (-1);
	}

	LIST_FOREACH(np2, head, lfd_link) {
		if (np2->lfd_idx == idx && np2->lfd_vnode->v_mount == mp) {
			/* Someone beat us to it */
			vp2 = np2->lfd_vnode;
			VI_LOCK(vp2);
			mtx_unlock(&linfdesc_hashmtx);
			error = vget(vp2, LK_EXCLUSIVE | LK_INTERLOCK, td);
			vgone(vp);
			vput(vp);
			if (error)
				vp2 = NULLVP;
			*vpp = vp2;
			return (error);
		}
	}

	LIST_INSERT_HEAD(head, np, lfd_link);
	mtx_unlock(&linfdesc_hashmtx);
	*vpp = vp;
	return (0);
}

static void
linfdesc_insmntque_dtr(struct vnode *vp, void *arg)
{
	vgone(vp);
	vput(vp);
}

static void
linfdesc_remove_entry(struct linfdesc_node *np)
{
	struct linfdesc_hashhead *head = LFD_NHASH(np->lfd_idx);
	struct linfdesc_node *np2;

	mtx_lock(&linfdesc_hashmtx);
	LIST_FOREACH(np2, head, lfd_link) {
		if (np == np2) {
			LIST_REMOVE(np, lfd_link);
			break;
		}
	}
	mtx_unlock(&linfdesc_hashmtx);
}

struct linfdesc_get_ino_args {
	linfdesc_node_type type;
	unsigned fd;
	int idx;
	struct file *fp;
	struct thread *td;
};

static int
linfdesc_get_ino_alloc(struct mount *mp, void *arg, int lkflags, struct vnode **rvp)
{
	struct linfdesc_get_ino_args *a;
	int error;

	a = arg;
	error = linfdesc_allocvp(a->type, a->fd, a->idx, mp, rvp);
	fdrop(a->fp, a->td);
	return (error);
}

static int
linfdesc_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct linfdesc_node *np = VTOLFD(vp);
	struct vattr *vap = ap->a_vap;

	vap->va_type = vp->v_type;
	vap->va_mode = 0555;
	vap->va_nlink = 1;
	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
	vap->va_fileid = np->lfd_idx;
	vap->va_size = 0;
	vap->va_blocksize = PAGE_SIZE;
	getnanotime(&vap->va_birthtime);
	vap->va_atime = vap->va_mtime = vap->va_ctime = vap->va_birthtime;
	vap->va_gen = 0;
	vap->va_flags = 0;
	vap->va_bytes = 0;
	vap->va_filerev = 0;
	return (0);
}

static int
linfdesc_lookup(struct vop_lookup_args *ap)
{
	struct vnode **vpp = ap->a_vpp;
	struct vnode *dvp = ap->a_dvp, *fvp;
	struct componentname *cnp = ap->a_cnp;
	char *np = cnp->cn_nameptr;
	int nlen = cnp->cn_namelen;
	struct thread *td = cnp->cn_thread;
	struct file *fp;
	struct linfdesc_get_ino_args arg;
	cap_rights_t rights;
	u_int fd, fd1;
	int error;

	if ((cnp->cn_flags & ISLASTCN) && (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME)) {
		error = EROFS;
		goto bad;
	}

	if (nlen <= 0) {
		error = EINVAL;
		goto bad;
	}

	if (nlen == 1 && *np == '.') {
		*vpp = dvp;
		VREF(dvp);
		return (0);
	}

	if (VTOLFD(dvp)->lfd_type != LFDN_ROOT) {
		error = ENOTDIR;
		goto bad;
	}

	if (*np == '0' && nlen != 1) {
		/* Invalid leading zero */
		error = ENOENT;
		goto bad;
	}
	fd = 0;
	while (nlen-- > 0) {
		if (*np < '0' || *np > '9') {
			error = ENOENT;
			goto bad;
		}
		fd1 = 10 * fd + *np++ - '0';
		if (fd1 < fd) {
			error = ENOENT;
			goto bad;
		}
		fd = fd1;
	}

	if ((error = fget(td, fd, cap_rights_init(&rights), &fp)) != 0)
		goto bad;

	if (VTOLFD(dvp)->lfd_idx == FD_DESC + fd) {
		/* fd is root dir */
		vhold(dvp);
		VOP_UNLOCK(dvp, 0);
		fdrop(fp, td);

		vn_lock(dvp, LK_RETRY | LK_EXCLUSIVE);
		vdrop(dvp);
		fvp = dvp;
		if ((dvp->v_iflag & VI_DOOMED) != 0)
			error = ENOENT;
	} else {
		arg.type = LFDN_DESC;
		arg.fd = fd;
		arg.idx = FD_DESC + fd;
		arg.fp = fp;
		arg.td = td;
		error = vn_vget_ino_gen(dvp, linfdesc_get_ino_alloc, &arg, LK_EXCLUSIVE, &fvp);
	}

	if (error)
		goto bad;

	*vpp = fvp;
	return (0);

bad:
	*vpp = NULL;
	return (error);
}

static int
linfdesc_open(struct vop_open_args *ap)
{
	int mode = ap->a_mode;

	/* Don't support locking */
	if ((mode & O_SHLOCK) || (mode & O_EXLOCK))
		return (EOPNOTSUPP);

	return (0);
}

#define DIRENT_SIZE 16

static int
linfdesc_readdir(struct vop_readdir_args *ap)
{
	struct uio *uio = ap->a_uio;
	struct filedesc *fdp;
	struct dirent d;
	int error, i, off, fd;

	if (VTOLFD(ap->a_vp)->lfd_type != LFDN_ROOT)
		panic("linfdesc_readdir");

	if (ap->a_ncookies != NULL)
		*ap->a_ncookies = 0;

	off = (int)uio->uio_offset;
	if (off != uio->uio_offset || off < 0 || (unsigned)off % DIRENT_SIZE != 0 || uio->uio_resid < DIRENT_SIZE)
		return (EINVAL);

	i = (unsigned)off / DIRENT_SIZE;
	error = 0;

	fdp = uio->uio_td->td_proc->p_fd;
	FILEDESC_SLOCK(fdp);
	for (fd = i - 2 /* Account for . and .. */; i < fdp->fd_nfiles + 2 && fd <= 9999999 && uio->uio_resid >= DIRENT_SIZE; ++i, ++fd) {
		bzero((caddr_t)&d, DIRENT_SIZE);

		switch (i) {
		case 0:	/* . */
		case 1: /* .. */
			d.d_fileno = i + FD_ROOT;
			d.d_namlen = i + 1;
			d.d_reclen = DIRENT_SIZE;
			bcopy("..", d.d_name, d.d_namlen);
			d.d_name[i + 1] = '\0';
			d.d_type = DT_DIR;
			break;

		default:
			if (fdp->fd_ofiles[fd].fde_file != NULL) {
				d.d_fileno = i + FD_DESC;
				d.d_namlen = sprintf(d.d_name, "%d", fd);
				d.d_reclen = DIRENT_SIZE;
				d.d_type = DT_LNK;
			}
			break;
		}

		if (d.d_namlen > 0) {
			FILEDESC_SUNLOCK(fdp);
			error = uiomove(&d, DIRENT_SIZE, uio);
			if (error)
				goto done;
			FILEDESC_SLOCK(fdp);
		}
	}
	FILEDESC_SUNLOCK(fdp);

done:
	uio->uio_offset = i * DIRENT_SIZE;
	return (error);
}

static int
linfdesc_readlink(struct vop_readlink_args *ap)
{
	struct uio *uio = ap->a_uio;
	struct vnode *vp = ap->a_vp;
	struct linfdesc_node *np = VTOLFD(vp);
	struct thread *td = uio->uio_td;
	struct file *fp;
	cap_rights_t rights;
	char buf[PATH_MAX];
	struct sbuf sb;
	char *fullpath, *freepath;
	int error, locked;

	if (vp->v_type != VLNK)
		return (EINVAL);

	if ((error = fget(td, np->lfd_fd, cap_rights_init(&rights), &fp)) != 0)
		return (EIO);

	vhold(vp);
	locked = VOP_ISLOCKED(vp);
	VOP_UNLOCK(vp, 0);

	fullpath = "unknown";
	freepath = NULL;
	vn_fullpath(td, fp->f_vnode, &fullpath, &freepath);

	sbuf_new(&sb, buf, sizeof(buf), 0);
	sbuf_cpy(&sb, fullpath);

	if (sbuf_finish(&sb) != 0) {
		sbuf_delete(&sb);
		error = ENAMETOOLONG;
		goto done;
	}

	error = uiomove_frombuf(sbuf_data(&sb), sbuf_len(&sb), uio);
	sbuf_delete(&sb);

done:
	if (freepath != NULL)
		free(freepath, M_TEMP);

	fdrop(fp, td);
	vn_lock(vp, locked | LK_RETRY);
	vdrop(vp);
	return (error);
}

static int
linfdesc_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct linfdesc_node *np = VTOLFD(vp);

	linfdesc_remove_entry(np);
	free(vp->v_data, M_TEMP);
	vp->v_data = NULL;
	return (0);
}
