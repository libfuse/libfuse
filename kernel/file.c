/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#ifdef KERNEL_2_6
#include <linux/writeback.h>
#include <linux/moduleparam.h>
#endif
#include <asm/uaccess.h>

static int user_mmap;
#ifdef KERNEL_2_6
module_param(user_mmap, int, 0644);
#else
MODULE_PARM(user_mmap, "i");
#define PageUptodate(page) Page_Uptodate(page)
#endif
MODULE_PARM_DESC(user_mmap, "Allow non root user to create a shared writable mapping");

static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_open_in inarg;
	struct fuse_open_out outarg;
	struct fuse_file *ff;
	int err;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	/* If opening the root node, no lookup has been performed on
	   it, so the attributes must be refreshed */
	if (get_node_id(inode) == FUSE_ROOT_ID) {
		int err = fuse_do_getattr(inode);
		if (err)
		 	return err;
	}

	down(&inode->i_sem);
	err = -ERESTARTSYS;
	req = fuse_get_request(fc);
	if (!req)
		goto out;

	err = -ENOMEM;
	ff = kmalloc(sizeof(struct fuse_file), GFP_KERNEL);
	if (!ff)
		goto out_put_request;

	ff->release_req = fuse_request_alloc();
	if (!ff->release_req) {
		kfree(ff);
		goto out_put_request;
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_OPEN;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err && !(fc->flags & FUSE_KERNEL_CACHE)) {
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif
	}
	if (err) {
		fuse_request_free(ff->release_req);
		kfree(ff);
	}
	else {
		ff->fh = outarg.fh;
		file->private_data = ff;
		INIT_LIST_HEAD(&ff->ff_list);
	}

 out_put_request:
	fuse_put_request(fc, req);
 out:
	up(&inode->i_sem);
	return err;
}

void fuse_sync_inode(struct inode *inode)
{
#ifdef KERNEL_2_6
	filemap_fdatawrite(inode->i_mapping);
	filemap_fdatawait(inode->i_mapping);
#else
#ifndef NO_MM
	filemap_fdatasync(inode->i_mapping);
	filemap_fdatawait(inode->i_mapping);
#endif
#endif
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->release_req;
	struct fuse_release_in inarg;
	
	down(&inode->i_sem);
	if (file->f_mode & FMODE_WRITE)
		fuse_sync_inode(inode);

	if (!list_empty(&ff->ff_list)) {
		struct fuse_inode *fi = get_fuse_inode(inode);
		down_write(&fi->write_sem);
		list_del(&ff->ff_list);
		up_write(&fi->write_sem);
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_RELEASE;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	fuse_put_request(fc, req);
	kfree(ff);
	up(&inode->i_sem);

	/* Return value is ignored by VFS */
	return 0;
}

static int fuse_flush(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->release_req;
	struct fuse_flush_in inarg;
	int err;
	
	if (fc->no_flush)
		return 0;

	down(&inode->i_sem);
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_reset_request(req);
	up(&inode->i_sem);
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	return err;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
	struct inode *inode = de->d_inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_fsync_in inarg;
	int err;
	
	if (fc->no_fsync)
		return 0;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	/* Make sure all writes to this inode are completed before
	   issuing the FSYNC request */
	down_write(&fi->write_sem);
	up_write(&fi->write_sem);

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.datasync = datasync;
	req->in.h.opcode = FUSE_FSYNC;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (err == -ENOSYS) {
		fc->no_fsync = 1;
		err = 0;
	}
	fuse_put_request(fc, req);
	return err;
}

static void fuse_read_init(struct fuse_req *req, struct file *file,
			   struct inode *inode, loff_t pos, size_t count)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_read_in *inarg = &req->misc.read_in;

	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	req->in.h.opcode = FUSE_READ;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_read_in);
	req->in.args[0].value = inarg;
	req->out.argpages = 1;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = count;
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_request_nonint(fc);
	loff_t pos = (loff_t) page->index << PAGE_SHIFT;
	int err;
	
	fuse_read_init(req, file, inode, pos, PAGE_SIZE);
	req->out.page_zeroing = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err)
		SetPageUptodate(page);
	unlock_page(page);
	return err;
}

#ifdef KERNEL_2_6
static void read_pages_end(struct fuse_conn *fc, struct fuse_req *req)
{
	unsigned i;
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (!req->out.h.error)
			SetPageUptodate(page);
		unlock_page(page);
	}
	fuse_put_request(fc, req);
}

static void fuse_send_readpages(struct fuse_req *req, struct file *file,
				struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	loff_t pos = (loff_t) req->pages[0]->index << PAGE_SHIFT;
	size_t count = req->num_pages << PAGE_SHIFT;
	fuse_read_init(req, file, inode, pos, count);
	req->out.page_zeroing = 1;
	request_send_async(fc, req, read_pages_end);
}

struct fuse_readpages_data {
	struct fuse_req *req;
	struct file *file;
	struct inode *inode;
};

static int fuse_readpages_fill(void *_data, struct page *page)
{
	struct fuse_readpages_data *data = _data;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	
	if (req->num_pages && 
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_SIZE > fc->max_read ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		struct fuse_conn *fc = get_fuse_conn(page->mapping->host);
		fuse_send_readpages(req, data->file, inode);
		data->req = req = fuse_get_request_nonint(fc);
	}
	req->pages[req->num_pages] = page;
	req->num_pages ++;
	return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_readpages_data data;

	data.req = fuse_get_request_nonint(fc);
	data.file = file;
	data.inode = inode;
	
	read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
	if (data.req->num_pages)
		fuse_send_readpages(data.req, file, inode);
	else
		fuse_put_request(fc, data.req);

	return 0;
}
#else /* KERNEL_2_6 */
#define FUSE_BLOCK_SHIFT 16
#define FUSE_BLOCK_SIZE (1UL << FUSE_BLOCK_SHIFT)
#define FUSE_BLOCK_MASK (~(FUSE_BLOCK_SIZE-1))
#if (1UL << (FUSE_BLOCK_SHIFT - PAGE_SHIFT)) > FUSE_MAX_PAGES_PER_REQ
#error FUSE_BLOCK_SHIFT too large
#endif

static int fuse_is_block_uptodate(struct inode *inode, unsigned start,
				  unsigned end)
{
	int index;

	for (index = start; index < end; index++) {
		struct page *page = find_get_page(inode->i_mapping, index);
		if (!page)
			return 0;
		if (!PageUptodate(page)) {
			page_cache_release(page);
			return 0;
		}
		page_cache_release(page);
	}
	return 1;
}

static void fuse_file_read_block(struct fuse_req *req, struct file *file,
				 struct inode *inode, unsigned start,
				 unsigned end)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	loff_t pos;
	size_t count;
	int index;
	int err = 1;
	int i;

	for (index = start; index < end; index++) {
		struct page *page = grab_cache_page(inode->i_mapping, index);
		if (!page)
			goto out;
		if (PageUptodate(page)) {
			unlock_page(page);
			page_cache_release(page);
			page = NULL;
		} 
		req->pages[req->num_pages++] = page;
	}
	pos = (loff_t) start << PAGE_SHIFT;
	count = req->num_pages << PAGE_SHIFT;
	fuse_read_init(req, file, inode, pos, count);
	request_send(fc, req);
	err = req->out.h.error;
 out:
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (page) {
			if (!err)
				SetPageUptodate(page);
			unlock_page(page);
			page_cache_release(page);
		}
	}
}   

static int fuse_file_bigread(struct file *file, struct inode *inode,
			     loff_t pos, size_t count)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	unsigned starti;
	unsigned endi;
	unsigned nexti;
	struct fuse_req *req;
	loff_t size = i_size_read(inode);
	loff_t end = (pos + count + FUSE_BLOCK_SIZE - 1) & FUSE_BLOCK_MASK;
	end = min(end, size);
	if (end <= pos)
		return 0;

	starti = (pos & FUSE_BLOCK_MASK) >> PAGE_SHIFT;
	endi = (end + PAGE_SIZE - 1) >> PAGE_SHIFT;
	
	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	for (; starti < endi; starti = nexti) {
		nexti = starti + (FUSE_BLOCK_SIZE >> PAGE_SHIFT);
		nexti = min(nexti, endi);
		if (!fuse_is_block_uptodate(inode, starti, nexti)) {
			fuse_file_read_block(req, file, inode, starti, nexti);
			fuse_reset_request(req);
		}
	}
	fuse_put_request(fc, req);
	return 0;
}
#endif /* KERNEL_2_6 */

static void fuse_write_init(struct fuse_req *req, struct fuse_file *ff,
			    struct inode *inode, loff_t pos, size_t count,
			    int iswritepage)
{
	struct fuse_write_in *inarg = &req->misc.write.in;

	inarg->writepage = iswritepage;
	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = get_node_id(inode);
	if (iswritepage) {
		req->in.h.uid = 0;
		req->in.h.gid = 0;
		req->in.h.pid = 0;
	}
	req->in.argpages = 1;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(struct fuse_write_in);
	req->in.args[0].value = inarg;
	req->in.args[1].size = count;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_write_out);
	req->out.args[0].value = &req->misc.write.out;
}

static int get_write_count(struct inode *inode, struct page *page)
{
	unsigned long end_index;
	loff_t size = i_size_read(inode);
	int count;
	
	end_index = size >> PAGE_SHIFT;
	if (page->index < end_index)
		count = PAGE_SIZE;
	else {
		count = size & (PAGE_SIZE - 1);
		if (page->index > end_index || count == 0)
			return 0;
	}
	return count;
}

static inline struct fuse_file *get_write_file(struct fuse_inode *fi)
{
	BUG_ON(list_empty(&fi->write_files));
	return list_entry(fi->write_files.next, struct fuse_file, ff_list);
}

#ifdef KERNEL_2_6
static void write_page_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct page *page = req->pages[0];
	struct inode *inode = page->mapping->host;
	struct fuse_inode *fi = get_fuse_inode(inode);
	if (!req->out.h.error &&
	    req->misc.write.out.size != req->in.args[1].size)
		req->out.h.error = -EPROTO;

	if (req->out.h.error) {
		SetPageError(page);
		if (req->out.h.error == -ENOSPC)
			set_bit(AS_ENOSPC, &page->mapping->flags);
		else
			set_bit(AS_EIO, &page->mapping->flags);
	}
	up_read(&fi->write_sem);
	end_page_writeback(page);
	fuse_put_request(fc, req);
}

static int fuse_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	int err;

	err = -EWOULDBLOCK;
	if (wbc->nonblocking)
		req = fuse_get_request_nonblock(fc);
	else
		req = fuse_get_request_nonint(fc);
	if (req) {
		int locked = 1;
		if (wbc->nonblocking)
			locked = down_read_trylock(&fi->write_sem);
		else
			down_read(&fi->write_sem);
		if (locked) {
			unsigned count = get_write_count(inode, page);
			loff_t pos = (loff_t) page->index << PAGE_SHIFT;
			err = 0;
			if (count) {
				struct fuse_file *ff = get_write_file(fi);
				SetPageWriteback(page);
				fuse_write_init(req, ff, inode, pos, count, 1);
				req->num_pages = 1;
				req->pages[0] = page;
				request_send_async(fc, req, write_page_end);
				goto out;
			}
			up_read(&fi->write_sem);
		}
		fuse_put_request(fc, req);
	}
	if (err == -EWOULDBLOCK) {
#ifdef KERNEL_2_6_6_PLUS
		redirty_page_for_writepage(wbc, page);
#else
		__set_page_dirty_nobuffers(page);
#endif
		err = 0;
	}
 out:
	unlock_page(page);
	return err;
}
#else
static int fuse_writepage(struct page *page)
{
	int err;
	unsigned count;
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req = fuse_get_request_nonint(fc);

	down_read(&fi->write_sem);
	count = get_write_count(inode, page);
	err = 0;
	if (count) {
		struct fuse_file *ff = get_write_file(fi);
		loff_t pos = ((loff_t) page->index << PAGE_SHIFT);

		fuse_write_init(req, ff, inode, pos, count, 1);
		req->num_pages = 1;
		req->pages[0] = page;
		request_send(fc, req);
		err = req->out.h.error;
		if (!err && req->misc.write.out.size != count)
			err = -EPROTO;
	}
	up_read(&fi->write_sem);
	fuse_put_request(fc, req);
	if (err)
		SetPageError(page);
	unlock_page(page);
	return err;
}
#endif

static int fuse_prepare_write(struct file *file, struct page *page,
			      unsigned offset, unsigned to)
{
	/* No op */
	return 0;
}

static int fuse_commit_write(struct file *file, struct page *page,
			     unsigned offset, unsigned to)
{
	int err;
	unsigned count = to - offset;
	struct inode *inode = page->mapping->host;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_request(fc);
	loff_t pos = ((loff_t) page->index << PAGE_SHIFT) + offset;
	if (!req)
		return -ERESTARTSYS;

	fuse_write_init(req, ff, inode, pos, count, 0);
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_offset = offset;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err && req->misc.write.out.size != count)
		err = -EPROTO;
	if (!err) {
		pos += count;
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		
		if (offset == 0 && to == PAGE_SIZE) {
#ifdef KERNEL_2_6
			clear_page_dirty(page);
#else
			ClearPageDirty(page);
#endif
			SetPageUptodate(page);
		}
	}
	fuse_put_request(fc, req);
	return err;
}

static void fuse_release_user_pages(struct fuse_req *req, int write)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (write) {
#ifdef KERNEL_2_6
			set_page_dirty_lock(page);
#else
			lock_page(page);
			set_page_dirty(page);
			unlock_page(page);
#endif
		}
		page_cache_release(page);
	}
}

static int fuse_get_user_pages(struct fuse_req *req, const char __user *buf,
			       unsigned nbytes, int write)
{
	unsigned long user_addr = (unsigned long) buf;
	unsigned offset = user_addr & ~PAGE_MASK;
	int npages;

	nbytes = min(nbytes, (unsigned) FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT);
	npages = (nbytes + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
	npages = min(npages, FUSE_MAX_PAGES_PER_REQ);
	npages = get_user_pages(current, current->mm, user_addr, npages, write,
				0, req->pages, NULL);
	if (npages < 0)
		return npages;

	req->num_pages = npages;
	req->page_offset = offset;
	return 0;
}

static ssize_t fuse_direct_io(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos, int write)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	unsigned nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	ssize_t res = 0;
	struct fuse_req *req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	while (count) {
		unsigned tmp;
		unsigned nres;
		size_t nbytes = min(count, nmax);
		int err = fuse_get_user_pages(req, buf, nbytes, !write);
		if (err) {
			res = err;
			break;
		}
		tmp = (req->num_pages << PAGE_SHIFT) - req->page_offset;
		nbytes = min(nbytes, tmp);
		if (write)
			fuse_write_init(req, ff, inode, pos, nbytes, 0);
		else
			fuse_read_init(req, file, inode, pos, nbytes);
		request_send(fc, req);
		fuse_release_user_pages(req, !write);
		if (req->out.h.error) {
			if (!res)
				res = req->out.h.error;
			break;
		}
		if (write) {
			nres = req->misc.write.out.size;
			if (nres > nbytes) {
				res = -EPROTO;
				break;
			}
		}
		else
			nres = req->out.args[0].size;
		count -= nres;
		res += nres;
		pos += nres;
		buf += nres;
		if (nres != nbytes)
			break;
		if (count)
			fuse_reset_request(req);
	}
	fuse_put_request(fc, req);
	if (res > 0) {
		if (write && pos > i_size_read(inode))
			i_size_write(inode, pos);
		*ppos = pos;
	}
	return res;
}

static ssize_t fuse_file_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	ssize_t res;

	if (fc->flags & FUSE_DIRECT_IO)
		res = fuse_direct_io(file, buf, count, ppos, 0);
	else {
#ifndef KERNEL_2_6
		if (fc->flags & FUSE_LARGE_READ) {
			down(&inode->i_sem);
			res = fuse_file_bigread(file, inode, *ppos, count);
			up(&inode->i_sem);
			if (res)
				return res;
		}
#endif
		res = generic_file_read(file, buf, count, ppos);
	}
	return res;
}  

static ssize_t fuse_file_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	
	if (fc->flags & FUSE_DIRECT_IO) {
		ssize_t res;
		down(&inode->i_sem);
		res = fuse_direct_io(file, buf, count, ppos, 1);
		up(&inode->i_sem);
		return res;
	}
	else 
		return generic_file_write(file, buf, count, ppos);
}
			       
static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (fc->flags & FUSE_DIRECT_IO)
		return -ENODEV;
	else {
		if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == 
		    (VM_WRITE | VM_SHARED)) {
			struct fuse_inode *fi = get_fuse_inode(inode);
			struct fuse_file *ff = file->private_data;

			if (!user_mmap && current->uid != 0)
				return -EPERM;

			down_write(&fi->write_sem);
			if (list_empty(&ff->ff_list))
				list_add(&ff->ff_list, &fi->write_files);
			up_write(&fi->write_sem);
		}
		return generic_file_mmap(file, vma);
	}
}

static struct file_operations fuse_file_operations = {
	.read		= fuse_file_read,
	.write		= fuse_file_write,
	.mmap		= fuse_file_mmap,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
#ifdef KERNEL_2_6
	.sendfile	= generic_file_sendfile,
#endif
};

static struct address_space_operations fuse_file_aops  = {
	.readpage	= fuse_readpage,
	.writepage	= fuse_writepage,
	.prepare_write	= fuse_prepare_write,
	.commit_write	= fuse_commit_write,
#ifdef KERNEL_2_6
	.readpages	= fuse_readpages,
	.set_page_dirty = __set_page_dirty_nobuffers,
#endif
};

void fuse_init_file_inode(struct inode *inode)
{
	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
}
