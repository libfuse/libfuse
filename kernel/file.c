/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#ifdef KERNEL_2_6
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#endif

#ifndef KERNEL_2_6
#define PageUptodate(page) Page_Uptodate(page)
#endif

static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	struct fuse_req *req2;
	struct fuse_open_in inarg;
	int err;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	/* If opening the root node, no lookup has been performed on
	   it, so the attributes must be refreshed */
	if (inode->i_ino == FUSE_ROOT_INO) {
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
	req2 = fuse_request_alloc();
	if (!req2)
		goto out_put_request;

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_OPEN;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	if (!err && !(fc->flags & FUSE_KERNEL_CACHE)) {
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif
	}
	if (err)
		fuse_request_free(req2);
	else
		file->private_data = req2;

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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_open_in *inarg;
	struct fuse_req *req = file->private_data;
	
	down(&inode->i_sem);
	if (file->f_mode & FMODE_WRITE)
		fuse_sync_inode(inode);

	inarg = &req->misc.open_in;
	inarg->flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_RELEASE;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_open_in);
	req->in.args[0].value = inarg;
	request_send(fc, req);
	fuse_put_request(fc, req);
	up(&inode->i_sem);

	/* Return value is ignored by VFS */
	return 0;
}

static int fuse_flush(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	int err;
	
	if (fc->no_flush)
		return 0;

	req = fuse_get_request(fc);
	if (!req)
		return -EINTR;

	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.ino = inode->i_ino;
	request_send(fc, req);
	err = req->out.h.error;
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	fuse_put_request(fc, req);
	return err;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
	struct inode *inode = de->d_inode;
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_conn *fc = INO_FC(inode);
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
	inarg.datasync = datasync;
	req->in.h.opcode = FUSE_FSYNC;
	req->in.h.ino = inode->i_ino;
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

static ssize_t fuse_send_read(struct inode *inode, char *buf, loff_t pos,
			      size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_req *req;
	struct fuse_read_in inarg;
	ssize_t res;
	
	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_READ;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = count;
	req->out.args[0].value = buf;
	request_send(fc, req);
	res = req->out.h.error;
	if (!res)
		res = req->out.args[0].size;
	fuse_put_request(fc, req);
	return res;
}


static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	char *buffer;
	ssize_t res;
	loff_t pos;

	pos = (unsigned long long) page->index << PAGE_CACHE_SHIFT;
	buffer = kmap(page);
	res = fuse_send_read(inode, buffer, pos, PAGE_CACHE_SIZE);
	if (res >= 0) {
		if (res < PAGE_CACHE_SIZE) 
			memset(buffer + res, 0, PAGE_CACHE_SIZE - res);
		flush_dcache_page(page);
		SetPageUptodate(page);
		res = 0;
	}
	kunmap(page);
	unlock_page(page);
	return res;
}

static int fuse_is_block_uptodate(struct inode *inode, size_t bl_index)
{
	size_t index = bl_index << FUSE_BLOCK_PAGE_SHIFT;
	size_t end_index = ((bl_index + 1) << FUSE_BLOCK_PAGE_SHIFT) - 1;
	size_t file_end_index = i_size_read(inode) >> PAGE_CACHE_SHIFT;

	if (end_index > file_end_index)
		end_index = file_end_index;

	for (; index <= end_index; index++) {
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


static int fuse_cache_block(struct inode *inode, char *bl_buf,
			    size_t bl_index)
{
	size_t start_index = bl_index << FUSE_BLOCK_PAGE_SHIFT;
	size_t end_index = ((bl_index + 1) << FUSE_BLOCK_PAGE_SHIFT) - 1;
	size_t file_end_index = i_size_read(inode) >> PAGE_CACHE_SHIFT;

	int i;

	if (end_index > file_end_index)
		end_index = file_end_index;

	for (i = 0; start_index + i <= end_index; i++) {
		size_t index = start_index + i;
		struct page *page;
		char *buffer;

		page = grab_cache_page(inode->i_mapping, index);
		if (!page)
			return -1;

		if (!PageUptodate(page)) {
			buffer = kmap(page);
			memcpy(buffer, bl_buf + i * PAGE_CACHE_SIZE,
					PAGE_CACHE_SIZE);
			flush_dcache_page(page);
			SetPageUptodate(page);
			kunmap(page);
		}

		unlock_page(page);
		page_cache_release(page);
	}

	return 0;
} 

static int fuse_file_read_block(struct inode *inode, char *bl_buf,
				size_t bl_index)
{
	ssize_t res;
	loff_t offset;
	
	offset = (unsigned long long) bl_index << FUSE_BLOCK_SHIFT;
	res = fuse_send_read(inode, bl_buf, offset, FUSE_BLOCK_SIZE);
	if (res >= 0) {
		if (res < FUSE_BLOCK_SIZE)
			memset(bl_buf + res, 0, FUSE_BLOCK_SIZE - res);
		res = 0;
	}
	return res;
}   

static void fuse_file_bigread(struct inode *inode, loff_t pos, size_t count)
{
	size_t bl_index = pos >> FUSE_BLOCK_SHIFT;
	size_t bl_end_index = (pos + count) >> FUSE_BLOCK_SHIFT;
	size_t bl_file_end_index = i_size_read(inode) >> FUSE_BLOCK_SHIFT;
	
	if (bl_end_index > bl_file_end_index)
		bl_end_index = bl_file_end_index;
	
	while (bl_index <= bl_end_index) {
		int res;
		char *bl_buf = kmalloc(FUSE_BLOCK_SIZE, GFP_KERNEL);
		if (!bl_buf)
			break;
		res = fuse_is_block_uptodate(inode, bl_index);
		if (!res)
			res = fuse_file_read_block(inode, bl_buf, bl_index);
		if (!res)
			fuse_cache_block(inode, bl_buf, bl_index);
		kfree(bl_buf);
		bl_index++;
	}
}

static ssize_t fuse_read(struct file *file, char *buf, size_t count,
			 loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	char *tmpbuf;
	ssize_t res = 0;
	loff_t pos = *ppos;
	unsigned int max_read = count < fc->max_read ? count : fc->max_read;

	do {
		tmpbuf = kmalloc(max_read, GFP_KERNEL);
		if (tmpbuf)
			break;
		
		max_read /= 2;
	} while (max_read > PAGE_CACHE_SIZE / 4);
	if (!tmpbuf)
		return -ENOMEM;

	while (count) {
		size_t nbytes = count < max_read ? count : max_read;
		ssize_t res1;
		res1 = fuse_send_read(inode, tmpbuf, pos, nbytes);
		if (res1 < 0) {
			if (!res)
				res = res1;
			break;
		}
		res += res1;
		if (copy_to_user(buf, tmpbuf, res1)) {
			res = -EFAULT;
			break;
		}
		count -= res1;
		buf += res1;
		pos += res1;
		if (res1 < nbytes)
			break;
	}
	kfree(tmpbuf);

	if (res > 0)
		*ppos += res;

	return res;
}

static ssize_t fuse_file_read(struct file *file, char *buf,
			      size_t count, loff_t * ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	ssize_t res;

	if (fc->flags & FUSE_DIRECT_IO) {
		res = fuse_read(file, buf, count, ppos);
	}
	else {
		if (fc->flags & FUSE_LARGE_READ) {
			down(&inode->i_sem);
			fuse_file_bigread(inode, *ppos, count);
			up(&inode->i_sem);
		}
		res = generic_file_read(file, buf, count, ppos);
	}

	return res;
}  

static ssize_t fuse_send_write(struct fuse_req *req, struct inode *inode,
			       const char *buf, loff_t pos, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	ssize_t res;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = count;
	req->in.args[1].value = buf;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	res = req->out.h.error;
	if (!res)
		return outarg.size;
	else
		return res;
}

static int write_buffer(struct inode *inode, struct page *page,
			unsigned offset, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	char *buffer;
	ssize_t res;
	loff_t pos;
	struct fuse_req *req;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	pos = ((unsigned long long) page->index << PAGE_CACHE_SHIFT) + offset;
	buffer = kmap(page);
	res = fuse_send_write(req, inode, buffer + offset, pos, count);
	fuse_put_request(fc, req);
	if (res >= 0) {
		if (res < count) {
			printk("fuse: short write\n");
			res = -EPROTO;
		} else
			res = 0;
	}
	kunmap(page);
	if (res)
		SetPageError(page);
	return res;
}

static int get_write_count(struct inode *inode, struct page *page)
{
	unsigned long end_index;
	loff_t size = i_size_read(inode);
	int count;
	
	end_index = size >> PAGE_CACHE_SHIFT;
	if (page->index < end_index)
		count = PAGE_CACHE_SIZE;
	else {
		count = size & (PAGE_CACHE_SIZE - 1);
		if (page->index > end_index || count == 0)
			return 0;
	}
	return count;
}


static int write_page_block(struct inode *inode, struct page *page)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	char *buffer;
	ssize_t res;
	loff_t pos;
	unsigned count;
	struct fuse_req *req;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	down_read(&fi->write_sem);
	count = get_write_count(inode, page);
	res = 0;
	if (count) {
		pos = ((unsigned long long) page->index << PAGE_CACHE_SHIFT);
		buffer = kmap(page);
		res = fuse_send_write(req, inode, buffer, pos, count);
		if (res >= 0) {
			if (res < count) {
				printk("fuse: short write\n");
				res = -EPROTO;
			} else
				res = 0;
		}
	}
	up_read(&fi->write_sem);
	fuse_put_request(fc, req);
	kunmap(page);
	if (res)
		SetPageError(page);
	return res;
}


#ifdef KERNEL_2_6


static void write_page_nonblock_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct page *page = (struct page *) req->data;
	struct inode *inode = page->mapping->host;
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_out *outarg = req->out.args[0].value;
	if (!req->out.h.error && outarg->size != req->in.args[1].size) {
		printk("fuse: short write\n");
		req->out.h.error = -EPROTO;
	}

	if (req->out.h.error) {
		SetPageError(page);
		if (req->out.h.error == -ENOSPC)
			set_bit(AS_ENOSPC, &page->mapping->flags);
		else
			set_bit(AS_EIO, &page->mapping->flags);
	}
	up_read(&fi->write_sem);

	end_page_writeback(page);
	kunmap(page);
	fuse_put_request(fc, req);
}

static void send_write_nonblock(struct fuse_req *req, struct inode *inode,
				    struct page *page, unsigned count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_write_in *inarg;
	char *buffer;

	inarg = &req->misc.write.in;
	buffer = kmap(page);
	inarg->offset = ((unsigned long long) page->index << PAGE_CACHE_SHIFT);
	inarg->size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.ino = inode->i_ino;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(struct fuse_write_in);
	req->in.args[0].value = inarg;
	req->in.args[1].size = count;
	req->in.args[1].value = buffer;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_write_out);
	req->out.args[0].value = &req->misc.write.out;
	request_send_nonblock(fc, req, write_page_nonblock_end, page);
}

static int write_page_nonblock(struct inode *inode, struct page *page)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_req *req;
	int err;

	err = -EWOULDBLOCK;
	req = fuse_get_request_nonblock(fc);
	if (req) {
		if (down_read_trylock(&fi->write_sem)) {
			unsigned count;
			err = 0;
			count = get_write_count(inode, page);
			if (count) {
				SetPageWriteback(page);		
				send_write_nonblock(req, inode, page, count);
				return 0;
			}
			up_read(&fi->write_sem);
		}
		fuse_put_request(fc, req);
	}
	return err;
}

static int fuse_writepage(struct page *page, struct writeback_control *wbc)
{
	int err;
	struct inode *inode = page->mapping->host;

	if (wbc->nonblocking) {
		err = write_page_nonblock(inode, page);
		if (err == -EWOULDBLOCK) {
			redirty_page_for_writepage(wbc, page);
			err = 0;
		}
	} else
		err = write_page_block(inode, page);

	unlock_page(page);
	return err;
}
#else
static int fuse_writepage(struct page *page)
{
	int err = write_page_block(page->mapping->host, page);
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
	struct inode *inode = page->mapping->host;

	err = write_buffer(inode, page, offset, to - offset);
	if (!err) {
		loff_t pos = (page->index << PAGE_CACHE_SHIFT) + to;
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		
		if (offset == 0 && to == PAGE_CACHE_SIZE) {
			clear_page_dirty(page);
			SetPageUptodate(page);
		}

	}
	return err;
}

static ssize_t fuse_write(struct file *file, const char *buf, size_t count,
			  loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	char *tmpbuf;
	ssize_t res = 0;
	loff_t pos = *ppos;
	struct fuse_req *req;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;

	tmpbuf = kmalloc(count < fc->max_write ? count : fc->max_write,
			 GFP_KERNEL);
	if (!tmpbuf) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	while (count) {
		size_t nbytes = count < fc->max_write ? count : fc->max_write;
		ssize_t res1;
		if (copy_from_user(tmpbuf, buf, nbytes)) {
			res = -EFAULT;
			break;
		}
		res1 = fuse_send_write(req, inode, tmpbuf, pos, nbytes);
		if (res1 < 0) {
			res = res1;
			break;
		}
		res += res1;
		count -= res1;
		buf += res1;
		pos += res1;
		if (res1 < nbytes)
			break;

		if (count)
			fuse_reset_request(req);
	}
	kfree(tmpbuf);
	fuse_put_request(fc, req);

	if (res > 0) {
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		*ppos = pos;
	}

	return res;
}

static ssize_t fuse_file_write(struct file *file, const char *buf,
			       size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	
	if (fc->flags & FUSE_DIRECT_IO) {
		ssize_t res;
		down(&inode->i_sem);
		res = fuse_write(file, buf, count, ppos);
		up(&inode->i_sem);
		return res;
	}
	else 
		return generic_file_write(file, buf, count, ppos);
}
			       
static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);

	if (fc->flags & FUSE_DIRECT_IO)
		return -ENODEV;
	else
		return generic_file_mmap(file, vma);
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
	.readpage =		fuse_readpage,
	.writepage =		fuse_writepage,
	.prepare_write =	fuse_prepare_write,
	.commit_write =		fuse_commit_write,
#ifdef KERNEL_2_6
	.set_page_dirty =	__set_page_dirty_nobuffers,
#endif
};

void fuse_init_file_inode(struct inode *inode)
{
#ifdef KERNEL_2_6
	struct fuse_conn *fc = INO_FC(inode);
	/* Readahead somehow defeats big reads on 2.6 (says Michael
           Grigoriev) */
	if (fc->flags & FUSE_LARGE_READ)
		inode->i_mapping->backing_dev_info->ra_pages = 0;
#endif
	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
