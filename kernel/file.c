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

static int user_mmap;
#ifdef KERNEL_2_6
#include <linux/moduleparam.h>
module_param(user_mmap, int, 0);
#else
MODULE_PARM(user_mmap, "i");
#endif

MODULE_PARM_DESC(user_mmap, "Allow non root user to create a shared writable mapping");


static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
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
	if (fi->nodeid == FUSE_ROOT_ID) {
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
	req->in.h.nodeid = fi->nodeid;
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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_release_in *inarg;
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->release_req;
	
	down(&inode->i_sem);
	if (file->f_mode & FMODE_WRITE)
		fuse_sync_inode(inode);

	if (!list_empty(&ff->ff_list)) {
		down_write(&fi->write_sem);
		list_del(&ff->ff_list);
		up_write(&fi->write_sem);
	}

	inarg = &req->misc.release_in;
	inarg->fh = ff->fh;
	inarg->flags = file->f_flags & ~O_EXCL;
	req->in.h.opcode = FUSE_RELEASE;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_release_in);
	req->in.args[0].value = inarg;
	request_send_nonint(fc, req);
	fuse_put_request(fc, req);
	kfree(ff);
	up(&inode->i_sem);

	/* Return value is ignored by VFS */
	return 0;
}

static int fuse_flush(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
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
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send_nonint(fc, req);
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
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_conn *fc = INO_FC(inode);
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
	req->in.h.nodeid = fi->nodeid;
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

static ssize_t fuse_send_read(struct file *file, struct inode *inode,
			      char *buf, loff_t pos, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_read_in inarg;
	ssize_t res;
	
	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_READ;
	req->in.h.nodeid = fi->nodeid;
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

	pos = (loff_t) page->index << PAGE_CACHE_SHIFT;
	buffer = kmap(page);
	res = fuse_send_read(file, inode, buffer, pos, PAGE_CACHE_SIZE);
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

#ifdef KERNEL_2_6

static int read_pages_copyout(struct fuse_req *req, const char *buf,
			      size_t nbytes)
{
	unsigned i;
	unsigned long base_index = req->pages[0]->index;
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		unsigned long offset;
		unsigned count;
		char *tmpbuf;
		int err;

		offset = (page->index - base_index) * PAGE_CACHE_SIZE;
		if (offset >= nbytes)
			count = 0;
		else if (offset + PAGE_CACHE_SIZE <= nbytes)
			count = PAGE_CACHE_SIZE;
		else
			count = nbytes - offset;

		tmpbuf = kmap(page);
		err = 0;
		if (count)
			err = copy_from_user(tmpbuf, buf + offset, count);
		if (count < PAGE_CACHE_SIZE)
			memset(tmpbuf + count, 0, PAGE_CACHE_SIZE - count);
		kunmap(page);
		if (err)
			return -EFAULT;

		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	return 0;
}

static void read_pages_end(struct fuse_conn *fc, struct fuse_req *req)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++)
		unlock_page(req->pages[i]);
	
	fuse_put_request(fc, req);
}

static void fuse_send_readpages(struct fuse_req *req, struct file *file,
				struct inode *inode)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_read_in *inarg;
	loff_t pos;
	unsigned numpages;
	
	pos = (loff_t) req->pages[0]->index << PAGE_CACHE_SHIFT;
	/* Allow for holes between the pages */
	numpages = req->pages[req->num_pages - 1]->index + 1 
		- req->pages[0]->index;
	
	inarg = &req->misc.read_in;
	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = numpages * PAGE_CACHE_SIZE;
	req->in.h.opcode = FUSE_READ;
	req->in.h.nodeid = fi->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_read_in);
	req->in.args[0].value = inarg;
	req->copy_out = read_pages_copyout;
	request_send_nonblock(fc, req, read_pages_end, NULL);
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
	struct fuse_conn *fc = INO_FC(inode);
	
	if (req->num_pages && 
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_CACHE_SIZE > fc->max_read ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		struct fuse_conn *fc = INO_FC(page->mapping->host);
		fuse_send_readpages(req, data->file, inode);
		data->req = req = fuse_get_request(fc);
	}
	req->pages[req->num_pages] = page;
	req->num_pages ++;
	return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_readpages_data data;

	data.req = fuse_get_request(fc);
	data.file = file;
	data.inode = inode;
	
	read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
	if (data.req->num_pages)
		fuse_send_readpages(data.req, file, inode);
	else
		fuse_put_request(fc, data.req);

	return 0;
}
#endif

#ifndef KERNEL_2_6
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

static int fuse_file_read_block(struct file *file, struct inode *inode,
				char *bl_buf, size_t bl_index)
{
	ssize_t res;
	loff_t offset;
	
	offset = (loff_t) bl_index << FUSE_BLOCK_SHIFT;
	res = fuse_send_read(file, inode, bl_buf, offset, FUSE_BLOCK_SIZE);
	if (res >= 0) {
		if (res < FUSE_BLOCK_SIZE)
			memset(bl_buf + res, 0, FUSE_BLOCK_SIZE - res);
		res = 0;
	}
	return res;
}   

static void fuse_file_bigread(struct file *file, struct inode *inode,
			      loff_t pos, size_t count)
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
			res = fuse_file_read_block(file, inode, bl_buf,
						   bl_index);
		if (!res)
			fuse_cache_block(inode, bl_buf, bl_index);
		kfree(bl_buf);
		bl_index++;
	}
}
#endif

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
		res1 = fuse_send_read(file, inode, tmpbuf, pos, nbytes);
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
#ifndef KERNEL_2_6
		if (fc->flags & FUSE_LARGE_READ) {
			down(&inode->i_sem);
			fuse_file_bigread(file, inode, *ppos, count);
			up(&inode->i_sem);
		}
#endif
		res = generic_file_read(file, buf, count, ppos);
	}

	return res;
}  

static ssize_t fuse_send_write(struct fuse_req *req, int writepage,
			       struct fuse_file *ff, struct inode *inode,
			       const char *buf, loff_t pos, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_in inarg;
	struct fuse_write_out outarg;
	ssize_t res;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.writepage = writepage;
	inarg.fh = ff->fh;
	inarg.offset = pos;
	inarg.size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = fi->nodeid;
	if (writepage) {
		req->in.h.uid = 0;
		req->in.h.gid = 0;
		req->in.h.pid = 0;
	}
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

static int write_buffer(struct inode *inode, struct file *file,
			struct page *page, unsigned offset, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_file *ff = file->private_data;
	char *buffer;
	ssize_t res;
	loff_t pos;
	struct fuse_req *req;

	req = fuse_get_request(fc);
	if (!req)
		return -ERESTARTSYS;
	
	pos = ((loff_t) page->index << PAGE_CACHE_SHIFT) + offset;
	buffer = kmap(page);
	res = fuse_send_write(req, 0, ff, inode, buffer + offset, pos, count);
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
		struct fuse_file *ff;
		BUG_ON(list_empty(&fi->write_files));
		ff = list_entry(fi->write_files.next, struct fuse_file, ff_list);
		pos = ((loff_t) page->index << PAGE_CACHE_SHIFT);
		buffer = kmap(page);
		res = fuse_send_write(req, 1, ff, inode, buffer, pos, count);
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
	struct fuse_inode *fi = INO_FI(inode);
	struct fuse_write_in *inarg;
	struct fuse_file *ff;
	char *buffer;

	BUG_ON(list_empty(&fi->write_files));
	ff = list_entry(fi->write_files.next, struct fuse_file, ff_list);
	
	inarg = &req->misc.write.in;
	buffer = kmap(page);
	inarg->writepage = 1;
	inarg->fh = ff->fh;
	inarg->offset = ((loff_t) page->index << PAGE_CACHE_SHIFT);
	inarg->size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = fi->nodeid;
	req->in.h.uid = 0;
	req->in.h.gid = 0;
	req->in.h.pid = 0;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)
			redirty_page_for_writepage(wbc, page);
#else
			__set_page_dirty_nobuffers(page);
#endif
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

	err = write_buffer(inode, file, page, offset, to - offset);
	if (!err) {
		loff_t pos = (page->index << PAGE_CACHE_SHIFT) + to;
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		
		if (offset == 0 && to == PAGE_CACHE_SIZE) {
#ifdef KERNEL_2_6
			clear_page_dirty(page);
#else
			ClearPageDirty(page);
#endif
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
	struct fuse_file *ff = file->private_data;
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
		res1 = fuse_send_write(req, 0, ff, inode, tmpbuf, pos, nbytes);
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
	else {
		if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == 
		    (VM_WRITE | VM_SHARED)) {
			struct fuse_inode *fi = INO_FI(inode);
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

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */
