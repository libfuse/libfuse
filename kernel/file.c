/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#ifdef KERNEL_2_6
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#endif

#ifndef KERNEL_2_6
#define PageUptodate(page) Page_Uptodate(page)
#define filemap_fdatawrite filemap_fdatasync
#endif

static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_open_in inarg;

	/* If opening the root node, no lookup has been performed on
	   it, so the attributes must be refreshed */
	if(inode->i_ino == FUSE_ROOT_INO) {
		int err = fuse_do_getattr(inode);
		if(err)
		 	return err;
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~O_EXCL;

	in.h.opcode = FUSE_OPEN;
	in.h.ino = inode->i_ino;
	in.numargs = 1;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	request_send(fc, &in, &out);
	if(!out.h.error && !(fc->flags & FUSE_KERNEL_CACHE)) {
#ifdef KERNEL_2_6
		invalidate_inode_pages(inode->i_mapping);
#else
		invalidate_inode_pages(inode);
#endif
	}

	return out.h.error;
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in *in = NULL;
	struct fuse_open_in *inarg = NULL;
	unsigned int s = sizeof(struct fuse_in) + sizeof(struct fuse_open_in);

	if(file->f_mode & FMODE_WRITE)
		filemap_fdatawrite(inode->i_mapping);

	in = kmalloc(s, GFP_NOFS);
	if(!in)
		return -ENOMEM;
	memset(in, 0, s);
	inarg = (struct fuse_open_in *) (in + 1);
	inarg->flags = file->f_flags & ~O_EXCL;

	in->h.opcode = FUSE_RELEASE;
	in->h.ino = inode->i_ino;
	in->numargs = 1;
	in->args[0].size = sizeof(struct fuse_open_in);
	in->args[0].value = inarg;
	if(!request_send_noreply(fc, in))
		return 0;

	kfree(in);
	return 0;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
	struct inode *inode = de->d_inode;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_fsync_in inarg;
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.datasync = datasync;

	in.h.opcode = FUSE_FSYNC;
	in.h.ino = inode->i_ino;
	in.numargs = 1;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	request_send(fc, &in, &out);
	return out.h.error;

	/* FIXME: need to ensure, that all write requests issued
           before this request are completed.  Should userspace take
           care of this? */
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_read_in inarg;
	char *buffer;

	buffer = kmap(page);
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = (unsigned long long) page->index << PAGE_CACHE_SHIFT;
	inarg.size = PAGE_CACHE_SIZE;

	in.h.opcode = FUSE_READ;
	in.h.ino = inode->i_ino;
	in.numargs = 1;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	out.argvar = 1;
	out.numargs = 1;
	out.args[0].size = PAGE_CACHE_SIZE;
	out.args[0].value = buffer;

	request_send(fc, &in, &out);
	if(!out.h.error) {
		size_t outsize = out.args[0].size;
		if(outsize < PAGE_CACHE_SIZE) 
			memset(buffer + outsize, 0, PAGE_CACHE_SIZE - outsize);
		SetPageUptodate(page);
	}

	kunmap(page);
	unlock_page(page);

	return out.h.error;
}

static int fuse_is_block_uptodate(struct address_space *mapping,
		struct inode *inode, size_t bl_index)
{
	size_t index = bl_index << FUSE_BLOCK_PAGE_SHIFT;
	size_t end_index = ((bl_index + 1) << FUSE_BLOCK_PAGE_SHIFT) - 1;
	size_t file_end_index = inode->i_size >> PAGE_CACHE_SHIFT;

	if (end_index > file_end_index)
		end_index = file_end_index;

	for (; index <= end_index; index++) {
		struct page *page = find_get_page(mapping, index);

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


static int fuse_cache_block(struct address_space *mapping,
		struct inode *inode, char *bl_buf,
		size_t bl_index)
{
	size_t start_index = bl_index << FUSE_BLOCK_PAGE_SHIFT;
	size_t end_index = ((bl_index + 1) << FUSE_BLOCK_PAGE_SHIFT) - 1;
	size_t file_end_index = inode->i_size >> PAGE_CACHE_SHIFT;

	int i;

	if (end_index > file_end_index)
		end_index = file_end_index;

	for (i = 0; start_index + i <= end_index; i++) {
		size_t index = start_index + i;
		struct page *page;
		char *buffer;

		page = grab_cache_page(mapping, index);
		if (!page)
			return -1;

		if (!PageUptodate(page)) {
			buffer = kmap(page);
			memcpy(buffer, bl_buf + i * PAGE_CACHE_SIZE,
					PAGE_CACHE_SIZE);
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
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_read_in inarg;

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = bl_index << FUSE_BLOCK_SHIFT;
	inarg.size = FUSE_BLOCK_SIZE;

	in.h.opcode = FUSE_READ;
	in.h.ino = inode->i_ino;
	in.numargs = 1;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	out.argvar = 1;
	out.numargs = 1;
	out.args[0].size = FUSE_BLOCK_SIZE;
	out.args[0].value = bl_buf;

	request_send(fc, &in, &out);

	if (!out.h.error) {
		size_t outsize = out.args[0].size;
		if (outsize < FUSE_BLOCK_SIZE)
			memset(bl_buf + outsize, 0, FUSE_BLOCK_SIZE - outsize);
	}

	return out.h.error;
}   

static void fuse_file_bigread(struct address_space *mapping,
			      struct inode *inode, loff_t pos, size_t count)
{
	size_t bl_index = pos >> FUSE_BLOCK_SHIFT;
	size_t bl_end_index = (pos + count) >> FUSE_BLOCK_SHIFT;
	size_t bl_file_end_index = inode->i_size >> FUSE_BLOCK_SHIFT;
	
	if (bl_end_index > bl_file_end_index)
		bl_end_index = bl_file_end_index;
	
	while (bl_index <= bl_end_index) {
		int res;
		char *bl_buf = kmalloc(FUSE_BLOCK_SIZE, GFP_NOFS);
		if (!bl_buf)
			break;
		res = fuse_is_block_uptodate(mapping, inode, bl_index);
		if (!res)
			res = fuse_file_read_block(inode, bl_buf, bl_index);
		if (!res)
			fuse_cache_block(mapping, inode, bl_buf, bl_index);
		kfree(bl_buf);
		bl_index++;
	}
}

static ssize_t fuse_file_read(struct file *filp, char *buf,
		size_t count, loff_t * ppos)
{
	struct address_space *mapping = filp->f_dentry->d_inode->i_mapping;
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = INO_FC(inode);

	if(fc->flags & FUSE_LARGE_READ)
		fuse_file_bigread(mapping, inode, *ppos, count);

	return generic_file_read(filp, buf, count, ppos);
}  

static int write_buffer(struct inode *inode, struct page *page,
			unsigned offset, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_write_in inarg;
	char *buffer;

	buffer = kmap(page);

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = ((unsigned long long) page->index << PAGE_CACHE_SHIFT) +
		offset;
	inarg.size = count;
	
	in.h.opcode = FUSE_WRITE;
	in.h.ino = inode->i_ino;
	in.numargs = 2;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	in.args[1].size = count;
	in.args[1].value = buffer + offset;
	request_send(fc, &in, &out);
	kunmap(page);
	if(out.h.error)
		SetPageError(page);

	return out.h.error;
}

static int get_write_count(struct inode *inode, struct page *page)
{
	unsigned long end_index;
	int count;
	
	end_index = inode->i_size >> PAGE_CACHE_SHIFT;
	if(page->index < end_index)
		count = PAGE_CACHE_SIZE;
	else {
		count = inode->i_size & (PAGE_CACHE_SIZE - 1);
		if(page->index > end_index || count == 0)
			return 0;
	}
	return count;
}

#ifdef KERNEL_2_6

static void write_buffer_end(struct fuse_conn *fc, struct fuse_in *in,
			     struct fuse_out *out, void *_page)
{
	struct page *page = (struct page *) _page;
	
	lock_page(page);
	if(out->h.error) {
		SetPageError(page);
		if(out->h.error == -ENOSPC)
			set_bit(AS_ENOSPC, &page->mapping->flags);
		else
			set_bit(AS_EIO, &page->mapping->flags);
	}
	end_page_writeback(page);
	kunmap(page);
	unlock_page(page);
	kfree(in);	
}

static int write_buffer_nonblock(struct inode *inode, struct page *page,
				 unsigned offset, size_t count)
{
	int err;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in *in = NULL;
	struct fuse_out *out = NULL;
	struct fuse_write_in *inarg = NULL;
	char *buffer;
	unsigned int s = sizeof(struct fuse_in) + sizeof(struct fuse_out) +
		sizeof(struct fuse_write_in);

	in = kmalloc(s, GFP_NOFS);
	if(!in)
		return -ENOMEM;
	memset(in, 0, s);
	out = (struct fuse_out *)(in + 1);
	inarg = (struct fuse_write_in *)(out + 1);
	
	buffer = kmap(page);

	inarg->offset = ((unsigned long long) page->index << PAGE_CACHE_SHIFT) + offset;
	inarg->size = count;
	
	in->h.opcode = FUSE_WRITE;
	in->h.ino = inode->i_ino;
	in->numargs = 2;
	in->args[0].size = sizeof(struct fuse_write_in);
	in->args[0].value = inarg;
	in->args[1].size = count;
	in->args[1].value = buffer + offset;
	err = request_send_nonblock(fc, in, out, write_buffer_end, page);
	if(err) {
		if(err != -EWOULDBLOCK)
			SetPageError(page);
		kunmap(page);
		kfree(in);
	}
	return err;
}

static int fuse_writepage(struct page *page, struct writeback_control *wbc)
{
	int err;
	struct inode *inode = page->mapping->host;
	unsigned count = get_write_count(inode, page);

	err = -EINVAL;
	if(count) {
		/* FIXME: check sync_mode, and wait for previous writes (or
		   signal userspace to do this) */
		if(wbc->nonblocking) {
			err = write_buffer_nonblock(inode, page, 0, count);
			if(!err)
				SetPageWriteback(page);
			else if(err == -EWOULDBLOCK) {
				__set_page_dirty_nobuffers(page);
				err = 0;
			}
		} else
			err = write_buffer(inode, page, 0, count);
	}

	unlock_page(page);
	return err;
}
#else
static int fuse_writepage(struct page *page)
{
	int err;
	struct inode *inode = page->mapping->host;
	int count = get_write_count(inode, page);
	err = -EINVAL;
	if(count)
		err = write_buffer(inode, page, 0, count);

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
	if(!err) {
		loff_t pos = (page->index << PAGE_CACHE_SHIFT) + to;
		if(pos > inode->i_size)
			inode->i_size = pos;
	}
	return err;
}

static struct file_operations fuse_file_operations = {
	.open =		fuse_open,
	.release =	fuse_release,
	.fsync =	fuse_fsync,
	.read =		fuse_file_read,
	.write =	generic_file_write,
	.mmap =		generic_file_mmap,
};

static struct address_space_operations fuse_file_aops  = {
	.readpage =		fuse_readpage,
	.writepage =		fuse_writepage,
	.prepare_write =	fuse_prepare_write,
	.commit_write =		fuse_commit_write,
};

void fuse_init_file_inode(struct inode *inode)
{
#ifdef KERNEL_2_6
	struct fuse_conn *fc = INO_FC(inode);
	/* Readahead somehow defeats big reads on 2.6 (says Michael
           Grigoriev) */
	if(fc->flags & FUSE_LARGE_READ)
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
